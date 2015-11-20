/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2015 Jolla Ltd. All rights reserved.
 *  Contact: Hannu Mallat <hannu.mallat@jollamobile.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <inttypes.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>

#include "gobex/gobex.h"
#include "gobex/gobex-apparam.h"

#include "obexd/src/obex.h"
#include "obexd/src/obex-priv.h"
#include "obexd/src/obexd.h"
#include "obexd/src/plugin.h"
#include "obexd/src/service.h"
#include "obexd/src/log.h"
#include "obexd/src/mimetype.h"

#include "obexd/plugins/ctn.h"
#include "obexd/plugins/cnc.h"
#include "obexd/plugins/cas-backend.h"

static const uint8_t CAS_TARGET[TARGET_SIZE] = {
			0x11, 0x5f, 0x1e, 0xc2, 0x29, 0x22, 0x11, 0xe4,
			0xb6, 0x5d, 0xa6, 0xc5, 0xe4, 0xd2, 0x2f, 0xb7 };

enum cas_op {
	CAS_OP_NULL = 0,
	CAS_OP_GET_LISTING,
	CAS_OP_GET_OBJECT,
	CAS_OP_PUT_OBJECT,
	CAS_OP_SET_STATUS,
};

struct access_session {
	struct obex_session *os;

	void *backend_data;

	/* Request state */
	enum cas_op op;
	gboolean finished;

	GObexApparam *inparams;
	ctn_param_t param_mask;

	GObexApparam *outparams;
	gboolean outparams_sent;
	GString *buffer;

	gboolean notify_changes;
	struct cnc_session *notify_session;
	gboolean pending_changes;
	gboolean pending_alarms;
};

static gboolean allow_alarms = TRUE;

static GSList *access_sessions = NULL;

static void access_session_free(struct access_session *as)
{
	access_sessions = g_slist_remove(access_sessions, as);

	if (as->inparams)
		g_obex_apparam_free(as->inparams);

	if (as->outparams)
		g_obex_apparam_free(as->outparams);

	if (as->buffer)
		g_string_free(as->buffer, TRUE);

	g_free(as);
}

static void access_session_reset(struct access_session *as)
{
	cas_backend_abort(as->backend_data);

	as->op = CAS_OP_NULL;

	as->finished = FALSE;

	if (as->inparams) {
		g_obex_apparam_free(as->inparams);
		as->inparams = NULL;
	}

	as->param_mask = 0;

	if (as->outparams) {
		g_obex_apparam_free(as->outparams);
		as->outparams = NULL;
	}

	as->outparams_sent = FALSE;

	if (as->buffer) {
		g_string_free(as->buffer, TRUE);
		as->buffer = NULL;
	}
}

static gboolean trigger_read(gpointer user_data)
{
	struct access_session *as = user_data;
	obex_object_set_io_flags(as, G_IO_IN, 0);
	return FALSE;
}

static ssize_t null_write(void *object, const void *buf, size_t count)
{
	return count;
}

static ssize_t generic_read(void *obj, void *buf, size_t count)
{
	struct access_session *as = obj;
	gsize len;

	DBG("");

	len = as->buffer ? string_read(as->buffer, buf, count) : 0;

	if (len == 0 && !as->finished)
		return -EAGAIN;

	return len;
}

static ssize_t generic_get_next_header(void *object, void *buf, size_t mtu,
								uint8_t *hi)
{
	struct access_session *as = object;

	DBG("");

	if (!as->buffer || (as->buffer->len == 0 && !as->finished))
		return -EAGAIN;

	*hi = G_OBEX_HDR_APPARAM;

	if (as->outparams_sent)
		return 0;

	as->outparams_sent = TRUE;
	if (!as->outparams)
		return 0;

	return g_obex_apparam_encode(as->outparams, buf, mtu);
}

static int generic_close(void *obj)
{
	struct access_session *as = obj;

	DBG("");

	access_session_reset(as);

	return 0;
}

/* GetCTNListing */

static void cas_list_cb(int err, gboolean final, gsize total, gsize count,
				struct ctn_entry *ent, void *user_data)
{
	struct access_session *as = user_data;
	gsize i;

	if (err < 0) {
		obex_object_set_io_flags(as, G_IO_ERR, err);
		as->finished = TRUE;
		return;
	}

	if (!as->buffer)
		as->buffer = g_string_new("<CTN-listing version=\"1.0\">");

	for (i = 0; i < count; i++) {
		gchar handle[CTN_HANDLE_STR_LEN + 1];
		gchar update[CTN_TSTAMP_STR_LEN + 1];
		gchar start[CTN_TSTAMP_STR_LEN + 1];

		ctn_handle2str(&ent[i].handle, handle);
		ctn_tstamp2str(ent[i].update, update);
		ctn_tstamp2str(ent[i].start, start);

		/* print all #REQUIRED attributes first */
		g_string_append_printf(as->buffer,
				"<ctn-entry "
				"handle=\"%s\" update=\"%s\" cal_type=\"%s\" "
				"starttime=\"%s\" size=\"%zu\"",
				handle, update,
				ctn_calendar_type2str(ent[i].type),
				start, ent[i].size);

		/* Append optional attributes as requested */

		if (as->param_mask & CTN_PARAM_SUMMARY)
			g_string_append_printf(as->buffer,
					" summary=\"%.256s\"",
					ent[i].summary ? ent[i].summary : "");

		if ((as->param_mask & CTN_PARAM_ENDTIME) &&
					ent[i].type != CTN_CALENDAR_TYPE_NOTE) {
			gchar end[CTN_TSTAMP_STR_LEN + 1];
			ctn_tstamp2str(ent[i].end, end);
			g_string_append_printf(as->buffer, " endtime=\"%s\"",
									end);
		}

		if (as->param_mask & CTN_PARAM_ORIG_NAME)
			g_string_append_printf(as->buffer,
						" originator_name=\"%.256s\"",
						ent[i].orig_name
						? ent[i].orig_name : "");

		if (as->param_mask & CTN_PARAM_ORIG_ADDR)
			g_string_append_printf(as->buffer,
						" originator_address=\"%.256s\"",
						ent[i].orig_addr
						? ent[i].orig_addr : "");

		if (as->param_mask & CTN_PARAM_PRIORITY)
			g_string_append_printf(as->buffer,
						" priority=\"%s\"",
						ctn_priority2str(ent[i].prio));

		if (as->param_mask & CTN_PARAM_PSTATUS)
			g_string_append_printf(as->buffer,
						" pstatus=\"%s\"",
						ctn_pstatus2str(ent[i].pstatus));

		if (as->param_mask & CTN_PARAM_ALARMSTATUS)
			g_string_append_printf(as->buffer,
						" alarmstatus=\"%s\"",
						ctn_alarm2str(ent[i].alarm));

		if (as->param_mask & CTN_PARAM_SENDSTATUS)
			g_string_append_printf(as->buffer,
						" sendstatus=\"%s\"",
						ent[i].sent ? "yes" : "no");

		if (as->param_mask & CTN_PARAM_RECURRENT)
			g_string_append_printf(as->buffer,
						" recurrent=\"%s\"",
						ent[i].recur ? "yes" : "no");

		g_string_append_printf(as->buffer, ">");

		/* Append attachments only if requested */
		if (as->param_mask & CTN_PARAM_ATTACHMENT) {
			gsize j;
			for (j = 0; j < ent[i].att_count; j++) {
				g_string_append_printf(as->buffer,
							"<attachment"
							" attach_id=\"%zu\""
							" attach_name=\"%.256s\""
							" attach_type=\"%s\""
							" attach_size=\"%zu\"/>",
							j + 1,
							ent[i].att[j].name,
							ent[i].att[j].type,
							ent[i].att[j].size);
			}
		}

		g_string_append_printf(as->buffer, "</ctn-entry>");
	}

	if (final) {
		gchar now[CTN_TSTAMP_STR_LEN + 1];

		ctn_tstamp2str(time(NULL), now);

		as->outparams = g_obex_apparam_set_string(as->outparams,
								CTN_AP_CSETIME,
								now);

		as->outparams = g_obex_apparam_set_uint16(as->outparams,
							CTN_AP_LISTINGSIZE,
							total);

		g_string_append(as->buffer, "</CTN-listing>\n");

		as->finished = TRUE;
	}

	trigger_read(as);
}

static void *cas_listing_open(const char *name, int oflag, mode_t mode,
				void *driver_data, gsize *size, int *err)
{
	struct access_session *as = driver_data;
	uint16_t maxcount = 1024;
	uint16_t offset = 0;
	time_t filter_begin, filter_end;
	time_t *filter_begin_ptr = NULL, *filter_end_ptr = NULL;
	char *apparam_begin = NULL;
	char *apparam_end = NULL;

        DBG("name '%s'", name);

	if (oflag != O_RDONLY) {
		*err = -EBADR;
		return NULL;
        }

	if (as->inparams) {
		g_obex_apparam_get_uint16(as->inparams, CTN_AP_MAXLISTCOUNT,
								&maxcount);
		g_obex_apparam_get_uint16(as->inparams, CTN_AP_LISTSTARTOFFSET,
								&offset);
		g_obex_apparam_get_uint32(as->inparams, CTN_AP_PARAMETERMASK,
								&as->param_mask);

		apparam_begin = g_obex_apparam_get_string(as->inparams,
							CTN_AP_FILTERPERIODBEGIN);
		if (apparam_begin) {
			DBG("FilterPeriodBegin '%s'", apparam_begin);
			if (!ctn_str2tstamp(apparam_begin, &filter_begin)) {
				DBG("Invalid FilterPeriodBegin apparam");
				*err = -EBADR;
				goto out;
			}
			filter_begin_ptr = &filter_begin;
		}

		apparam_end = g_obex_apparam_get_string(as->inparams,
							CTN_AP_FILTERPERIODEND);
		if (apparam_end) {
			DBG("FilterPeriodBegin '%s'", apparam_end);
			if (!ctn_str2tstamp(apparam_end, &filter_end)) {
				DBG("Invalid FilterPeriodEnd apparam");
				*err = -EBADR;
				goto out;
			}
			filter_end_ptr = &filter_end;
		}
	}

	as->op = CAS_OP_GET_LISTING;
	*err = cas_backend_list(as->backend_data, name, maxcount, offset,
				filter_begin_ptr, filter_end_ptr,
				as->param_mask,	cas_list_cb, as);
	if (*err)
		goto out;

out:
	g_free(apparam_begin);
	g_free(apparam_end);
	return (*err < 0) ? NULL : as;
}

static struct obex_mime_type_driver cas_listing_mime = {
	.target = CAS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/CTN-listing",
	.get_next_header = generic_get_next_header,
	.open = cas_listing_open,
	.close = generic_close,
	.read = generic_read,
};

/* GetCTNObject/PutCTNObject */

static void cas_get_cb(int err, const gchar *chunk, gsize length,
			gboolean final, void *user_data)
{
	struct access_session *as = user_data;

	if (err < 0) {
		obex_object_set_io_flags(as, G_IO_ERR, err);
		as->finished = TRUE;
		return;
	}

	g_string_append_len(as->buffer, chunk, length);

	if (final) {
		as->finished = TRUE;
	}

	trigger_read(as);
}

static void *cas_object_open(const char *name, int oflag, mode_t mode,
				void *driver_data, gsize *size, int *err)
{
	struct access_session *as = driver_data;

        DBG("name '%s'", name);

	if (oflag == O_RDONLY) {
		uint8_t recur = 0, attach = 0x01 /* off */, attachid = 0x00;

		if (as->inparams) {
			g_obex_apparam_get_uint8(as->inparams,
							CTN_AP_RECURRENT,
							&recur);
			g_obex_apparam_get_uint8(as->inparams,
							CTN_AP_ATTACHMENT,
							&attach);
			if (attach == 0x02) {
				g_obex_apparam_get_uint8(as->inparams,
							CTN_AP_ATTACHID,
							&attachid);
				if (!attachid) {
					*err = -EBADR;
					return NULL;
				}
			}
		}

		as->op = CAS_OP_GET_OBJECT;
		*err = cas_backend_get(as->backend_data, name, recur, attach,
					attachid, cas_get_cb, as);

	} else {
		gchar outname[CTN_HANDLE_STR_LEN + 1];
		uint8_t send = 0;

		if (as->inparams) {
			g_obex_apparam_get_uint8(as->inparams,
							CTN_AP_SEND,
							&send);
		}

		as->op = CAS_OP_PUT_OBJECT;
		*err = cas_backend_put(as->backend_data, name, send, outname);
		if (!*err) {
			g_free(as->os->rspname);
			as->os->rspname = g_strdup(outname);
		}
        }

	return (*err) ? NULL : as;
}

static ssize_t cas_object_write(void *object, const void *buf, size_t count)
{
	struct access_session *as = object;

	DBG("buf %p count %zu", buf, count);

	if (as->op == CAS_OP_PUT_OBJECT) {
		int err;

		err = cas_backend_put_continue(as->backend_data, buf, count);
		if (err < 0) {
			DBG("Error in storing object");
			obex_object_set_io_flags(as, G_IO_ERR, err);
			as->finished = TRUE;
			return err;
		}

		if (!as->os->final)
			return count;

		err = cas_backend_put_finalize(as->backend_data);
		if (err < 0) {
			DBG("Error in committing object");
			obex_object_set_io_flags(as, G_IO_ERR, err);
			as->finished = TRUE;
			return err;
		}

		as->finished = TRUE;
		return count;
	}

	return -EOPNOTSUPP;
}

static struct obex_mime_type_driver cas_object_mime = {
	.target = CAS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/Calendar",
	.get_next_header = generic_get_next_header,
	.open = cas_object_open,
	.close = generic_close,
	.read = generic_read,
	.write = cas_object_write,
};

/* SetCTNStatus */

/* TODO: by spec the Body header should contain a single byte, 0x30;
   might check its presence for correctness instead of ignoring Body. */

static void *cas_set_status_open(const char *name, int oflag, mode_t mode,
				void *driver_data, gsize *size, int *err)
{
	struct access_session *as = driver_data;
	uint8_t type, value;
	uint32_t postpone = 0;
	enum ctn_status status;
	enum ctn_pstatus pstatus;
	gboolean send = FALSE;

	void *ptr = NULL;

        DBG("name '%s'", name);

	if (oflag == O_RDONLY) {
		*err = -EBADR;
		return NULL;
	}

	if (!g_obex_apparam_get_uint8(as->inparams,
					CTN_AP_STATUSINDICATOR,
					&type) ||
		!g_obex_apparam_get_uint8(as->inparams,
					CTN_AP_STATUSVALUE,
					&value)) {
		*err = -EBADR;
		return NULL;
	}

	type &= 0x03;
	value &= 0x0f;

	if (type == 0x01 && value == 0x02) {
		/* PostponeVal is M if type == alarm && value == postpone */
		if (!g_obex_apparam_get_uint32(as->inparams,
						CTN_AP_POSTPONEVAL,
						&postpone)) {
			*err = -EBADR;
			return NULL;
		}
	} else {
		/* Otherwise X */
		if (g_obex_apparam_get_uint32(as->inparams,
						CTN_AP_POSTPONEVAL,
						&postpone)) {
			*err = -EBADR;
			return NULL;
		}
	}

	switch (type) {

	case 0x00:
		status = CTN_STATUS_PART;
		pstatus =
			value == 0x03 ? CTN_PSTATUS_TENTATIVE :
			value == 0x04 ? CTN_PSTATUS_NEEDS_ACTION :
			value == 0x05 ? CTN_PSTATUS_ACCEPTED :
			value == 0x06 ? CTN_PSTATUS_DECLINED :
			value == 0x07 ? CTN_PSTATUS_DELEGATED :
			value == 0x08 ? CTN_PSTATUS_COMPLETED :
			value == 0x09 ? CTN_PSTATUS_IN_PROCESS :
			CTN_PSTATUS_UNDEFINED;
		if (pstatus == CTN_PSTATUS_UNDEFINED) {
			*err = -EBADR;
			return NULL;
		}
		ptr = &pstatus;
		break;

	case 0x01:
		status = CTN_STATUS_ALARM;
		if (value == 0x00) {
			ptr = NULL;
		} else if (value == 0x01 || value == 0x02) {
			ptr = &postpone;
		} else {
			*err = -EBADR;
			return NULL;
		}
		break;

	case 0x02:
		status = CTN_STATUS_SEND;
		if (value == 0x00) {
			send = FALSE;
		} else if (value == 0x01) {
			send = TRUE;
		} else {
			*err = -EBADR;
			return NULL;
		}
		ptr = &send;
		break;

	case 0x03:
		status = CTN_STATUS_DELETE;
		if (value != 0x01) {
			/* value has to be "yes" */
			*err = -EBADR;
			return NULL;
		}
		ptr = NULL;
		break;

	}

	as->op = CAS_OP_SET_STATUS;
	*err = cas_backend_set_status(as->backend_data, name, status, ptr);

	return (*err) ? NULL : as;
}

static struct obex_mime_type_driver cas_status_mime = {
	.target = CAS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/CalendarStatus",
	.get_next_header = generic_get_next_header,
	.open = cas_set_status_open,
	.close = generic_close,
	.read = generic_read,
	.write = null_write
};

/* GetCTNAccountInformation */

static void *cas_account_open(const char *name, int oflag, mode_t mode,
				void *driver_data, gsize *size, int *err)
{
	struct access_session *as = driver_data;
	uint8_t instance;
	const gchar *mail = NULL;
	const gchar *descr = NULL;
	gchar tstamp[CTN_TSTAMP_STR_LEN + 1];
	time_t lastup = 0;

        DBG("");

	if (oflag != O_RDONLY) {
		*err = -EBADR;
		return NULL;
        }

	if (!g_obex_apparam_get_uint8(as->inparams,
					CTN_AP_INSTANCEID,
					&instance)) {
		*err = -EBADR;
		return NULL;
	}

	*err = cas_backend_account(instance, &mail, &lastup, &descr);
	if (*err < 0)
		return NULL;

	ctn_tstamp2str(lastup, tstamp);

	as->outparams = g_obex_apparam_set_string(as->outparams,
							CTN_AP_EMAILURL,
							mail ? mail : "");
	as->outparams = g_obex_apparam_set_string(as->outparams,
							CTN_AP_LASTUPDATE,
							tstamp);
	as->buffer = g_string_new_len(descr ? descr : "",
					descr ? MIN(199, strlen(descr)) : 0);
	g_string_append_c(as->buffer, 0); /* Per spec */

	as->finished = TRUE;
	trigger_read(as);
	return as;
}

static struct obex_mime_type_driver cas_account_mime = {
	.target = CAS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/InstanceDescription",
	.get_next_header = generic_get_next_header,
	.open = cas_account_open,
	.close = generic_close,
	.read = generic_read,
};

/* CTNNotificationRegistration and notification sending */

static void cas_event_cb(struct ctn_event *e)
{
	GSList *l;

	for (l = access_sessions; l; l = l->next) {
		struct access_session *as = l->data;
		if (as->notify_changes && as->notify_session) {
			/* Note: delivery errors currently ignored */
			cnc_push(as->notify_session, e, NULL, NULL);
		}
	}
}

static void cnc_disconnect_cb(struct cnc_session *session, int err,
				void *user_data)
{
	struct access_session *as = user_data;

	DBG("");

	as->finished = TRUE;

	if (err < 0) {
		obex_object_set_io_flags(as, G_IO_ERR, err);
	} else {
		as->notify_session = NULL;
		as->notify_changes = as->pending_changes;
		allow_alarms = as->pending_alarms;
		cas_backend_set_alarm(allow_alarms);
		trigger_read(as);
	}
}

static void cnc_connect_cb(struct cnc_session* session, int err,
				void *user_data)
{
	struct access_session *as = user_data;

	as->finished = TRUE;

	if (err < 0) {
		as->notify_session = NULL;
		obex_object_set_io_flags(as, G_IO_ERR, err);
	} else {
		as->notify_changes = as->pending_changes;
		allow_alarms = as->pending_alarms;
		cas_backend_set_alarm(allow_alarms);
		trigger_read(as);
	}
}

static void *cas_notification_open(const char *name, int oflag, mode_t mode,
				void *driver_data, gsize *size, int *err)
{
	struct access_session *as = driver_data;
	GSList *l;
	uint8_t alarms;
	uint8_t changes;

        DBG("");

	if (oflag != O_RDONLY) {
		*err = -EBADR;
		return NULL;
        }

	if (!g_obex_apparam_get_uint8(as->inparams,
					CTN_AP_ACOUSTICALARMSTATUS,
					&alarms) ||
		g_obex_apparam_get_uint8(as->inparams,
					CTN_AP_NOTIFICATIONSTATUS,
					&changes)) {
		*err = -EBADR;
		return NULL;
	}

	if (as->notify_changes == changes)
		goto immediately_done;

	/* Note: the spec is not clear whether an OBEX reply needs to
	   be given right away or only after session connecting or
	   disconnecting is complete (message sequences do not show
	   the reply).

	   Pending the reply until session management is complete
	   introduces a delay but also makes the state management
	   clearer (e.g., an impatient client will not send another
	   registration request while session is being connected). */

	if (!changes) {
		if (!as->notify_session) {
			as->notify_changes = changes;
			goto immediately_done;
		}

		*err = cnc_disconnect(as->notify_session, cnc_disconnect_cb, as);
		if (*err)
			goto immediately_done;

	} else {
		if (as->notify_session) {
			as->notify_changes = changes;
			goto immediately_done;
		}

		/* Note: role reversal */
		*err = cnc_connect(as->os->dst, as->os->src,
					&as->notify_session, cnc_connect_cb, as);
		if (*err)
			goto immediately_done;
				
	}

	as->pending_changes = changes;
	as->pending_alarms = alarms;

	return as;

immediately_done:
	if (*err == 0) {
		allow_alarms = alarms;
		cas_backend_set_alarm(allow_alarms);
	}

	as->finished = TRUE;
	return (*err) ? NULL : as;
}

static struct obex_mime_type_driver cas_notification_mime = {
	.target = CAS_TARGET,
	.target_size = TARGET_SIZE,
	.mimetype = "x-bt/CTN-NotificationRegistration",
	.get_next_header = generic_get_next_header,
	.open = cas_notification_open,
	.close = generic_close,
	.read = generic_read,
	.write = null_write,
};

/* Service functions */

static int cas_get_apparams(struct obex_session *os, struct access_session *as)
{
	const uint8_t *buffer;
	gsize size;

	size = obex_get_apparam(os, &buffer);
	if (size <= 0)
		return 0;

	as->inparams = g_obex_apparam_decode(buffer, size);
	if (as->inparams == NULL) {
		DBG("Error when parsing parameters!");
		return -EBADR;
	}

	return 0;
}

static int cas_get(struct obex_session *os, void *user_data)
{
	struct access_session *as = user_data;
	const char *type = obex_get_type(os);
	const char *name = obex_get_name(os);
	int ret;

	DBG("GET: name %s type %s cas %p", name, type, as);

	if (type == NULL)
		return -EBADR;

	ret = cas_get_apparams(os, as);
	if (ret < 0)
		goto failed;

	ret = obex_get_stream_start(os, name);
	if (ret < 0)
		goto failed;

	return 0;

failed:
	access_session_reset(as);
	return ret;
}

static int cas_put(struct obex_session *os, void *user_data)
{
	struct access_session *as = user_data;
	const char *type = obex_get_type(os);
	const char *name = obex_get_name(os);
	int ret;

	DBG("PUT: name %s type %s as %p", name, type, as);

	if (type == NULL || name == NULL)
		return -EBADR;

	ret = cas_get_apparams(os, as);
	if (ret < 0)
		goto failed;

	ret = obex_put_stream_start(os, name);
	if (ret < 0)
		goto failed;

	return 0;

failed:
	access_session_reset(as);
	return ret;
}

static void *cas_connect(struct obex_session *os, int *err)
{
	struct access_session *as;

	DBG("");

	as = g_new0(struct access_session, 1);

	*err = cas_backend_connect(&as->backend_data);
	if (*err < 0)
		goto failed;

	manager_register_session(os);

	as->os = os;

	access_sessions = g_slist_prepend(access_sessions, as);

	return as;

failed:
	access_session_free(as);

	return NULL;
}

static void cas_disconnect(struct obex_session *os, void *user_data)
{
	struct access_session *as = (struct access_session *)user_data;

	DBG("");

	manager_unregister_session(os);
	access_session_reset(as);
	cas_backend_disconnect(as->backend_data);
	access_session_free(as);
}

static struct obex_service_driver cas_service = {
	.name = "CAS server",
	.service = OBEX_CAS,
	.target = CAS_TARGET,
	.target_size = TARGET_SIZE,
	.connect = cas_connect,
	.get = cas_get,
	.put = cas_put,
	.disconnect = cas_disconnect
};

/* Plugin management */

static struct obex_mime_type_driver *cas_mime_drivers[] = {
	&cas_listing_mime,
	&cas_object_mime,
	&cas_status_mime,
	&cas_account_mime,
	&cas_notification_mime,
	NULL
};

static int cas_init(void)
{
	int err, i;

	err = cas_backend_init(cas_event_cb);
	if (err < 0)
		goto failed;

	for (i = 0; cas_mime_drivers[i] != NULL; ++i) {
		err = obex_mime_type_driver_register(cas_mime_drivers[i]);
		if (err < 0)
			goto failed;
	}

	err = obex_service_driver_register(&cas_service);
	if (err < 0)
		goto failed;

	tzset();

	return 0;

failed:
	DBG("CAS plugin initialization failed, %s(%d)", strerror(-err), -err);

	for (--i; i >= 0; --i)
		obex_mime_type_driver_unregister(cas_mime_drivers[i]);

	cas_backend_exit();

	return err;
}

static void cas_exit(void)
{
	int i;

	obex_service_driver_unregister(&cas_service);

	for (i = 0; cas_mime_drivers[i] != NULL; ++i)
		obex_mime_type_driver_unregister(cas_mime_drivers[i]);

	cas_backend_exit();
}

OBEX_PLUGIN_DEFINE(cas, cas_init, cas_exit)
