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

/*
 * A simplistic filesystem based CAS backend, for testing purposes only.
 *
 * Object storage
 * --------------
 *
 * For object storage backend uses $CAS_ROOT/ctn/objects if $CAS_ROOT
 * is defined in the environment. Otherwise it uses
 * <user-data-dir>/ctn/objects, where <user-data-dir> is the return
 * value of g_get_user_data_dir().
 *
 * The directory will contain all CTN objects as individual files.
 * Each file's name is 32 upper case hexadecimal digits equal to the
 * 128 bit handle for the object. Each file contains iCalendar data;
 * bCalendar fields are generated automatically (version-property is
 * always "1.0", handle-property is derived from the file name, and
 * update-property from file modification timestamp).
 *
 * At startup, existing files are parsed to form a cache in order to
 * speed up operations. The cache is kept up to date by monitoring
 * file system changes within the directory.
 *
 * To keep things reasonably simple, backend suspends file system
 * monitoring during processing of requests from CCEs. Thus changes
 * in the storage during, e.g., listings can go unnoticed. Keep this
 * in mind while testing.
 *
 * Configuration
 * -------------
 *
 * Instance information is stored in a simple configuration file; its
 * format is as follows:
 *
 *     [InstanceN]
 *     Description=...
 *     EmailURI=...
 *
 * Currently, only [Instance0] is supported.
 *
 * Configuration file is located at $CAS_ROOT/ctn/instances if
 * $CAS_ROOT is defined. If not, it is read from
 * <user-config-dir>/ctn/instances, where <user-config-dir> is the
 * return value of g_get_user_config_dir().
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <glib.h>
#include <gio/gio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utime.h>

#include <libical/icalparser.h>
#include <libical/icalcomponent.h>

#include "obexd/src/obexd.h"
#include "obexd/src/log.h"

#include "ctn.h"
#include "cas-backend.h"

/* Work around PTS issues */
#define PTS_WORKAROUND

#define CAS_STORAGE		"objects"

#define CTN_ROOT		"/"
#define CTN_CALENDAR		"telecom/CTN/calendar"
#define CTN_TASKS		"telecom/CTN/tasks"
#define CTN_NOTES		"telecom/CTN/notes"

#define BCALENDAR_PREFIX				\
	"BEGIN:BCAL\r\n"				\
	"VERSION:1.0\r\n"				\
	"HANDLE:%32s\r\n"				\
	"UPDATE:%21s\r\n"

#ifdef PTS_WORKAROUND
#define BCALENDAR_PREFIX_PTS				\
	"BEGIN:BCAL\r\n"				\
	"VERSION:1.0\r\n"				\
	"UPDATE;TZID=PST:%15s\r\n"
#endif

#define BCALENDAR_SUFFIX			\
	"END:BCAL\r\n"

/* fixed bCalendar overhead (not including handle and timestamp) */
#define BCALENDAR_ENVELOPE_LEN 53

enum request_type {
	REQUEST_LIST,
	REQUEST_GET,
	REQUEST_PUT
};

struct config {
	gchar *data_root;
	gchar *description;
	gchar *email_uri;
	void (*change_event_cb)(struct ctn_event *);
};

struct data_cache_entry {
	time_t update;
	gchar *handle;
	time_t dtstart;
	time_t dtend;
	gsize size;
	enum ctn_calendar_type cal_type;
};

struct handle_time_entry {
	gchar *handle;
	time_t tstamp;
};

struct list_params {
	guint source;
	void (*cas_list_cb)(int err, gboolean final, gsize total,
				gsize count, struct ctn_entry *ent,
				void *user_data);
	enum ctn_calendar_type cal_type;
	ctn_param_t param_mask;
	gsize total;
	GPtrArray *handle_time;
	void *user_data;
};

struct get_params {
	guint source;
	void (*cas_get_cb)(int err, const gchar *chunk, gsize length,
				gboolean final,	void *user_data);
	struct data_cache_entry *entry;
	gboolean attachments;
	uint8_t attachment_id;
	void *user_data;
};

struct put_params {
	gchar handle[CTN_HANDLE_STR_LEN + 1];
	enum ctn_calendar_type cal_type;
	gboolean send;
	int tmpfd;
	gchar *tmpname;
};

struct session_data {
	enum request_type type;
	union {
		void *params;
		struct list_params *list_params;
		struct get_params *get_params;
		struct put_params *put_params;
	};
};

static struct config config = {
	.data_root = NULL,
	.description = NULL,
	.email_uri = NULL,
	.change_event_cb = NULL
};

/* Ongoing sessions */
static GSList *sessions = NULL;

/* Calendar object storage */
static GHashTable *data_cache = NULL;

/* Monitor for storage changes */
static GFileMonitor *storage_monitor = NULL;
static int storage_suspend = 1;

static void monitor_resume(void);

static void monitor_suspend(void);

static gchar *storage_path(const gchar *handle)
{
	return g_build_path("/", config.data_root, CAS_STORAGE, handle, NULL);
}

static void next_uuid(struct ctn_handle *ptr)
{
	gchar buf[CTN_HANDLE_STR_LEN + 1];
	static GRand *rand = NULL;
	struct ctn_handle handle;

	if (!rand)
		rand = g_rand_new();

	do {
		int i;

		for (i = 0; i < 4; i++) {
			guint32 u = g_rand_int(rand);
			memcpy(&handle.data[i*4], &u, 4);
		}

		ctn_handle2str(&handle, buf);

	} while (g_hash_table_lookup(data_cache, buf));

	memcpy(ptr, &handle, sizeof(struct ctn_handle));
}

static int path2type(const gchar *path, enum ctn_calendar_type *ret)
{
	int err = 0;

	if (!strcmp(path, CTN_CALENDAR))
		*ret = CTN_CALENDAR_TYPE_EVENT;
	else if (!strcmp(path, CTN_TASKS))
		*ret = CTN_CALENDAR_TYPE_TASK;
	else if (!strcmp(path, CTN_NOTES))
		*ret = CTN_CALENDAR_TYPE_NOTE;
	else
		err = -EBADR;

	return err;
}

static void list_params_free(struct list_params *params)
{
	if (params->source)
		g_source_remove(params->source);
	g_ptr_array_unref(params->handle_time);
	g_free(params);
}

static void get_params_free(struct get_params *params)
{
	if (params->source)
		g_source_remove(params->source);
	g_free(params);
}

static void put_params_free(struct put_params *params)
{
	if (params->tmpfd)
		close(params->tmpfd);

	if (params->tmpname) {
		g_remove(params->tmpname);
		g_free(params->tmpname);
	}

	g_free(params);
}

static void request_begin(struct session_data *session,
				enum request_type type, gpointer params)
{
	monitor_suspend();
	session->type = type;
	session->params = params;
}

static void request_free(struct session_data *session)
{
	if (session->params) {
		switch (session->type) {
		case REQUEST_LIST:
			list_params_free(session->list_params);
			break;
		case REQUEST_GET:
			get_params_free(session->get_params);
			break;
		case REQUEST_PUT:
			put_params_free(session->put_params);
			break;
		}
		session->params = NULL;
	}

	monitor_resume();
}

static void data_cache_entry_free(gpointer p)
{
	struct data_cache_entry *d = p;
	g_free(d->handle);
	g_free(d);
}

static void handle_time_entry_free(gpointer p)
{
	struct handle_time_entry *h = p;
	g_free(h->handle);
	g_free(h);
}

static gint handle_time_entry_compare(gconstpointer a, gconstpointer b)
{
	const struct handle_time_entry *h1 = a;
	const struct handle_time_entry *h2 = b;
	return
		(h1->tstamp < h2->tstamp) ? -1 :
		(h1->tstamp == h2->tstamp) ? 0 :
		1;
}

static int read_object(const gchar *handle, gchar **contents, gsize *length,
			struct stat *st)
{
	GError *err = NULL;
	int ret = 0;
	gchar *path = storage_path(handle);

	if (st && stat(path, st) < 0) {
		ret = -EIO;
		goto done;
	}

	if (!g_file_get_contents(path, contents, length, &err)) {
		switch (err->code) {

		case G_FILE_ERROR_NOENT:
			ret = -ENOENT;
			break;

		case G_FILE_ERROR_ACCES:
		case G_FILE_ERROR_PERM:
			ret = -EPERM;
			break;

		default:
			ret = -EIO;
			break;

		}

		goto done;
	}

done:
	if (err)
		g_error_free(err);
	g_free(path);
	return ret;
}

static gboolean validate_object(icalcomponent *obj,
				enum ctn_calendar_type *cal_type,
				time_t *dtstart, time_t *dtend,
				time_t update)
{
	icalcomponent *sub = NULL;

	/* Note: not a proper content validity check */

	sub = icalcomponent_get_first_component(obj, ICAL_VEVENT_COMPONENT);
	if (sub) {
		icalproperty *s = icalcomponent_get_first_property
			(sub, ICAL_DTSTART_PROPERTY);
		icalproperty *e = icalcomponent_get_first_property
			(sub, ICAL_DTEND_PROPERTY);
		struct icaltimetype t;
		if (s) {
			t = icalvalue_get_datetime(icalproperty_get_value(s));
			*dtstart = icaltime_as_timet(t);
		}
		if (e) {
			t = icalvalue_get_datetime(icalproperty_get_value(e));
			*dtend = icaltime_as_timet(t);
		}
		*cal_type = CTN_CALENDAR_TYPE_EVENT;
		return TRUE;
	}

	sub = icalcomponent_get_first_component(obj, ICAL_VTODO_COMPONENT);
	if (sub) {
		icalproperty *s = icalcomponent_get_first_property
			(sub, ICAL_DTSTART_PROPERTY);
		struct icaltimetype t;
		if (s) {
			t = icalvalue_get_datetime(icalproperty_get_value(s));
			*dtstart = icaltime_as_timet(t);
		}
		*cal_type = CTN_CALENDAR_TYPE_TASK;
		return TRUE;
	}

	sub = icalcomponent_get_first_component(obj, ICAL_VJOURNAL_COMPONENT);
	if (sub) {
		*dtstart = update;
		*cal_type = CTN_CALENDAR_TYPE_NOTE;
		return TRUE;
	}

	return FALSE;
}

static void cache_remove(const gchar *handle)
{
	g_hash_table_remove(data_cache, handle);
}

static void cache_add(const gchar *handle, enum ctn_calendar_type cal_type,
		time_t update, time_t dtstart, time_t dtend, gsize size)
{
	struct data_cache_entry *d;

	DBG("adding file '%s' (%s) to cache", handle,
		ctn_calendar_type2str(cal_type));

	d = g_new0(struct data_cache_entry, 1);
	d->update = update;
	d->handle = g_strdup(handle);
	d->dtstart = dtstart;
	d->dtend = dtend;
	d->size = size + BCALENDAR_ENVELOPE_LEN + CTN_HANDLE_STR_LEN +
		CTN_TSTAMP_STR_LEN;
	d->cal_type = cal_type;
	g_hash_table_replace(data_cache, g_strdup(handle), d);
}

static void cache_fill_handle(const gchar *handle)
{
	enum ctn_calendar_type cal_type;
	time_t dtstart = 0, dtend = 0;
	gchar *contents = NULL;
	icalcomponent *obj = NULL;
	struct stat st;

	if (read_object(handle, &contents, NULL, &st) < 0) {
		DBG("Read error for '%s'", handle);
		goto done;
	}

	obj = icalparser_parse_string(contents);
	if (!obj) {
		DBG("iCalendar parsing failure for '%s'", handle);
		goto done;
	}

	if (!validate_object(obj, &cal_type, &dtstart, &dtend, st.st_mtime)) {
		DBG("iCalendar validation failure for '%s'", handle);
		goto done;
	}

	cache_add(handle, cal_type, st.st_mtime, dtstart, dtend, st.st_size);

done:
	if (obj)
		icalcomponent_free(obj);
	g_free(contents);
}

static void cache_fill(void)
{
	GDir *dir = NULL;
	const gchar *next;
	gchar *path = storage_path(NULL);

	data_cache = g_hash_table_new_full(g_str_hash, 
						g_str_equal,
						g_free, 
						data_cache_entry_free);

	dir = g_dir_open(path, 0, NULL);
	if (!dir)
		goto done;

	while ((next = g_dir_read_name(dir))) {
		DBG("checking file '%s'", next);

		if (!ctn_valid_handle(next))
			continue;

		cache_fill_handle(next);
	}

done:
	if (dir)
		g_dir_close(dir);

	g_free(path);
}

static void session_data_free(struct session_data *s)
{
	cas_backend_abort(s);
	g_free(s);
}

static void read_instance_config(void)
{
	const gchar *config_root = NULL;
	gchar *inst_path = NULL;
	GKeyFile *inst_file = NULL;
	gchar *s;

	config_root = g_getenv("CAS_ROOT");
	if (!config_root)
		config_root = g_get_user_config_dir();

	inst_path = g_build_path("/", config_root, "ctn", "instances", NULL);
	DBG("Reading CTN configuration from '%s'", inst_path);

	inst_file = g_key_file_new();
	g_key_file_load_from_file(inst_file, inst_path, 0, NULL);
	s = g_key_file_get_string(inst_file, "Instance0", "Description", NULL);
	if (s)
		config.description = g_strdup(s);
	s = g_key_file_get_string(inst_file, "Instance0", "EmailURI", NULL);
	if (s)
		config.email_uri = g_strdup(s);
	g_key_file_free(inst_file);
	g_free(inst_path);
}

static void monitor_event(GFileMonitor *monitor,
				GFile *file,
				GFile *other_file,
				GFileMonitorEvent event_type,
				gpointer user_data)
{
	char *name = NULL;
	GSList *l;

	name = g_file_get_basename(file);
	if (!ctn_valid_handle(name))
		goto done;

	switch (event_type) {

	case G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT:
		DBG("'%s' changes done, (re)inserting into cache. ", name);
		cache_remove(name);
		cache_fill_handle(name);
		break;

	case G_FILE_MONITOR_EVENT_DELETED:
		DBG("'%s' removed. ", name);
		cache_remove(name);
		break;

	case G_FILE_MONITOR_EVENT_CREATED:
		DBG("'%s' created; waiting for changes done. ", name);
		break;

	default:
		goto done;
	}

	/* Storage modifications abort ongoing requests */
	for (l = sessions; l; l = l->next)
		cas_backend_abort(l->data);

done:
	g_free(name);
}

static void monitor_resume(void)
{
	storage_suspend--;
	if (!storage_suspend) {
		gchar *path = storage_path(NULL);
		GFile *storage = NULL;

		storage = g_file_new_for_path(path);
		storage_monitor = g_file_monitor_directory(storage, 0, NULL,
									NULL);
		if (storage_monitor)
			g_signal_connect(storage_monitor, "changed",
					G_CALLBACK(monitor_event), NULL);
		else
			info("Warning: cannot monitor storage changes");

		g_object_unref(storage);
		g_free(path);
	}
}

static void monitor_suspend(void)
{
	if (storage_monitor) {
		g_object_unref(storage_monitor);
		storage_monitor = NULL;
	}
	storage_suspend++;
}

int cas_backend_init(void (*cb)(struct ctn_event *))
{
	const gchar *data_root = NULL;

	read_instance_config();

	config.change_event_cb = cb;

	data_root = g_getenv("CAS_ROOT");
	if (!data_root)
		data_root = g_get_user_data_dir();

	config.data_root = g_build_path("/", data_root, "ctn", NULL);
	DBG("Reading CTN data from '%s'", config.data_root);

	cache_fill();

	monitor_resume();

	return 0;
}

void cas_backend_exit(void)
{
	monitor_suspend();
	g_hash_table_unref(data_cache);
	data_cache = NULL;
	config.change_event_cb = NULL;
	g_free(config.data_root);
	config.data_root = NULL;
	g_free(config.description);
	config.description = NULL;
	g_free(config.email_uri);
	config.email_uri = NULL;
}

int cas_backend_account(int instance, const gchar **mail, time_t *lastup,
			const gchar **descr)
{
	if (instance != 0)
		return -ENOENT;

	*mail = config.email_uri;
	*lastup = time(NULL); /* TODO */
	*descr = config.description;
	return 0;
}

void cas_backend_set_alarm(gboolean allow)
{
	/* TODO: just a null stub for now */
}

int cas_backend_connect(void **backend_data)
{
	struct session_data *session = g_new0(struct session_data, 1);
	*backend_data = session;
	sessions = g_slist_prepend(sessions, session);
	return 0;
}

void cas_backend_disconnect(void *backend_data)
{
	struct session_data *session = (struct session_data *)backend_data;
	sessions = g_slist_remove(sessions, session);
	session_data_free(session);
}

#define LIST_CHUNK 128

gboolean cas_backend_list_generate(gpointer user_data)
{
	struct session_data *session = user_data;
	struct ctn_entry ent[LIST_CHUNK];
	gboolean final;
	int err = 0;
	int curr = 0;

	if (!session->list_params) /* Aborted due to storage change */
		return FALSE;

	session->list_params->source = 0;

	while (session->list_params->handle_time->len && curr < LIST_CHUNK) {
		struct handle_time_entry *h;
		struct data_cache_entry *d;

		h = g_ptr_array_index(session->list_params->handle_time, 0);

		d = g_hash_table_lookup(data_cache, h->handle);
		if (!d) { /* should not happen */
			err = -EIO;
			goto done;
		}

		/* Only fill in what is #REQUIRED for now */

		ctn_str2handle(h->handle, &ent[curr].handle);
		ent[curr].update = d->update;
		ent[curr].type = session->list_params->cal_type;
		ent[curr].start = d->dtstart;
		ent[curr].end = d->dtend;
		ent[curr].size = d->size;

		curr++;

		g_ptr_array_remove_index(session->list_params->handle_time, 0);
	}

	final = session->list_params->handle_time->len ? FALSE : TRUE;

done:
	(session->list_params->cas_list_cb)
		(err, final, session->list_params->total, curr, ent,
			session->list_params->user_data);
	if (err || final)
		request_free(session);

	return err ? FALSE : !final;
}

int cas_backend_list(void *backend_data, const gchar *name, uint16_t max_count,
			uint16_t start_offset, time_t *filter_begin,
			time_t *filter_end, ctn_param_t param_mask,
			void (*cas_list_cb)(int err, gboolean final,
						gsize total, gsize count,
						struct ctn_entry *ent,
						void *user_data),
			void *user_data)
{
	struct session_data *session = backend_data;
	enum ctn_calendar_type cal_type;
	GSList *handles = NULL;
	int i, err, count = 0;
	struct list_params *params = NULL;
	GPtrArray *handle_time = NULL;
	GHashTableIter iter;
	gchar *iter_key;
	struct data_cache_entry *iter_value;

	err = path2type(name, &cal_type);
	if (err < 0)
		return -ENOENT;

	/* Per spec filter first, segment then -- so construct an
	   auxilliary array with contents that matches the filter and
	   segment from that. */

	handle_time = g_ptr_array_new_with_free_func(handle_time_entry_free);

	g_hash_table_iter_init(&iter, data_cache);
	while (g_hash_table_iter_next(&iter, (gpointer *)&iter_key,
						(gpointer *)&iter_value)) {
		struct handle_time_entry *h;

		if (iter_value->cal_type != cal_type)
			continue;
		if (filter_begin && iter_value->dtstart < *filter_begin)
			continue;
		if (filter_end && iter_value->dtstart > *filter_end)
			continue;

		h = g_new0(struct handle_time_entry, 1);
		h->handle = g_strdup(iter_value->handle);
		h->tstamp = iter_value->dtstart;
		g_ptr_array_add(handle_time, h);

		count++;
	}
	g_ptr_array_sort(handle_time, handle_time_entry_compare);

	if (start_offset)
		g_ptr_array_remove_range(handle_time, 0, start_offset);

	if (max_count < handle_time->len)
		g_ptr_array_remove_range(handle_time, max_count,
					handle_time->len - max_count);

	params = g_new0(struct list_params, 1);
	params->cas_list_cb = cas_list_cb;
	params->cal_type = cal_type;
	params->param_mask = param_mask;
	params->total = count;
	params->handle_time = handle_time;
	params->user_data = user_data;
	params->source = g_idle_add(cas_backend_list_generate, session);

	request_begin(session, REQUEST_LIST, params);

	return 0;
}

gboolean cas_backend_get_generate(gpointer user_data)
{
	struct session_data *session = user_data;
	gchar update[CTN_TSTAMP_STR_LEN + 1];
	gchar *contents = NULL;
	gchar *out = NULL;
	gsize length = 0;
	int err = 0;

	if (!session->get_params) /* Aborted due to storage change */
		return FALSE;

	ctn_tstamp2str(session->get_params->entry->update, update);

	err = read_object(session->get_params->entry->handle, &contents,
				NULL, NULL);
	if (err)
		goto done;

	out = g_strdup_printf(BCALENDAR_PREFIX "%s" BCALENDAR_SUFFIX,
					session->get_params->entry->handle,
					update,
					contents);
	length = strlen(out);

done:
	(session->get_params->cas_get_cb)
		(err, out, length, TRUE, session->get_params->user_data);

	g_free(out);
	g_free(contents);
	request_free(session);

	return FALSE;
}

int cas_backend_get(void *backend_data, const gchar *name, gboolean recurrence,
			gboolean attachments, uint8_t attachment_id,
			void (*cas_get_cb)(int err, const gchar *chunk,
						gsize length, gboolean final,
						void *user_data),
			void *user_data)
{
	struct session_data *session = backend_data;
	struct data_cache_entry *d;
	struct get_params *params = NULL;
	gchar handle[CTN_HANDLE_STR_LEN + 1];
	int err;

	DBG("'%s'", name);

	/* TODO: attachments not handled yet */

	if (!ctn_canonicalize_handle(name, handle))
		return -EBADR;

	d = g_hash_table_lookup(data_cache, handle);
	if (!d)
		return -ENOENT;

	params = g_new0(struct get_params, 1);
	params->entry = d;
	params->cas_get_cb = cas_get_cb;
	params->attachments = attachments;
	params->attachment_id = attachment_id;
	params->user_data = user_data;
	params->source = g_idle_add(cas_backend_get_generate, session);

	request_begin(session, REQUEST_GET, params);

	return 0;
}

int cas_backend_put(void *backend_data, const gchar *folder, gboolean send,
			gchar *handle_buf)
{
	/* Write initially to a temporary file; only move to object
	   storage after receiving the full object data and validating
	   it */

	struct session_data *session = backend_data;
	struct put_params *params = NULL;
	enum ctn_calendar_type cal_type;
	int tmpfd = -1;
	gchar *tmpname = NULL;
	struct ctn_handle handle;
	int err;

	DBG("'%s'", folder);

	err = path2type(folder, &cal_type);
	if (err < 0)
		return -EBADR;

	tmpfd = g_file_open_tmp("cas-object-XXXXXX", &tmpname, NULL);
	if (tmpfd < 0) {
		DBG("Cannot open temporary upload file");
		return -EIO;
	}

	next_uuid(&handle);

	params = g_new0(struct put_params, 1);
	ctn_handle2str(&handle, params->handle);
	params->cal_type = cal_type;
	params->send = send;
	params->tmpfd = tmpfd;
	params->tmpname = tmpname;

	strncpy(handle_buf, params->handle, CTN_HANDLE_STR_LEN + 1);

	request_begin(session, REQUEST_PUT, params);

	return 0;
}

int cas_backend_put_continue(void *backend_data, const gchar *buf, gsize count)
{
	struct session_data *session = backend_data;
	gssize pos = 0, left = count;
	int ret = 0;

	if (!session->put_params) /* Aborted due to storage change */
		return -EIO;

	DBG("'%s' %zu bytes", session->put_params->tmpname, count);

	pos = 0;
	left = count;
	while (left) {
		gssize chunk;
		chunk = write(session->put_params->tmpfd, &buf[pos], left);
		if (chunk < 0) {
			if (errno != EAGAIN && errno != EINTR) {
				DBG("write error: %s (%d)", strerror(errno),
								errno);
				ret = -EIO;
				goto done;
			}
		}
		pos += chunk;
		left -= chunk;
	}

	ret = count;

done:
	if (ret < 0)
		request_free(session);

	return ret;
}

int cas_backend_put_finalize(void *backend_data)
{
	struct session_data *session = backend_data;
	enum ctn_calendar_type cal_type;
	gchar htmp[CTN_HANDLE_STR_LEN + 1];
	gchar utmp[CTN_TSTAMP_STR_LEN + 1];
	gchar handle[CTN_HANDLE_STR_LEN + 1];
	time_t dtstart = 0, dtend = 0, update;
	gchar *bcal_contents = NULL;
	gchar *ptr;
	gsize length, skip;
	int ret = 0;
	icalcomponent *obj = NULL;
	struct stat st;
	gchar *path = NULL;
	struct utimbuf times;
	gchar *icaldata = NULL;

	if (!session->put_params) /* Aborted due to storage change */
		return -EIO;

	DBG("'%s'", session->put_params->tmpname);

	if (!g_file_get_contents(session->put_params->tmpname, &bcal_contents,
					NULL, NULL)) {
		DBG("Read error for temporary upload file");
		ret = -EIO;
		goto done;
	}

	/* Incoming data needs to be validated before storing; quick
	   and dirty parsing here as the bCalendar format is not very
	   complex. */

	ptr = bcal_contents;

	if (sscanf(ptr, BCALENDAR_PREFIX, htmp, utmp) == 2) {
		skip = 43 + strlen(htmp) + strlen(utmp);
		if (!ctn_str2tstamp(utmp, &update)) {
			DBG("Invalid BCALENDAR timestamp");
			ret = -EBADR;
			goto done;
		}
#ifdef PTS_WORKAROUND
	} else if (sscanf(ptr, BCALENDAR_PREFIX_PTS, utmp) == 1) {

		/* Spec declares that bCalendar objects must always
		   have a handle (see BNF for bCalendar); however, PTS
		   sends objects without one. As we allocate one
		   anyway it's not hugely important.

		   Also, spec declares that timestamps must always be
		   in a given fixed format where timezone is
		   represented by a numeric offset; PTS sends objects
		   with timezone names. Work around that too, but
		   don't bother to do name-offset conversion. */

		skip = 43 + strlen(utmp);
		memcpy(utmp + 15, "-08:00\0", 7);
		if (!ctn_str2tstamp(utmp, &update)) {
			DBG("Invalid BCALENDAR timestamp");
			ret = -EBADR;
			goto done;
		}
#endif
	} else {
		DBG("Invalid BCALENDAR prefix");
		ret = -EBADR;
		goto done;
	}

	ptr += skip;

	if (!g_str_has_suffix(ptr, BCALENDAR_SUFFIX)) {
		DBG("Invalid BCALENDAR suffix");
		ret = -EBADR;
		goto done;
	}

	length = strlen(ptr) - strlen(BCALENDAR_SUFFIX);
	icaldata = g_strndup(ptr, length);

	DBG("Object dump");
	DBG("%s", icaldata);

	obj = icalparser_parse_string(icaldata);
	if (!obj) {
		DBG("iCalendar parsing failure");
		ret = -EBADR;
		goto done;
	}

	if (!validate_object(obj, &cal_type, &dtstart, &dtend, update)) {
		DBG("iCalendar validation failure");
		ret = -EBADR;
		goto done;
	}

	path = storage_path(session->put_params->handle);

	if (!g_file_set_contents(path, ptr, length, NULL)) {
		ret = -EIO;
		goto done;
	}

	times.actime = time(NULL);
	times.modtime = update;
	utime(path, &times);

	/* Writing into storage will automatically trigger cache
	   update and event reporting, but it can take time.
	   So force the entry into the cache here already. */
	cache_add(session->put_params->handle, cal_type, update, dtstart,
			dtend, length);

	ret = 0;

done:
	g_free(icaldata);
	g_free(path);
	if (obj)
		icalcomponent_free(obj);
	g_free(bcal_contents);
	request_free(session);

	return ret;
}

int cas_backend_set_status(void *backend_data, const gchar *name,
				enum ctn_status type, void *value)
{
	gchar handle[CTN_HANDLE_STR_LEN + 1];
	struct data_cache_entry *d;
	gchar *path = NULL;

	DBG("'%s'", name);

	if (!ctn_canonicalize_handle(name, handle))
		return -EBADR;

	d = g_hash_table_lookup(data_cache, handle);
	if (!d)
		return -ENOENT;

	switch (type) {

	case CTN_STATUS_PART:
	case CTN_STATUS_ALARM:
	case CTN_STATUS_SEND:
		/* TODO: just a null stub for now */
		return -EOPNOTSUPP;

	case CTN_STATUS_DELETE:
		cache_remove(handle);
		path = storage_path(handle);
		g_remove(path);
		break;
	}

	g_free(path);
	return 0;
}

void cas_backend_abort(void *backend_data)
{
	struct session_data *session = backend_data;
	request_free(session);
}
