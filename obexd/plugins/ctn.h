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

/* CTN apparams */
enum ctn_ap_tag {
	CTN_AP_ACOUSTICALARMSTATUS	= 0x01, /* uint8_t (bitmask) */
	CTN_AP_ATTACHMENT		= 0x02, /* uint8_t (bitmask) */
	CTN_AP_SEND			= 0x03, /* uint8_t (bitmask) */
	CTN_AP_FILTERPERIODBEGIN	= 0x04, /* char * */
	CTN_AP_FILTERPERIODEND		= 0x05, /* char * */
	CTN_AP_PARAMETERMASK		= 0x06, /* uint32_t */
	CTN_AP_STATUSINDICATOR		= 0x07, /* uint8_t (bitmask) */
	CTN_AP_STATUSVALUE		= 0x08, /* uint8_t (bitmask) */
	CTN_AP_POSTPONEVAL		= 0x09, /* uint32_t */
	CTN_AP_EMAILURL			= 0x0a, /* char * */
	CTN_AP_CSETIME			= 0x0b, /* char * */
	CTN_AP_RECURRENT		= 0x0c, /* uint8_t (bitmask) */
	CTN_AP_ATTACHID			= 0x0d, /* uint8_t */
	CTN_AP_LASTUPDATE		= 0x0e, /* char * */

	/* From GPP */
	CTN_AP_MAXLISTCOUNT		= 0x41,	/* uint16_t */
	CTN_AP_LISTSTARTOFFSET		= 0x42,	/* uint16_t */
	CTN_AP_NOTIFICATIONSTATUS	= 0x43,	/* uint8_t (bitmask) */
	CTN_AP_INSTANCEID		= 0x44, /* uint8_t */
	CTN_AP_LISTINGSIZE		= 0x45, /* uint16_t */
};

struct ctn_handle {
	uint8_t data[16];
};

#define CTN_HANDLE_STR_LEN 32

static inline gboolean ctn_valid_handle(const gchar *handle)
{
	gsize pos;

	if (!handle)
		return FALSE;

	for (pos = 0; pos < CTN_HANDLE_STR_LEN; pos++) {
		if (handle[pos] >= '0' && handle[pos] <= '9')
			continue;
		else if (handle[pos] >= 'A' && handle[pos] <= 'F')
			continue;
		else
			return FALSE;
	}

	return handle[pos] == '\0' ? TRUE : FALSE;
}

/* Make a full length handle (32 hex digits) */
static inline gboolean ctn_canonicalize_handle(const gchar *in, gchar *out)
{
	gsize inpos, outpos, len;

	len = in ? strlen(in) : 0;
	if (len < 1 || len > CTN_HANDLE_STR_LEN)
		return FALSE;

	outpos = 32 - len;
	memset(out, '0', outpos);

	for (inpos = 0; in[inpos]; inpos++, outpos++) {
		if (in[inpos] >= '0' && in[inpos] <= '9')
			out[outpos] = in[inpos];
		else if (in[inpos] >= 'A' && in[inpos] <= 'F')
			out[outpos] = in[inpos];
		else
			return FALSE;
	}
	out[CTN_HANDLE_STR_LEN] = '\0';

	return TRUE;
}

static inline void ctn_handle2str(const struct ctn_handle *h, gchar *buf) {
	static const gchar hex[] = { '0', '1', '2', '3', '4', '5', '6', '7',
				     '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
	int i, pos;

	for (i = 0, pos = 0; i < 16; i++) {
		buf[pos++] = hex[h->data[i] >> 4];
		buf[pos++] = hex[h->data[i] & 15];
	}
	buf[pos] = '\0';
}

static inline void ctn_str2handle(const gchar *buf, struct ctn_handle *ret)
{
	const gchar *p;
	int i;

	for (p = buf, i = 0; i < 16; i++) {
		uint8_t hi, lo;
		hi =
			(*p >= '0' && *p <= '9') ? *p - '0' :
			(*p >= 'A' && *p <= 'F') ? *p - 'A' + 10 :
			0;
		p++;
		lo =
			(*p >= '0' && *p <= '9') ? *p - '0' :
			(*p >= 'A' && *p <= 'F') ? *p - 'A' + 10 :
			0;
		p++;
		ret->data[i] = (hi << 4) | lo;
	}
}

#define CTN_TSTAMP_STR_LEN 21

static inline void ctn_tstamp2str(time_t t, gchar *buf)
{
	/* Spec wants timezone with semicolon, but strftime's %z won't
	   add that; fudge a bit. Can't use g_time_val_to_iso8601() as
	   spec wants the local timezone and g_time... prints Zulu. */
	struct tm tm;
	localtime_r(&t, &tm);
	strftime(buf, CTN_TSTAMP_STR_LEN + 1, "%Y%m%dT%H%M%S%z", &tm);
	memmove(buf + 19, buf + 18, 2);
	buf[18] = ':';
	buf[CTN_TSTAMP_STR_LEN] = '\0';
}

static inline gboolean ctn_str2tstamp(const gchar *buf, time_t *ret)
{
	GTimeVal t;

	if (!g_time_val_from_iso8601(buf, &t))
		return FALSE;

	*ret = t.tv_sec;
	return TRUE;
}

enum ctn_calendar_type {
	CTN_CALENDAR_TYPE_EVENT,
	CTN_CALENDAR_TYPE_TASK,
	CTN_CALENDAR_TYPE_NOTE
};

static inline const gchar *ctn_calendar_type2str(enum ctn_calendar_type t)
{
	static const gchar *s[] = { "event", "task", "note" };
	return s[t];
}

enum ctn_priority {
	CTN_PRIORITY_HIGH,
	CTN_PRIORITY_NORMAL,
	CTN_PRIORITY_LOW
};

static inline const gchar *ctn_priority2str(enum ctn_priority p)
{
	static const gchar *s[] = { "high", "normal", "low" };
	return s[p];
}

enum ctn_pstatus {
	CTN_PSTATUS_UNDEFINED = 0,
	CTN_PSTATUS_NEEDS_ACTION,
	CTN_PSTATUS_ACCEPTED,
	CTN_PSTATUS_DECLINED,
	CTN_PSTATUS_TENTATIVE,
	CTN_PSTATUS_DELEGATED,
	CTN_PSTATUS_COMPLETED,
	CTN_PSTATUS_IN_PROCESS,
};

static inline const gchar *ctn_pstatus2str(enum ctn_pstatus p)
{
	static const gchar *s[] = { "NEEDS-ACTION", "ACCEPTED", "DECLINED",
				    "TENTATIVE", "DELEGATED", "COMPLETED",
				    "IN-PROCESS" };
	return s[p];
}

enum ctn_alarm {
	CTN_ALARM_ON,
	CTN_ALARM_NO,
	CTN_ALARM_OFF
};

static inline const gchar *ctn_alarm2str(enum ctn_alarm a)
{
	static const gchar *s[] = { "on", "no", "off" };
	return s[a];
}

enum ctn_status {
	CTN_STATUS_PART,
	CTN_STATUS_ALARM,
	CTN_STATUS_SEND,
	CTN_STATUS_DELETE
};

#define CTN_PARAM_ATTACHMENT	(1 << 0)
#define CTN_PARAM_SUMMARY	(1 << 1)
#define CTN_PARAM_ENDTIME	(1 << 2)
#define CTN_PARAM_ORIG_NAME	(1 << 3)
#define CTN_PARAM_ORIG_ADDR	(1 << 4)
#define CTN_PARAM_PRIORITY	(1 << 5)
#define CTN_PARAM_PSTATUS	(1 << 6)
#define CTN_PARAM_ALARMSTATUS	(1 << 7)
#define CTN_PARAM_SENDSTATUS	(1 << 8)
#define CTN_PARAM_RECURRENT	(1 << 9)

typedef uint32_t ctn_param_t;

struct ctn_attachment {
	gchar *name;
	gchar *type;
	size_t size;
	gchar *data;
};

struct ctn_entry {
	struct ctn_handle handle;
	time_t update;
	enum ctn_calendar_type type;
	gchar *summary;
	time_t start;
	time_t end;
	gchar *orig_name;
	gchar *orig_addr;
	size_t size;
	enum ctn_priority prio;
	enum ctn_pstatus pstatus;
	enum ctn_alarm alarm;
	gboolean sent;
	gboolean recur;
	size_t att_count;
	struct ctn_attachment *att;
};

enum ctn_event_type {
	CTN_EVENT_TYPE_NEWOBJECT,
	CTN_EVENT_TYPE_OBJECTUPDATE,
	CTN_EVENT_TYPE_ALARM,
	CTN_EVENT_TYPE_SENDINGSUCCESS,
	CTN_EVENT_TYPE_SENDINGFAILURE,
	CTN_EVENT_TYPE_DELIVERYSUCCESS,
	CTN_EVENT_TYPE_DELIVERYFAILURE,
	CTN_EVENT_TYPE_MEMORYFULL,
	CTN_EVENT_TYPE_MEMORYAVAILABLE,
	CTN_EVENT_TYPE_OBJECTDELETED
};

static inline const gchar *ctn_event_type2str(enum ctn_event_type t)
{
	static const gchar *s[] = { "NewObject", "ObjectUpdate", "Alarm",
				    "SendingSuccess", "SendingFailure",
				    "DeliverySuccess", "DeliveryFailure",
				    "MemoryFull", "MemoryAvailable",
				    "ObjectDeleted" };
	return s[t];
}

struct ctn_event {
	enum ctn_event_type event_type;
	struct ctn_handle handle;
	enum ctn_calendar_type calendar_type;
	const gchar *summary;
	time_t update;
	const gchar *originator_name;
	const gchar *originator_address;
};
