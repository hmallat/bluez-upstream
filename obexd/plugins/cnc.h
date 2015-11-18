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

struct cnc_session;

/**
 * Initiate a new notification session. If a new session can not be
 * created, returns an error code; otherwise, returns zero, stores a
 * pointer to a session structure in the return parameter and will
 * call the given callback either when session is connected or an
 * error occurs.
 */
int cnc_connect(const gchar *src, const gchar *dst,
		struct cnc_session **ret,
		void (*cb)(struct cnc_session *, int err, void *),
		void *user_data);

/**
 * Disconnect an existing session. Will return an error code if
 * session closing cannot be attempted; otherwise will call the given
 * callback when session has been closed or an error has occurred. The
 * session will not be usable after successful closing, and can be
 * considered freed by the caller.
 */
int cnc_disconnect(struct cnc_session *session,
			void (*cb)(struct cnc_session *, int err, void *),
			void *user_data);

/**
 * Push a change notification to the CCE. Note that this function will
 * return immediately; the given callback function will be called
 * when event report delivery is completed, or if an error occurs
 * during delivery.
 */
int cnc_push(struct cnc_session *session, struct ctn_event *event, 
			void (*cb)(struct cnc_session *, int err, void *),
			void *user_data);
