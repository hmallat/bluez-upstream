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

/**
 * Initialize CAS backend
 *
 * Will be called when CAS server plugin is initializing. Returns zero
 * on success, an error code otherwise. An error will prevent a
 * successful CAS server plugin initialization.
 *
 * The backend is required to report events through the given callback
 * at least when there are ongoing connections (see
 * cas_backend_connect, cas_backend_disconnect) so that the access
 * server can deliver change notifications to CCEs that have registered
 * to receive them.
 *
 * Note that only mandatory fields, as defined by the spec for the
 * event type, need to be filled in the event structure.
 */
int cas_backend_init(void (*event_cb)(struct ctn_event *));

/**
 * Clean up CAS backend
 *
 * Will be called when CAS server plugin is shutting down.
 */
void cas_backend_exit(void);

/**
 * Get CTN account information
 *
 * Returns CTN account information for the given instance. 
 */
int cas_backend_account(int instance, const gchar **mail, time_t *lastup,
			const gchar **descr);

/**
 * Alarm suppression
 *
 * Will be called when acoustic alarms are to be suppressed or
 * allowed.
 */
void cas_backend_set_alarm(gboolean allow);

/**
 * OBEX connection
 *
 * Will be called when an OBEX connection attempt is made by
 * CCE. Returns zero on success (connection will be accepted), an
 * error code otherwise. An error will lead to rejecting the
 * connection attempt.
 *
 * A pointer to connection-specific backend data can be written to the
 * backend_data argument; the value will be passed to any following
 * callback function calls for the session. If any resources are
 * allocated in this function, they should be released when
 * cas_backend_disconnect() is called.
 */
int cas_backend_connect(void **backend_data);

/**
 * OBEX disconnection
 *
 * Will be called when a previously established OBEX connection
 * disconnects.  The callback is responsible for deallocating any
 * session-specific resources allocated during cas_backend_connect()
 * or later during session handling.
 */
void cas_backend_disconnect(void *backend_data);

/**
 * Begin CTN listing
 *
 * Will be called when CCE requests a CTN listing object with the
 * given application parameters. Backend will need to call the given
 * callback function when data for the listing becomes available.
 * Callback accepts listing entries as an array of structs that needs
 * to be filled in as indicated by the parameter mask.
 *
 * When filtering the listing by event time, filter_begin/filter_end
 * will be NULL if there is no corresponding limit, and otherwise
 * point to a time_t value to be used in filtering.
 */
int cas_backend_list(void *backend_data, const gchar *name, uint16_t max_count,
			uint16_t start_offset, time_t *filter_begin,
			time_t *filter_end, ctn_param_t param_mask,
			void (*cas_list_cb)(int err, gboolean final,
						gsize total, gsize count,
						struct ctn_entry *ent,
						void *user_data),
			void *user_data);

/**
 * Begin object retrieval
 *
 * Will be called when CCE requests an object with the given
 * application parameters. Backend will need to call the given
 * callback function when data for the object becomes available,
 * either in part or completely. Backend needs to return data as
 * bCalendar object that can be sent to CCE as is, but can do it
 * in chunks.
 *
 * If "attachments" is TRUE, attachment_id specifies which attachment
 * is to be returned. If ID is invalid (0), all attahcments should be
 * returned, otherwise only the selected one.
 */
int cas_backend_get(void *backend_data, const gchar *handle, gboolean recur,
			gboolean attachments, uint8_t attachment_id,
			void (*cas_get_cb)(int err, const gchar *chunk,
						gsize length, gboolean final,
						void *user_data),
			void *user_data);

/**
 * Begin object upload
 *
 * Will be called when CCE requests to upload an object with the given
 * application parameters. This function does not yet convey any data;
 * see cas_put_continue(). Returns zero on success, an error code
 * otherwise.
 *
 * Backend has to assign a handle for the received object in case
 * upload can be successfully started. Handle of the created object
 * must be written into handle_buf; it is guaranteed to hold
 * CTN_HANDLE_STR_LEN characters and a terminating null byte.
 */
int cas_backend_put(void *backend_data, const gchar *folder, gboolean send,
			gchar *handle_buf);

/**
 * Continue object upload
 *
 * Will be called whenever there is data sent by the CCE to be
 * saved. If needed, the backend can store the data in temporary
 * storage and perform the actual saving only when the final data
 * chunk has been received; see cas_backend_put_finalize().
 * Data given to the backend is the raw OBEX body sent by the CCE,
 * and backend will need to validate it as it sees fit.
 *
 * Returns zero on success, an error code otherwise.
 */
int cas_backend_put_continue(void *backend_data, const gchar *buf, gsize count);

/**
 * Finalize object upload
 *
 * All data for the object has been received, and backend needs to
 * finalize storing the object.
 *
 * Returns an error code if an error is immediately detected; otherwise,
 * returns zero and calls the given callback when storing is complete.
 */
int cas_backend_put_finalize(void *backend_data,
				void (*cas_put_cb)(int err, void *user_data),
				void *user_data);

/**
 * Set object status
 *
 * Will be called when CCE makes a status request for an object with
 * the given application parameters. Backend will need to call the
 * given callback function when status change operation is completed.
 *
 * Status value to set depends on status type; for CTN_STATUS_PART it
 * is a pointer to an enum ctn_pstatus, for CTN_STATUS_SEND it is a
 * pointer to a gboolean, for CTN_STATUS_DELETE it is always a null
 * pointer, and for CTN_STATUS_ALARM it is a pointer to an uint32_t
 * with the following meaning:
 *
 *     !p:	deactivate alarm
 *     *p == 0:	activate alarm now
 *     *p > 0:	postpone alarm for n minutes
 *
 */
int cas_backend_set_status(void *backend_data, const gchar *handle,
				enum ctn_status type, void *value,
				void (*cas_set_status_cb)(int err,
							void *user_data),
				void *user_data);
 
/**
 * Abort current request
 *
 * Will be called if the current ongoing CCE request is to be aborted.
 */
void cas_backend_abort(void *backend_data);
