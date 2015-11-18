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
#include <inttypes.h>
#include <glib.h>
#include <errno.h>

#include "obexd/plugins/ctn.h"
#include "obexd/plugins/cnc.h"

struct cnc_session {
};

int cnc_connect(const gchar *src, const gchar *dst,
		struct cnc_session **ret,
		void (*cb)(struct cnc_session *, int err, void *),
		void *user_data)
{
	/* TODO: just a null stub for now */
	return -EOPNOTSUPP;
}

int cnc_disconnect(struct cnc_session *session,
			void (*cb)(struct cnc_session *, int err, void *),
			void *user_data)
{
	/* TODO: just a null stub for now */
}

int cnc_push(struct cnc_session *session, struct ctn_event *event, 
			void (*cb)(struct cnc_session *, int err, void *),
			void *user_data)
{
	/* TODO: just a null stub for now */
	return -EOPNOTSUPP;
}
