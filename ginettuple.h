/* GInetTuple - IP Tuple object
 *
 * Copyright (C) Allied Telesis Labs NZ
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this library. If not, see <http://www.gnu.org/licenses/>
 */
#ifndef __G_INET_TUPLE_H__
#define __G_INET_TUPLE_H__

#include <glib-object.h>
#include <glib.h>
#include <gio/gio.h>


G_BEGIN_DECLS GType g_inet_tuple_get_type(void) G_GNUC_CONST;
#define G_INET_TUPLE_TYPE      (g_inet_tuple_get_type ())
typedef struct _GInetTuple GInetTuple;
typedef struct _GInetTupleClass GInetTupleClass;
#define G_INET_TUPLE(o)        (G_TYPE_CHECK_INSTANCE_CAST ((o), G_INET_TUPLE_TYPE, GInetTuple))

GInetAddress *g_inet_tuple_get_src(GInetTuple * tuple);
/* g_inet_tuple_set_src_address owns src after this call */
void g_inet_tuple_set_src_address(GInetTuple * tuple, GInetAddress * src);
void g_inet_tuple_set_src_port(GInetTuple * tuple, guint16 port);
GInetAddress *g_inet_tuple_get_dst(GInetTuple * tuple);
/* g_inet_tuple_set_dst_address owns dst after this call */
void g_inet_tuple_set_dst_address(GInetTuple * tuple, GInetAddress * dst);
void g_inet_tuple_set_dst_port(GInetTuple * tuple, guint16 port);
void g_inet_tuple_set_protocol(GInetTuple * tuple, guint16 protocol);
GInetSocketAddress *g_inet_tuple_get_lower(GInetTuple * tuple);
GInetSocketAddress *g_inet_tuple_get_upper(GInetTuple * tuple);
GInetSocketAddress *g_inet_tuple_get_server(GInetTuple * tuple);
GInetSocketAddress *g_inet_tuple_get_client(GInetTuple * tuple);
guint16 g_inet_tuple_get_protocol(GInetTuple * tuple);
gboolean g_inet_tuple_equal(GInetTuple * a, GInetTuple * b);

G_END_DECLS
#endif                          /* __G_INET_TUPLE_H__ */
