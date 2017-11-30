/* GInetTuple - IP Tuple
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

#include "ginettuple.h"

/** GInetTuple */
struct _GInetTuple {
    GObject parent;
    GInetAddress *src;
    guint16 sport;
    GInetAddress *dst;
    guint16 dport;
    guint16 protocol;

    /* Internal use only */
    GInetSocketAddress *lower;
    GInetSocketAddress *upper;
};

struct _GInetTupleClass {
    GObjectClass parent;
};
G_DEFINE_TYPE(GInetTuple, g_inet_tuple, G_TYPE_OBJECT);

void clear_cached(GInetTuple *tuple)
{
    if (tuple->lower)
    {
        g_object_unref(tuple->lower);
        tuple->lower = NULL;
    }
    if (tuple->upper)
    {
        g_object_unref(tuple->upper);
        tuple->upper = NULL;
    }
}

GInetAddress *g_inet_tuple_get_src (GInetTuple *tuple)
{
    return tuple->src;
}

GInetAddress *g_inet_tuple_get_dst (GInetTuple *tuple)
{
    return tuple->dst;
}

void g_inet_tuple_set_src_address (GInetTuple *tuple, GInetAddress *src)
{
    if (tuple->src)
        g_object_unref((GObject*) tuple->src);
    clear_cached(tuple);
    tuple->src = src;
}

void g_inet_tuple_set_src_port (GInetTuple *tuple, guint16 port)
{
    tuple->sport = port;
    clear_cached(tuple);
}

void g_inet_tuple_set_dst_address (GInetTuple *tuple, GInetAddress *dst)
{
    if (tuple->dst)
        g_object_unref((GObject*) tuple->dst);
    clear_cached(tuple);
    tuple->dst = dst;
}

void g_inet_tuple_set_dst_port (GInetTuple *tuple, guint16 port)
{
    tuple->dport = port;
    clear_cached(tuple);
}

void g_inet_tuple_set_protocol (GInetTuple *tuple, guint16 protocol)
{
    tuple->protocol = protocol;
}

GInetSocketAddress *g_inet_tuple_get_lower (GInetTuple *tuple)
{
    GInetAddress *src = g_inet_tuple_get_src(tuple);
    GInetAddress *dst = g_inet_tuple_get_dst(tuple);

    if (!src || !dst)
        return NULL;

    if (tuple->lower)
        return tuple->lower;

    if (tuple->sport > tuple->dport)
    {
        tuple->lower = (GInetSocketAddress*)g_inet_socket_address_new(dst, tuple->dport);
    }
    else
    {
        tuple->lower = (GInetSocketAddress*)g_inet_socket_address_new(src, tuple->sport);
    }
    return tuple->lower;
}

GInetSocketAddress *g_inet_tuple_get_upper (GInetTuple *tuple)
{
    GInetAddress *src = g_inet_tuple_get_src(tuple);
    GInetAddress *dst = g_inet_tuple_get_dst(tuple);

    if (!src || !dst)
        return NULL;

    if (tuple->upper)
        return tuple->upper;

    if (tuple->sport <= tuple->dport)
    {
        tuple->upper = (GInetSocketAddress*)g_inet_socket_address_new(dst, tuple->dport);
    }
    else
    {
        tuple->upper = (GInetSocketAddress*)g_inet_socket_address_new(src, tuple->sport);
    }
    return tuple->upper;
}

GInetSocketAddress *g_inet_tuple_get_server (GInetTuple *tuple)
{
    return g_inet_tuple_get_lower (tuple);
}

GInetSocketAddress *g_inet_tuple_get_client (GInetTuple *tuple)
{
    return g_inet_tuple_get_upper (tuple);
}

guint16 g_inet_tuple_get_protocol (GInetTuple *tuple)
{
    return tuple->protocol;
}

/* This function is a candidate for going upstream into GInetSocketAddress */
gboolean g_inet_socket_address_equal (GInetSocketAddress *a, GInetSocketAddress *b)
{
    if (!a && b)
    {
        return FALSE;
    }
    if (a && !b)
    {
        return FALSE;
    }
    if (g_inet_socket_address_get_port(a) != g_inet_socket_address_get_port(b))
    {
        return FALSE;
    }
    if (!g_inet_address_equal(g_inet_socket_address_get_address(a), g_inet_socket_address_get_address(b)))
    {
        return FALSE;
    }
    return TRUE;
}

gboolean g_inet_tuple_equal (GInetTuple *a, GInetTuple *b)
{
    GInetSocketAddress *lower_a = g_inet_tuple_get_lower(a);
    GInetSocketAddress *upper_a = g_inet_tuple_get_upper(a);
    GInetSocketAddress *lower_b = g_inet_tuple_get_lower(b);
    GInetSocketAddress *upper_b = g_inet_tuple_get_upper(b);
    gboolean equal = FALSE;

    if (!lower_a || !upper_a || !lower_b || !upper_b)
    {
        goto exit;
    }
    if (a->protocol != b->protocol)
    {
        goto exit;
    }
    if (!g_inet_socket_address_equal (lower_a, lower_b))
    {
        goto exit;
    }
    if (!g_inet_socket_address_equal (upper_a, upper_b))
    {
        goto exit;
    }
    equal = TRUE;
exit:
    return equal;
}

static void g_inet_tuple_init(GInetTuple *tuple)
{
    tuple->src = NULL;
    tuple->dst = NULL;
    tuple->upper = NULL;
    tuple->lower = NULL;
    return;
}

static void g_inet_tuple_dispose (GObject *gobject)
{
    GInetTuple *tuple = (GInetTuple*)gobject;
    if (tuple->src)
        g_object_unref(tuple->src);
    if (tuple->dst)
        g_object_unref(tuple->dst);
    if (tuple->lower)
        g_object_unref(tuple->lower);
    if (tuple->upper)
        g_object_unref(tuple->upper);
}

static void g_inet_tuple_class_init(GInetTupleClass * class)
{
    GObjectClass *object_class = G_OBJECT_CLASS(class);
    object_class->dispose = g_inet_tuple_dispose;
    return;
}
