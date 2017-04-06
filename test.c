/* GInetFlow - Unit tests
 *
 * Copyright (C) 2017 ECLB Ltd
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
#include "ginetflow.c"
#include <np.h>

static GInetFlow test_flow;
#define MAX_BUFFER_SIZE     1600
static guint8 test_buffer[MAX_BUFFER_SIZE];

static const ethernet_hdr_t test_ethhdr =  {{0,1,2,3,4,5},{6,7,8,9},g_htons(ETH_PROTOCOL_IP)};
static const ip_hdr_t test_iphdr = {0x45,0x00,0x0000,0x1234,0x0000,0xff,IP_PROTOCOL_UDP,0x00,0x12345678,0x87654321};
static const udp_hdr_t test_udphdr = {0x0007,0x0007,0x0000,0x0000};

static guint
pkt_udp(guint8 *buffer)
{
    guint8 *p = buffer;
    memcpy(p, &test_ethhdr, sizeof(ethernet_hdr_t));
    p += sizeof(ethernet_hdr_t);
    memcpy(p, &test_iphdr, sizeof(ip_hdr_t));
    p += sizeof(ip_hdr_t);
    memcpy(p, &test_udphdr, sizeof(udp_hdr_t));
    p += sizeof(udp_hdr_t);
    return (guint)(p - buffer);
}

static void
setup_test()
{
    memset(&test_flow, 0 , sizeof(GInetFlow));
    memset(test_buffer, 0, MAX_BUFFER_SIZE);
}

void test_flow_parse_null_flow()
{
    setup_test();
    NP_ASSERT_FALSE(flow_parse(NULL, test_buffer, 64, 0));
}

void test_flow_parse_null_buffer()
{
    setup_test();
    NP_ASSERT_FALSE(flow_parse(&test_flow, NULL, 64, 0));
}

void test_flow_parse_0_length()
{
    setup_test();
    NP_ASSERT_FALSE(flow_parse(&test_flow, test_buffer, 0, 0));
}

void test_flow_parse_less_than_eth_length()
{
    setup_test();
    NP_ASSERT_FALSE(flow_parse(&test_flow, test_buffer, sizeof(ethernet_hdr_t) - 1, 0));
}

void test_flow_parse_udp()
{
    setup_test();
    NP_ASSERT(flow_parse(&test_flow, test_buffer, pkt_udp(test_buffer), 0));
}
