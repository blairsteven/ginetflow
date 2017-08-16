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
static guint8 test_src[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
static guint8 test_dst[] = { 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB };

static guint8 test_ip6src[] = {
    0xfc, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01
};

static guint8 test_ip6dst[] = {
    0xfc, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01
};

static guint16 test_sport = 0x1111;
static guint16 test_dport = 0x2222;
static guint32 test_saddr = 0x12345678;
static guint32 test_daddr = 0x87654321;

typedef struct icmp_hdr_t {
    guint8 type;
    guint8 code;
    guint16 chksum;
} __attribute__ ((packed)) icmp_hdr_t;

static guint8 *build_hdr_eth(guint8 * buffer, guint16 next_eth_protocol)
{
    guint8 *p = buffer;
    ethernet_hdr_t *eth = (ethernet_hdr_t *) p;
    memcpy(eth->destination, test_src, 6);
    memcpy(eth->source, test_dst, 6);
    eth->protocol = g_htons(next_eth_protocol);
    p += sizeof(ethernet_hdr_t);
    return p;
}

static guint8 *build_hdr_vlan(guint8 * buffer,
                              guint16 vlan_protocol, guint16 next_protocol, int count)
{
    guint8 *p = buffer;

    for (int i = 1; i < count; i++) {
        vlan_hdr_t *vlan = (vlan_hdr_t *) p;
        vlan->tci = 0xc7db;
        vlan->protocol = g_htons(vlan_protocol);
        p += sizeof(vlan_hdr_t);
    }

    vlan_hdr_t *vlan = (vlan_hdr_t *) p;
    vlan->tci = 0xc7db;
    vlan->protocol = g_htons(next_protocol);
    p += sizeof(vlan_hdr_t);

    return p;
}

static guint8 *build_hdr_ipv4(guint8 * buffer, guint next_ip_protocol, gboolean reverse)
{
    guint8 *p = buffer;
    ip_hdr_t *ip = (ip_hdr_t *) p;
    ip->ihl_version = 0x45;
    ip->tos = 0x00;
    ip->tot_len = 0x0000;
    ip->id = 0x1234;
    ip->frag_off = 0x0000;
    ip->ttl = 0xff;
    ip->protocol = next_ip_protocol;
    ip->check = 0x00;
    if (reverse) {
        ip->saddr = test_daddr;
        ip->daddr = test_saddr;
    } else {
        ip->saddr = test_saddr;
        ip->daddr = test_daddr;
    }
    p += sizeof(ip_hdr_t);
    return p;
}

static guint8 *build_hdr_ipv6(guint8 * buffer, guint next_ip_protocol, gboolean reverse)
{
    guint8 *p = buffer;
    ip6_hdr_t *ip6 = (ip6_hdr_t *) p;
    ip6->ver_tc_fl = 0x600d684a;
    ip6->pay_len = 0x28;
    ip6->next_hdr = next_ip_protocol;
    ip6->hop_limit = 0x40;
    if (reverse) {
        memcpy(ip6->saddr, test_ip6dst, 16);
        memcpy(ip6->daddr, test_ip6src, 16);
    } else {
        memcpy(ip6->saddr, test_ip6src, 16);
        memcpy(ip6->daddr, test_ip6dst, 16);
    }
    p += sizeof(ip6_hdr_t);
    return p;
}

static guint8 *build_hdr_sctp(guint8 * buffer, gboolean reverse)
{
    guint8 *p = buffer;
    sctp_hdr_t *sctp_hdr = (sctp_hdr_t *) p;
    if (reverse) {
        sctp_hdr->source = test_dport;
        sctp_hdr->destination = test_sport;
    } else {
        sctp_hdr->source = test_sport;
        sctp_hdr->destination = test_dport;
    }
    sctp_hdr->ver_tag = 0x0;
    sctp_hdr->checksum = 0x1234;
    p += sizeof(sctp_hdr_t);
    return p;
}

static guint8 *build_hdr_fragment(guint8 * buffer, guint16 next_ip_protocol)
{
    guint8 *p = buffer;
    frag_hdr_t *fragment_hdr = (frag_hdr_t *) p;
    fragment_hdr->next_hdr = next_ip_protocol;
    fragment_hdr->res = 0x0;
    fragment_hdr->fo_res_mflag = 0x0;
    fragment_hdr->id = 0x01;
    p += sizeof(frag_hdr_t);
    return p;
}

static guint8 *build_hdr_auth(guint8 * buffer, guint16 next_ip_protocol)
{
    guint8 *p = buffer;
    auth_hdr_t *auth_hdr = (auth_hdr_t *) p;
    auth_hdr->next_hdr = next_ip_protocol;
    auth_hdr->payload_len = 4;
    auth_hdr->reserved;
    auth_hdr->spi_seq;
    auth_hdr->icv;
    p += (auth_hdr->payload_len + AH_HEADER_LEN_ADD) * FOUR_BYTE_UNITS;
    return p;
}

static guint8 *build_hdr_ipv6_part(guint8 * buffer, guint16 next_ip_protocol)
{
    guint8 *p = buffer;
    ipv6_partial_ext_hdr_t *ipv6_part_hdr = (ipv6_partial_ext_hdr_t *) p;
    ipv6_part_hdr->next_hdr = next_ip_protocol;
    ipv6_part_hdr->hdr_ext_len = 4;
    p += get_hdr_len(ipv6_part_hdr->hdr_ext_len);
    return p;
}

static guint8 *build_hdr_ipv6_ext(guint8 * buffer,
                                  guint ip_protocol,
                                  guint16 next_ip_protocol, gboolean reverse)
{
    guint8 *p = buffer;

    switch (ip_protocol) {
    case IP_PROTOCOL_IPV4:
        p = build_hdr_ipv4(p, next_ip_protocol, reverse);
        break;
    case IP_PROTOCOL_IPV6:
        p = build_hdr_ipv6(p, next_ip_protocol, reverse);
        break;
    case IP_PROTOCOL_SCTP:
        p = build_hdr_sctp(p, reverse);
        break;
    case IP_PROTOCOL_HBH_OPT:
    case IP_PROTOCOL_DEST_OPT:
    case IP_PROTOCOL_ROUTING:
    case IP_PROTOCOL_MOBILITY:
    case IP_PROTOCOL_HIPV2:
    case IP_PROTOCOL_SHIM6:
        p = build_hdr_ipv6_part(p, next_ip_protocol);
        break;
    case IP_PROTOCOL_FRAGMENT:
        p = build_hdr_fragment(p, next_ip_protocol);
        break;
    case IP_PROTOCOL_AUTH:
        p = build_hdr_auth(p, next_ip_protocol);
        break;
    case IP_PROTOCOL_ESP:
    case IP_PROTOCOL_NO_NEXT_HDR:
    default:
        return buffer;
    }
    return p;
}

static guint8 *build_hdr_pppoe(guint8 * buffer, guint next_ip_protocol, guint16 ppp_proto,
                               gboolean reverse)
{
    if (ppp_proto != PPP_PROTOCOL_IPV4 && ppp_proto != PPP_PROTOCOL_IPV6) {
        return buffer;
    }

    guint8 *p = buffer;
    pppoe_sess_hdr_t *pppoe = (pppoe_sess_hdr_t *) p;
    pppoe->ver_type = 0x11;
    pppoe->code = 0x00;
    pppoe->session_id = 0x0001;
    pppoe->payload_length = 0x0032;
    pppoe->ppp_protocol_id = g_htons(ppp_proto);
    p += sizeof(pppoe_sess_hdr_t);
    switch (ppp_proto) {
    case PPP_PROTOCOL_IPV4:
    default:
        p = build_hdr_ipv4(p, next_ip_protocol, reverse);
        break;
    case PPP_PROTOCOL_IPV6:
        p = build_hdr_ipv6(p, next_ip_protocol, reverse);
        break;
    }
    return p;
}

static guint8 *build_hdr_tcp(guint8 * buffer, gboolean reverse)
{
    guint8 *p = buffer;
    tcp_hdr_t *tcp = (tcp_hdr_t *) p;
    if (reverse) {
        tcp->source = test_dport;
        tcp->destination = test_sport;
    } else {
        tcp->source = test_sport;
        tcp->destination = test_dport;
    }
    tcp->seq = 0;
    tcp->ack = 0;
    tcp->flags = 0;
    tcp->window = 0;
    tcp->check = 0;
    tcp->urg_ptr = 0;
    p += sizeof(tcp_hdr_t);
    return p;
}

static guint8 *build_hdr_udp(guint8 * buffer, gboolean reverse)
{
    guint8 *p = buffer;
    udp_hdr_t *udp = (udp_hdr_t *) p;
    if (reverse) {
        udp->source = test_dport;
        udp->destination = test_sport;
    } else {
        udp->source = test_sport;
        udp->destination = test_dport;
    }
    udp->length = 0x0020;
    udp->check = 0x0000;
    p += sizeof(udp_hdr_t);
    return p;
}

static guint8 *build_hdr_icmp(guint8 * buffer, gboolean reverse)
{
    guint8 *p = buffer;
    icmp_hdr_t *icmp = (icmp_hdr_t *) p;
    icmp->type = 0x08;
    icmp->code = 0x00;;
    icmp->chksum = 0x4008;
    p += sizeof(icmp_hdr_t);
    return p;
}

static guint8 *build_hdr_after_ip(guint8 * buffer, guint ip_protocol, gboolean reverse)
{
    guint8 *p = buffer;

    switch (ip_protocol) {
    case IP_PROTOCOL_TCP:
        p = build_hdr_tcp(p, reverse);
        break;
    case IP_PROTOCOL_UDP:
        p = build_hdr_udp(p, reverse);
        break;
    case IP_PROTOCOL_ICMP:
    case IP_PROTOCOL_ICMPV6:
        p = build_hdr_icmp(p, reverse);
        break;
    default:
        return buffer;
    }
    return p;
}

static guint8 *build_hdr_ip(guint8 * buffer,
                            guint16 eth_protocol, guint next_ip_protocol, gboolean reverse)
{
    guint8 *p = buffer;

    switch (eth_protocol) {
    case ETH_PROTOCOL_IP:
        p = build_hdr_ipv4(buffer, next_ip_protocol, reverse);
        break;
    case ETH_PROTOCOL_IPV6:
        p = build_hdr_ipv6(buffer, next_ip_protocol, reverse);
        break;
    default:
        return buffer;
    }

    return p;
}

static guint8 *build_pkt(guint8 * buffer,
                         guint16 eth_protocol, guint ip_protocol, gboolean reverse)
{
    guint8 *p = build_hdr_eth(buffer, eth_protocol);
    p = build_hdr_ip(p, eth_protocol, ip_protocol, reverse);
    return build_hdr_after_ip(p, ip_protocol, reverse);
}

static guint make_pkt(guint8 * buffer, guint16 eth_protocol, guint ip_protocol)
{
    guint8 *p = build_pkt(buffer, eth_protocol, ip_protocol, FALSE);
    return (guint) (p - buffer);
}

static guint make_pkt_reverse(guint8 * buffer, guint16 eth_protocol, guint ip_protocol)
{
    guint8 *p = build_pkt(buffer, eth_protocol, ip_protocol, TRUE);
    return (guint) (p - buffer);
}

static guint make_pkt_pppoe(guint8 * buffer, guint ip_protocol, guint16 ppp_protocol)
{
    guint8 *p = build_hdr_eth(buffer, ETH_PROTOCOL_PPPOE_SESS);
    p = build_hdr_pppoe(p, ip_protocol, ppp_protocol, FALSE);
    p = build_hdr_after_ip(p, ip_protocol, FALSE);
    return (guint) (p - buffer);
}

static guint make_pkt_vlan(guint8 * buffer,
                           guint16 eth_protocol,
                           guint16 vlan_protocol, guint ip_protocol, int count)
{
    guint8 *p = build_hdr_eth(buffer, vlan_protocol);
    p = build_hdr_vlan(p, vlan_protocol, eth_protocol, count);
    p = build_hdr_ip(p, eth_protocol, ip_protocol, FALSE);
    p = build_hdr_after_ip(p, ip_protocol, FALSE);
    return (guint) (p - buffer);
}

static guint make_pkt_vlan_Q_AD(guint8 * buffer, guint16 eth_protocol, guint ip_protocol)
{
    guint8 *p = build_hdr_eth(buffer, ETH_PROTOCOL_8021Q);
    p = build_hdr_vlan(p, ETH_PROTOCOL_8021Q, ETH_PROTOCOL_8021AD, 1);
    p = build_hdr_vlan(p, ETH_PROTOCOL_8021AD, eth_protocol, 1);
    p = build_hdr_ip(p, eth_protocol, ip_protocol, FALSE);
    return (guint) (p - buffer);
}

static guint make_pkt_ipv6_ext(guint8 * buffer, guint16 next_ip_protocol, gboolean reverse)
{
    guint8 *p = build_hdr_ip(buffer, ETH_PROTOCOL_IPV6, next_ip_protocol, FALSE);

    if (next_ip_protocol != IP_PROTOCOL_NO_NEXT_HDR) {
        if (next_ip_protocol == IP_PROTOCOL_IPV4) {
            p = build_hdr_ipv6_ext(p, next_ip_protocol, IP_PROTOCOL_ICMP, reverse);
        } else {
            p = build_hdr_ipv6_ext(p, next_ip_protocol, IP_PROTOCOL_ICMPV6, reverse);
        }
        p = build_hdr_after_ip(p, IP_PROTOCOL_ICMPV6, FALSE);
    }
    return (guint) (p - buffer);
}

static void setup_test()
{
    memset(&test_flow, 0, sizeof(GInetFlow));
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

    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    NP_ASSERT(flow_parse(&test_flow, test_buffer, len, 0));

    len = make_pkt(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_UDP);
    NP_ASSERT(flow_parse(&test_flow, test_buffer, len, 0));

    /* Reverse */
    len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    NP_ASSERT(flow_parse(&test_flow, test_buffer, len, 0));

    len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_UDP);
    NP_ASSERT(flow_parse(&test_flow, test_buffer, len, 0));
}

void test_flow_parse_tcp()
{
    setup_test();

    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    NP_ASSERT(flow_parse(&test_flow, test_buffer, len, 0));

    len = make_pkt(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_TCP);
    NP_ASSERT(flow_parse(&test_flow, test_buffer, len, 0));

    /* Reverse */
    len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    NP_ASSERT(flow_parse(&test_flow, test_buffer, len, 0));

    len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_TCP);
    NP_ASSERT(flow_parse(&test_flow, test_buffer, len, 0));
}

void test_flow_parse_icmp()
{
    setup_test();

    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_ICMP);
    NP_ASSERT(flow_parse(&test_flow, test_buffer, len, 0));

    len = make_pkt(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_ICMPV6);
    NP_ASSERT(flow_parse(&test_flow, test_buffer, len, 0));
}

void test_flow_parse_pppoe()
{
    setup_test();

    guint len = make_pkt_pppoe(test_buffer, IP_PROTOCOL_UDP, PPP_PROTOCOL_IPV4);
    NP_ASSERT(flow_parse(&test_flow, test_buffer, len, 0));

    len = make_pkt_pppoe(test_buffer, IP_PROTOCOL_UDP, PPP_PROTOCOL_IPV6);
    NP_ASSERT(flow_parse(&test_flow, test_buffer, len, 0));
}

void test_flow_parse_vlan()
{
    setup_test();

    guint len =
        make_pkt_vlan(test_buffer, ETH_PROTOCOL_IP, ETH_PROTOCOL_8021Q, IP_PROTOCOL_ICMP,
                      1);
    NP_ASSERT(flow_parse(&test_flow, test_buffer, len, 0));

    len =
        make_pkt_vlan(test_buffer, ETH_PROTOCOL_IP, ETH_PROTOCOL_8021Q, IP_PROTOCOL_ICMP,
                      2);
    NP_ASSERT(flow_parse(&test_flow, test_buffer, len, 0));

    len =
        make_pkt_vlan(test_buffer, ETH_PROTOCOL_IPV6, ETH_PROTOCOL_8021AD,
                      IP_PROTOCOL_ICMPV6, 1);
    NP_ASSERT(flow_parse(&test_flow, test_buffer, len, 0));

    len =
        make_pkt_vlan(test_buffer, ETH_PROTOCOL_IPV6, ETH_PROTOCOL_8021AD,
                      IP_PROTOCOL_ICMPV6, 2);
    NP_ASSERT(flow_parse(&test_flow, test_buffer, len, 0));

    len = make_pkt_vlan_Q_AD(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_ICMPV6);
    NP_ASSERT(flow_parse(&test_flow, test_buffer, len, 0));
}

void test_flow_parse_ipv6_ext()
{
    setup_test();

    guint len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_HBH_OPT, FALSE);
    NP_ASSERT(flow_parse_ipv6(&test_flow, test_buffer, len));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_DEST_OPT, FALSE);
    NP_ASSERT(flow_parse_ipv6(&test_flow, test_buffer, len));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_ROUTING, FALSE);
    NP_ASSERT(flow_parse_ipv6(&test_flow, test_buffer, len));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_MOBILITY, FALSE);
    NP_ASSERT(flow_parse_ipv6(&test_flow, test_buffer, len));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_HIPV2, FALSE);
    NP_ASSERT(flow_parse_ipv6(&test_flow, test_buffer, len));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_SHIM6, FALSE);
    NP_ASSERT(flow_parse_ipv6(&test_flow, test_buffer, len));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_FRAGMENT, FALSE);
    NP_ASSERT(flow_parse_ipv6(&test_flow, test_buffer, len));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_AUTH, FALSE);
    NP_ASSERT(flow_parse_ipv6(&test_flow, test_buffer, len));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_SCTP, FALSE);
    NP_ASSERT(flow_parse_ipv6(&test_flow, test_buffer, len));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_SCTP, TRUE);
    NP_ASSERT(flow_parse_ipv6(&test_flow, test_buffer, len));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_IPV4, FALSE);
    NP_ASSERT(flow_parse_ipv6(&test_flow, test_buffer, len));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_IPV6, FALSE);
    NP_ASSERT(flow_parse_ipv6(&test_flow, test_buffer, len));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_ESP, FALSE);
    NP_ASSERT_FALSE(flow_parse_ipv6(&test_flow, test_buffer, len));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_NO_NEXT_HDR, FALSE);
    NP_ASSERT_FALSE(flow_parse_ipv6(&test_flow, test_buffer, len));
}

void test_flow_parse_unsupported_eth_protocols()
{
    setup_test();

    /* ARP */
    guint len = make_pkt(test_buffer, 0x0806, IP_PROTOCOL_ICMP);
    NP_ASSERT_FALSE(flow_parse(&test_flow, test_buffer, len, 0));

    /* AARP */
    len = make_pkt(test_buffer, 0x80F3, IP_PROTOCOL_ICMP);
    NP_ASSERT_FALSE(flow_parse(&test_flow, test_buffer, len, 0));

    /* IPX */
    len = make_pkt(test_buffer, 0x8137, IP_PROTOCOL_ICMP);
    NP_ASSERT_FALSE(flow_parse(&test_flow, test_buffer, len, 0));

    /* PPPoE Discovery */
    len = make_pkt(test_buffer, 0x8863, IP_PROTOCOL_ICMP);
    NP_ASSERT_FALSE(flow_parse(&test_flow, test_buffer, len, 0));
}

void test_flow_parse_not_ipv6_ext()
{
    setup_test();

    /* KRYPTOLAN */
    guint len = make_pkt_ipv6_ext(test_buffer, 65, FALSE);
    NP_ASSERT_FALSE(flow_parse_ipv6(&test_flow, test_buffer, len));

    /* IGMP */
    len = make_pkt_ipv6_ext(test_buffer, 2, FALSE);
    NP_ASSERT_FALSE(flow_parse_ipv6(&test_flow, test_buffer, len));
}

void test_flow_parse_unsupported_after_ip_protocols()
{
    setup_test();

    /* CRUDP */
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, 127);
    NP_ASSERT_FALSE(flow_parse(&test_flow, test_buffer, len, 0));

    /* UDPLite */
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, 136);
    NP_ASSERT_FALSE(flow_parse(&test_flow, test_buffer, len, 0));

    /* IL */
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, 40);
    NP_ASSERT_FALSE(flow_parse_ipv6(&test_flow, test_buffer, len));

    /* IPv4 SCTP */
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_SCTP);
    NP_ASSERT_FALSE(flow_parse_ipv6(&test_flow, test_buffer, len));
}

void test_flow_parse_unsupported_ppp_protocols()
{
    setup_test();

    /* IPCP */
    guint len = make_pkt_pppoe(test_buffer, IP_PROTOCOL_UDP, 0x8021);
    NP_ASSERT_FALSE(flow_parse(&test_flow, test_buffer, len, 0));

    /* ATCP */
    len = make_pkt_pppoe(test_buffer, IP_PROTOCOL_UDP, 0x8029);
    NP_ASSERT_FALSE(flow_parse(&test_flow, test_buffer, len, 0));

    /* IPXCP */
    len = make_pkt_pppoe(test_buffer, IP_PROTOCOL_UDP, 0x802B);
    NP_ASSERT_FALSE(flow_parse(&test_flow, test_buffer, len, 0));
}

void test_flow_parse_more_than_2_vlan_tags()
{
    setup_test();

    guint len =
        make_pkt_vlan(test_buffer, ETH_PROTOCOL_IP, ETH_PROTOCOL_8021Q, IP_PROTOCOL_ICMP,
                      3);
    NP_ASSERT_FALSE(flow_parse(&test_flow, test_buffer, len, 0));

    len =
        make_pkt_vlan(test_buffer, ETH_PROTOCOL_IPV6, ETH_PROTOCOL_8021AD,
                      IP_PROTOCOL_ICMPV6, 3);
    NP_ASSERT_FALSE(flow_parse(&test_flow, test_buffer, len, 0));
}

void test_flow_create()
{
    GInetFlowTable *table = g_inet_flow_table_new();
    guint64 now = get_time_us();
    setup_test();
    NP_ASSERT_NOT_NULL(table);
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    GInetFlow *flow = g_inet_flow_get_full(table, test_buffer, len, 0, now, TRUE);
    NP_ASSERT_NOT_NULL(flow);
    guint64 size;
    g_object_get(table, "size", &size, NULL);
    NP_ASSERT_EQUAL(size, 1);
    g_object_unref(table);
}

void test_flow_table_size()
{
    GInetFlowTable *table = g_inet_flow_table_new();
    setup_test();
    NP_ASSERT_NOT_NULL(table);

    guint64 max;
    g_object_get(table, "max", &max, NULL);
    NP_ASSERT_EQUAL(max, 0);

    g_inet_flow_table_max_set(table, 1);
    g_object_get(table, "max", &max, NULL);
    NP_ASSERT_EQUAL(max, 1);

    guint pk1 = make_pkt(test_buffer, 4, IP_PROTOCOL_UDP);
    GInetFlow *flow1 = g_inet_flow_get_full(table, test_buffer, pk1, 0, get_time_us(), TRUE);
    NP_ASSERT_NOT_NULL(flow1);

    guint pk2 = make_pkt(test_buffer, 4, IP_PROTOCOL_TCP);
    GInetFlow *flow2 = g_inet_flow_get_full(table, test_buffer, pk2, 0, get_time_us(), TRUE);
    NP_ASSERT_NULL(flow2);

    g_object_unref(table);
}

void test_flow_not_expired()
{
    guint64 now = get_time_us();
    GInetFlowTable *table;
    GInetFlow *flow;
    guint64 size;

    setup_test();
    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, now, TRUE)));
    NP_ASSERT_NULL(g_inet_flow_expire
                   (table, now + (G_INET_FLOW_DEFAULT_NEW_TIMEOUT * 1000000) - 1));
    g_object_get(table, "size", &size, NULL);
    NP_ASSERT_EQUAL(size, 1);
    g_object_unref(table);
}

void test_flow_expired()
{
    guint64 now = get_time_us();
    GInetFlowTable *table;
    GInetFlow *flow;
    guint64 size;

    setup_test();
    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    NP_ASSERT_NOT_NULL((flow =
                        g_inet_flow_get_full(table, test_buffer, len, 0, now, TRUE)));
    NP_ASSERT_NOT_NULL(g_inet_flow_expire
                       (table, now + (G_INET_FLOW_DEFAULT_NEW_TIMEOUT * 1000000)));
    g_object_get(table, "size", &size, NULL);
    NP_ASSERT_EQUAL(size, 0);
    g_object_unref(table);
}

void test_flow_tcp_new()
{
    GInetFlowTable *table;
    GInetFlow *flow;
    guint state = FLOW_CLOSED;

    setup_test();
    NP_ASSERT_NOT_NULL((table = g_inet_flow_table_new()));
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    NP_ASSERT_NOT_NULL((flow = g_inet_flow_get_full(table, test_buffer, len, 0, 0, TRUE)));
    g_object_get(flow, "state", &state, NULL);
    NP_ASSERT_EQUAL(state, FLOW_NEW);

    g_object_unref(table);
}
