#include "packet.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>

static wofw_packet_t make_error(wofw_pkt_status_t status)
{
    wofw_packet_t pkt;

    memset(&pkt, 0, sizeof(pkt));
    pkt.status = status;
    pkt.l4_proto = WOFW_L4_NONE;
    return pkt;
}

wofw_packet_t wofw_packet_parse(const uint8_t *data, size_t len)
{
    wofw_packet_t pkt;
    const struct iphdr *ip;
    size_t ip_hdr_len;
    size_t ip_total_len;
    const uint8_t *l4;
    size_t l4_len;

    memset(&pkt, 0, sizeof(pkt));
    pkt.status = WOFW_PKT_OK;
    pkt.l4_proto = WOFW_L4_NONE;

    if (data == NULL || len < sizeof(struct iphdr)) {
        return make_error(WOFW_PKT_TRUNCATED);
    }

    ip = (const struct iphdr *)data;

    if (ip->version != 4) {
        return make_error(WOFW_PKT_MALFORMED);
    }

    ip_hdr_len = (size_t)ip->ihl * 4u;
    if (ip->ihl < 5 || ip_hdr_len > len) {
        return make_error(WOFW_PKT_TRUNCATED);
    }

    ip_total_len = ntohs(ip->tot_len);
    if (ip_total_len < ip_hdr_len || ip_total_len > len) {
        return make_error(WOFW_PKT_TRUNCATED);
    }

    pkt.src_ip = ip->saddr;
    pkt.dst_ip = ip->daddr;
    pkt.ip_proto = ip->protocol;

    l4 = data + ip_hdr_len;
    l4_len = ip_total_len - ip_hdr_len;

    switch (ip->protocol) {
    case IPPROTO_TCP: {
        const struct tcphdr *tcp;

        if (l4_len < sizeof(struct tcphdr)) {
            return make_error(WOFW_PKT_TRUNCATED);
        }

        tcp = (const struct tcphdr *)l4;
        pkt.l4_proto = WOFW_L4_TCP;
        pkt.src_port = ntohs(tcp->source);
        pkt.dst_port = ntohs(tcp->dest);
        break;
    }
    case IPPROTO_UDP: {
        const struct udphdr *udp;

        if (l4_len < sizeof(struct udphdr)) {
            return make_error(WOFW_PKT_TRUNCATED);
        }

        udp = (const struct udphdr *)l4;
        pkt.l4_proto = WOFW_L4_UDP;
        pkt.src_port = ntohs(udp->source);
        pkt.dst_port = ntohs(udp->dest);
        break;
    }
    case IPPROTO_ICMP: {
        if (l4_len < ICMP_MINLEN) {
            return make_error(WOFW_PKT_TRUNCATED);
        }

        pkt.l4_proto = WOFW_L4_ICMP;
        break;
    }
    default:
        pkt.l4_proto = WOFW_L4_NONE;
        break;
    }

    return pkt;
}
