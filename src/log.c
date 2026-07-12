#include "log.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

void wofw_log_init(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
}

static const char *l4_proto_name(const wofw_packet_t *pkt)
{
    switch (pkt->l4_proto) {
    case WOFW_L4_TCP:
        return "tcp";
    case WOFW_L4_UDP:
        return "udp";
    case WOFW_L4_ICMP:
        return "icmp";
    case WOFW_L4_NONE:
        if (pkt->ip_proto != 0) {
            return "ip";
        }
        return "unknown";
    }
    return "unknown";
}

static void format_ip_port(char *buf, size_t buflen, uint32_t addr, uint16_t port,
                           bool show_port)
{
    struct in_addr in;

    in.s_addr = addr;
    if (inet_ntop(AF_INET, &in, buf, (socklen_t)buflen) == NULL) {
        snprintf(buf, buflen, "?");
        return;
    }

    if (show_port && port != 0) {
        size_t used = strlen(buf);
        snprintf(buf + used, buflen - used, ":%u", port);
    }
}

void wofw_log_decision(const wofw_packet_t *pkt, const wofw_match_result_t *result)
{
    char src[64];
    char dst[64];
    char ts[32];
    struct timespec now;
    struct tm tm_buf;
    bool show_ports;

    if (pkt == NULL || result == NULL) {
        return;
    }

    clock_gettime(CLOCK_REALTIME, &now);
    localtime_r(&now.tv_sec, &tm_buf);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_buf);

    show_ports = (pkt->l4_proto == WOFW_L4_TCP || pkt->l4_proto == WOFW_L4_UDP);
    format_ip_port(src, sizeof(src), pkt->src_ip, pkt->src_port, show_ports);
    format_ip_port(dst, sizeof(dst), pkt->dst_ip, pkt->dst_port, show_ports);

    if (result->rule_index >= 0) {
        printf("%s proto=%s src=%s dst=%s rule=%zd action=%s\n",
               ts,
               l4_proto_name(pkt),
               src,
               dst,
               result->rule_index,
               wofw_action_str(result->action));
    } else {
        printf("%s proto=%s src=%s dst=%s rule=default action=%s\n",
               ts,
               l4_proto_name(pkt),
               src,
               dst,
               wofw_action_str(result->action));
    }

    fflush(stdout);
}
