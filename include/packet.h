#ifndef WOFW_PACKET_H
#define WOFW_PACKET_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    WOFW_PKT_OK,
    WOFW_PKT_MALFORMED,
    WOFW_PKT_TRUNCATED
} wofw_pkt_status_t;

typedef enum {
    WOFW_L4_NONE,
    WOFW_L4_TCP,
    WOFW_L4_UDP,
    WOFW_L4_ICMP
} wofw_l4_proto_t;

typedef struct {
    wofw_pkt_status_t status;
    wofw_l4_proto_t   l4_proto;
    uint32_t          src_ip;   /* network byte order */
    uint32_t          dst_ip;
    uint16_t          src_port; /* host byte order; 0 if N/A */
    uint16_t          dst_port;
    uint8_t           ip_proto; /* raw IP protocol number */
} wofw_packet_t;

wofw_packet_t wofw_packet_parse(const uint8_t *data, size_t len);

#endif /* WOFW_PACKET_H */
