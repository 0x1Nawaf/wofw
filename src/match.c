#include "match.h"

#include <netinet/in.h>

static bool proto_matches(wofw_proto_t rule_proto, const wofw_packet_t *pkt)
{
    switch (rule_proto) {
    case WOFW_PROTO_ANY:
        return true;
    case WOFW_PROTO_TCP:
        return pkt->l4_proto == WOFW_L4_TCP || pkt->ip_proto == IPPROTO_TCP;
    case WOFW_PROTO_UDP:
        return pkt->l4_proto == WOFW_L4_UDP || pkt->ip_proto == IPPROTO_UDP;
    case WOFW_PROTO_ICMP:
        return pkt->l4_proto == WOFW_L4_ICMP || pkt->ip_proto == IPPROTO_ICMP;
    }
    return false;
}

static bool rule_matches(const wofw_rule_t *rule, const wofw_packet_t *pkt)
{
    if (!proto_matches(rule->proto, pkt)) {
        return false;
    }

    if (!wofw_cidr_match(pkt->src_ip, &rule->src)) {
        return false;
    }

    if (!wofw_cidr_match(pkt->dst_ip, &rule->dst)) {
        return false;
    }

    if (rule->has_port) {
        if (pkt->l4_proto != WOFW_L4_TCP && pkt->l4_proto != WOFW_L4_UDP) {
            return false;
        }
        if (pkt->dst_port != rule->port) {
            return false;
        }
    }

    return true;
}

wofw_match_result_t wofw_match_evaluate(const wofw_packet_t *pkt,
                                        const wofw_ruleset_t *ruleset)
{
    wofw_match_result_t result;
    size_t i;

    result.rule_index = -1;
    result.action = ruleset->default_policy;

    if (pkt == NULL || ruleset == NULL) {
        return result;
    }

    for (i = 0; i < ruleset->count; i++) {
        if (rule_matches(&ruleset->rules[i], pkt)) {
            result.action = ruleset->rules[i].action;
            result.rule_index = (ssize_t)i;
            return result;
        }
    }

    return result;
}
