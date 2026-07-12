#ifndef WOFW_MATCH_H
#define WOFW_MATCH_H

#include <sys/types.h>

#include "packet.h"
#include "rules.h"

typedef struct {
    wofw_action_t action;
    ssize_t       rule_index; /* -1 when default policy applies */
} wofw_match_result_t;

wofw_match_result_t wofw_match_evaluate(const wofw_packet_t *pkt,
                                        const wofw_ruleset_t *ruleset);

#endif /* WOFW_MATCH_H */
