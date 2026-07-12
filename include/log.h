#ifndef WOFW_LOG_H
#define WOFW_LOG_H

#include "match.h"
#include "packet.h"
#include "rules.h"

void wofw_log_init(void);
void wofw_log_decision(const wofw_packet_t *pkt, const wofw_match_result_t *result);

#endif /* WOFW_LOG_H */
