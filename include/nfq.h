#ifndef WOFW_NFQ_H
#define WOFW_NFQ_H

#include "rules.h"

typedef struct wofw_nfq wofw_nfq_t;

wofw_nfq_t *wofw_nfq_open(uint16_t queue_num, wofw_ruleset_t *ruleset);
void wofw_nfq_close(wofw_nfq_t *nfq);
int wofw_nfq_fd(const wofw_nfq_t *nfq);
int wofw_nfq_handle_packet(wofw_nfq_t *nfq);

#endif /* WOFW_NFQ_H */
