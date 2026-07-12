#ifndef WOFW_IPTABLES_H
#define WOFW_IPTABLES_H

#include <stdbool.h>
#include <stdint.h>

#define WOFW_IPTABLES_DEFAULT "INPUT -p tcp --dport 9999"
#define WOFW_IPTABLES_MAX_ARGS 32

typedef struct {
    bool     active;
    uint16_t queue_num;
    char    *rule_spec;
} wofw_iptables_t;

int wofw_iptables_add(wofw_iptables_t *ip, const char *rule_spec, uint16_t queue_num);
void wofw_iptables_remove(wofw_iptables_t *ip);
void wofw_iptables_reset(wofw_iptables_t *ip);

#endif /* WOFW_IPTABLES_H */
