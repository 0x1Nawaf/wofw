#ifndef WOFW_RULES_H
#define WOFW_RULES_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef enum {
    WOFW_ACTION_ACCEPT,
    WOFW_ACTION_DROP
} wofw_action_t;

typedef enum {
    WOFW_PROTO_ANY,
    WOFW_PROTO_TCP,
    WOFW_PROTO_UDP,
    WOFW_PROTO_ICMP
} wofw_proto_t;

typedef struct {
    uint32_t addr;   /* network byte order */
    uint8_t  prefix; /* 0-32 */
    bool     is_any;
} wofw_cidr_t;

typedef struct {
    wofw_action_t action;
    wofw_proto_t  proto;
    wofw_cidr_t   src;
    wofw_cidr_t   dst;
    uint16_t      port; /* host byte order; 0 when unused */
    bool          has_port;
} wofw_rule_t;

typedef struct {
    wofw_rule_t  *rules;
    size_t        count;
    wofw_action_t default_policy;
} wofw_ruleset_t;

typedef struct {
    char *message;
    int   line;
} wofw_parse_error_t;

void wofw_rules_init(wofw_ruleset_t *rs);
int wofw_rules_parse_line(const char *line, int line_no, wofw_ruleset_t *rs,
                          wofw_parse_error_t *err);
int wofw_rules_load(const char *path, wofw_ruleset_t *rs, wofw_parse_error_t *err);
void wofw_rules_free(wofw_ruleset_t *rs);
const char *wofw_action_str(wofw_action_t action);
const char *wofw_proto_str(wofw_proto_t proto);
bool wofw_cidr_match(uint32_t addr, const wofw_cidr_t *cidr);

#endif /* WOFW_RULES_H */
