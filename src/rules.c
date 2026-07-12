#include "rules.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WOFW_RULES_INITIAL_CAP 16

const char *wofw_action_str(wofw_action_t action)
{
    switch (action) {
    case WOFW_ACTION_ACCEPT:
        return "accept";
    case WOFW_ACTION_DROP:
        return "drop";
    }
    return "unknown";
}

const char *wofw_proto_str(wofw_proto_t proto)
{
    switch (proto) {
    case WOFW_PROTO_ANY:
        return "any";
    case WOFW_PROTO_TCP:
        return "tcp";
    case WOFW_PROTO_UDP:
        return "udp";
    case WOFW_PROTO_ICMP:
        return "icmp";
    }
    return "unknown";
}

bool wofw_cidr_match(uint32_t addr, const wofw_cidr_t *cidr)
{
    uint32_t mask;

    if (cidr->is_any) {
        return true;
    }

    if (cidr->prefix == 0) {
        return true;
    }

    if (cidr->prefix == 32) {
        mask = 0xFFFFFFFFu;
    } else {
        mask = ~((1u << (32u - cidr->prefix)) - 1u);
    }

    mask = htonl(mask);
    return (addr & mask) == (cidr->addr & mask);
}

static void set_parse_error(wofw_parse_error_t *err, int line, const char *fmt, ...)
{
    va_list ap;
    char buf[256];

    if (err == NULL) {
        return;
    }

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    err->line = line;
    free(err->message);
    err->message = strdup(buf);
}

static char *trim(char *s)
{
    char *end;

    while (*s != '\0' && isspace((unsigned char)*s)) {
        s++;
    }

    if (*s == '\0') {
        return s;
    }

    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }

    return s;
}

static int parse_action(const char *token, wofw_action_t *action)
{
    if (strcmp(token, "accept") == 0) {
        *action = WOFW_ACTION_ACCEPT;
        return 0;
    }
    if (strcmp(token, "drop") == 0) {
        *action = WOFW_ACTION_DROP;
        return 0;
    }
    return -1;
}

static int parse_proto(const char *token, wofw_proto_t *proto)
{
    if (strcmp(token, "any") == 0) {
        *proto = WOFW_PROTO_ANY;
        return 0;
    }
    if (strcmp(token, "tcp") == 0) {
        *proto = WOFW_PROTO_TCP;
        return 0;
    }
    if (strcmp(token, "udp") == 0) {
        *proto = WOFW_PROTO_UDP;
        return 0;
    }
    if (strcmp(token, "icmp") == 0) {
        *proto = WOFW_PROTO_ICMP;
        return 0;
    }
    return -1;
}

static int parse_cidr(const char *token, wofw_cidr_t *cidr)
{
    char buf[64];
    char *slash;
    char *end;
    long prefix;
    struct in_addr addr;

    if (strcmp(token, "any") == 0) {
        cidr->is_any = true;
        cidr->addr = 0;
        cidr->prefix = 0;
        return 0;
    }

    if (strlen(token) >= sizeof(buf)) {
        return -1;
    }

    strncpy(buf, token, sizeof(buf));
    buf[sizeof(buf) - 1] = '\0';

    slash = strchr(buf, '/');
    if (slash == NULL) {
        if (inet_pton(AF_INET, buf, &addr) != 1) {
            return -1;
        }
        cidr->is_any = false;
        cidr->addr = addr.s_addr;
        cidr->prefix = 32;
        return 0;
    }

    *slash = '\0';
    if (inet_pton(AF_INET, buf, &addr) != 1) {
        return -1;
    }

    prefix = strtol(slash + 1, &end, 10);
    if (*end != '\0' || prefix < 0 || prefix > 32) {
        return -1;
    }

    cidr->is_any = false;
    cidr->addr = addr.s_addr;
    cidr->prefix = (uint8_t)prefix;
    return 0;
}

static int parse_port(const char *token, uint16_t *port)
{
    char *end;
    long value;

    value = strtol(token, &end, 10);
    if (*end != '\0' || value < 1 || value > 65535) {
        return -1;
    }

    *port = (uint16_t)value;
    return 0;
}

static int append_rule(wofw_ruleset_t *rs, const wofw_rule_t *rule)
{
    wofw_rule_t *new_rules;

    if (rs->count == 0) {
        rs->rules = malloc(sizeof(*rs->rules) * WOFW_RULES_INITIAL_CAP);
        if (rs->rules == NULL) {
            return -1;
        }
    } else if ((rs->count % WOFW_RULES_INITIAL_CAP) == 0) {
        new_rules = realloc(rs->rules,
                            sizeof(*rs->rules) * (rs->count + WOFW_RULES_INITIAL_CAP));
        if (new_rules == NULL) {
            return -1;
        }
        rs->rules = new_rules;
    }

    rs->rules[rs->count++] = *rule;
    return 0;
}

static int parse_rule_line(const char *line, int line_no, wofw_ruleset_t *rs,
                           wofw_parse_error_t *err)
{
    char buf[512];
    char *cursor;
    char *token;
    wofw_rule_t rule;
    bool seen_from = false;
    bool seen_to = false;
    bool seen_port = false;

    if (strlen(line) >= sizeof(buf)) {
        set_parse_error(err, line_no, "line too long");
        return -1;
    }

    strncpy(buf, line, sizeof(buf));
    buf[sizeof(buf) - 1] = '\0';
    cursor = trim(buf);

    memset(&rule, 0, sizeof(rule));
    rule.src.is_any = true;
    rule.dst.is_any = true;

    token = strtok(cursor, " \t");
    if (token == NULL) {
        set_parse_error(err, line_no, "empty rule");
        return -1;
    }

    if (parse_action(token, &rule.action) != 0) {
        set_parse_error(err, line_no, "unknown action '%s'", token);
        return -1;
    }

    token = strtok(NULL, " \t");
    if (token == NULL) {
        set_parse_error(err, line_no, "missing protocol");
        return -1;
    }

    if (parse_proto(token, &rule.proto) != 0) {
        set_parse_error(err, line_no, "unknown protocol '%s'", token);
        return -1;
    }

    while ((token = strtok(NULL, " \t")) != NULL) {
        if (strcmp(token, "from") == 0) {
            if (seen_from) {
                set_parse_error(err, line_no, "duplicate 'from' clause");
                return -1;
            }
            seen_from = true;
            token = strtok(NULL, " \t");
            if (token == NULL) {
                set_parse_error(err, line_no, "missing source CIDR after 'from'");
                return -1;
            }
            if (parse_cidr(token, &rule.src) != 0) {
                set_parse_error(err, line_no, "invalid source CIDR '%s'", token);
                return -1;
            }
            continue;
        }

        if (strcmp(token, "to") == 0) {
            if (seen_to) {
                set_parse_error(err, line_no, "duplicate 'to' clause");
                return -1;
            }
            seen_to = true;
            token = strtok(NULL, " \t");
            if (token == NULL) {
                set_parse_error(err, line_no, "missing destination CIDR after 'to'");
                return -1;
            }
            if (parse_cidr(token, &rule.dst) != 0) {
                set_parse_error(err, line_no, "invalid destination CIDR '%s'", token);
                return -1;
            }
            continue;
        }

        if (strcmp(token, "port") == 0) {
            if (seen_port) {
                set_parse_error(err, line_no, "duplicate 'port' clause");
                return -1;
            }
            if (rule.proto == WOFW_PROTO_ICMP || rule.proto == WOFW_PROTO_ANY) {
                set_parse_error(err, line_no,
                                "port clause not allowed with protocol '%s'",
                                wofw_proto_str(rule.proto));
                return -1;
            }
            seen_port = true;
            token = strtok(NULL, " \t");
            if (token == NULL) {
                set_parse_error(err, line_no, "missing port number after 'port'");
                return -1;
            }
            if (parse_port(token, &rule.port) != 0) {
                set_parse_error(err, line_no, "invalid port '%s'", token);
                return -1;
            }
            rule.has_port = true;
            continue;
        }

        set_parse_error(err, line_no, "unexpected token '%s'", token);
        return -1;
    }

    return append_rule(rs, &rule);
}

static int parse_policy_line(const char *line, int line_no, wofw_ruleset_t *rs,
                             wofw_parse_error_t *err)
{
    char buf[128];
    char *cursor;
    char *token;

    if (strlen(line) >= sizeof(buf)) {
        set_parse_error(err, line_no, "line too long");
        return -1;
    }

    strncpy(buf, line, sizeof(buf));
    buf[sizeof(buf) - 1] = '\0';
    cursor = trim(buf);

    token = strtok(cursor, " \t");
    if (token == NULL || strcmp(token, "policy") != 0) {
        set_parse_error(err, line_no, "expected 'policy' directive");
        return -1;
    }

    token = strtok(NULL, " \t");
    if (token == NULL) {
        set_parse_error(err, line_no, "missing policy action");
        return -1;
    }

    if (parse_action(token, &rs->default_policy) != 0) {
        set_parse_error(err, line_no, "invalid policy '%s'", token);
        return -1;
    }

    if (strtok(NULL, " \t") != NULL) {
        set_parse_error(err, line_no, "extra tokens after policy directive");
        return -1;
    }

    return 0;
}

static int parse_line(const char *line, int line_no, wofw_ruleset_t *rs,
                      wofw_parse_error_t *err)
{
    char buf[512];
    char *cursor;
    char *token;

    if (strlen(line) >= sizeof(buf)) {
        set_parse_error(err, line_no, "line too long");
        return -1;
    }

    strncpy(buf, line, sizeof(buf));
    buf[sizeof(buf) - 1] = '\0';
    cursor = trim(buf);

    if (*cursor == '\0' || *cursor == '#') {
        return 0;
    }

    token = strtok(cursor, " \t");
    if (token == NULL) {
        return 0;
    }

    if (strcmp(token, "policy") == 0) {
        return parse_policy_line(line, line_no, rs, err);
    }

    return parse_rule_line(line, line_no, rs, err);
}

void wofw_rules_init(wofw_ruleset_t *rs)
{
    if (rs == NULL) {
        return;
    }

    memset(rs, 0, sizeof(*rs));
    rs->default_policy = WOFW_ACTION_ACCEPT;
}

int wofw_rules_parse_line(const char *line, int line_no, wofw_ruleset_t *rs,
                          wofw_parse_error_t *err)
{
    if (rs == NULL || line == NULL) {
        return -1;
    }

    return parse_line(line, line_no, rs, err);
}

int wofw_rules_load(const char *path, wofw_ruleset_t *rs, wofw_parse_error_t *err)
{
    FILE *fp;
    char *line = NULL;
    size_t cap = 0;
    ssize_t nread;
    int line_no = 0;
    int rc = 0;

    if (rs == NULL || path == NULL) {
        return -1;
    }

    if (err != NULL) {
        err->line = 0;
        err->message = NULL;
    }

    fp = fopen(path, "r");
    if (fp == NULL) {
        set_parse_error(err, 0, "cannot open '%s': %s", path, strerror(errno));
        return -1;
    }

    while ((nread = getline(&line, &cap, fp)) != -1) {
        line_no++;

        if (nread > 0 && line[nread - 1] == '\n') {
            line[nread - 1] = '\0';
        }

        if (parse_line(line, line_no, rs, err) != 0) {
            rc = -1;
            break;
        }
    }

    free(line);
    fclose(fp);

    if (rc != 0) {
        wofw_rules_free(rs);
        return -1;
    }

    return 0;
}

void wofw_rules_free(wofw_ruleset_t *rs)
{
    if (rs == NULL) {
        return;
    }

    free(rs->rules);
    rs->rules = NULL;
    rs->count = 0;
}
