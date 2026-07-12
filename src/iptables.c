#include "iptables.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
    char *argv[WOFW_IPTABLES_MAX_ARGS + 6];
    int   argc;
} wofw_iptables_cmd_t;

static int tokenize_rule(const char *rule_spec, char **tokens, size_t max_tokens)
{
    char buf[256];
    char *cursor;
    char *token;
    size_t count = 0;

    if (rule_spec == NULL || strlen(rule_spec) >= sizeof(buf)) {
        return -1;
    }

    strncpy(buf, rule_spec, sizeof(buf));
    buf[sizeof(buf) - 1] = '\0';
    cursor = buf;

    while ((token = strtok(cursor, " \t")) != NULL) {
        cursor = NULL;

        if (strcmp(token, "-j") == 0) {
            return -1;
        }

        if (strpbrk(token, ";|&$`<>(){}") != NULL) {
            return -1;
        }

        if (count >= max_tokens) {
            return -1;
        }

        tokens[count] = strdup(token);
        if (tokens[count] == NULL) {
            return -1;
        }

        count++;
    }

    if (count == 0) {
        return -1;
    }

    return (int)count;
}

static void free_tokens(char **tokens, int count)
{
    int i;

    for (i = 0; i < count; i++) {
        free(tokens[i]);
        tokens[i] = NULL;
    }
}

static int run_iptables(char *const argv[])
{
    pid_t pid;
    int status;

    pid = fork();
    if (pid < 0) {
        return -1;
    }

    if (pid == 0) {
        execvp("iptables", argv);
        _exit(127);
    }

    if (waitpid(pid, &status, 0) < 0) {
        return -1;
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return -1;
    }

    return 0;
}

static void free_command(wofw_iptables_cmd_t *cmd, int token_count)
{
    int i;

    if (cmd == NULL) {
        return;
    }

    for (i = 0; i < token_count; i++) {
        free(cmd->argv[2 + i]);
    }

    if (cmd->argc > 0) {
        free(cmd->argv[cmd->argc - 1]);
    }

    memset(cmd, 0, sizeof(*cmd));
}

static int build_command(wofw_iptables_cmd_t *cmd, const char *action,
                         const char *rule_spec, uint16_t queue_num,
                         int *token_count_out)
{
    char queue_buf[16];
    char **tokens = NULL;
    int token_count;
    int i;
    int argc = 0;

    tokens = calloc(WOFW_IPTABLES_MAX_ARGS, sizeof(*tokens));
    if (tokens == NULL) {
        return -1;
    }

    token_count = tokenize_rule(rule_spec, tokens, WOFW_IPTABLES_MAX_ARGS);
    if (token_count < 0) {
        free(tokens);
        return -1;
    }

    cmd->argv[argc++] = "iptables";
    cmd->argv[argc++] = (char *)action;
    for (i = 0; i < token_count; i++) {
        cmd->argv[argc++] = tokens[i];
    }
    cmd->argv[argc++] = "-j";
    cmd->argv[argc++] = "NFQUEUE";
    cmd->argv[argc++] = "--queue-num";
    snprintf(queue_buf, sizeof(queue_buf), "%u", queue_num);
    cmd->argv[argc++] = strdup(queue_buf);
    if (cmd->argv[argc - 1] == NULL) {
        free_tokens(tokens, token_count);
        free(tokens);
        return -1;
    }
    cmd->argv[argc] = NULL;
    cmd->argc = argc;

    free(tokens);
    *token_count_out = token_count;
    return 0;
}

static void remove_all_matching(const char *rule_spec, uint16_t queue_num)
{
    wofw_iptables_cmd_t cmd = {0};
    int token_count = 0;

    if (rule_spec == NULL) {
        return;
    }

    if (build_command(&cmd, "-D", rule_spec, queue_num, &token_count) != 0) {
        return;
    }

    while (run_iptables(cmd.argv) == 0) {
        /* Remove duplicate or stale rules. */
    }

    free_command(&cmd, token_count);
}

void wofw_iptables_reset(wofw_iptables_t *ip)
{
    if (ip == NULL) {
        return;
    }

    ip->active = false;
    ip->queue_num = 0;
    free(ip->rule_spec);
    ip->rule_spec = NULL;
}

int wofw_iptables_add(wofw_iptables_t *ip, const char *rule_spec, uint16_t queue_num)
{
    wofw_iptables_cmd_t cmd = {0};
    int token_count = 0;

    if (ip == NULL || rule_spec == NULL) {
        return -1;
    }

    wofw_iptables_reset(ip);

    ip->rule_spec = strdup(rule_spec);
    if (ip->rule_spec == NULL) {
        return -1;
    }

    if (build_command(&cmd, "-I", rule_spec, queue_num, &token_count) != 0) {
        wofw_iptables_reset(ip);
        errno = EINVAL;
        return -1;
    }

    remove_all_matching(rule_spec, queue_num);

    if (run_iptables(cmd.argv) != 0) {
        free_command(&cmd, token_count);
        wofw_iptables_reset(ip);
        errno = EIO;
        return -1;
    }

    free_command(&cmd, token_count);
    ip->queue_num = queue_num;
    ip->active = true;
    return 0;
}

void wofw_iptables_remove(wofw_iptables_t *ip)
{
    if (ip == NULL || !ip->active || ip->rule_spec == NULL) {
        wofw_iptables_reset(ip);
        return;
    }

    remove_all_matching(ip->rule_spec, ip->queue_num);
    wofw_iptables_reset(ip);
}
