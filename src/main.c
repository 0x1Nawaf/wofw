#include "ctl.h"
#include "iptables.h"
#include "log.h"
#include "nfq.h"
#include "rules.h"

#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define WOFW_DEFAULT_QUEUE 0
#define WOFW_DEFAULT_RULES_SYSTEM "/etc/wofw/rules.conf"
#define WOFW_DEFAULT_RULES_LOCAL "examples/rules.conf"
#define WOFW_DEFAULT_IPTABLES_INPUT "INPUT"

static volatile sig_atomic_t g_stop = 0;

typedef struct {
    wofw_ruleset_t ruleset;
    char *rules_path;
    wofw_nfq_t *nfq;
    wofw_iptables_t iptables;
    int ctl_fd;
    uint16_t queue_num;
} wofw_daemon_t;

static void on_signal(int signo)
{
    (void)signo;
    g_stop = 1;
}

static bool is_daemon_mode(const char *argv0)
{
    const char *base = strrchr(argv0, '/');

    base = base != NULL ? base + 1 : argv0;
    return strcmp(base, "wofwd") == 0;
}

static const char *find_default_rules_file(void)
{
    if (access(WOFW_DEFAULT_RULES_SYSTEM, R_OK) == 0) {
        return WOFW_DEFAULT_RULES_SYSTEM;
    }

    if (access(WOFW_DEFAULT_RULES_LOCAL, R_OK) == 0) {
        return WOFW_DEFAULT_RULES_LOCAL;
    }

    return NULL;
}

static int format_rule_line(const wofw_rule_t *rule, char *buf, size_t buflen)
{
    int n = snprintf(buf, buflen, "%s %s",
                     wofw_action_str(rule->action),
                     wofw_proto_str(rule->proto));

    if (n < 0 || (size_t)n >= buflen) {
        return -1;
    }

    if (!rule->src.is_any) {
        n += snprintf(buf + n, buflen - (size_t)n, " from <src>");
    }
    if (!rule->dst.is_any) {
        n += snprintf(buf + n, buflen - (size_t)n, " to <dst>");
    }
    if (rule->has_port) {
        n += snprintf(buf + n, buflen - (size_t)n, " port %u", rule->port);
    }

    return n;
}

static void daemon_cleanup(wofw_daemon_t *daemon)
{
    if (daemon == NULL) {
        return;
    }

    wofw_nfq_close(daemon->nfq);
    wofw_iptables_remove(&daemon->iptables);
    wofw_ctl_server_close(daemon->ctl_fd);
    wofw_rules_free(&daemon->ruleset);
    free(daemon->rules_path);
    memset(daemon, 0, sizeof(*daemon));
}

static int daemon_reload_rules(wofw_daemon_t *daemon)
{
    wofw_parse_error_t err = {0};

    if (daemon->rules_path == NULL) {
        return -1;
    }

    wofw_rules_free(&daemon->ruleset);
    wofw_rules_init(&daemon->ruleset);

    if (wofw_rules_load(daemon->rules_path, &daemon->ruleset, &err) != 0) {
        fprintf(stderr, "wofw: reload failed: %s\n",
                err.message != NULL ? err.message : "unknown error");
        free(err.message);
        return -1;
    }

    free(err.message);
    return 0;
}

static void daemon_handle_command(wofw_daemon_t *daemon, int client_fd, const char *cmd)
{
    char resp[WOFW_CTL_BUF_SIZE];
    wofw_parse_error_t err = {0};
    size_t i;

    if (strcmp(cmd, "PING") == 0) {
        snprintf(resp, sizeof(resp), "OK running rules=%zu policy=%s",
                 daemon->ruleset.count,
                 wofw_action_str(daemon->ruleset.default_policy));
        wofw_ctl_send_response(client_fd, resp);
        return;
    }

    if (strncmp(cmd, "ADD ", 4) == 0) {
        const char *line = cmd + 4;

        if (wofw_rules_parse_line(line, 0, &daemon->ruleset, &err) != 0) {
            snprintf(resp, sizeof(resp), "ERR %s",
                     err.message != NULL ? err.message : "parse error");
            free(err.message);
            wofw_ctl_send_response(client_fd, resp);
            return;
        }

        free(err.message);
        snprintf(resp, sizeof(resp), "OK added rule=%zu",
                 daemon->ruleset.count - 1);
        wofw_ctl_send_response(client_fd, resp);
        return;
    }

    if (strcmp(cmd, "RELOAD") == 0) {
        if (daemon_reload_rules(daemon) != 0) {
            wofw_ctl_send_response(client_fd, "ERR reload failed");
            return;
        }

        snprintf(resp, sizeof(resp), "OK reloaded rules=%zu", daemon->ruleset.count);
        wofw_ctl_send_response(client_fd, resp);
        return;
    }

    if (strcmp(cmd, "LIST") == 0) {
        char linebuf[256];

        wofw_ctl_write_line(client_fd, "OK");
        for (i = 0; i < daemon->ruleset.count; i++) {
            snprintf(linebuf, sizeof(linebuf), "%zu ", i);
            format_rule_line(&daemon->ruleset.rules[i],
                             linebuf + strlen(linebuf),
                             sizeof(linebuf) - strlen(linebuf));
            wofw_ctl_write_line(client_fd, linebuf);
        }
        wofw_ctl_write_line(client_fd, "END");
        wofw_ctl_close_client(client_fd);
        return;
    }

    wofw_ctl_send_response(client_fd, "ERR unknown command");
}

static int daemon_run_loop(wofw_daemon_t *daemon)
{
    while (!g_stop) {
        struct pollfd fds[2];
        int rv;

        fds[0].fd = wofw_nfq_fd(daemon->nfq);
        fds[0].events = POLLIN;
        fds[1].fd = daemon->ctl_fd;
        fds[1].events = POLLIN;

        rv = poll(fds, 2, -1);
        if (rv < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        if (fds[1].revents & POLLIN) {
            char cmd[WOFW_CTL_BUF_SIZE];
            int client_fd = wofw_ctl_accept_one(daemon->ctl_fd, cmd, sizeof(cmd));

            if (client_fd >= 0) {
                daemon_handle_command(daemon, client_fd, cmd);
            }
        }

        if (fds[0].revents & POLLIN) {
            if (wofw_nfq_handle_packet(daemon->nfq) < 0 && errno != EINTR) {
                return -1;
            }
        }
    }

    return 0;
}

static int run_daemon(int argc, char *argv[])
{
    wofw_daemon_t daemon = {0};
    const char *rules_path = NULL;
    const char *iptables_spec = WOFW_DEFAULT_IPTABLES_INPUT;
    struct sigaction sa;
    int opt;

    static const struct option long_opts[] = {
        {"queue", required_argument, NULL, 'q'},
        {"help",  no_argument,       NULL, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "q:h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'q': {
            char *end;
            long value = strtol(optarg, &end, 10);
            if (*end != '\0' || value < 0 || value > 65535) {
                return 1;
            }
            daemon.queue_num = (uint16_t)value;
            break;
        }
        case 'h':
            return 0;
        default:
            return 1;
        }
    }

    if (daemon.queue_num == 0) {
        daemon.queue_num = WOFW_DEFAULT_QUEUE;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "wofwd: must be run as root\n");
        return 1;
    }

    rules_path = find_default_rules_file();
    if (rules_path == NULL) {
        fprintf(stderr, "wofwd: no rules file found\n");
        return 1;
    }

    daemon.rules_path = strdup(rules_path);
    wofw_rules_init(&daemon.ruleset);
    if (wofw_rules_load(rules_path, &daemon.ruleset, NULL) != 0) {
        fprintf(stderr, "wofwd: failed to load %s\n", rules_path);
        daemon_cleanup(&daemon);
        return 1;
    }

    fprintf(stderr, "wofwd: loaded %s (%zu rules)\n",
            rules_path, daemon.ruleset.count);

    wofw_log_init();

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    daemon.nfq = wofw_nfq_open(daemon.queue_num, &daemon.ruleset);
    if (daemon.nfq == NULL) {
        fprintf(stderr, "wofwd: failed to bind NFQUEUE %u\n", daemon.queue_num);
        daemon_cleanup(&daemon);
        return 1;
    }

    if (wofw_iptables_add(&daemon.iptables, iptables_spec, daemon.queue_num) != 0) {
        fprintf(stderr, "wofwd: failed to add iptables rule\n");
        daemon_cleanup(&daemon);
        return 1;
    }

    daemon.ctl_fd = wofw_ctl_server_open();
    if (daemon.ctl_fd < 0) {
        fprintf(stderr, "wofwd: failed to open control socket\n");
        daemon_cleanup(&daemon);
        return 1;
    }

    fprintf(stderr, "wofwd: listening (NFQUEUE %u, iptables %s)\n",
            daemon.queue_num, iptables_spec);

    daemon_run_loop(&daemon);
    daemon_cleanup(&daemon);
    fprintf(stderr, "wofwd: shutdown complete\n");
    return 0;
}

static void client_usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s rule add <rule-line>\n"
            "  %s rule list\n"
            "  %s reload\n"
            "  %s status\n"
            "\n"
            "Start the daemon first:\n"
            "  sudo wofwd\n"
            "\n"
            "Example:\n"
            "  %s rule add \"drop tcp from any to any port 443\"\n",
            prog, prog, prog, prog, prog);
}

static int client_print_line(const char *line, void *ctx)
{
    (void)ctx;

    if (strcmp(line, "OK") == 0 || strncmp(line, "ERR", 3) == 0) {
        printf("%s\n", line);
        return strncmp(line, "ERR", 3) == 0;
    }

    if (strcmp(line, "END") == 0) {
        return 1;
    }

    printf("%s\n", line);
    return 0;
}

static int run_client(int argc, char *argv[])
{
    char cmd[WOFW_CTL_BUF_SIZE];
    char resp[WOFW_CTL_BUF_SIZE];

    if (argc < 2) {
        client_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "status") == 0) {
        if (wofw_ctl_client_request("PING", resp, sizeof(resp)) != 0) {
            fprintf(stderr, "wofw: cannot connect to wofwd (is it running?)\n");
            return 1;
        }
        printf("%s\n", resp);
        return strncmp(resp, "OK", 2) == 0 ? 0 : 1;
    }

    if (strcmp(argv[1], "reload") == 0) {
        if (wofw_ctl_client_request("RELOAD", resp, sizeof(resp)) != 0) {
            fprintf(stderr, "wofw: cannot connect to wofwd\n");
            return 1;
        }
        printf("%s\n", resp);
        return strncmp(resp, "OK", 2) == 0 ? 0 : 1;
    }

    if (strcmp(argv[1], "rule") == 0 && argc >= 3) {
        if (strcmp(argv[2], "add") == 0) {
            if (argc < 4) {
                fprintf(stderr, "wofw: missing rule line\n");
                return 1;
            }
            snprintf(cmd, sizeof(cmd), "ADD %s", argv[3]);
            if (wofw_ctl_client_request(cmd, resp, sizeof(resp)) != 0) {
                fprintf(stderr, "wofw: cannot connect to wofwd\n");
                return 1;
            }
            printf("%s\n", resp);
            return strncmp(resp, "OK", 2) == 0 ? 0 : 1;
        }

        if (strcmp(argv[2], "list") == 0) {
            if (wofw_ctl_client_talk("LIST", client_print_line, NULL) != 0) {
                fprintf(stderr, "wofw: cannot connect to wofwd\n");
                return 1;
            }
            return 0;
        }
    }

    client_usage(argv[0]);
    return 1;
}

int main(int argc, char *argv[])
{
    if (is_daemon_mode(argv[0])) {
        return run_daemon(argc, argv);
    }

    return run_client(argc, argv);
}
