#include "ctl.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int bind_socket_path(const char *path)
{
    struct sockaddr_un addr;
    int fd;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    unlink(path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, 8) < 0) {
        close(fd);
        unlink(path);
        return -1;
    }

    return fd;
}

static int connect_socket(const char *path)
{
    struct sockaddr_un addr;
    int fd;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        return fd;
    }

    close(fd);
    return -1;
}

static ssize_t read_line(int fd, char *buf, size_t buflen)
{
    size_t pos = 0;
    ssize_t nread;
    char ch;

    while (pos + 1 < buflen) {
        nread = recv(fd, &ch, 1, 0);
        if (nread == 0) {
            break;
        }
        if (nread < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        if (ch == '\n') {
            break;
        }

        buf[pos++] = ch;
    }

    buf[pos] = '\0';
    return (ssize_t)pos;
}

static int connect_any(void)
{
    const char *paths[2] = { WOFW_SOCKET_PATH, WOFW_SOCKET_FALLBACK };
    size_t i;
    int fd;

    for (i = 0; i < 2; i++) {
        fd = connect_socket(paths[i]);
        if (fd >= 0) {
            return fd;
        }
    }

    return -1;
}

int wofw_ctl_server_open(void)
{
    int fd;

    fd = bind_socket_path(WOFW_SOCKET_PATH);
    if (fd >= 0) {
        return fd;
    }

    return bind_socket_path(WOFW_SOCKET_FALLBACK);
}

void wofw_ctl_server_close(int fd)
{
    if (fd < 0) {
        return;
    }

    close(fd);
    unlink(WOFW_SOCKET_PATH);
    unlink(WOFW_SOCKET_FALLBACK);
}

int wofw_ctl_accept_one(int server_fd, char *out, size_t outlen)
{
    int client_fd;
    ssize_t nread;

    client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) {
        return -1;
    }

    nread = read_line(client_fd, out, outlen);
    if (nread < 0) {
        close(client_fd);
        return -1;
    }

    return client_fd;
}

int wofw_ctl_write_line(int client_fd, const char *msg)
{
    char buf[WOFW_CTL_BUF_SIZE];

    if (msg == NULL) {
        return -1;
    }

    if (snprintf(buf, sizeof(buf), "%s\n", msg) >= (int)sizeof(buf)) {
        return -1;
    }

    if (write(client_fd, buf, strlen(buf)) < 0) {
        return -1;
    }

    return 0;
}

int wofw_ctl_send_response(int client_fd, const char *msg)
{
    if (wofw_ctl_write_line(client_fd, msg) != 0) {
        return -1;
    }

    close(client_fd);
    return 0;
}

void wofw_ctl_close_client(int client_fd)
{
    if (client_fd >= 0) {
        close(client_fd);
    }
}

typedef struct {
    char *out;
    size_t outlen;
    int done;
} wofw_ctl_first_line_ctx_t;

static int capture_first_line(const char *line, void *ctx)
{
    wofw_ctl_first_line_ctx_t *c = ctx;

    strncpy(c->out, line, c->outlen - 1);
    c->out[c->outlen - 1] = '\0';
    c->done = 1;
    return 1;
}

int wofw_ctl_client_talk(const char *cmd,
                         int (*handler)(const char *line, void *ctx), void *ctx)
{
    int fd;
    char line[WOFW_CTL_BUF_SIZE];
    ssize_t nread;

    if (cmd == NULL || handler == NULL) {
        return -1;
    }

    fd = connect_any();
    if (fd < 0) {
        return -1;
    }

    if (snprintf(line, sizeof(line), "%s\n", cmd) >= (int)sizeof(line)) {
        close(fd);
        return -1;
    }

    if (write(fd, line, strlen(line)) < 0) {
        close(fd);
        return -1;
    }

    shutdown(fd, SHUT_WR);

    while ((nread = read_line(fd, line, sizeof(line))) >= 0) {
        if (nread == 0 && line[0] == '\0') {
            break;
        }
        if (handler(line, ctx) != 0) {
            break;
        }
        if (strcmp(line, "END") == 0) {
            break;
        }
    }

    close(fd);
    return nread < 0 ? -1 : 0;
}

int wofw_ctl_client_request(const char *cmd, char *out, size_t outlen)
{
    wofw_ctl_first_line_ctx_t ctx = { out, outlen, 0 };

    if (cmd == NULL || out == NULL || outlen == 0) {
        return -1;
    }

    if (wofw_ctl_client_talk(cmd, capture_first_line, &ctx) != 0) {
        return -1;
    }

    return ctx.done ? 0 : -1;
}
