#ifndef WOFW_CTL_H
#define WOFW_CTL_H

#include <stddef.h>

#define WOFW_SOCKET_PATH "/run/wofw.sock"
#define WOFW_SOCKET_FALLBACK "/tmp/wofw.sock"
#define WOFW_CTL_BUF_SIZE 4096

int wofw_ctl_server_open(void);
void wofw_ctl_server_close(int fd);
int wofw_ctl_accept_one(int server_fd, char *out, size_t outlen);
int wofw_ctl_send_response(int client_fd, const char *msg);
int wofw_ctl_write_line(int client_fd, const char *msg);
void wofw_ctl_close_client(int client_fd);
int wofw_ctl_client_request(const char *cmd, char *out, size_t outlen);
int wofw_ctl_client_talk(const char *cmd,
                         int (*handler)(const char *line, void *ctx), void *ctx);

#endif /* WOFW_CTL_H */
