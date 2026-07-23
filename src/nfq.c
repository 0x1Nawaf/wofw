#include "nfq.h"

#include "log.h"
#include "match.h"
#include "packet.h"

#include <arpa/inet.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct wofw_nfq {
    struct nfq_handle   *h;
    struct nfq_q_handle *qh;
    wofw_ruleset_t *ruleset;
};

static int wofw_nfq_apply_verdict(struct nfq_q_handle *qh, uint32_t id,
                                  wofw_action_t action)
{
    uint32_t verdict = (action == WOFW_ACTION_DROP) ? NF_DROP : NF_ACCEPT;

    if (nfq_set_verdict(qh, id, verdict, 0, NULL) == 0) {
        return 0;
    }

    fprintf(stderr,
            "wofwd: nfq_set_verdict failed (id=%u errno=%s); accepting packet\n",
            id, strerror(errno));
    nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    return 0;
}

static int wofw_nfq_callback(struct nfq_q_handle *qh,
                      struct nfgenmsg *nfmsg,
                      struct nfq_data *nfa,
                      void *data)
{
    wofw_nfq_t *nfq = data;
    uint32_t id;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *payload;
    int payload_len;
    wofw_packet_t pkt;
    wofw_match_result_t result;

    (void)nfmsg;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph == NULL) {
        return 0;
    }

    id = ntohl(ph->packet_id);
    payload_len = nfq_get_payload(nfa, &payload);
    if (payload_len < 0) {
        result.action = nfq->ruleset->default_policy;
        result.rule_index = -1;
        pkt.status = WOFW_PKT_TRUNCATED;
        pkt.l4_proto = WOFW_L4_NONE;
        pkt.src_ip = 0;
        pkt.dst_ip = 0;
        pkt.src_port = 0;
        pkt.dst_port = 0;
        pkt.ip_proto = 0;
        wofw_log_decision(&pkt, &result);
        return wofw_nfq_apply_verdict(qh, id, result.action);
    }

    pkt = wofw_packet_parse(payload, (size_t)payload_len);
    if (pkt.status != WOFW_PKT_OK) {
        result.action = nfq->ruleset->default_policy;
        result.rule_index = -1;
        wofw_log_decision(&pkt, &result);
        return wofw_nfq_apply_verdict(qh, id, result.action);
    }

    result = wofw_match_evaluate(&pkt, nfq->ruleset);
    wofw_log_decision(&pkt, &result);
    return wofw_nfq_apply_verdict(qh, id, result.action);
}

wofw_nfq_t *wofw_nfq_open(uint16_t queue_num, wofw_ruleset_t *ruleset)
{
    wofw_nfq_t *nfq;
    int rv;

    nfq = calloc(1, sizeof(*nfq));
    if (nfq == NULL) {
        return NULL;
    }

    nfq->ruleset = ruleset;
    nfq->h = nfq_open();
    if (nfq->h == NULL) {
        free(nfq);
        return NULL;
    }

    if (nfq_unbind_pf(nfq->h, AF_INET) < 0) {
        /* Not fatal if nothing was bound yet. */
    }

    if (nfq_bind_pf(nfq->h, AF_INET) < 0) {
        nfq_close(nfq->h);
        free(nfq);
        return NULL;
    }

    nfq->qh = nfq_create_queue(nfq->h, queue_num, wofw_nfq_callback, nfq);
    if (nfq->qh == NULL) {
        nfq_unbind_pf(nfq->h, AF_INET);
        nfq_close(nfq->h);
        free(nfq);
        return NULL;
    }

    rv = nfq_set_mode(nfq->qh, NFQNL_COPY_PACKET, 0xffff);
    if (rv < 0) {
        nfq_destroy_queue(nfq->qh);
        nfq_unbind_pf(nfq->h, AF_INET);
        nfq_close(nfq->h);
        free(nfq);
        return NULL;
    }

    if (nfq_set_queue_maxlen(nfq->qh, 8192) < 0) {
        /* Non-fatal on older kernels. */
    }

    return nfq;
}

void wofw_nfq_close(wofw_nfq_t *nfq)
{
    if (nfq == NULL) {
        return;
    }

    if (nfq->qh != NULL) {
        nfq_destroy_queue(nfq->qh);
        nfq->qh = NULL;
    }

    if (nfq->h != NULL) {
        nfq_unbind_pf(nfq->h, AF_INET);
        nfq_close(nfq->h);
        nfq->h = NULL;
    }

    free(nfq);
}

int wofw_nfq_fd(const wofw_nfq_t *nfq)
{
    if (nfq == NULL || nfq->h == NULL) {
        return -1;
    }
    return nfq_fd(nfq->h);
}

int wofw_nfq_handle_packet(wofw_nfq_t *nfq)
{
    char buf[65536];
    ssize_t nread;
    int rv;

    if (nfq == NULL || nfq->h == NULL) {
        return -1;
    }

    nread = recv(wofw_nfq_fd(nfq), buf, sizeof(buf), 0);
    if (nread < 0) {
        if (errno == EINTR) {
            return 0;
        }
        return -1;
    }
    if (nread == 0) {
        return 0;
    }

    rv = nfq_handle_packet(nfq->h, buf, (int)nread);
    if (rv < 0 && errno == EINTR) {
        return 0;
    }

    return rv;
}
