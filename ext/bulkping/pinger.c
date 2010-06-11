#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "pinger.h"

#define TIMEOUT         2
#define SEND_LIMIT     16

#define ICMP_ECHO_REQ   8
#define ICMP_ECHO_REP   0

typedef struct {
    uint8_t   icmpe_type;
    uint8_t   icmpe_code;
    uint16_t  icmpe_csum;
    uint16_t  icmpe_id;
    uint16_t  icmpe_seq;
} icmp_echo_t;

static pinger_target_t *pinger_tset_get_target(pinger_tset_t *tset);
static int pinger_tset_add_addr(pinger_tset_t *tset, char *addr);
static int pinger_tset_add_net(pinger_tset_t *tset, char *netaddr);
static int pinger_tset_add_range(pinger_tset_t *tset, char *range);

static int pinger_send(pinger_t *pinger, pinger_tset_t *tset, int limit);
static int pinger_send_one(pinger_t *pinger, pinger_target_t *target, void *buf, int len);
static int pinger_receive(pinger_t *pinger, pinger_tset_t *tset, int (*receive_func)(int *echo_seq, int *echo_id, void *buf, int len));
static pinger_target_t *pinger_lookup_target(pinger_tset_t *tset, int echo_seq, int echo_id);

static int pinger_icmp_open(void);
static int pinger_icmp_bufinit(void *buf, int len, int echo_seq, int echo_id);
static int pinger_icmp_receive(int *echo_seq, int *echo_id, void *buf, int len);

static int sa2str(char *buf, int bufmax, struct sockaddr *sa);
static int str2sa(struct sockaddr *sa, char *addr);
static int sacmp(struct sockaddr *a, struct sockaddr *b);
static int sacmp4(struct sockaddr_in *a, struct sockaddr_in *b);
static int sacmp6(struct sockaddr_in6 *a, struct sockaddr_in6 *b);
static int getabc(uint32_t *addr_base, int *addr_count, char *netaddr);
static int getsea(uint32_t *saddr, uint32_t *eaddr, char *range);

static uint16_t checksum(void *buf, int len);

pinger_vtable_t PingerICMP = {
    pinger_icmp_open,
    pinger_icmp_bufinit,
    pinger_icmp_receive,
};

void
pinger_tset_init(pinger_tset_t *tset, void *targets, int tmax)
{
    tset->s_tmax = tmax;
    tset->s_tcount = 0;
    tset->s_targets = (pinger_target_t *) targets;
    memset(targets, 0, sizeof(pinger_target_t) * tmax);
}

int
pinger_tset_add(pinger_tset_t *tset, char *addr)
{
    if (strchr(addr, '/') != NULL)
        return pinger_tset_add_net(tset, addr);
    if (strchr(addr, '-') != NULL)
        return pinger_tset_add_range(tset, addr);

    return pinger_tset_add_addr(tset, addr);
}

pinger_target_t *
pinger_tset_find(pinger_tset_t *tset, char *addr)
{
    int i;
    pinger_target_t *target;
    struct sockaddr_storage ss;

    if (str2sa((SA *) &ss, addr) < 0)
        return NULL;

    for (i = 0; i < tset->s_tcount; i++) {
        target = &tset->s_targets[i];
        if (sacmp((SA *) &ss, (SA *) &target->t_addr) == 0)
            return target;
    }

    return NULL;
}

int
pinger_open(pinger_t *pinger, pinger_vtable_t *vt)
{
    pinger->p_vt = vt;

    if ((pinger->p_sock = vt->v_open()) < 0)
        return -1;

    return 0;
}

void
pinger_close(pinger_t *pinger)
{
    close(pinger->p_sock);
}

int
pinger_execute(pinger_t *pinger, pinger_tset_t *tset)
{
    pinger->p_scount = 0;
    pinger->p_acount = 0;

    while (pinger->p_acount < tset->s_tcount) {
        if (pinger_send(pinger, tset, SEND_LIMIT) < 0)
            return -1;
        if (pinger_receive(pinger, tset, pinger->p_vt->v_receive) < 0) {
            if (pinger->p_scount == tset->s_tcount)
                break;
        }
    }

    return 0;
}

static pinger_target_t *
pinger_tset_get_target(pinger_tset_t *tset)
{
    if (tset->s_tcount >= tset->s_tmax)
        return NULL;

    return &tset->s_targets[tset->s_tcount];
}

static int
pinger_tset_add_addr(pinger_tset_t *tset, char *addr)
{
    pinger_target_t *target;

    if ((target = pinger_tset_get_target(tset)) == NULL)
        return -1;
    if (str2sa((SA *) &target->t_addr, addr) < 0)
        return -1;

    tset->s_tcount++;

    return 0;
}

static int
pinger_tset_add_net(pinger_tset_t *tset, char *netaddr)
{
    int i, count;
    uint32_t base;
    struct sockaddr_in *sin;
    pinger_target_t *target;

    if (getabc(&base, &count, netaddr) < 0)
        return -1;

    for (i = 0; i < count; i++) {
        if ((target = pinger_tset_get_target(tset)) == NULL)
            return -1;

        sin = (struct sockaddr_in *) &target->t_addr;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = htonl(base + i);
        tset->s_tcount++;
    }

    return count;
}

static int
pinger_tset_add_range(pinger_tset_t *tset, char *range)
{
    unsigned saddr, eaddr;
    struct sockaddr_in *sin;
    pinger_target_t *target;

    if (getsea(&saddr, &eaddr, range) < 0)
        return -1;

    for (; saddr <= eaddr; saddr++) {
        if ((target = pinger_tset_get_target(tset)) == NULL)
            return -1;

        sin = (struct sockaddr_in *) &target->t_addr;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = htonl(saddr);
        tset->s_tcount++;
    }

    return 0;
}

static int
pinger_send(pinger_t *pinger, pinger_tset_t *tset, int limit)
{
    char buf[256];
    int i, len, count;
    pinger_target_t *target;

    for (i = 0, count = 0; i < tset->s_tcount && count < limit; i++) {
        target = &tset->s_targets[i];
        if (!target->t_sent) {
#ifdef TEST
            target->t_id = rand();
#else
            target->t_id = rb_genrand_int32();
#endif
            if ((len = pinger->p_vt->v_bufinit(buf, sizeof(buf), ++target->t_seq, target->t_id)) < 0)
                return -1;

            pinger_send_one(pinger, target, buf, len);
            count++;
        }
    }

    return 0;
}

static int
pinger_send_one(pinger_t *pinger, pinger_target_t *target, void *buf, int len)
{
    struct sockaddr *to;

    /* update counters even if sendto() failed */
    pinger->p_scount++;
    target->t_sent = 1;

    to = (SA *) &target->t_addr;
    if (sendto(pinger->p_sock, buf, len, 0, to, SALEN(to)) < 0) {
        /* perror("sendto() failed"); */
        return -1;
    }

    return 0;
}

static int
pinger_receive(pinger_t *pinger, pinger_tset_t *tset, int (*receive_func)(int *echo_seq, int *echo_id, void *buf, int len))
{
    char buf[256];
    int len, echo_seq, echo_id;
    fd_set fds;
    socklen_t fromlen;
    struct timeval tv;
    struct sockaddr_storage from;
    pinger_target_t *target;

    FD_ZERO(&fds);
    FD_SET(pinger->p_sock, &fds);

    if (pinger->p_scount < tset->s_tcount) {
        tv.tv_sec = 0;
        tv.tv_usec = TIMEOUT * 100 * 1000;
    } else {
        tv.tv_sec = TIMEOUT;
        tv.tv_usec = 0;
    }

    if (select(pinger->p_sock + 1, &fds, NULL, NULL, &tv) > 0) {
        if (FD_ISSET(pinger->p_sock, &fds)) {
            fromlen = sizeof(from);
            if ((len = recvfrom(pinger->p_sock, buf, sizeof(buf), 0, (SA *) &from, &fromlen)) < 0) {
                /* perror("recvfrom() failed"); */
                return -1;
            }

            if (receive_func(&echo_seq, &echo_id, buf, len) < 0)
                return 0;   /* mesage is not for me. simply ignore it */
            if ((target = pinger_lookup_target(tset, echo_seq, echo_id)) == NULL)
                return -1;

            target->t_alive = 1;
            pinger->p_acount++;

            if (pinger_send(pinger, tset, 1) < 0)
                return -1;

            return 0;
        }
    }

    return -1;
}

static pinger_target_t *
pinger_lookup_target(pinger_tset_t *tset, int echo_seq, int echo_id)
{
    int i;
    pinger_target_t *target;

    for (i = 0; i < tset->s_tcount; i++) {
        target = &tset->s_targets[i];
        if (target->t_seq == echo_seq && target->t_id == echo_id)
            return target;
    }

    return NULL;
}


static int
pinger_icmp_open(void)
{
    return socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
}

static int
pinger_icmp_bufinit(void *buf, int len, int echo_seq, int echo_id)
{
    icmp_echo_t *icmpe;

    if (len < sizeof(*icmpe))
        return -1;

    memset(buf, 0, len);
    icmpe = (icmp_echo_t *) buf;
    icmpe->icmpe_type = ICMP_ECHO_REQ;
    icmpe->icmpe_code = 0;
    icmpe->icmpe_csum = 0;
    icmpe->icmpe_id = htons(echo_id);
    icmpe->icmpe_seq = htons(echo_seq);
    icmpe->icmpe_csum = checksum(buf, sizeof(*icmpe));

    return sizeof(*icmpe);
}

static int
pinger_icmp_receive(int *echo_seq, int *echo_id, void *buf, int len)
{
    int ihl;
    icmp_echo_t *icmpe;

    /* IP header length */
    ihl = (*((uint8_t *) buf) & 0x0f) * 4;
    icmpe = (icmp_echo_t *) (buf + ihl);

    if (len < ihl + sizeof(icmp_echo_t))
        return -1;
    if (icmpe->icmpe_type != ICMP_ECHO_REP || icmpe->icmpe_code != 0)
        return -1;

    *echo_id = ntohs(icmpe->icmpe_id);
    *echo_seq = ntohs(icmpe->icmpe_seq);

    return 0;
}


static int
sa2str(char *buf, int bufmax, struct sockaddr *sa)
{
    return getnameinfo(sa, SALEN(sa), buf, bufmax, NULL, 0, NI_NUMERICHOST);
}

static int
str2sa(struct sockaddr *sa, char *addr)
{
    struct addrinfo hints, *res;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(addr, NULL, &hints, &res) != 0)
        return -1;

    memcpy(sa, res->ai_addr, SALEN(res->ai_addr));
    freeaddrinfo(res);

    return 0;
}

static int
sacmp(struct sockaddr *a, struct sockaddr *b)
{
    if (a->sa_family != b->sa_family)
        return -1;

    switch (a->sa_family) {
    case AF_INET:
        return sacmp4((struct sockaddr_in *) a, (struct sockaddr_in *) b);
    case AF_INET6:
        return sacmp6((struct sockaddr_in6 *) a, (struct sockaddr_in6 *) b);
    }

    return -1;
}

static int
sacmp4(struct sockaddr_in *a, struct sockaddr_in *b)
{
    return memcmp(&a->sin_addr, &b->sin_addr, sizeof(a->sin_addr));
}

static int
sacmp6(struct sockaddr_in6 *a, struct sockaddr_in6 *b)
{
    return memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(a->sin6_addr));
}

static int
getabc(uint32_t *addr_base, int *addr_count, char *netaddr)
{
    char *p, buf[256];
    int i, plen, alen;
    uint32_t base, mask;

    strncpy(buf, netaddr, sizeof(buf));
    buf[sizeof(buf) - 1] = 0;

    if ((p = strchr(buf, '/')) == NULL)
        return -1;

    *p = 0;
    plen = atoi(p + 1);
    alen = 32 - plen;

    if (plen > 24)
        return -1;   /* safety */
    if (inet_pton(AF_INET, buf, &base) < 0)
        return -1;
    for (i = 0, mask = 0; i < alen; i++)
        mask = (mask << 1) | 1;

    *addr_base = ntohl(base) & ~mask;
    *addr_count = 1 << alen;

    return 0;
}

static int
getsea(uint32_t *saddr, uint32_t *eaddr, char *range)
{
    char *p;

    if ((p = strchr(range, '-')) == NULL)
        return -1;

    *p++ = 0;
    if (inet_pton(AF_INET, range, saddr) < 0)
        return -1;
    if (inet_pton(AF_INET, p, eaddr) < 0)
        return -1;

    *saddr = ntohl(*saddr);
    *eaddr = ntohl(*eaddr);

    if (*eaddr < *saddr)
        return -1;
    if (*eaddr - *saddr + 1 > 256)
        return -1;

    return 0;
}

static uint16_t
checksum(void *buf, int len)
{
    unsigned sum;

    for (sum = 0; len > 1; buf += 2, len -= 2)
        sum += *((uint16_t *) buf);
    if (len > 0)
        sum += *(u_int8_t *) buf;

    sum = (sum & 0xffff) + (sum >> 16);
    sum += (sum >> 16);
    
    return ~sum;
}


#ifdef TEST

int
main(int argc, char *argv[])
{
    int i;
    char buf[256];
    pinger_t pinger;
    pinger_tset_t tset;
    pinger_target_t targets[256];

    pinger_tset_init(&tset, targets, NELEMS(targets));
    while (*++argv != NULL) {
        if (pinger_tset_add(&tset, *argv) < 0) {
            printf("ERROR: pinger_tset_add() failed\n");
            return EXIT_FAILURE;
        }
    }

    if (pinger_open(&pinger, &PingerICMP) < 0) {
        printf("ERROR: pinger_open() failed\n");
        return EXIT_FAILURE;
    }

    pinger_execute(&pinger, &tset);
    pinger_close(&pinger);

    for (i = 0; i < tset.s_tcount; i++) {
        sa2str(buf, sizeof(buf), (SA *) &targets[i].t_addr);
        if (targets[i].t_alive)
            printf("%s is alive\n", buf);
        else
            printf("%s is not alive\n", buf);
    }

    return EXIT_SUCCESS;
}

#endif
