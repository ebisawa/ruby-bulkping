#ifndef __PINGER_H__
#define __PINGER_H__

#define SA              struct sockaddr
#define SALEN(sa)       (((struct sockaddr *) (sa))->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : \
                        ((((struct sockaddr *) (sa))->sa_family == AF_INET6) ? sizeof(struct sockaddr_in6) : 0)
#define NELEMS(array)   (sizeof(array) / sizeof(array[0]))

typedef struct {
    int (*v_open)(void);
    int (*v_bufinit)(void *buf, int len, int echo_seq, int echo_id);
    int (*v_receive)(int *echo_seq, int *echo_id, void *buf, int len);
} pinger_vtable_t;

typedef struct {
    struct sockaddr_storage  t_addr;
    uint16_t                 t_id;
    uint16_t                 t_seq;
    int                      t_sent;
    int                      t_alive;
} pinger_target_t;

typedef struct {
    int                      s_tmax;
    int                      s_tcount;
    pinger_target_t         *s_targets;
} pinger_tset_t;

typedef struct {
    int                      p_sock;
    int                      p_acount;
    int                      p_scount;
    pinger_vtable_t         *p_vt;
} pinger_t;

void pinger_tset_init(pinger_tset_t *tset, void *targets, int tmax);
int pinger_tset_add(pinger_tset_t *tset, char *addr);
pinger_target_t *pinger_tset_find(pinger_tset_t *tset, char *addr);

int pinger_open(pinger_t *pinger, pinger_vtable_t *vt);
void pinger_close(pinger_t *pinger);
int pinger_execute(pinger_t *pinger, pinger_tset_t *tset);

extern pinger_vtable_t PingerICMP;

#endif
