#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "ruby.h"
#include "pinger.h"

#define TARGETS_MAX   256

typedef struct {
    pinger_t          bp_pinger;
    pinger_tset_t     bp_tset;
    pinger_target_t  *bp_targets;
} bulkping_t;

static VALUE bulkping_s_alloc(VALUE klass);
static void bulkping_free(bulkping_t *bp);
static VALUE bulkping_ping(VALUE self, VALUE args);
static VALUE bulkping_is_alive(VALUE self, VALUE args);
static VALUE bulkping_alive(VALUE self);
static VALUE bulkping_dead(VALUE self);

static int bulkping_set_targets(bulkping_t *bp, VALUE args);
static int bulkping_init_targets(bulkping_t *bp, int count);
static int bulkping_add_targets(pinger_tset_t *tset, VALUE args);
static void bulkping_yield_result(bulkping_t *bp);
static VALUE bulkping_tarray(VALUE self, int alive);
static VALUE sa2v(struct sockaddr *sa);

Init_bulkping()
{
    VALUE m_bp, c_icmp;

    m_bp = rb_define_module("BulkPing");
    c_icmp = rb_define_class_under(m_bp, "ICMP", rb_cObject);

    rb_define_alloc_func(c_icmp, bulkping_s_alloc);
    rb_define_method(c_icmp, "ping", bulkping_ping, -2);
    rb_define_method(c_icmp, "alive?", bulkping_is_alive, -2);
    rb_define_method(c_icmp, "alive", bulkping_alive, 0);
    rb_define_method(c_icmp, "dead", bulkping_dead, 0);
}

static VALUE
bulkping_s_alloc(VALUE klass)
{
    VALUE obj;
    bulkping_t *bp;

    obj = Data_Make_Struct(klass, bulkping_t, 0, bulkping_free, bp);
    memset(bp, 0, sizeof(bulkping_t));

    return obj;
}

static void
bulkping_free(bulkping_t *bp)
{
    if (bp->bp_targets != NULL) {
        free(bp->bp_targets);
        bp->bp_targets = NULL;
    }
}

static VALUE
bulkping_ping(VALUE self, VALUE args)
{
    bulkping_t *bp;

    Data_Get_Struct(self, bulkping_t, bp);

    if (bulkping_set_targets(bp, args) < 0) {
        rb_raise(rb_eRuntimeError, "invalid ping target");
        return self;
    }

    if (pinger_open(&bp->bp_pinger, &PingerICMP) < 0) {
        rb_raise(rb_eRuntimeError, "can't open raw socket");
        return self;
    }

    pinger_execute(&bp->bp_pinger, &bp->bp_tset);
    pinger_close(&bp->bp_pinger);

    if (rb_block_given_p())
        bulkping_yield_result(bp);

    return self;
}

static VALUE
bulkping_is_alive(VALUE self, VALUE args)
{
    int i;
    char *p;
    bulkping_t *bp;
    pinger_target_t *target;
    VALUE v;

    Data_Get_Struct(self, bulkping_t, bp);

    for (i = 0; i < RARRAY_LEN(args); i++) {
        v = RARRAY_PTR(args)[i];
        if (TYPE(v) == T_STRING) {
            p = StringValuePtr(v);
            if ((target = pinger_tset_find(&bp->bp_tset, p)) == NULL)
                return Qfalse;
            if (!target->t_alive)
                return Qfalse;
        }
    }

    return Qtrue;
}

static VALUE
bulkping_alive(VALUE self)
{
    return bulkping_tarray(self, 1);
}

static VALUE
bulkping_dead(VALUE self)
{
    return bulkping_tarray(self, 0);
}

static int
bulkping_set_targets(bulkping_t *bp, VALUE args)
{
    int tmax;

    for (tmax = 16; tmax <= TARGETS_MAX; tmax *= 2) {
        if (bulkping_init_targets(bp, tmax) < 0)
            return -1;
        if (bulkping_add_targets(&bp->bp_tset, args) == 0)
            return 0;
    }

    return -1;
}

static int
bulkping_init_targets(bulkping_t *bp, int count)
{
    void *p;

    if ((p = calloc(1, sizeof(pinger_target_t) * count)) == NULL)
        return -1;
    if (bp->bp_targets != NULL)
        free(bp->bp_targets);

    bp->bp_targets = (pinger_target_t *) p;
    pinger_tset_init(&bp->bp_tset, p, count);

    return 0;
}

static int
bulkping_add_targets(pinger_tset_t *tset, VALUE args)
{
    int i;
    char *p;
    VALUE v;

    for (i = 0; i < RARRAY_LEN(args); i++) {
        v = RARRAY_PTR(args)[i];
        switch (TYPE(v)) {
        case T_STRING:
            p = StringValuePtr(v);
            if (pinger_tset_add(tset, p) < 0)
                return -1;
            break;
        case T_ARRAY:
            if (bulkping_add_targets(tset, v) < 0)
                return -1;
            break;
        }
    }
    return 0;
}

static void
bulkping_yield_result(bulkping_t *bp)
{
    int i;
    VALUE arg;

    for (i = 0; i < bp->bp_tset.s_tcount; i++) {
        arg = rb_ary_new();
        rb_ary_push(arg, sa2v((SA *) &bp->bp_targets[i].t_addr));
        rb_ary_push(arg, (bp->bp_targets[i].t_alive) ? Qtrue : Qfalse);
        rb_yield(arg);
    }
}

static VALUE
bulkping_tarray(VALUE self, int alive)
{
    int i;
    bulkping_t *bp;
    VALUE ary;

    Data_Get_Struct(self, bulkping_t, bp);
    ary = rb_ary_new();

    for (i = 0; i < bp->bp_tset.s_tcount; i++) {
        if (bp->bp_targets[i].t_alive == alive)
            rb_ary_push(ary, sa2v((SA *) &bp->bp_targets[i].t_addr));
    }

    return ary;
}

static VALUE
sa2v(struct sockaddr *sa)
{
    char buf[256];
    VALUE string;

    getnameinfo(sa, SALEN(sa), buf, sizeof(buf), NULL, 0, NI_NUMERICHOST);
    string = rb_tainted_str_new2(buf);

    return string;
}
