#ifndef __LIBPROMSRV_H__
#define __LIBPROMSRV_H__


#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#include "list.h"

#ifndef PROM_MAX_LABELS
#define PROM_MAX_LABELS 50
#endif

#ifndef PROM_MAX_METRICS
#define PROM_MAX_METRICS 256
#endif

#ifndef PROM_MAX_SRV_CTXS
#define PROM_MAX_SRV_CTXS 5
#endif

#ifndef PROM_BUF_SIZE
#define PROM_BUF_SIZE 1024
#endif

// Generic definition for a metric including name, help and type
typedef struct prom_metric_def {
        char *name;
        char *help;
        const char *type;
} prom_metric_def;

// Key-value pair representing a label name with an assigned value
typedef struct prom_label {
        char *key;
        char *value;
} prom_label;

// Represents an instance of a metric with a given value and set of labels
typedef struct prom_metric {
        struct list_head node;
        int num_labels;
        struct prom_label labels[PROM_MAX_LABELS];
        double value;
} prom_metric;

// A container for metrics that share a common definition
typedef struct prom_metric_def_set {
        prom_metric_def *def;
        struct list_head metrics;
} prom_metric_def_set;

// Container for a set of references to prom_metrics
typedef struct prom_metric_set {
        int n_defs;
        prom_metric_def_set *defs[PROM_MAX_METRICS];
} prom_metric_set;

typedef struct prom_ctx {
        const char *uri;
        struct evbuffer *evbuf;
        struct evbuffer *evbuf_next;
        int (*on_http_get)(struct prom_ctx *, void *);
        void *userdata;
        pthread_mutex_t lck_commit;
} prom_content;

typedef struct prom_server {
        struct event_base *ev_base;
        struct evhttp *ev_http;
        struct evhttp_bound_socket *ev_httpsk;
        size_t ctx_cnt;
        prom_content *ctxs[PROM_MAX_SRV_CTXS];
} prom_server;

static const char PROM_METRIC_TYPE_COUNTER[]   = "counter";
static const char PROM_METRIC_TYPE_GAUGE[]     = "gauge";
static const char PROM_METRIC_TYPE_HISTOGRAM[] = "histogram";
static const char PROM_METRIC_TYPE_SUMMARY[]   = "summary";

#define GAUGE_METRIC_DEF(_name, _help) \
        { .name = _name, .help = _help, .type = PROM_METRIC_TYPE_GAUGE }

#define COUNTER_METRIC_DEF(_name, _help) \
        { .name = _name, .help = _help, .type = PROM_METRIC_TYPE_GAUGE }

void prom_ctx_init(prom_content *ctx, const char *uri);
void prom_ctx_deinit(prom_content *ctx);

int prom_srv_ctx_register(prom_server *srv, prom_content *ctx);

void prom_srv_run(prom_server *srv);
void prom_srv_stop(prom_server *srv);
int prom_srv_init(prom_server *srv, const char *bind_addr, uint32_t port);
void prom_srv_deinit(prom_server *srv);

void prom_metric_set_init(prom_metric_set *set);
// Metric(s) free inside
void prom_metric_set_deinit(prom_metric_set *set);
// Add metric to a set
void prom_metric_register(prom_metric_set *s, prom_metric_def *d);
// Create or get a metric
prom_metric *prom_metric_create_or_get(prom_metric_set *s, prom_metric_def *d, int n, ...);
prom_metric *prom_label_metric_create_or_get(prom_metric_set *s, prom_metric_def *d, int n, prom_label *labels);
// Delete a metric from set
void prom_metric_del(prom_metric *m);

// Save a metric set to prometheus http buffer
void prom_commit_start(prom_content *ctx);
int prom_commit(prom_content *ctx, prom_metric_set *s);
void prom_commit_end(prom_content *ctx);

static inline void prom_ctx_on_http_get_cb(prom_content *ctx, int (*on_http_get)(prom_content *, void *), void *userdata)
{
        ctx->on_http_get = on_http_get;
        ctx->userdata = userdata;
}

#endif // __LIBPROMSRV_H__
