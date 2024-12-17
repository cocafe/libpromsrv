#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#include <sys/socket.h>
#include <netdb.h>

#include <event2/event.h>
#include <event2/http.h>
#include <event2/http_struct.h>
#include <event2/buffer.h>
#include <event2/buffer_compat.h>
#include <event2/thread.h>

#include "promsrv.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#endif

static const char *http_errcode_get(long code)
{
        switch(code) {
        case   0: return "No Response";
        case 101: return "Switching Protocols";
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 203: return "Non-Authoritative Information";
        case 204: return "No Content";
        case 205: return "Reset Content";
        case 206: return "Partial Content";
        case 300: return "Multiple Choices";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 303: return "See Other";
        case 304: return "Not Modified";
        case 305: return "Use Proxy";
        case 306: return "(Unused)";
        case 307: return "Temporary Redirect";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 402: return "Payment Required";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 406: return "Not Acceptable";
        case 407: return "Proxy Authentication Required";
        case 408: return "Request Timeout";
        case 409: return "Conflict";
        case 410: return "Gone";
        case 411: return "Length Required";
        case 412: return "Precondition Failed";
        case 413: return "Request Entity Too Large";
        case 414: return "Request-URI Too Long";
        case 415: return "Unsupported Media Type";
        case 416: return "Requested Range Not Satisfiable";
        case 417: return "Expectation Failed";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        case 505: return "HTTP Version Not Supported";
        default:  return "Unknown Error";
        }
}

static void http_simple_reason_send(struct evhttp_request* req, int code, char const* text)
{
        char const *code_str = http_errcode_get(code);
        struct evbuffer *body = evbuffer_new();

        evbuffer_add_printf(body, "<h1>%d: %s</h1>", code, code_str);

        if (text) {
                evbuffer_add_printf(body, "%s", text);
        }

        evhttp_send_reply(req, code, code_str, body);

        evbuffer_free(body);
}

static void _prom_escape(char *buf, char *str)
{
        int pos = 0;
        int len = strlen(str);

        for (int i = 0; i < len; i++) {
                switch (str[i]) {
                case '\n':
                        buf[pos] = '\\';
                        pos++;
                        buf[pos] = 'n';
                        pos++;
                        break;
                case '\\':
                        buf[pos] = '\\';
                        pos++;
                        buf[pos] = '\\';
                        pos++;
                        break;
                case '"':
                        buf[pos] = '\\';
                        pos++;
                        buf[pos] = '"';
                        pos++;
                        break;
                default:
                        buf[pos] = str[i];
                        pos++;
                }
        }
        buf[pos] = '\0';
}

static void prom_metric_label_set(prom_metric *m, char *key, char *value)
{
        m->labels[m->num_labels].key = key;
        m->labels[m->num_labels].value = value;
        m->num_labels++;
}

static void prom_metric_init(prom_metric *m)
{
        m->num_labels = 0;
        memset(&m->labels, 0, sizeof(prom_label) * PROM_MAX_LABELS);
        m->value = 0;
        INIT_LIST_HEAD(&m->node);
}

void prom_metric_del(prom_metric *m)
{
        list_del(&m->node);
        free(m);
}

prom_metric *__prom_metric_create_or_get(prom_metric_set *s, prom_metric_def *d, int n, prom_label *ulabels)
{
        int found = 0;
        prom_metric *m_found;
        prom_metric_def_set *ds = NULL;

        for (int i = 0; i < s->n_defs; i++) {
                if (s->defs[i]->def == d) {
                        prom_metric *m;

                        ds = s->defs[i];

                        list_for_each_entry(m, &ds->metrics, node) {
                                // Compare labels
                                int labels_match = 1;

                                if (m->num_labels != n)
                                        continue;

                                for (int l = 0; l < m->num_labels; l++) {
                                        prom_label mlab = m->labels[l];
                                        prom_label ulab = ulabels[l];
                                        if (strcmp(mlab.key, ulab.key) || strcmp(mlab.value, ulab.value))
                                                labels_match = 0;
                                }

                                if (labels_match == 1) {
                                        m_found = m;
                                        found = 1;
                                        break;
                                }
                        }

                        break;
                }
        }

        // Create if not found
        if (found == 0) {
                if (!ds) {
                        return NULL;
                } else {
                        prom_metric *m = calloc(1, sizeof(prom_metric));
                        prom_metric_init(m);

                        for (int i = 0; i < n; i++) {
                                prom_metric_label_set(m, ulabels[i].key, ulabels[i].value);
                        }

                        list_add_tail(&m->node, &ds->metrics);

                        return m;
                }
        } else {
                return m_found;
        }
}

prom_metric *prom_metric_create_or_get(prom_metric_set *s, prom_metric_def *d, int n, ...)
{
        va_list args;
        va_start(args, n);
        prom_label ulabels[PROM_MAX_LABELS];
        for (int i = 0; i < n && i < PROM_MAX_LABELS; i++) {
                ulabels[i] = va_arg(args, prom_label);
        }
        va_end(args);

        return __prom_metric_create_or_get(s, d, n, ulabels);
}

prom_metric *prom_label_metric_create_or_get(prom_metric_set *s, prom_metric_def *d, int n, prom_label *labels)
{
        return __prom_metric_create_or_get(s, d, n, labels);
}

void prom_metric_register(prom_metric_set *s, prom_metric_def *d)
{
        // Check if we already have this definition
        int existing = -1;

        for (int i = 0; i < s->n_defs; i++) {
                if (s->defs[i]->def == d) {
                        existing = i;
                }
        }

        if (existing == -1) {
                // It doesn't exist, create it
                existing = s->n_defs;
                s->n_defs++;
                s->defs[existing] = malloc(sizeof(prom_metric_def_set));
                memset(s->defs[existing], 0, sizeof(prom_metric_def_set));
                s->defs[existing]->def = d;
                INIT_LIST_HEAD(&s->defs[existing]->metrics);
        }
}

void prom_metric_write(prom_metric_def_set *s, struct evbuffer *evbuf)
{
        char buf[PROM_BUF_SIZE];
        prom_metric *m;

        // Write the header comments
        evbuffer_add_printf(evbuf, "# TYPE %s %s\n", s->def->name, s->def->type);
        evbuffer_add_printf(evbuf, "# HELP %s %s\n", s->def->name, s->def->help ? s->def->help : "");

        // Write the metric values
        list_for_each_entry(m, &s->metrics, node) {
                evbuffer_add_printf(evbuf, "%s", s->def->name);
                if (m->num_labels > 0) {
                        evbuffer_add_printf(evbuf, "{");
                        for (int i = 0; i < m->num_labels; i++) {
                                _prom_escape(buf, m->labels[i].key);
                                evbuffer_add_printf(evbuf, "%s", buf);
                                evbuffer_add_printf(evbuf, "=\"");
                                _prom_escape(buf, m->labels[i].value);
                                evbuffer_add_printf(evbuf, "%s", buf);
                                evbuffer_add_printf(evbuf, "\"");
                                if (i < (m->num_labels - 1)) {
                                        evbuffer_add_printf(evbuf, ",");
                                }
                        }
                        evbuffer_add_printf(evbuf, "}");
                }
                evbuffer_add_printf(evbuf, " %f\n", m->value);
        }
}

void prom_metric_set_init(prom_metric_set *set)
{
        memset(set, 0, sizeof(*set));
}

void prom_metric_set_deinit(prom_metric_set *set)
{
        for (int i = 0; i < set->n_defs; i++) {
                prom_metric_def_set *ds = set->defs[i];
                prom_metric *m, *n;

                // Free each metric pointer
                list_for_each_entry_safe(m, n, &ds->metrics, node) {
                        list_del(&m->node);
                        free(m);
                }

                // Free the def set
                free(ds);
        }
}

void prom_commit_start(prom_ctx *ctx)
{
        struct evbuffer *next = evbuffer_new();

        while (!__sync_bool_compare_and_swap(&ctx->evbuf_next, NULL, next));
}

int prom_commit(prom_ctx *ctx, prom_metric_set *s)
{
        struct evbuffer *evbuf = ctx->evbuf_next;

        if (!evbuf)
                return -ENOENT;

        for (int i = 0; i < s->n_defs; i++) {
                prom_metric_write(s->defs[i], evbuf);
        }

        return 0;
}

void prom_commit_end(prom_ctx *ctx)
{
        pthread_mutex_lock(&ctx->lck_commit);
        if (ctx->evbuf)
                evbuffer_free(ctx->evbuf);

        ctx->evbuf = ctx->evbuf_next;
        ctx->evbuf_next = NULL;
        pthread_mutex_unlock(&ctx->lck_commit);
}

static void http_metrics_response(prom_ctx *ctx, struct evhttp_request *req)
{
        // {
        //         static struct timespec ts1 = { };
        //         struct timespec ts2 = { };
        //         clock_gettime(CLOCK_REALTIME, &ts2);

        //         if (ts1.tv_sec || ts1.tv_nsec)
        //                 printf("query interval: %lu s %ju nsec\n",
        //                        ts2.tv_sec - ts1.tv_sec,
        //                        (ts2.tv_sec - ts1.tv_sec) == 0 ? ts2.tv_nsec - ts1.tv_nsec : ts2.tv_nsec);

        //         ts1 = ts2;
        // }

        if (ctx->evbuf) {
                struct evbuffer *reply_buf = evbuffer_new();
                void *data = NULL;
                size_t len = 0;

                evhttp_add_header(req->output_headers,
                                  "Content-Type",
                                  "text/plain; version=0.0.1; charset=utf-8");

                pthread_mutex_lock(&ctx->lck_commit);

                len = evbuffer_get_length(ctx->evbuf);
                data = evbuffer_pullup(ctx->evbuf, len);
                if (data)
                        evbuffer_add(reply_buf, data, len);

                pthread_mutex_unlock(&ctx->lck_commit);

                if (evbuffer_get_length(reply_buf) > 0) {
                        evhttp_send_reply(req, HTTP_OK, "OK", reply_buf);
                } else {
                        http_simple_reason_send(req, HTTP_NOCONTENT, NULL);
                }

                evbuffer_free(reply_buf);
        } else {
                http_simple_reason_send(req, HTTP_NOCONTENT, NULL);
        }
}

static void http_request_handler(struct evhttp_request *req, void *arg) {
        prom_server *srv = arg;

        if (!req || !req->evcon)
                return;

        if (srv->ctx_cnt == 0) {
                http_simple_reason_send(req, HTTP_NOTIMPLEMENTED, NULL);
                return;
        }

        if (req->type != EVHTTP_REQ_GET) {
                http_simple_reason_send(req, HTTP_NOTIMPLEMENTED, NULL);
                return;
        }

        for (size_t i = 0; i < ARRAY_SIZE(srv->ctxs); i++) {
                prom_ctx *c = srv->ctxs[i];

                if (!strncmp(req->uri, c->uri, strlen(c->uri))) {
                        int err;

                        if (c->on_http_get && (err = c->on_http_get(c, c->userdata))) {
                                http_simple_reason_send(req, HTTP_INTERNAL, strerror(abs(err)));
                                return;
                        }

                        http_metrics_response(c, req);
                        return;
                }
        }

        http_simple_reason_send(req, HTTP_NOTFOUND, NULL);
}

void prom_ctx_init(prom_ctx *ctx, const char *uri)
{
        memset(ctx, 0x00, sizeof(*ctx));
        ctx->uri = uri;
        pthread_mutex_init(&ctx->lck_commit, NULL);
}

void prom_ctx_deinit(prom_ctx *ctx)
{
        if (ctx->evbuf)
                evbuffer_free(ctx->evbuf);

        if (ctx->evbuf_next)
                evbuffer_free(ctx->evbuf_next);

        pthread_mutex_destroy(&ctx->lck_commit);
}

int prom_srv_ctx_register(prom_server *srv, prom_ctx *ctx)
{
        if (!srv || !ctx)
                return -EINVAL;

        if (srv->ctx_cnt >= ARRAY_SIZE(srv->ctxs))
                return -ENOSPC;

        size_t cnt = srv->ctx_cnt;

        if (!__sync_bool_compare_and_swap(&srv->ctx_cnt, cnt, cnt + 1))
                return -EAGAIN;

        srv->ctxs[cnt] = ctx;

        return 0;
}

void prom_srv_run(prom_server *srv)
{
        event_base_dispatch(srv->ev_base);
}

void prom_srv_stop(prom_server *srv)
{
        event_base_loopbreak(srv->ev_base);
}

int prom_srv_init(prom_server *srv, const char *bind_addr, uint32_t port)
{
        int err = -EINVAL;

        memset(srv, 0, sizeof(*srv));

        evthread_use_pthreads();

        srv->ev_base = event_base_new();
        if (!srv->ev_base) {
                return -EFAULT;
        }

        srv->ev_http = evhttp_new(srv->ev_base);
        if (!srv->ev_http) {
                err = -ENOENT;
                goto free_base;
        }

        evhttp_set_gencb(srv->ev_http, http_request_handler, srv);

        srv->ev_httpsk = evhttp_bind_socket_with_handle(srv->ev_http, bind_addr, port);
        if (!srv->ev_httpsk) {
                err = -EADDRNOTAVAIL;
                goto free_http;
        }

        return 0;

free_http:
        evhttp_free(srv->ev_http);

free_base:
        event_base_free(srv->ev_base);

        return err;
}

void prom_srv_deinit(prom_server *srv)
{
        if (srv->ev_httpsk)
                evhttp_del_accept_socket(srv->ev_http, srv->ev_httpsk);

        if (srv->ev_http)
                evhttp_free(srv->ev_http);

        if (srv->ev_base)
                event_base_free(srv->ev_base);
}
