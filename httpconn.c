
#include <sys/queue.h>
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <event2/util.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include "httpconn.h"
#include "conn.h"
#include "headers.h"
#include "util.h"
#include "log.h"

#define EVENT0(conn, slot) \
	(conn)->cbs->slot((conn), (conn)->cbarg)
#define EVENT1(conn, slot, a) \
	(conn)->cbs->slot((conn), (a), (conn)->cbarg)
#define EVENT2(conn, slot, a, b) \
	(conn)->cbs->slot((conn), (a), (b), (conn)->cbarg)
#define EVENT3(conn, slot, a, b, c) \
	(conn)->cbs->slot((conn), (a), (b), (c), (conn)->cbarg)
#define EVENT4(conn, slot, a, b, c, d) \
	(conn)->cbs->slot((conn), (a), (b), (c), (d), (conn)->cbarg)

/* max amount of data we can have backlogged on outbuf before choaking */
static size_t max_write_backlog = 50 * 1024;

/* the number of seconds to keep an idle connections hanging around */
static struct timeval idle_client_timeout = {120, 0};
static struct timeval idle_server_timeout = {120, 0};

struct http_conn {
	enum http_state state;
	enum http_version vers;
	enum http_te te;
	enum http_type type;
	enum http_te output_te;
	int choked;
	int has_body;
	int read_paused;
	int tunnel_read_paused;
	int msg_complete_on_eof;
	int persistent;
	int expect_continue;
	int will_flush;
	int will_free;
	const struct http_cbs *cbs;
	void *cbarg;
	ev_int64_t body_length;
	ev_int64_t data_remaining;
	char *firstline;
	struct header_list *headers;
	struct event_base *base;
	struct bufferevent *bev;
	struct bufferevent *tunnel_bev;
	struct evbuffer *inbuf_processed;
};

static int
method_from_string(enum http_method *m, const char *method)
{
	if (!evutil_ascii_strcasecmp(method, "GET"))
		*m = METH_GET;
	else if (!evutil_ascii_strcasecmp(method, "HEAD"))
		*m = METH_HEAD;
	else if (!evutil_ascii_strcasecmp(method, "POST"))
		*m = METH_POST;
	else if (!evutil_ascii_strcasecmp(method, "PUT"))
		*m = METH_PUT;
	else if (!evutil_ascii_strcasecmp(method, "CONNECT"))
		*m = METH_CONNECT;
	else {
		log_warn("method_from_string: unknown method, '%s'", method);
		return -1;
	}

	return 0;
}

const char *
http_method_to_string(enum http_method m)
{
	switch (m) {
	case METH_GET:
		return "GET";
	case METH_HEAD:
		return "HEAD";
	case METH_POST:
		return "POST";
	case METH_PUT:
		return "PUT";
	case METH_CONNECT:
		return "CONNECT";
	}

	log_fatal("http_method_to_string: unknown method %d", m);
	return "???";
}

static int
version_from_string(enum http_version *v, const char *vers)
{
	if (evutil_ascii_strncasecmp(vers, "HTTP/", 5)) {
		log_warn("version_from_string: bad http-version, '%s'", vers);
		return -1;
	}

	vers += 5;

	/* XXX this only understands 1.0 and 1.1 */

	if (!strcmp(vers, "1.0"))
		*v = HTTP_10;
	else if (!strcmp(vers, "1.1"))
		*v = HTTP_11;
	else {
		log_warn("version_from_string: unknown http-version, '%s'",
		         vers);
		return -1;
	}
	
	return 0;
}

const char *
http_version_to_string(enum http_version v)
{
	switch (v) {
	case HTTP_UNKNOWN:
		return "HTTP/??";
	case HTTP_10:
		return "HTTP/1.0";
	case HTTP_11:
		return "HTTP/1.1";
	}
	
	log_fatal("http_version_to_string: unknown version %d", v);
	return "???";
}

const char *
http_conn_error_to_string(enum http_conn_error err)
{
	switch (err) {
	case ERROR_NONE:
		return "No error";
	case ERROR_CONNECT_FAILED:
		return "Connection failed";
	case ERROR_IDLE_CONN_TIMEDOUT:
		return "Idle connection timed out";
	case ERROR_CLIENT_EXPECTATION_FAILED:
		return "Can't statisfy client's expectation";
	case ERROR_CLIENT_POST_WITHOUT_LENGTH:
		return "Client post with unknown length";
	case ERROR_INCOMPLETE_HEADERS:
		return "Connection terminated while reading headers";
	case ERROR_INCOMPLETE_BODY:
		return "Connection terminated prematurely while reading body";
	case ERROR_HEADER_PARSE_FAILED:
		return "Invalid client request";
	case ERROR_CHUNK_PARSE_FAILED:
		return "Invalid chunked data";
	case ERROR_WRITE_FAILED:
		return "Write failed";
	case ERROR_TUNNEL_CONNECT_FAILED:
		return "Tunnel connection failed";
	case ERROR_TUNNEL_CLOSED:
		return "Tunnel closed";
	}

	return "???";
}

static void
begin_message(struct http_conn *conn)
{
	assert(conn->headers == NULL && conn->firstline == NULL);
	conn->headers = mem_calloc(1, sizeof(*conn->headers));
	TAILQ_INIT(conn->headers);
	conn->state = HTTP_STATE_IDLE;
	if (!conn->read_paused)
		bufferevent_enable(conn->bev, EV_READ);
	// XXX we should have a separate function to tell that server is idle.
	if (conn->type == HTTP_SERVER)
		bufferevent_set_timeouts(conn->bev, &idle_server_timeout, NULL);
	else
		bufferevent_set_timeouts(conn->bev, &idle_client_timeout, NULL);
}

static void
end_message(struct http_conn *conn, enum http_conn_error err)
{
	if (conn->firstline)
		mem_free(conn->firstline);
	if (conn->headers) {
		headers_clear(conn->headers);
		mem_free(conn->headers);
	}

	conn->firstline = NULL;
	conn->headers = NULL;

	if (err != ERROR_NONE || !conn->persistent) {
		conn->state = HTTP_STATE_MANGLED;
		http_conn_stop_reading(conn);
	} else
		begin_message(conn);

	if (err != ERROR_NONE)
		EVENT1(conn, on_error, err);
	else
		EVENT0(conn, on_msg_complete);
}

static struct http_request *
build_request(struct http_conn *conn)
{
	struct http_request *req;
	struct token_list tokens;
	struct token *method, *url, *vers;
	enum http_method m;
	enum http_version v;
	struct url *u = NULL;
	size_t ntokens;

	assert(conn->type == HTTP_CLIENT);

	TAILQ_INIT(&tokens);
	req = NULL;

	ntokens = tokenize(conn->firstline, " ", 4, &tokens);
	if (ntokens != 3)
		goto out;

	method = TAILQ_FIRST(&tokens);
	url = TAILQ_NEXT(method, next);	
	vers = TAILQ_NEXT(url, next);

	if (method_from_string(&m, method->token) < 0 ||
            version_from_string(&v, vers->token) < 0)
		goto out;

	if (m == METH_CONNECT)
		u = url_connect_tokenize(url->token);
	else
		u = url_tokenize(url->token);
	if (!u)
		goto out;

	req = mem_calloc(1, sizeof(*req));
	req->meth = m;
	req->vers = v;
	req->url = u;
	u = NULL;
	req->headers = conn->headers;

out:
	url_free(u);
	token_list_clear(&tokens);
	
	return req;
}

static struct http_response *
build_response(struct http_conn *conn)
{
	struct http_response *resp;
	struct token_list tokens;
	struct token *vers, *code, *reason;
	enum http_version v;
	int c;
	size_t ntokens;

	assert(conn->type == HTTP_SERVER);

	TAILQ_INIT(&tokens);
	resp = NULL;

	ntokens = tokenize(conn->firstline, " ", 2, &tokens);
	if (ntokens != 3)
		goto out;

	vers = TAILQ_FIRST(&tokens);
	code = TAILQ_NEXT(vers, next);
	reason = TAILQ_NEXT(code, next);
	c = atoi(code->token);

        if (version_from_string(&v, vers->token) < 0 || c < 100 || c > 999)
		goto out;

	resp = mem_calloc(1, sizeof(*resp));
	resp->vers = v;
	resp->code = c;
	resp->reason = reason->token;
	reason->token = NULL; /* so token_list_clear will skip this */
	resp->headers = conn->headers;

out:
	token_list_clear(&tokens);
	
	return resp;
}

/* return -1 failure, 0 incomplete, 1 ok */
static int
parse_chunk_len(struct http_conn *conn)
{
	struct evbuffer *inbuf = bufferevent_get_input(conn->bev);
	char *line;
	ev_int64_t len;

	while ((line = evbuffer_readln(inbuf, NULL, EVBUFFER_EOL_CRLF))) {
		if (*line == '\0') {
			mem_free(line);
			continue;
		}

		len = get_int(line, 16);
		mem_free(line);
		if (len < 0) {
			log_warn("parse_chunk_len: invalid chunk len");
			return -1;
		}

		conn->data_remaining = len;
		return 1;
	}

	return 0;
}

static void
read_chunk(struct http_conn *conn)
{
	struct evbuffer *inbuf = bufferevent_get_input(conn->bev);
	size_t len;
	char *line;
	int ret;
	
	while ((len = evbuffer_get_length(inbuf)) > 0) {
		if (conn->data_remaining < 0) {
			ret = parse_chunk_len(conn);
			if (ret <= 0) {
				if (ret < 0)
					end_message(conn,
						    ERROR_CHUNK_PARSE_FAILED);
				return;
			}
		} else if (conn->data_remaining == 0) {
			line = evbuffer_readln(inbuf, NULL, EVBUFFER_EOL_CRLF);
			if (line) {
				/* XXX doesn't handle trailers */
				mem_free(line);		
				end_message(conn, ERROR_NONE);
			}
			return;
		} else {
			/* XXX should mind potential overflow */
			if (len >= (size_t)conn->data_remaining)
				len = (size_t)conn->data_remaining;

			evbuffer_remove_buffer(inbuf, conn->inbuf_processed,
					       len);
			EVENT1(conn, on_read_body, conn->inbuf_processed);
			conn->data_remaining -= len;

			if (conn->data_remaining == 0)
				conn->data_remaining = -1;
		}
	}
}

static void
read_body(struct http_conn *conn)
{
	struct evbuffer *inbuf = bufferevent_get_input(conn->bev);
	size_t len;

	assert(conn->has_body);

	if (conn->te == TE_CHUNKED) {
		read_chunk(conn);
		return;
	}

	len = evbuffer_get_length(inbuf);
	if (len) {
		/* XXX should mind potential overflow */
		if (conn->data_remaining >= 0 &&
		    len > (size_t)conn->data_remaining) {
			len = (size_t)conn->data_remaining;
			evbuffer_remove_buffer(inbuf, conn->inbuf_processed,
					       len);
			EVENT1(conn, on_read_body, conn->inbuf_processed);
		} else {
			evbuffer_add_buffer(conn->inbuf_processed, inbuf);
			EVENT1(conn, on_read_body, conn->inbuf_processed);
		}

		conn->data_remaining -= len;
		if (conn->data_remaining == 0)
			end_message(conn, ERROR_NONE);
	}
}

static enum http_conn_error
check_headers(struct http_conn *conn, struct http_request *req,
	   struct http_response *resp)
{
	enum http_version vers;
	int persistent;
	int tunnel;
	char *val;

	conn->te = TE_IDENTITY;
	conn->has_body = 1;
	conn->msg_complete_on_eof = 0;
	conn->data_remaining = -1;
	conn->body_length = -1;
	conn->expect_continue = 0;
	tunnel = 0;

	if (conn->type == HTTP_CLIENT) {
		vers = req->vers;
		conn->has_body = 0;
		if (req->meth == METH_POST ||
		    req->meth == METH_PUT)
			conn->has_body = 1;
		else if (req->meth == METH_CONNECT)
			tunnel = 1;

		val = headers_find(conn->headers, "Expect");
		if (val) {
			int cont;

			cont = !evutil_ascii_strcasecmp(val, "100-continue");
			mem_free(val);
			if (cont == 0 || !conn->has_body)
				return ERROR_CLIENT_EXPECTATION_FAILED;
			
			if (cont && req->vers != HTTP_11) {
				cont = 0;
				log_info("http: ignoring expect continue from "
					 "old client");
				headers_remove(conn->headers, "Expect");
			}

			conn->expect_continue = cont;
		}
	} else { /* server */
		vers = resp->vers;
		if ((resp->code >= 100 && resp->code < 200) ||
		    resp->code == 204 || resp->code == 205 ||
		    resp->code == 304)
			conn->has_body = 0;
	}

	/* check headers */
	if (conn->has_body) {
		val = headers_find(conn->headers, "transfer-encoding");
		if (val) {
			if (!evutil_ascii_strcasecmp(val, "chunked"))
				conn->te = TE_CHUNKED;
			mem_free(val);
		}

		if (conn->te != TE_CHUNKED) {
			val = headers_find(conn->headers, "content-length");
			if (val) {
				ev_int64_t iv;
				iv = get_int(val, 10);
				if (iv < 0) {
					log_warn("http: mangled "
						 "Content-Length");
					headers_remove(conn->headers,
						       "content-length");
				} else
					conn->body_length = iv;
				mem_free(val);
				if (conn->body_length == 0)
					conn->has_body = 0;
			} else {
				conn->msg_complete_on_eof = 1;
			}
		}

		if (conn->type == HTTP_CLIENT && conn->body_length < 0 &&
		    conn->te != TE_CHUNKED)
			return ERROR_CLIENT_POST_WITHOUT_LENGTH;
	}
	conn->data_remaining = conn->body_length;

	assert(vers != HTTP_UNKNOWN);

	persistent = 0;
	if (!tunnel && !conn->msg_complete_on_eof && vers == HTTP_11)
		persistent = 1;

	if (conn->vers != HTTP_UNKNOWN && conn->vers != vers) {
		log_warn("http_conn: http version changed!");
		persistent = 0;
	}
	conn->vers = vers;

	if (persistent) {
		val = headers_find(conn->headers, "connection");
		if (val) {
			if (!evutil_ascii_strcasecmp(val, "close"))
				persistent = 0;
			mem_free(val);
		}
	}
	conn->persistent = persistent;

	return ERROR_NONE;
}

static void
read_headers(struct http_conn *conn)
{
	int failed = 0;
	struct evbuffer *inbuf = bufferevent_get_input(conn->bev);
	struct http_request *req = NULL;
	struct http_response *resp = NULL;
	enum http_conn_error err;

	assert(conn->state == HTTP_STATE_READ_HEADERS);

	switch (headers_load(conn->headers, inbuf)) {
	case -1:
		end_message(conn, ERROR_HEADER_PARSE_FAILED);
		return;
	case 0:
		return;
	/* case 1: finished, fall thru */
	}

	assert(conn->firstline);

	if (conn->type == HTTP_CLIENT) {
		req = build_request(conn);
		if (!req)
			failed = 1;
	} else {
		resp = build_response(conn);
		if (!resp)
			failed = 1;
	}
	
	mem_free(conn->firstline);
	conn->firstline = NULL;

	if (failed) {
		assert(!req && !resp);
		end_message(conn, ERROR_HEADER_PARSE_FAILED);
		return;
	}

	err = check_headers(conn, req, resp);
	conn->headers = NULL;

	if (err == ERROR_NONE) {
		int server_continuation = 0;

		/* ownership of req or resp is now passed on */
		if (req)
			EVENT1(conn, on_client_request, req);
		if (resp) {
			if (resp->code == 100) {
				http_response_free(resp);
				EVENT0(conn, on_server_continuation);
				begin_message(conn);
				server_continuation = 1;
			} else
				EVENT1(conn, on_server_response, resp);
		}

		if (!server_continuation &&
		    conn->state != HTTP_STATE_TUNNEL_CONNECTING) {
			if (!conn->has_body)
				end_message(conn, ERROR_NONE);
			else
				conn->state = HTTP_STATE_READ_BODY;
		}
	} else {
		http_request_free(req);
		http_response_free(resp);
		end_message(conn, err);
	}
}

static void
tunnel_transfer_data(struct http_conn *conn, struct bufferevent *to,
		     struct bufferevent *from)
{
	struct evbuffer *frombuf = bufferevent_get_input(from);
	struct evbuffer *tobuf = bufferevent_get_output(to);

	if (evbuffer_get_length(frombuf) == 0)
		return;

	evbuffer_add_buffer(tobuf, frombuf);
	if (evbuffer_get_length(tobuf) > max_write_backlog) {
		bufferevent_setwatermark(to, EV_WRITE,
					 max_write_backlog / 2, 0);
		bufferevent_disable(from, EV_READ);
		if (from == conn->bev) {
			log_debug("tunnel: throttling client read");
			conn->read_paused = 1;
		} else {
			log_debug("tunnel: throttling server read");
			conn->tunnel_read_paused = 1;
		}
	}
}

static void
tunnel_writecb(struct bufferevent *bev, void *_conn)
{
	struct http_conn *conn = _conn;

	if (conn->state == HTTP_STATE_TUNNEL_OPEN) {
		if (conn->tunnel_read_paused && bev == conn->bev) {
			log_debug("tunnel: unthrottling server read");
			conn->tunnel_read_paused = 0;
			bufferevent_enable(conn->tunnel_bev, EV_READ);
			bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
		} else if (conn->read_paused && bev == conn->tunnel_bev) {
			log_debug("tunnel: unthrottling client read");
			conn->read_paused = 0;
			bufferevent_enable(conn->bev, EV_READ);
			bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
		}
	} else {
		log_debug("tunnel: flushed!");
		bufferevent_setcb(conn->bev, NULL, NULL, NULL, NULL);
		bufferevent_setcb(conn->tunnel_bev, NULL, NULL, NULL, NULL);
		EVENT1(conn, on_error, ERROR_TUNNEL_CLOSED);
	}
}

static void
tunnel_readcb(struct bufferevent *bev, void *_conn)
{
	struct http_conn *conn = _conn;

	if (bev == conn->bev)
		tunnel_transfer_data(conn, conn->tunnel_bev, bev);
	else
		tunnel_transfer_data(conn, conn->bev, bev);
}

static void
tunnel_errorcb(struct bufferevent *bev, short what, void *_conn)
{
	struct http_conn *conn = _conn;
	struct evbuffer *buf;

	switch (conn->state) {
	case HTTP_STATE_TUNNEL_OPEN:
		if (bev == conn->bev) {
			log_debug("tunnel: client closed conn...");
			bev = conn->tunnel_bev;
		} else {
			log_debug("tunnel: server closed conn...");
			bev = conn->bev;
		}
		buf = bufferevent_get_output(bev);
		if (evbuffer_get_length(buf)) {
			conn->state = HTTP_STATE_TUNNEL_FLUSHING;
			log_debug("tunnel: flushing %lu bytes...",
				  (unsigned long)evbuffer_get_length(buf));
			bufferevent_disable(bev, EV_READ);
			bufferevent_setcb(bev, NULL, tunnel_writecb,
					  tunnel_errorcb, conn);
			break;
		}
		/* nothing left to write.. lets just fall thru... */
	case HTTP_STATE_TUNNEL_FLUSHING:
		/* an error happend while flushing, lets just give up. */
		bufferevent_setcb(conn->bev, NULL, NULL, NULL, NULL);
		bufferevent_setcb(conn->tunnel_bev, NULL, NULL, NULL, NULL);
		EVENT1(conn, on_error, ERROR_TUNNEL_CLOSED);
		break;
	default:
		log_fatal("tunnel: errorcb called in invalid state!");
	}
}

static void
tunnel_connectcb(struct bufferevent *bev, int ok, void *_conn)
{
	struct http_conn *conn = _conn;

	assert(conn->state == HTTP_STATE_TUNNEL_CONNECTING);

	if (ok) {
		conn->state = HTTP_STATE_TUNNEL_OPEN;
		bufferevent_setcb(conn->tunnel_bev, tunnel_readcb,
				  tunnel_writecb, tunnel_errorcb, conn);
		bufferevent_enable(conn->bev, EV_READ);
		bufferevent_enable(conn->tunnel_bev, EV_READ);
		conn->read_paused = 0;
		conn->tunnel_read_paused = 0;
		tunnel_transfer_data(conn, conn->tunnel_bev, conn->bev);
		evbuffer_add_printf(bufferevent_get_output(conn->bev),
				"%s 200 Connection established\r\n\r\n",
				http_version_to_string(conn->vers));
	} else {
		bufferevent_setcb(conn->tunnel_bev, NULL, NULL,
				  NULL, NULL);
		EVENT1(conn, on_error, ERROR_TUNNEL_CONNECT_FAILED);
	}
}

static void
http_errorcb(struct bufferevent *bev, short what, void *_conn)
{
	enum http_state state;
	struct http_conn *conn = _conn;

	assert(!(what & BEV_EVENT_CONNECTED));

	state = conn->state;
	conn->state = HTTP_STATE_MANGLED;

	if (what & BEV_EVENT_WRITING) {
		end_message(conn, ERROR_WRITE_FAILED);
		return;
	}
	
	switch (state) {
	case HTTP_STATE_IDLE:
		end_message(conn, ERROR_IDLE_CONN_TIMEDOUT);
		break;
	case HTTP_STATE_READ_FIRSTLINE:
	case HTTP_STATE_READ_HEADERS:
		end_message(conn, ERROR_INCOMPLETE_HEADERS);
		break;
	case HTTP_STATE_READ_BODY:
		if ((what & BEV_EVENT_EOF) && conn->msg_complete_on_eof)
			end_message(conn, ERROR_NONE);
		else
			end_message(conn, ERROR_INCOMPLETE_BODY);
		break;
	default:
		log_fatal("http_conn: errorcb called in invalid state");
	}
}

static void
process_one_step(struct http_conn *conn)
{
	struct evbuffer *inbuf = bufferevent_get_input(conn->bev);

	switch (conn->state) {
	case HTTP_STATE_IDLE:
		conn->state = HTTP_STATE_READ_FIRSTLINE;
		bufferevent_set_timeouts(conn->bev, NULL, NULL);
		/* fallthru... */
	case HTTP_STATE_READ_FIRSTLINE:
		assert(conn->firstline == NULL);
		conn->firstline = evbuffer_readln(inbuf, NULL,
						  EVBUFFER_EOL_CRLF);
		if (conn->firstline)
			conn->state = HTTP_STATE_READ_HEADERS;
		break;	
	case HTTP_STATE_READ_HEADERS:
		read_headers(conn);
		break;
	case HTTP_STATE_READ_BODY:
		read_body(conn);
		break;
	default:
		log_fatal("http_conn: read cb called in invalid state");	
	}
}

static void
process_inbuf(struct http_conn *conn)
{
	struct evbuffer *inbuf = bufferevent_get_input(conn->bev);
	enum http_state state_before;

	do {
		state_before = conn->state;
		process_one_step(conn);
	} while (!conn->read_paused &&
		 evbuffer_get_length(inbuf) > 0 &&
		 state_before != conn->state);
}

static void
http_readcb(struct bufferevent *bev, void *_conn)
{
	process_inbuf(_conn);
}

static void
http_writecb(struct bufferevent *bev, void *_conn)
{
	struct http_conn *conn = _conn;
	struct evbuffer *outbuf = bufferevent_get_output(bev);

	if (conn->choked) {
		bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
		conn->choked = 0;
		EVENT0(conn, on_write_more);
	} else if (evbuffer_get_length(outbuf) == 0) {
		if (!conn->will_flush)
			EVENT0(conn, on_flush);
	}
}

static void
http_connectcb(struct bufferevent *bev, int ok, void *_conn)
{
	struct http_conn *conn = _conn;

	assert(conn->state == HTTP_STATE_CONNECTING);
	bufferevent_setcb(conn->bev, http_readcb, http_writecb,
			  http_errorcb, conn);

	if (ok) {
		begin_message(conn);
		EVENT0(conn, on_connect);
	} else {	
		conn->state = HTTP_STATE_MANGLED;
		EVENT1(conn, on_error, ERROR_CONNECT_FAILED);
	}
}


struct http_conn *
http_conn_new(struct event_base *base, evutil_socket_t sock,
	      enum http_type type, const struct http_cbs *cbs, void *cbarg)
{
	struct http_conn *conn;

	conn = mem_calloc(1, sizeof(*conn));
	conn->base = base;
	conn->type = type;
	conn->cbs = cbs;
	conn->cbarg = cbarg;
	conn->bev = bufferevent_socket_new(base, sock,
			BEV_OPT_CLOSE_ON_FREE);
	if (!conn->bev)
		log_fatal("http_conn: failed to create bufferevent");

	conn->inbuf_processed = evbuffer_new();
	if (!conn->inbuf_processed)
		log_fatal("http_conn: failed to create evbuffer");

	if (type != HTTP_SERVER)
		bufferevent_setcb(conn->bev, http_readcb, http_writecb,
				  http_errorcb, conn);
	
	if (sock >= 0)
		begin_message(conn);

	return conn;
}

int
http_conn_connect(struct http_conn *conn, struct evdns_base *dns,
		      int family, const char *host, int port)
{
	assert(conn->type == HTTP_SERVER);
	conn->state = HTTP_STATE_CONNECTING;
	return conn_connect_bufferevent(conn->bev, dns, family, host, port,
				        http_connectcb, conn);
}

static void
deferred_free(evutil_socket_t s, short what, void *arg)
{
	struct http_conn *conn = arg;
	bufferevent_free(conn->bev);
	if (conn->tunnel_bev)
		bufferevent_free(conn->tunnel_bev);
	evbuffer_free(conn->inbuf_processed);
	mem_free(conn);
}

void
http_conn_free(struct http_conn *conn)
{
	if (conn->will_free)
		return;

	conn->will_free = 1;
	http_conn_stop_reading(conn);
	bufferevent_disable(conn->bev, EV_WRITE);
	bufferevent_setcb(conn->bev, NULL, NULL, NULL, NULL);
	conn->cbs = NULL;
	event_base_once(conn->base, -1, EV_TIMEOUT, deferred_free, conn, NULL);
}

void
http_conn_write_request(struct http_conn *conn, struct http_request *req)
{
	struct evbuffer *outbuf;

	assert(conn->type == HTTP_SERVER);

	headers_remove(req->headers, "connection");
	req->vers = HTTP_11;
		
	outbuf = bufferevent_get_output(conn->bev);

	evbuffer_add_printf(outbuf, "%s %s %s\r\n",
		http_method_to_string(req->meth),
		req->url->path,
		http_version_to_string(req->vers));
		
	headers_dump(req->headers, outbuf);	
}

int
http_conn_expect_continue(struct http_conn *conn)
{
	return conn->expect_continue;
}

void
http_conn_write_continue(struct http_conn *conn)
{
	struct evbuffer *outbuf;

	if (conn->expect_continue) {
		outbuf = bufferevent_get_output(conn->bev);
		conn->expect_continue = 0;
		assert(conn->vers == HTTP_11);
		evbuffer_add_printf(outbuf, "HTTP/1.1 100 Continue\r\n\r\n");
	}
}

void
http_conn_write_response(struct http_conn *conn, struct http_response *resp)
{
	struct evbuffer *outbuf;

	assert(conn->type == HTTP_CLIENT);
	assert(conn->vers != HTTP_UNKNOWN);

	headers_remove(resp->headers, "connection");
	headers_remove(resp->headers, "transfer-encoding");
	resp->vers = conn->vers;

	if (conn->vers == HTTP_10 || !conn->persistent) {
		if (conn->vers == HTTP_10)
			conn->output_te = TE_IDENTITY;
		headers_add_key_val(resp->headers, "Connection", "close");
	} 
	if (conn->output_te == TE_CHUNKED) {
		headers_add_key_val(resp->headers,
			            "Transfer-Encoding", "chunked");
	}

	outbuf = bufferevent_get_output(conn->bev);

	evbuffer_add_printf(outbuf, "%s %d %s\r\n",
		        http_version_to_string(conn->vers),
			resp->code,
			resp->reason);
		
	headers_dump(resp->headers, outbuf);	
}

int
http_conn_write_buf(struct http_conn *conn, struct evbuffer *buf)
{
	struct evbuffer *outbuf;
	
	outbuf = bufferevent_get_output(conn->bev);

	if (conn->output_te == TE_CHUNKED)
		evbuffer_add_printf(outbuf, "%x\r\n",
				    (unsigned)evbuffer_get_length(buf));
	evbuffer_add_buffer(outbuf, buf);
	if (conn->output_te == TE_CHUNKED)
		evbuffer_add(outbuf, "\r\n", 2);

	/* have we choked? */	
	if (evbuffer_get_length(outbuf) > max_write_backlog) {
		bufferevent_setwatermark(conn->bev, EV_WRITE,
					 max_write_backlog / 2, 0);
		conn->choked = 1;
		return 0;
	}

	return 1;
}

void
http_conn_write_finished(struct http_conn *conn)
{
	if (conn->output_te == TE_CHUNKED)
		bufferevent_write(conn->bev, "0\r\n\r\n", 5);
	conn->output_te = TE_IDENTITY;
		
}

int
http_conn_current_message_has_body(struct http_conn *conn)
{
	return conn->has_body;
}

void
http_conn_set_current_message_bodyless(struct http_conn *conn)
{
	assert(conn->type == HTTP_SERVER);
	conn->has_body = 0;
}

enum http_te
http_conn_get_current_message_body_encoding(struct http_conn *conn)
{
	return conn->te;
}

ev_int64_t
http_conn_get_current_message_body_length(struct http_conn *conn)
{
	return conn->body_length;
}

void
http_conn_set_output_encoding(struct http_conn *conn, enum http_te te)
{
	conn->output_te = te;
}

int
http_conn_is_persistent(struct http_conn *conn)
{
	return conn->persistent;
}

void
http_conn_disable_persistence(struct http_conn *conn)
{
	conn->persistent = 0;
}

void
http_conn_stop_reading(struct http_conn *conn)
{
	bufferevent_disable(conn->bev, EV_READ);
	conn->read_paused = 1;
}

void
http_conn_start_reading(struct http_conn *conn)
{
	struct evbuffer *inbuf = bufferevent_get_input(conn->bev);

	bufferevent_enable(conn->bev, EV_READ);
	conn->read_paused = 0;
	// XXX this might cause recursion
	if (evbuffer_get_length(inbuf) > 0)
		process_inbuf(conn);
}

static void
deferred_flush(evutil_socket_t fd, short what, void *_conn)
{
	struct http_conn *conn = _conn;
	struct evbuffer *outbuf = bufferevent_get_output(conn->bev);

	if (evbuffer_get_length(outbuf) == 0) {
		conn->will_flush = 0;
		EVENT0(conn, on_flush);
	}
}

void
http_conn_flush(struct http_conn *conn)
{
	assert(!conn->will_free);
	conn->will_flush = 1;
	event_base_once(conn->base, -1, EV_TIMEOUT, deferred_flush, conn, NULL);
}

void
http_conn_send_error(struct http_conn *conn, int code, const char *fmt, ...)
{
	char length[64];
	char reason[256];
	struct evbuffer *msg;
	struct http_response resp;
	struct header_list headers;
	va_list ap;

	assert(conn->type == HTTP_CLIENT);

	TAILQ_INIT(&headers);
	msg = evbuffer_new();
	resp.headers = &headers;

	if (conn->vers == HTTP_UNKNOWN)
		conn->vers = HTTP_11;

	
	va_start(ap, fmt);
	evutil_vsnprintf(reason, sizeof(reason), fmt, ap);
	va_end(ap);

	conn->output_te = TE_IDENTITY;
	resp.vers = HTTP_11;
	resp.code = code;
	resp.reason = reason;

	evbuffer_add_printf(msg,
		"<html>\n"
		"<head>\n"
		"<title>%d %s</title>\n"
		"</head>\n"
		"<body>\n"
		"<h1>%d %s</h1>\n"
		"</body>\n"
		"</html>\n",
		code, resp.reason, code, resp.reason);

	evutil_snprintf(length, sizeof(length), "%u", 
		        (unsigned)evbuffer_get_length(msg));
	headers_add_key_val(&headers, "Content-Type", "text/html");
	headers_add_key_val(&headers, "Content-Length", length);	
	headers_add_key_val(&headers, "Expires", "0");
	headers_add_key_val(&headers, "Cache-Control", "no-cache");
	headers_add_key_val(&headers, "Pragma", "no-cache");

	http_conn_write_response(conn, &resp);
	http_conn_write_buf(conn, msg);
	headers_clear(&headers);
	evbuffer_free(msg);
}

int
http_conn_start_tunnel(struct http_conn *conn, struct evdns_base *dns,
		       int family, const char *host, int port)
{
	assert(conn->type == HTTP_CLIENT);
	assert(conn->tunnel_bev == NULL);

	http_conn_stop_reading(conn);
	conn->tunnel_bev = bufferevent_socket_new(conn->base, -1,
						  BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(conn->bev, tunnel_readcb,
			  tunnel_writecb, tunnel_errorcb, conn);
	log_info("tunnel: attempting connection to %s:%d",
		 log_scrub(host), port);
	conn->state = HTTP_STATE_TUNNEL_CONNECTING;
	return conn_connect_bufferevent(conn->tunnel_bev, dns, family,
				host, port, tunnel_connectcb, conn);
}

void
http_request_free(struct http_request *req)
{
	if (!req)
		return;

	url_free(req->url);
	headers_clear(req->headers);
	mem_free(req);
}

void
http_response_free(struct http_response *resp)
{
	if (!resp)
		return;

	headers_clear(resp->headers);
	mem_free(resp->headers);
	mem_free(resp->reason);
	mem_free(resp);
}

#ifdef TEST_HTTP
#include <netinet/in.h>
#include <stdio.h>
#include <event2/dns.h>
#include <event2/listener.h>

static void
proxy_connected(struct http_conn *conn, void *arg)
{
	struct http_request req;
	struct header_list headers;
	struct evbuffer *buf;

	TAILQ_INIT(&headers);
	req.meth = METH_GET;
	req.url = arg;
	req.vers = HTTP_11;
	req.headers = &headers;	

	buf = evbuffer_new();
	evbuffer_add_printf(buf, "Host: %s\r\n\r\n", req.url->host);
	headers_load(&headers, buf);
	evbuffer_free(buf);

	http_conn_write_request(conn, &req);
}

static void
proxy_error(struct http_conn *conn, enum http_conn_error err, void *arg)
{
	fprintf(stderr, "error %d\n", err);
	http_conn_free(conn);
}

static void
proxy_request(struct http_conn *conn, struct http_request *req, void *arg)
{
	struct evbuffer *buf;

	fprintf(stderr, "request: %s %s %s\n",
			http_method_to_string(req->meth),
			req->url->path,
			http_version_to_string(req->vers));

	buf = evbuffer_new();
	headers_dump(req->headers, buf);
	fwrite(evbuffer_pullup(buf, evbuffer_get_length(buf)), evbuffer_get_length(buf), 1, stderr);
	evbuffer_free(buf);


	http_conn_send_error(conn, 401);
}

static void
proxy_response(struct http_conn *conn, struct http_response *resp, void *arg)
{
	struct evbuffer *buf;

	fprintf(stderr, "response: %s, %d, %s\n",
		http_version_to_string(resp->vers),
		resp->code,
		resp->reason);

	buf = evbuffer_new();
	headers_dump(resp->headers, buf);
	fwrite(evbuffer_pullup(buf, evbuffer_get_length(buf)), evbuffer_get_length(buf), 1, stderr);
	evbuffer_free(buf);
}

static void
proxy_read_body(struct http_conn *conn, struct evbuffer *buf, void *arg)
{
	size_t len = evbuffer_get_length(buf);
	fwrite(evbuffer_pullup(buf, len), len, 1, stderr);
	evbuffer_drain(buf, len);
}

static void
proxy_msg_complete(struct http_conn *conn, void *arg)
{
	fprintf(stderr, "\n...MSG COMPLETE...\n");
}

static void
proxy_write_more(struct http_conn *conn, void *arg)
{
}

static void
proxy_flush(struct http_conn *conn, void *arg)
{
	fprintf(stderr, "\n....FLUSHED...\n");
}

static struct http_cbs test_proxy_cbs = {
	proxy_connected,
	proxy_error,
	proxy_request,
	proxy_response,
	proxy_read_body,
	proxy_msg_complete,
	proxy_write_more,
	proxy_flush
};


static void
clientcb(struct evconnlistener *ecs, evutil_socket_t s,
              struct sockaddr *addr, int len, void *arg) 
{
	struct http_conn *client;

	client = http_conn_new(evconnlistener_get_base(ecs), s, HTTP_CLIENT, &test_proxy_cbs, arg);
}

int
main(int argc, char **argv)
{
	struct event_base *base;
	struct evdns_base *dns;
	struct http_conn *http;
	struct url *url;

	base = event_base_new();

	if (argc < 2) {
		struct evconnlistener *ecs;
		struct sockaddr_in sin;
		memset(&sin, 0, sizeof(sin));
		sin.sin_family=AF_INET;
		sin.sin_port = htons(8080);
		ecs = evconnlistener_new_bind(base, clientcb, NULL, 0,
						LEV_OPT_REUSEABLE, &sin, sizeof(sin));
		event_base_dispatch(base);
		return 0;
	}

	url = url_tokenize(argv[1]);
	if (!url)
		return 0;

	if (url->port < 0)
		url->port = 80;

	dns = evdns_base_new(base, 1);

	http = http_conn_new(base, -1, HTTP_SERVER, &test_proxy_cbs, url);
	http_conn_connect(http, dns, AF_UNSPEC, url->host, url->port);

	event_base_dispatch(base);

	return 0;
}

#endif
