
#include <sys/queue.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <event2/util.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include "httpconn.h"
#include "headers.h"
#include "util.h"

#define METHOD0(conn, slot) \
	(conn)->cbs.slot((conn), (conn)->cbarg)
#define METHOD1(conn, slot, a) \
	(conn)->cbs.slot((conn), (a), (conn)->cbarg)
#define METHOD2(conn, slot, a, b) \
	(conn)->cbs.slot((conn), (a), (b), (conn)->cbarg)
#define METHOD3(conn, slot, a, b, c) \
	(conn)->cbs.slot((conn), (a), (b), (c), (conn)->cbarg)
#define METHOD4(conn, slot, a, b, c, d) \
	(conn)->cbs.slot((conn), (a), (b), (c), (d), (conn)->cbarg)

/* max amount of data we can have backlogged on outbuf before choaking */
static size_t max_write_backlog = 50 * 1024;

/* the number of seconds to keep an idle connections hanging around */
static int idle_client_timeout = 120;
static int idle_server_timeout = 120;

struct http_conn {
	enum http_state state;
	enum http_version vers;
	enum http_te te;
	enum http_type type;
	int is_choaked;
	int has_body;
	int msg_complete_on_eof;
	int keepalive;
	struct http_cbs cbs;
	void *cbarg;
	ev_int64_t data_remaining;
	char *firstline;
	struct header_list *headers;
	struct bufferevent *bev;
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

static const char *
method_to_string(enum http_method m)
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

	log_fatal("method_to_string: unknown method %d", m);
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

static const char *
version_to_string(enum http_version v)
{
	switch (v) {
	case HTTP_UNKNOWN:
		return "HTTP/??";
	case HTTP_10:
		return "HTTP/1.0";
	case HTTP_11:
		return "HTTP/1.1";
	}
	
	log_fatal("version_to_string: unknown version %d", v);
	return "???";
}

static void
begin_input(struct http_conn *conn)
{
	// XXX read timeout?
	assert(conn->headers == NULL && conn->firstline == NULL);
	conn->headers = mem_calloc(1, sizeof(*conn->headers));
	TAILQ_INIT(conn->headers);
	conn->state = STATE_IDLE;
	bufferevent_enable(conn->bev, EV_WRITE | EV_READ);
}

static void
end_input(struct http_conn *conn, enum http_conn_error err)
{
	if (conn->firstline)
		mem_free(conn->firstline);
	if (conn->headers)
		headers_clear(conn->headers);

	if (err != ERROR_NONE || !conn->keepalive) {
		conn->state = STATE_MANGLED;
		bufferevent_disable(conn->bev, EV_WRITE | EV_READ);
	} else
		begin_input(conn);

	if (err != ERROR_NONE)
		METHOD1(conn, on_error, err);
	else
		METHOD0(conn, on_msg_complete);
}

static struct http_request *
build_request(struct http_conn *conn)
{
	struct http_request *req;
	struct token_list tokens;
	struct token *method, *uri, *vers;
	enum http_method m;
	enum http_version v;
	size_t ntokens;

	assert(conn->type == HTTP_CLIENT);

	TAILQ_INIT(&tokens);
	req = NULL;

	ntokens = tokenize(conn->firstline, " ", 4, &tokens);
	if (ntokens != 3)
		goto out;

	method = TAILQ_FIRST(&tokens);
	uri = TAILQ_NEXT(method, next);	
	vers = TAILQ_NEXT(uri, next);	

	if (method_from_string(&m, method->token) < 0 ||
            version_from_string(&v, vers->token) < 0)
		goto out;

	req = mem_calloc(1, sizeof(*req));
	req->meth = m;
	req->vers = v;
	req->uri = uri->token;
	uri->token = NULL; /* so free_token_list will skip this */
	req->headers = conn->headers;

out:
	free_token_list(&tokens);
	
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
	reason->token = NULL; /* so free_token_list will skip this */
	resp->headers = conn->headers;

out:
	free_token_list(&tokens);
	
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

		len = parse_int(line, 16);
		if (len < 0) {
			mem_free(line);
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

	while ((len = evbuffer_get_length(inbuf))) {
		if (conn->data_remaining < 0) {
			switch (parse_chunk_len(conn)) {
			case -1:
				end_input(conn, ERROR_CHUNK_PARSE_FAILED);
				return;
			case 0:
				return;	
			/* case 1: finished, fall thru */
			}

			/* XXX doesn't handle trailers */
			/* are we done yet? */
			if (conn->data_remaining == 0) {
				end_input(conn, ERROR_NONE);
				return;
			}
			continue;
		}

		/* XXX should mind potential overflow */
		if (len >= (size_t)conn->data_remaining) {
			len = (size_t)conn->data_remaining;
			conn->data_remaining = -1;
		}

		evbuffer_remove_buffer(inbuf, conn->inbuf_processed, len);
		METHOD1(conn, on_read_body, conn->inbuf_processed);
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
			evbuffer_remove_buffer(inbuf, conn->inbuf_processed, len);
			METHOD1(conn, on_read_body, conn->inbuf_processed);
		} else {
			evbuffer_add_buffer(conn->inbuf_processed, inbuf);
			METHOD1(conn, on_read_body, conn->inbuf_processed);
		}

		conn->data_remaining -= len;
		if (conn->data_remaining == 0)
			end_input(conn, ERROR_NONE);
	}
}

static void
check_headers(struct http_conn *conn, struct http_request *req,
	   struct http_response *resp)
{
	enum http_version vers;
	int keepalive;
	char *val;
	
	assert(req);
	assert(conn->type != HTTP_SERVER || resp);

	conn->te = TE_IDENTITY;
	conn->has_body = 1;
	conn->msg_complete_on_eof = 0;
	conn->data_remaining = -1;

	if (req->meth == METH_HEAD)
		conn->has_body = 0;

	if (conn->type == HTTP_CLIENT) {
		vers = req->vers;
		conn->has_body = 0;
		if (req->meth == METH_POST ||
		    req->meth == METH_PUT)
			conn->has_body = 1;
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
				iv = parse_int(val, 10);
				if (iv < 0)
					log_warn("http_conn: mangled Content-Length");
				else
					conn->data_remaining = iv;
				mem_free(val);
			} else {
				conn->msg_complete_on_eof = 1;
			}
		}

		if (conn->type == HTTP_CLIENT && conn->data_remaining < 0
		    && conn->te != TE_CHUNKED) {
			METHOD1(conn, on_error,
				ERROR_CLIENT_POST_WITHOUT_LENGTH);
			return;
		}
	}

	assert(vers != HTTP_UNKNOWN);

	keepalive = 0;
	if (!conn->msg_complete_on_eof && vers == HTTP_11)
		keepalive = 1;

	if (conn->vers != HTTP_UNKNOWN && conn->vers != vers) {
		log_warn("http_conn: http version changed!");
		keepalive = 0;
	}
	conn->vers = vers;

	if (keepalive) {
		val = headers_find(conn->headers, "connection");
		if (val) {
			if (evutil_ascii_strcasecmp(val, "close"))
				keepalive = 0;
			mem_free(val);
		}
	}
	conn->keepalive = keepalive;
}

static void
parse_headers(struct http_conn *conn)
{
	int failed = 0;
	struct evbuffer *inbuf = bufferevent_get_input(conn->bev);
	struct http_request *req = NULL;
	struct http_response *resp = NULL;

	assert(conn->state == STATE_READ_HEADERS);

	switch (headers_parse(conn->headers, inbuf)) {
	case -1:
		conn->state = STATE_MANGLED;
		METHOD1(conn, on_error, ERROR_HEADER_PARSE_FAILED);
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
		end_input(conn, ERROR_HEADER_PARSE_FAILED);
		return;
	}

	check_headers(conn, req, resp);
	conn->headers = NULL;

	/* ownership of req or resp is now passed on */
	if (req)
		METHOD1(conn, on_client_request, req);
	if (resp)
		METHOD1(conn, on_server_response, resp);

	if (conn->has_body) {
		conn->state = STATE_READ_BODY;
		read_body(conn);
	} else {
		end_input(conn, ERROR_NONE);
	}
}

static void
http_errorcb(struct bufferevent *bev, short what, void *_conn)
{
	enum http_state state;
	struct http_conn *conn = _conn;

	assert(!(what & BEV_EVENT_CONNECTED));
	
	state = conn->state;
	conn->state = STATE_MANGLED;

	if (what & BEV_EVENT_WRITING) {
		end_input(conn, ERROR_WRITE_FAILED);
		return;
	}
	
	switch (state) {
	case STATE_IDLE:
		end_input(conn, ERROR_IDLE_CONN_TIMEDOUT);
		break;
	case STATE_READ_FIRSTLINE:
	case STATE_READ_HEADERS:
		end_input(conn, ERROR_INCOMPLETE_HEADERS);
		break;
	case STATE_READ_BODY:
		if ((what & BEV_EVENT_EOF) && conn->msg_complete_on_eof)
			end_input(conn, ERROR_NONE);
		else
			end_input(conn, ERROR_INCOMPLETE_BODY);
		break;
	default:
		log_fatal("http_conn: errorcb called in invalid state");
	}
}

static void
http_readcb(struct bufferevent *bev, void *_conn)
{
	struct http_conn *conn = _conn;
	struct evbuffer *inbuf = bufferevent_get_input(bev);

	switch (conn->state) {
	case STATE_IDLE:
		conn->state = STATE_READ_FIRSTLINE;		
		/* fallthru... */
	case STATE_READ_FIRSTLINE:
		assert(conn->firstline == NULL);
		conn->firstline = evbuffer_readln(inbuf, NULL, EVBUFFER_EOL_CRLF);
		if (conn->firstline) {
			conn->state = STATE_READ_HEADERS;
			parse_headers(conn);
		}
		break;	
	case STATE_READ_HEADERS:
		parse_headers(conn);
		break;
	case STATE_READ_BODY:
		read_body(conn);
		break;
	default:
		log_fatal("http_conn: read cb called in invalid state");	
	}
}

static void
http_writecb(struct bufferevent *bev, void *_conn)
{
	struct http_conn *conn = _conn;

	if (conn->is_choaked) {
		bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
		conn->is_choaked = 0;
		METHOD0(conn, on_write_more);
	}
}

struct http_conn *
http_conn_new(struct event_base *base, evutil_socket_t sock,
	      enum http_type type, struct http_cbs *cbs, void *cbarg)
{
	struct http_conn *conn;

	conn = mem_calloc(1, sizeof(*conn));
	conn->type = type;
	// XXX if cbs contains null cbs, we should add reasonable defaults
	memcpy(&conn->cbs, cbs, sizeof(*cbs));
	conn->bev = bufferevent_socket_new(base, sock,
			BEV_OPT_CLOSE_ON_FREE);
	if (!conn->bev)
		log_fatal("http_conn: failed to create bufferevent");

	conn->inbuf_processed = evbuffer_new();
	if (!conn->inbuf_processed)
		log_fatal("http_conn: failed to create evbuffer");

	bufferevent_setcb(conn->bev, http_readcb, http_writecb,
		          http_errorcb, conn);

	begin_input(conn);

	return conn;
}

void
http_conn_free(struct http_conn *conn)
{
	bufferevent_free(conn->bev);
	evbuffer_free(conn->inbuf_processed);
	mem_free(conn);
}

void
http_conn_write_response(struct http_conn *conn, struct http_response *resp)
{
	struct evbuffer *outbuf;

	// XXX note the TE of resp

	outbuf = bufferevent_get_output(conn->bev);

	evbuffer_add_printf(outbuf, "%s %d %s\r\n",
		        version_to_string(conn->vers),
			resp->code,
			resp->reason);
		
	headers_dump(resp->headers, outbuf);	
}

int
http_conn_write_buf(struct http_conn *conn, struct evbuffer *buf)
{
	struct evbuffer *outbuf;
	
	// XXX translate input to chunked format if needed

	outbuf = bufferevent_get_output(conn->bev);

	evbuffer_add_buffer(outbuf, buf);

	/* have we choaked? */	
	if (evbuffer_get_length(outbuf) > max_write_backlog) {
		bufferevent_setwatermark(conn->bev, EV_WRITE,
					 max_write_backlog / 2, 0);
		conn->is_choaked = 1;
		return 0;
	}

	return 1;
}

int
http_conn_has_body(struct http_conn *conn)
{
	return conn->has_body;
}

#ifdef TEST_HTTP
#include <netinet/in.h>
#include <stdio.h>
#include <event2/listener.h>

static void
proxy_error(struct http_conn *conn, enum http_conn_error err, void *arg)
{
	fprintf(stderr, "error %d\n", err);
}

static void
proxy_client_request(struct http_conn *conn, struct http_request *req, void *arg)
{
	struct evbuffer *buf;

	//XXX need a way to free req
	fprintf(stderr, "new request: %s, %s, %s\n",
		method_to_string(req->meth),
		req->uri,
		version_to_string(req->vers));

	buf = evbuffer_new();
	headers_dump(req->headers, buf);
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

static struct http_cbs test_proxy_client_cbs = {
	proxy_error,
	proxy_client_request,
	0,
	proxy_read_body,
	proxy_msg_complete,
	proxy_write_more
};

static void
accept_cb(struct evconnlistener *listener, evutil_socket_t sock,
	  struct sockaddr *addr, int socklen, void *arg)
{
	struct http_conn *conn;

	conn = http_conn_new(evconnlistener_get_base(listener), sock,
			     HTTP_CLIENT, &test_proxy_client_cbs, NULL);
}

int
main()
{
	struct sockaddr_in sin;
	struct event_base *base;
	struct evconnlistener *listener;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(8080);

	base = event_base_new();
	listener = evconnlistener_new_bind(base, accept_cb, NULL,
			LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
			-1, (struct sockaddr *)&sin, sizeof(sin));

	event_base_dispatch(base);

	return 0;
}

#endif
