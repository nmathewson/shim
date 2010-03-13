
#include <sys/queue.h>
#include <event2/util.h>

#include "httpconn.h"
#include "headers.h"

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
	struct http_cbs cbs;
	ev_int64_t body_total;
	ev_int64_t body_transfered;
	char *firstline;
	struct header_list *headers;
	struct bufferevent *bev;
};

static int
method_from_string(enum http_method *m, const char *method)
{
	if (!evutil_ascii_strncasecmp(method, "GET"))
		*m = METH_GET;
	else if (!evutil_ascii_strncasecmp(method, "HEAD"))
		*m = METH_HEAD;
	else if (!evutil_ascii_strncasecmp(method, "POST"))
		*m = METH_POST;
	else if (!evutil_ascii_strncasecmp(method, "PUT"))
		*m = METH_PUT;
	else if (!evutil_ascii_strncasecmp(method, "CONNECT"))
		*m = METH_CONNECT:
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
		return "PUT;
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

	/* XXX this only understand 1.0 and 1.1 */

	if (!evutil_ascii_strcmp(vers, "1.0"))
		*v = HTTP_10;
	else if (!evutil_ascii_strcmp(vers, "1.1"))
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
	case HTTP_10:
		return "HTTP/1.0";
	case HTTP_11:
		return "HTTP/1.1";
	}
	
	log_fatal("version_to_string: unknown version %d", v);
	return "???";
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

	assert(conn->type = HTTP_CLIENT);

	TAILQ_INIT(&tokens);
	req = NULL;

	ntokens = tokenize(conn->firstline, ' ', 4, &tokens);
	if (ntokens != 3)
		goto out;

	method = TAILQ_FIRST(&tokens);
	uri = TAILQ_NEXT(method, next);	
	vers = TAILQ_NEXT(uri, next);	

	if (method_from_str(&m, method->token) < 0 ||
            version_from_str(&v, vers->token) < 0)
		goto out;

	req = mem_calloc(1, sizeof(*req));
	req->meth = m;
	req->vers = v;
	req->uri = uri->token;
	uri->token = NULL; /* so free_token_list will skip this */
	req->headers = conn->headers;
	conn->headers = NULL;

out:
	free_token_list(&tokens);
	if (!req)
		conn->cbs.on_error(conn, ERROR_HEADER_PARSE_FAILED);
	
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

	assert(conn->type = HTTP_SERVER);

	TAILQ_INIT(&tokens);
	resp = NULL;

	ntokens = tokenize(conn->firstline, ' ', 2, &tokens);
	if (ntokens != 3)
		goto out;

	vers = TAILQ_FIRST(&tokens);
	code = TAILQ_NEXT(vers, next);
	reason = TAILQ_NEXT(code, next);
	c = atoi(code->token);

        if (version_from_str(&v, vers->token) < 0 || c < 100 || c > 999)
		goto out;

	resp = mem_calloc(1, sizeof(*resp));
	resp->vers = v;
	resp->code = c;
	resp->reason = reason->token;
	reason->token = NULL; /* so free_token_list will skip this */
	resp->headers = conn->headers;
	conn->headers = NULL;

out:
	free_token_list(&tokens);
	if (!resp)
		conn->cbs.on_error(conn, ERROR_HEADER_PARSE_FAILED);
	
	return resp;
}

static void
read_body(struct http_conn *conn)
{
}

static void
parse_headers(struct http_conn *conn)
{
	// first line is different depending on whether we're the client
	// or the server. for client it should be a request... for server,
	// it should be a status line.
	struct evbuffer *inbuf = bufferevent_get_input(conn->bev);

	assert(conn->state == STATE_READ_HEADERS);

	switch (headers_parse(conn->headers, inbuf)) {
	case -1:
		if (conn->cbs.on_error)
			conn->cbs.on_error(conn, ERROR_HEADER_PARSE_FAILED);
		break;
	case 1:
		assert(conn->firstline);
		
		if (conn->type == HTTP_CLIENT) {
			struct http_request *req = build_request(conn);
			if (req)
				conn->cbs.on_client_request(conn, req);
		 } else {
			struct http_response *resp = build_response(conn);
			if (resp)
				conn->cbs.on_server_response(conn, resp);
		}

		mem_free(conn->firstline);
		conn->firstline = NULL;
		conn->headers = NULL;

		// XXX need to determine bodylen
		conn->state = STATE_READ_BODY;
		read_body(conn);
		break;
	/* case 0: fall through */
	}
}

static void
http_errorcb(struct bufferevent *bev, short what, void *_conn)
{
	struct http_conn *conn = _conn;

}

static void
http_readcb(struct bufferevent *bev, void *_conn)
{
	struct http_conn *conn = _conn;
	struct evbuffer *inbuf = bufferevent_get_input(bev);
	char *line;

	switch (conn->state) {
	case STATE_IDLE:
		// XXX no good reason here if client? should be in err cb, rhgt?
		break;
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
		break;;
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
		if (conn->cbs.on_write_more)
			conn->cbs.on_write_more(conn);
	}
}

struct http_conn *
http_conn_new(struct event_base *base, evutil_socket_t sock,
	      enum http_type type, struct http_cbs *cbs)
{
	struct http_conn *conn;

	conn = mem_calloc(1, sizeof(*conn));
	conn->type = type;
	memcpy(conn->cbs, cbs, sizeof(*cbs));
	conn->bev = bufferevent_socket_new(base, sock,
			BEV_OPT_FREE_ON_CLOSE);

	if (!conn->bev)
		log_fatal("http_conn: failed to create bufferevent");

	bufferevent_setcb(conn->bev, http_readcb, http_writecb,
		          http_errorcb, conn);

	return conn;
}

void
http_conn_write_response(struct http_conn *conn, struct http_response *resp)
{
	struct evbuffer *outbuf;

	assert(conn->state == STATE_WRITE_RESPONSE);

	outbuf = bufferevent_get_output(conn->bev);

	evbuffer_add_printf(outbuf, "%s %d %s\r\n",
		        version_to_string(conn->vers),
			resp->code,
			resp->reason);
		
	headers_dump(resp->headers, outbuf);	

	conn->state = STATE_WRITE_BODY;
}

int
http_conn_write_buf(struct http_conn *conn, struct evbuffer *buf)
{
	struct evbuffer *outbuf;

	assert(conn->state == STATE_WRITE_BODY);

	outbuf = bufferevent_get_output(conn->bev);

	evbuffer_add_buffer(outbuf, buf);

	/* have we choaked? */	
	if (evbuffer_get_length(outbuf) >= max_write_backlog) {
		bufferevent_setwatermark(conn->bev, EV_WRITE,
					 max_write_backlog / 2, 0);
		conn->is_choaked = 1;
		return 0;
	}

	return 1;
}

void
http_conn_start_reading(struct http_conn *conn)
{
	bufferevent_enable(conn->bev, EV_READ);
}

void
http_conn_stop_reading(struct http_conn *conn)
{
	bufferevent_disable(conn->bev, EV_READ);
}
