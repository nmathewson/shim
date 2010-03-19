#include <sys/queue.h>
#include <event2/event.h>
#include <event2/listener.h>
#include "proxy.h"
#include "httpconn.h"

enum server_state {
	SERVER_STATE_INITIAL,
	SERVER_STATE_CONNECTING,
	SERVER_STATE_CONNECTED,
	SERVER_STATE_REQUEST_SENT,
	SERVER_STATE_IDLE
};

struct server {
	TAILQ_ENTRY(server) next;
	enum server_state state;
	size_t nserviced;
	char *host;
	int port;
	struct http_conn *conn;
	struct client *client;
};
TAILQ_HEAD(server_list, server);

enum client_state {
	CLIENT_STATE_ACTIVE,
	CLIENT_STATE_CLOSING
};

struct client {
	enum client_state state;
	struct server_list requests;
	size_t nrequests;
	struct http_conn *conn;
	struct server *server;
};

static void on_client_error(struct http_conn *, enum http_conn_error, void *);
static void on_client_request(struct http_conn *, struct http_request *, void *);
static void on_client_read_body(struct http_conn *, struct evbuffer *, void *);
static void on_client_msg_complete(struct http_conn *, void *);
static void on_client_write_more(struct http_conn *, void *);

static void on_server_connected(struct http_conn *, void *);
static void on_server_error(struct http_conn *, enum http_conn_error, void *);
static void on_server_response(struct http_conn *, struct http_response *, void *);
static void on_server_read_body(struct http_conn *, struct evbuffer *, void *);
static void on_server_msg_complete(struct http_conn *, void *);
static void on_server_write_more(struct http_conn *, void *);

static const struct http_cbs client_methods = {
	0,
	on_client_error,
	on_client_request,
	0,
	on_client_read_body,
	on_client_msg_complete,
	on_client_write_more,
	on_client_flush
};

static const struct http_cbs server_methods = {
	on_server_connected,
	on_server_error,
	0,
	on_server_response,
	on_server_read_body,
	on_server_msg_complete,
	on_server_write_more,
	on_server_flush
};

static struct event_base *proxy_event_base;
static struct evdns_base *proxy_evdns_base;
static struct evconnlistener *listener = NULL;
static struct server_list idle_servers = TAILQ_HEAD_INITIALIZER(&idle_servers);
static size_t max_pending_requests = 8;

static struct server *
server_new(const char *host, int port)
{
	struct server *server;

	server = mem_calloc(1, sizeof(*server));
	server->host = mem_strdup(host);
	server->port = port;
	server->conn = http_conn_new(proxy_event_base, -1, HTTP_SERVER,
				&server_methods, server);

	return server;
}

static void
server_free(struct server *server)
{
	if (!server)
		return;

	mem_free(server->host);
	http_conn_free(server->conn);
	mem_free(server);
}

static int
server_connect(struct server *server)
{
	server->state = SERVER_STATE_CONNECTING;
	return http_conn_connect(server->conn, proxy_evdns_base, AF_UNSPEC,
				 server->host, server->port);
}

static int
server_write_client_request(struct server *server)
{
	struct http_request *req;

	req = TAILQ_FIRST(&server->client->requests);
	
	if (!req || server->state == SERVER_STATE_REQUEST_SENT ||
	    server->state < SERVER_STATE_CONNECTED)
		return 0;

	/* it might be nice to support pipelining... */
	if (!evutil_ascii_strcasecmp(server->host, req->url->host) &&
	    server->port == req->url->port) {
		http_conn_write_request(server->conn, req);
		server->state = SERVER_STATE_REQUEST_SENT;
		return 1;
	}

	return 0;
}

static struct client *
client_new(evutil_socket_t sock)
{
	struct client *client;

	client = mem_calloc(1, sizeof(*client));
	TAILQ_INIT(&client->requests);
	client->conn = http_conn_new(proxy_event_base, sock, HTTP_CLIENT,
				&client_methods, client);

	return client;
}

static void
client_free(struct client *client)
{
	struct http_request *req;

	if (!client)
		return;

	while ((req = TAILQ_FIRST(&client->requests))) {
		TAILQ_REMOVE(req, &client->requests, next);
		http_request_free(req);
	}

	server_free(client->server);
	http_conn_free(client->conn);
	mem_free(client);
}

static int
client_scrub_request(struct client *client, struct http_request *req)
{
	// prune headers; verify that req contains a host to connect to
	// XXX remove proxy auth msgs?
	
	if (!req->url->host) {
		http_conn_send_error(client->conn, 401);
		goto fail;
	}
	if (evutil_ascii_strcasecmp(req->url->scheme, "http")) {
		http_conn_send_error(client->conn, 400);
		goto fail;
	}

	if (req->url->port < 0)
		req->url->port = 80;

	headers_remove(req->headers, "connection");

	return 0;

fail:
	http_request_free(req);
	return -1;
}

static int
client_scrub_response(struct client *client, struct http_response *resp)
{
	headers_remove(req->headers, "connection");
}

static int
client_associate_server(struct client *client, const struct url *url)
{
	struct server *it;

	assert(client->server == NULL);
	assert(url->host != NULL && url->port > 0);

	/* try to find an idle server */
	TAILQ_FOREACH(it, &idle_servers, next) {
		if (!evutil_ascii_strcasecmp(it->host, url->host) &&
		    it->port == url->port) {
			TAILQ_REMOVE(&idle_servers, it, next);
			client->server = it;
			return 0;
		}
	}

	/* we didn't find one. lets setup a new one. */
	client->server = server_new(url->host, url->port);
	server->client = client;

	return server_connect(client->server);	
}

static void
client_start_reading_request_body(struct client *client)
{
	if (http_conn_current_message_has_body(client->conn) &&
	    client->nrequests == 1)
		http_conn_start_reading(client->conn);
}

static void
client_request_serviced(struct client *client)
{
	struct http_request *req;

	assert(client->nrequests > 0)

	// - pop the first req on our req list
	// - if the server's connection isn't persistent, we should terminate the server connection.
	// - if the client's connection isn't persistent, we should terminate the client connection.
	// - if we expect more reqs on the client connection, start reading again in case we stopped
	//   earlier.
	
	req = TAILQ_FIRST(&client->requests);
	TAILQ_REMOVE(&client->requests, req, next);
	http_request_free(req);
	client->nrequests--;

	/* let's try to reuse this server connection */
	if (http_conn_is_persistent(client->server->conn)) {
		if (!server_write_client_request(client->server)) {
			client->server->state = SERVER_STATE_IDLE;
			TAILQ_INSERT_TAIL(&idle_servers, client->server, next);
			client->server->client = NULL;
			client->server = NULL;
		}
	} else {
		server_free(client->server);
		client->server = NULL;
	}

	if (!http_conn_is_persistent(client->conn)) {
		// XXX maybe shutdown the socket?
		client->state = STATE_CLIENT_CLOSING;
		http_conn_stop_reading(client->conn);
		http_conn_flush(client->conn);
	} else if (!http_conn_current_message_has_body(client->conn) &&
		   client->nrequests < max_pending_requests) {
		http_conn_start_reading(client->conn);
	}
}

static void
client_notice_server_failed(struct client *client)
{
	// respond with proxy errors for all pending reqs for our active server
}

/* http event slots */

static void
on_client_error(struct http_conn *conn, enum http_conn_error err, void *arg)
{
	// what can we do here?
	log_warn("proxy: client connection failed.");
	client_free(arg);
}

static void
on_client_request(struct http_conn *conn, struct http_request *req, void *arg)
{
	struct client *client = arg;

	// - translate proxy request into a server request
	// - if the proxy request doesn't include a scheme and host,
	//   probably reject with 404 not found
	// - create a new transaction for this request
	// - if npending >= max_pending_requests OR the request has a msg body
	//   coming, stop reading from the conn for now
	// - if client has no active server, connect or reuse an idle one
	// - if the active server is for the same address and port as the request,
	//   and the server is known to support pipelining, write the request to
	//   the server

	assert(client->state == CLIENT_STATE_ACTIVE);

	if (client_scrub_request(client, req) < 0)
		return;

	TAILQ_INSERT_TAIL(&client->requests, req, next);
	if (++client->nrequests > max_pending_requests ||
	    http_conn_current_message_has_body(conn))
		http_conn_stop_reading(conn);

	if (!client->server && client_associate_server(client, req->url) < 0)
		return;

	server_write_client_request(client->server);
}

static void
on_client_read_body(struct http_conn *conn, struct evbuffer *buf, void *arg)
{
	struct client *client = arg;
	
	if (!http_conn_write_buf(client->server->conn, buf))
		http_conn_stop_reading(conn);
}

static void
on_client_msg_complete(struct http_conn *conn, void *arg)
{
	// XXX not much to do here?
}

static void
on_client_write_more(struct http_conn *conn, void *arg)
{
	struct client *client = arg;

	http_conn_start_reading(client->server->conn);
}

static void
on_client_flush(struct http_conn *conn, void *arg)
{
	struct client *client = arg;

	// XXX perhaps delay before closing?
	if (client->state == CLIENT_STATE_CLOSING)
		client_free(client);
}

static void
on_server_connected(struct http_conn *conn, void *arg)
{
	struct server *server = arg;

	assert(server->state == SERVER_STATE_CONNECTING);
	server->state = SERVER_STATE_CONNECTED;
	server_write_client_request(server);
}

static void
on_server_error(struct http_conn *conn, enum http_conn_error err, void *arg)
{
	struct server *server = arg;

	switch (server->state) {
	case SERVER_STATE_CONNECTING:
	case SERVER_STATE_CONNECTED:
	case SERVER_STATE_REQUEST_SENT:
		// XXX if we haven't serviced any reqs on this server yet,
		//     we should try resending the first request
		assert(server->client != NULL);
		client_notice_server_failed(server->client);
		break;
	case SERVER_STATE_IDLE:
		assert(server->client == NULL);
		TAILQ_REMOVE(&idle_servers, server, next);
		break;
	default:
		log_fatal("server: error cb called in invalid state");
	}

	server_free(server);
}

static void
on_server_response(struct http_conn *conn, struct http_response *resp, void *arg)
{
	struct server *server = arg;
	
	// XXX anything we need to do scrub this response?
	http_conn_write_response(server->client->conn, resp);
	// XXX maybe not read body on error?
	// XXX handle expect 100-continue, etc
	client_start_reading_body(server->client);
}

static void
on_server_read_body(struct http_conn *conn, struct evbuffer *buf, void *arg)
{
	struct server *server = arg;

	if (!http_conn_write_buf(server->client->conn, buf))
		http_conn_stop_reading(conn);
}

static void
on_server_msg_complete(struct http_conn *conn, void *arg)
{
	struct server *server = arg;

	client_request_serviced(server->client);
}

static void
on_server_write_more(struct http_conn *conn, void *arg)
{
	struct server *server = arg;

	http_conn_start_reading(server->client->conn);
}

static void
on_server_flush(struct http_conn *conn, void *arg)
{
}

static void
client_accept(struct evconnlistener *ecs, evutil_socket_t s,
	      struct sockaddr *addr, int len, void *arg) 
{
	struct client *client;

	client = client_new(s);
	// XXX do we want to keep track of the client obj somehow?
}

/* public API */

void
proxy_client_set_max_pending_requests(size_t nreqs)
{
	max_pending_requests = nreqs;
}

size_t
proxy_client_get_max_pending_requests(void)
{
	return max_pending_requests;
}

int
proxy_init(const struct sockaddr *listen_here, int socklen)
{
	struct evconlistener *lcs = NULL;
	struct event_base *base = NULL;
	struct evdns_base *dns = NULL;

	base = event_base_new();
	if (!base)
		goto fail;

	dns = evdns_base_new(base, 1);
	if (!dns)
		goto fail;

	lcs = evconnlistener_new_bind(base, client_accept, NULL, CLOSE_ON_FREE,
					-1, listen_here, len);

	if (!lcs) {
		log_error("proxy: couldn't listen on %s: %s",
			  format_addr(listen_here),
			  socket_error_string(-1));
		goto fail;
	}
	
	listener = lcs;
	proxy_event_base = base;
	proxy_evdns_base = dns;	

	return 0;

fail:
	if (ecs)
		evconlistener_free(ecs);
	if (dns)
		evdns_base_free(dns, 0);
	if (base)
		event_base_free(base);

	return -1;
}

void
proxy_cleanup(void)
{
	// TODO
}
