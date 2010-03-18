#include <sys/queue.h>
#include <event2/event.h>
#include <event2/listener.h>
#include "proxy.h"
#include "httpconn.h"

enum server_state {
	SERVER_STATE_INITIAL,
	SERVER_STATE_CONNECTING,
	SERVER_STATE_CONNECTED,
	SERVER_STATE_PIPELINE_PROBE,
	SERVER_STATE_PIPELINE_NONE,
	SERVER_STATE_PIPELINE_OK,
	SERVER_STATE_IDLE
};

struct server {
	TAILQ_ENTRY(server) next;
	enum server_state state;
	char *host;
	int port;
	struct http_conn *conn;
	struct client *client;
};
TAILQ_HEAD(server_list, server);

struct client {
	struct server_list requests;
	size_t nrequests;
	struct http_conn *conn;
	struct server *active;
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
	on_client_write_more
};

static const struct http_cbs server_methods = {
	on_server_connected,
	on_server_error,
	0,
	on_server_response,
	on_server_read_body,
	on_server_msg_complete,
	on_server_write_more
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

static int
server_connect(struct server *server)
{
	server->state = SERVER_STATE_CONNECTING;
	return http_conn_connect(server->conn, proxy_evdns_base, AF_UNSPEC,
				 server->host, server->port);
}

static void
server_write_requests(struct server *server, struct http_request_list *reqs)
{
	struct http_request *req;

	if (server->state == SERVER_STATE_PIPELINE_PROBE ||
	    server->state < SERVER_STATE_CONNECTED)
		return;
	
	TAILQ_FOREACH(req, reqs, next) {
		if (evutil_ascii_strcasecmp(server->host, req->url->host) ||
		    server->port != req->url->port)
			break;
		
		http_conn_write_request(server->conn, req);
		if (server->state == SERVER_STATE_CONNECTED) {
			/* we'll need to wait for the response to see if we can
 			   reuse this connection. */
			server->state = SERVER_STATE_PIPELINE_PROBE;
			return;
		}
	}
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

static int
client_scrub_request(struct client *client, struct http_request *req)
{
	// prune headers; verify that req contains a host to connect to
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
client_request_serviced(struct client *client)
{
	struct http_request *req;

	assert(client->nrequests > 0)

	// - pop the first req on our req list
	// - if we've stopped reading, start again:
	// 	* if we're going to read a message body wait until theres only one pending request
	// 	* otherwise we can just start accepting more reqs
	//
	
	req = TAILQ_FIRST(&client->requests);
	TAILQ_REMOVE(&client->requests, req, next);
	http_request_free(req);
	client->nrequests--;

	if (!http_conn_current_message_has_body(client->conn) ||
	    client->nrequests == 1)
		http_conn_start_reading(client->conn);
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

	if (client_scrub_request(client, req) < 0)
		return;

	TAILQ_INSERT_TAIL(&client->requests, req, next);
	if (++client->nrequests > max_pending_requests ||
	    http_conn_current_message_has_body(conn))
		http_conn_stop_reading(conn); // XXX when to start reading again?

	if (!client->server && client_associate_server(client, req->url) < 0)
		return;

	server_write_requests(client->server, &client->requests);
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
on_server_connected(struct http_conn *conn, void *arg)
{
	struct server *server = arg;

	assert(server->state == SERVER_STATE_CONNECTING);
	server->state = SERVER_STATE_CONNECTED;
	server_write_requests(server, &server->client->requests);
}

static void
on_server_error(struct http_conn *conn, enum http_conn_error err, void *arg)
{
	struct server *server = arg;

	switch (server->state) {
	case SERVER_STATE_CONNECTING:
	case SERVER_STATE_CONNECTED:
		// XXX perhaps auto retry connection failures??
	case SERVER_STATE_PIPELINE_PROBE:
	case SERVER_STATE_PIPELINE_NONE:
	case SERVER_STATE_PIPELINE_OK:
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

	// XXX free server
}

static void
on_server_response(struct http_conn *conn, struct http_response *req, void *arg)
{
	// tell if this server can do pipelining. if the connection only
	// supports one request, then we'll have to remove it once it's complete.
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
