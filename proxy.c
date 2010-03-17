#include <sys/queue.h>
#include <event2/event.h>
#include <event2/listener.h>
#include "proxy.h"
#include "httpconn.h"

enum server_state {
	SERVER_STATE_IDLE,
	SERVER_STATE_CONNECTING,
	SERVER_STATE_CONNECTED
};

struct client {
	struct http_request_list requests;
	size_t nrequests;
	struct http_conn *conn;
};

struct server {
	TAILQ_ENTRY(server) next;
	enum server_state state;
	struct http_conn *conn;
};
TAILQ_HEAD(server_list, server);

static void client_error(struct http_conn *, enum http_conn_error, void *);
static void client_request(struct http_conn *, struct http_request *, void *);
static void client_read_body(struct http_conn *, struct evbuffer *, void *);
static void client_msg_complete(struct http_conn *, void *);
static void client_write_more(struct http_conn *, void *);

static void server_error(struct http_conn *, enum http_conn_error, void *);
static void server_response(struct http_conn *, struct http_response *, void *);
static void server_read_body(struct http_conn *, struct evbuffer *, void *);
static void server_msg_complete(struct http_conn *, void *);
static void server_write_more(struct http_conn *, void *);

static const struct http_cbs client_methods = {
	client_error,
	client_request,
	0,
	client_read_body,
	client_msg_complete,
	client_write_more
};

static const struct http_cbs server_methods = {
	server_error,
	0,
	server_response,
	server_read_body,
	server_msg_complete,
	server_write_more
};

static struct evconnlistener *listener = NULL;
static struct server_list servers;
static size_t max_pending_requests = 8;

static struct client *
client_new(struct event_base *base, evutil_socket_t sock)
{
	struct client *client;

	client = mem_calloc(1, sizeof(*client));
	TAILQ_INIT(&client->requests);
	client->conn = http_conn_new(base, sock, HTTP_CLIENT,
				&client_methods, client);

	return client;
}

static struct server *
server_new(struct event_base *base, evutil_socket_t sock)
{
	struct server *server;

	server = mem_calloc(1, sizeof(*server));
	server->conn = http_conn_new(base, sock, HTTP_SERVER,
				&server_methods, server);

	return server;
}

static void
client_error(struct http_conn *conn, enum http_conn_error err, void *arg)
{
}

static void
client_request(struct http_conn *conn, struct http_request *req, void *arg)
{
	struct client *client = arg;

	// - translate proxy request into a server request
	// - if the proxy request doesn't include a scheme and host,
	//   probably reject with 404 not found
	// - add the request to the request queue
	// - if nrequests >= max_pending_requests OR the request has a msg body
	//   coming, stop reading from the conn for now

	TAILQ_INSERT_TAIL(&client->requests, req, next);
	
	if (++client->nrequests >= max_pending_requests ||
	    http_conn_current_message_has_body(conn))
		http_conn_stop_reading(conn);

	// TODO
}

static void
client_read_body(struct http_conn *conn, struct evbuffer *buf, void *arg)
{
}

static void
client_msg_complete(struct http_conn *conn, void *arg)
{
}

static void
client_write_more(struct http_conn *conn, void *arg)
{
}

static void
server_error(struct http_conn *conn, enum http_conn_error err, void *arg)
{
}

static void
server_response(struct http_conn *conn, struct http_response *req, void *arg)
{
}

static void
server_read_body(struct http_conn *conn, struct evbuffer *buf, void *arg)
{
}

static void
server_msg_complete(struct http_conn *conn, void *arg)
{
}

static void
server_write_more(struct http_conn *conn, void *arg)
{
}
