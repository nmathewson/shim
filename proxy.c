#include <sys/queue.h>
#include <assert.h>
#include <string.h>
#include <event2/event.h>
#include <event2/listener.h>
#include "proxy.h"
#include "httpconn.h"
#include "util.h"
#include "headers.h"
#include "log.h"

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
	CLIENT_STATE_TUNNEL,
	CLIENT_STATE_CLOSING
};

struct client {
	enum client_state state;
	struct http_request_list requests;
	size_t nrequests;
	struct http_conn *conn;
	struct server *server;
};

static void on_client_error(struct http_conn *, enum http_conn_error, void *);
static void on_client_request(struct http_conn *, struct http_request *, void *);
static void on_client_read_body(struct http_conn *, struct evbuffer *, void *);
static void on_client_msg_complete(struct http_conn *, void *);
static void on_client_write_more(struct http_conn *, void *);
static void on_client_flush(struct http_conn *, void *);

static void on_server_connected(struct http_conn *, void *);
static void on_server_error(struct http_conn *, enum http_conn_error, void *);
static void on_server_response(struct http_conn *, struct http_response *, void *);
static void on_server_read_body(struct http_conn *, struct evbuffer *, void *);
static void on_server_msg_complete(struct http_conn *, void *);
static void on_server_write_more(struct http_conn *, void *);
static void on_server_flush(struct http_conn *, void *);

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
static struct server_list idle_servers;
static size_t max_pending_requests = 8;

static struct server *
server_new(const char *host, int port, struct client *client)
{
	struct server *server;

	server = mem_calloc(1, sizeof(*server));
	server->host = mem_strdup(host);
	server->port = port;
	server->client = client;
	server->conn = http_conn_new(proxy_event_base, -1, HTTP_SERVER,
				&server_methods, server);
	log_debug("proxy: new server: %p, %s:%d",
		  server, server->host, server->port);

	return server;
}

static inline int
server_match(const struct server *server, const char *host, int port)
{
	return (!evutil_ascii_strcasecmp(server->host, host) &&
		server->port == port);
}

static void
server_free(struct server *server)
{
	struct server *tmp;

	if (!server)
		return;

	log_debug("proxy: freeing server: %p, %s:%d",
		  server, server->host, server->port);

	TAILQ_FOREACH(tmp, &idle_servers, next) {
		if (tmp == server)
			log_fatal("proxy: idle server %p still queued!",
				  server);
	}

	mem_free(server->host);
	http_conn_free(server->conn);
	mem_free(server);
}

static int
server_connect(struct server *server)
{
	server->state = SERVER_STATE_CONNECTING;
	log_debug("proxy: server %p, %s:%d connecting",
		  server, server->host, server->port);
	// XXX AF_UNSPEC seems to cause crashes w/ IPv6 queries
	return http_conn_connect(server->conn, proxy_evdns_base, AF_INET,
				 server->host, server->port);
}

static struct client *
client_new(evutil_socket_t sock)
{
	struct client *client;

	client = mem_calloc(1, sizeof(*client));
	TAILQ_INIT(&client->requests);
	client->conn = http_conn_new(proxy_event_base, sock, HTTP_CLIENT,
				&client_methods, client);

	log_debug("proxy: new client %p", client);

	return client;
}

static void
client_free(struct client *client)
{
	struct http_request *req;

	if (!client)
		return;

	log_debug("proxy: freeing client: %p", client);

	while ((req = TAILQ_FIRST(&client->requests))) {
		TAILQ_REMOVE(&client->requests, req, next);
		http_request_free(req);
	}

	server_free(client->server);
	http_conn_free(client->conn);
	mem_free(client);
}

static int
client_scrub_request(struct client *client, struct http_request *req)
{
	if (req->meth == METH_CONNECT) {
		assert(req->url->host && req->url->port >= 1);
		// XXX we could filter host/port here
	} else {
		if (!req->url->host) {
			http_conn_send_error(client->conn, 403, "Forbidden");
			goto fail;
		}
		if (evutil_ascii_strcasecmp(req->url->scheme, "http")) {
			http_conn_send_error(client->conn, 400, "Invalid URL");
			goto fail;
		}

		if (req->url->port < 0)
			req->url->port = 80;

		if (!headers_has_key(req->headers, "Host")) {
			char *host;
			size_t len = strlen(req->url->host) + 6;
			host = mem_calloc(1, len);
			evutil_snprintf(host, len, "%s:%d", req->url->host,
					req->url->port);
			headers_add_key_val(req->headers, "Host", host);
			mem_free(host);	
		}
	}
	// XXX remove proxy auth msgs?

	return 0;

fail:
	http_request_free(req);
	return -1;
}

static void
client_disassociate_server(struct client *client)
{
	if (!client->server)
		return;

	if (http_conn_is_persistent(client->server->conn)) {
		assert(client->server->state == SERVER_STATE_IDLE);
		TAILQ_INSERT_TAIL(&idle_servers, client->server, next);
		client->server->client = NULL;
		client->server = NULL;
	} else {
		server_free(client->server);
		client->server = NULL;
	}
}

/* find a server to handle our current req */
static int
client_associate_server(struct client *client)
{
	struct server *it;
	struct url *url;
	struct http_request *req;

	req = TAILQ_FIRST(&client->requests);
	if (!req)
		return 0;
	
	url = req->url;
	assert(url && url->host != NULL && url->port > 0);

	/* should we remove our current server? */
	if (client->server &&
	    (!server_match(client->server, url->host, url->port) ||
	     req->meth == METH_CONNECT)) {
		client_disassociate_server(client);
	}

	/* nothing more to do here... */
	if (req->meth == METH_CONNECT)
		return 0;

	/* try to find an idle server */
	TAILQ_FOREACH(it, &idle_servers, next) {
		if (server_match(it, url->host, url->port)) {
			TAILQ_REMOVE(&idle_servers, it, next);
			assert(it->client == NULL);
			client->server = it;
			it->client = client;
			log_debug("proxy: idle server %p, %s:%d associated to "
				  "client %p", it, it->host, it->port, client);
			return 0;
		}
	}

	/* we didn't find one. lets setup a new one. */
	client->server = server_new(url->host, url->port, client);

	return server_connect(client->server);	
}

/* returns 1 when there's a request we can dispatch with the associated
   server. */
static int
client_dispatch_request(struct client *client)
{
	struct http_request *req;
	struct server *server = client->server;

	req = TAILQ_FIRST(&client->requests);
	if (!req)
		return 0;

	if (req->meth == METH_CONNECT) {
		assert(server == NULL);
		http_conn_start_tunnel(client->conn, proxy_evdns_base, AF_INET,
				       req->url->host, req->url->port);
		return 0;
	}
	
	assert(server != NULL);
	if (server->state == SERVER_STATE_REQUEST_SENT ||
	    server->state < SERVER_STATE_CONNECTED)
		return 0;

	/* it might be nice to support pipelining... */
	if (server_match(server, req->url->host, req->url->port)) {
		log_debug("proxy: writing %s request for %s from client %p to "
			  "server %p, %s:%d", 
			  http_method_to_string(req->meth),
			  req->url->path, server->client, server,
			  server->host, server->port);
		http_conn_write_request(server->conn, req);
		server->state = SERVER_STATE_REQUEST_SENT;
		return 1;
	}

	return 0;
}

static void
client_start_reading_request_body(struct client *client)
{
	//XXX make sure server knows what transefer encodign to use.
	if (http_conn_current_message_has_body(client->conn) &&
	    client->nrequests == 1)
		http_conn_start_reading(client->conn);
}

static void
client_write_response(struct client *client, struct http_response *resp)
{
	struct http_request *req;

	req = TAILQ_FIRST(&client->requests);
	assert(req != NULL);

	log_debug("proxy: got response for %s %s %s from %p, %s:%d: %s %d %s",
		  http_method_to_string(req->meth),
		  req->url->path,
		  http_version_to_string(req->vers),
		  client->server, client->server->host, client->server->port,
		  http_version_to_string(resp->vers), resp->code,
		  resp->reason);

	if (req->meth == METH_HEAD)
		http_conn_set_current_message_bodyless(client->server->conn);

	http_conn_set_output_encoding(client->conn, TE_IDENTITY);
	if (http_conn_current_message_has_body(client->server->conn) &&
	    http_conn_is_persistent(client->conn) &&
	    http_conn_get_current_message_body_length(client->server->conn) < 0)
		http_conn_set_output_encoding(client->conn, TE_CHUNKED);
	
	http_conn_write_response(client->conn, resp);
}

static void
client_request_serviced(struct client *client)
{
	struct http_request *req;

	req = TAILQ_FIRST(&client->requests);
	assert(req && client->nrequests > 0);
	log_debug("proxy: request for client %p, %s %s %s serviced",
		  client, http_method_to_string(req->meth), req->url->path,
		  http_version_to_string(req->vers));
	TAILQ_REMOVE(&client->requests, req, next);
	http_request_free(req);
	client->nrequests--;

	if (client->server)
		client->server->state = SERVER_STATE_IDLE;
	if (client->nrequests) {
		client_associate_server(client);
		client_dispatch_request(client);
	} else
		client_disassociate_server(client);

	if (client->state != CLIENT_STATE_TUNNEL) {
		if (!http_conn_is_persistent(client->conn)) {
			// XXX maybe shutdown the socket?
			client->state = CLIENT_STATE_CLOSING;
			http_conn_stop_reading(client->conn);
			http_conn_flush(client->conn);
		} else if (!http_conn_current_message_has_body(client->conn) &&
			   client->nrequests < max_pending_requests) {
			http_conn_start_reading(client->conn);
		}
	}
}

static void
client_notice_server_failed(struct client *client)
{
	struct http_request *req;
	struct server *server = client->server;

	client->server = NULL;

	while ((req = TAILQ_FIRST(&client->requests))) {
		if (evutil_ascii_strcasecmp(req->url->host, server->host) ||
		    req->url->port != server->port)
			break;
		http_conn_send_error(client->conn, 502,
				     "Server connection failed");
		client_request_serviced(client);
	}
}

/* http event slots */

static void
on_client_error(struct http_conn *conn, enum http_conn_error err, void *arg)
{
	if (err == ERROR_IDLE_CONN_TIMEDOUT) {
		log_info("proxy: closing idle client connection.");
	} else {
		log_warn("proxy: client error: %s",
			 http_conn_error_to_string(err));
	}
	// XXX return an error message as needed
	client_free(arg);
}

static void
on_client_request(struct http_conn *conn, struct http_request *req, void *arg)
{
	struct client *client = arg;

	assert(client->state == CLIENT_STATE_ACTIVE);

	if (client_scrub_request(client, req) < 0)
		return;

	TAILQ_INSERT_TAIL(&client->requests, req, next);
	if (++client->nrequests > max_pending_requests ||
	    http_conn_current_message_has_body(conn))
		http_conn_stop_reading(conn);

	log_debug("proxy: new %s request for %s:%d%s (pipeline %u)",
		  http_method_to_string(req->meth),
		  req->url->host, req->url->port, req->url->path,
		  (unsigned)client->nrequests);

	if (req->meth == METH_CONNECT)
		client->state = CLIENT_STATE_TUNNEL;

	if (!client->server && client_associate_server(client) < 0)
		return;

	client_dispatch_request(client);
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
	struct client *client = arg;

	if (http_conn_current_message_has_body(conn))
		http_conn_write_finished(client->server->conn);
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
	log_debug("proxy: server %p, %s:%d finished connecting",
		  server, server->host, server->port);
	client_dispatch_request(server->client);
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
		if (err == ERROR_CONNECT_FAILED) {
			assert(server->state == SERVER_STATE_CONNECTING);
			log_socket_error("proxy: connection to %s:%d failed",
					 log_scrub(server->host), server->port);
		} else {
			log_error("proxy: error while communicating with "
				  "%s:%d: %s", log_scrub(server->host),
				  server->port,
				  http_conn_error_to_string(err));
		}
		assert(server->client != NULL);
		client_notice_server_failed(server->client);
		break;
	case SERVER_STATE_IDLE:
		assert(server->client == NULL);
		TAILQ_REMOVE(&idle_servers, server, next);
		log_debug("proxy: idle server %p, %s:%d timedout",
			  server, server->host, server->port);
		break;
	default:
		log_fatal("proxy: error cb called in invalid state");
	}

	server_free(server);
}

static void
on_server_response(struct http_conn *conn, struct http_response *resp,
		   void *arg)
{
	struct server *server = arg;

	client_write_response(server->client, resp);

	if (http_conn_current_message_has_body(conn))
		log_debug("proxy: will copy body from server %p to client %p",
			  server, server->client);


	// XXX maybe not read body on error?
	// XXX handle expect 100-continue, etc

	client_start_reading_request_body(server->client);

	http_response_free(resp);
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

	if (http_conn_current_message_has_body(conn))
		http_conn_write_finished(server->client->conn);
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

	log_info("proxy: new client connection from %s",
		 format_addr(addr));

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
proxy_init(struct event_base *base, struct evdns_base *dns,
	   const struct sockaddr *listen_here, int socklen)
{
	struct evconnlistener *lcs = NULL;

	TAILQ_INIT(&idle_servers);

	lcs = evconnlistener_new_bind(base, client_accept, NULL,
				      LEV_OPT_CLOSE_ON_FREE |
				      LEV_OPT_REUSEABLE,
				      -1, listen_here, socklen);

	if (!lcs) {
		log_socket_error("proxy: couldn't listen on %s",
				 format_addr(listen_here));
		return -1;
	}
	
	listener = lcs;
	proxy_event_base = base;
	proxy_evdns_base = dns;	

	return 0;

}

void
proxy_cleanup(void)
{
	// TODO
}
