#ifndef _HTTPCONN_H_
#define _HTTPCONN_H_

enum http_version {
	HTTP_10,
	HTTP_11
};

enum http_state {
	STATE_IDLE,
	STATE_READ_FIRSTLINE,
	STATE_READ_HEADERS,
	STATE_READ_BODY,
	STATE_WRITE_RESPONSE,
	STATE_WRITE_BODY
};

enum http_type {
	HTTP_CLIENT,
	HTTP_SERVER
};

enum http_method {
	METH_GET,
	METH_HEAD,
	METH_POST,
	METH_PUT,
	METH_CONNECT
};

enum http_te {
	TE_IDENTITY,
	TE_CHUNKED
};

enum http_conn_error {
	ERROR_NONE,
	ERROR_READ_FAILED,
	ERROR_WRITE_FAILED,
	ERROR_HEADER_PARSE_FAILED,
};

struct http_conn;
struct evbuffer;
struct headers;

struct http_request {
	TAILQ_ENTRY(http_request) next;
	enum http_method meth;
	char *uri;
	enum http_version vers;
	struct header_list *headers;
};
TAILQ_HEAD(http_request_list, http_request);

struct http_response {
	enum http_version vers;
	int code;
	char *reason;
	struct header_list *headers;
};

struct http_cbs {
	void (*on_error)(struct http_conn *, enum http_conn_error);
	void (*on_client_request)(struct http_conn *, struct http_request *);
	void (*on_server_response)(struct http_conn *, struct http_response *);
	void (*on_read_body)(struct http_conn *, struct evbuffer *buf);
	void (*on_read_finished)(struct http_conn *);

	/* called when it is ok to write more data after choaking */
	void (*on_write_more)(struct http_conn *);
};

void http_conn_add_request(struct http_conn *conn, struct http_request *req);
void http_conn_del_request(struct http_conn *conn, struct http_request *req);

void http_conn_write_response(struct http_conn *conn, struct http_response *resp);

/* return: -1 on failure, 0 on choaked, 1 on queued. */
int http_conn_write_buf(struct http_conn *conn, struct evbuffer *buf);

void http_conn_start_reading(struct http_conn *conn);
void http_conn_stop_reading(struct http_conn *conn);

#endif
