#ifndef _CONN_H_
#define _CONN_H_

enum socks_ver {
	SOCKS_NONE,
	SOCKS_4,
	SOCKS_4a
};

/* called on connect completion with the bev, conn status (0 failed, 1 ok). */

struct bufferevent;  
 
typedef void (*conn_connectcb)(struct bufferevent *bev, int ok, void *arg);

int conn_connect_bufferevent(struct bufferevent *bev, struct evdns_base *dns,
			     int family, const char *name, int port,
			     conn_connectcb conncb, void *arg);
int conn_set_socks_server(const char *name, int port, enum socks_ver ver);
const char *conn_get_connect_error(void);

#endif
