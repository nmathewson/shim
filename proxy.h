#ifndef _PROXY_H_
#define _PROXY_H_

struct sockaddr;
struct event_base;
struct evdns_base;

void proxy_client_set_max_pending_requests(size_t nreqs);
size_t proxy_client_get_max_pending_requests(void);

int proxy_init(struct event_base *base, struct evdns_base *dns,
	       const struct sockaddr *listen_here, int socklen);
void proxy_cleanup(void);

#endif
