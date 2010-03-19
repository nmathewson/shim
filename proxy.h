#ifndef _PROXY_H_
#define _PROXY_H_

struct sockaddr;

void proxy_client_set_max_pending_requests(size_t nreqs);
size_t proxy_client_get_max_pending_requests(void);

int proxy_init(const struct sockaddr *listen_here, int socklen);
void proxy_cleanup(void);

#endif
