#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <event2/event.h>
#include <event2/dns.h>
#include "proxy.h"
#include "log.h"

int main()
{
	struct sockaddr_in sin;
	struct event_base *base;
	struct evdns_base *dns;

	base = event_base_new();
	dns = evdns_base_new(base, 1);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(8888);

	log_set_min_level(LOG_DEBUG);
	log_set_file(NULL);
	
	proxy_init(base, dns, (struct sockaddr *)&sin, sizeof(sin));

	event_base_dispatch(base);

	return 0;	
}
