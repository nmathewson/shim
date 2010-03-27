#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <event2/event.h>
#include <event2/dns.h>
#include <event2/util.h>
#include "proxy.h"
#include "conn.h"
#include "log.h"
#include "util.h"

int
main(int argc, char **argv)
{
	struct sockaddr_in sin;
	struct event_base *base;
	struct evdns_base *dns;

	base = event_base_new();
	dns = evdns_base_new(base, 1);
	log_set_min_level(LOG_DEBUG);
	log_set_file(NULL);

	if (argc >= 2) {
		struct url *url;
		enum socks_ver socksv;

		url = url_tokenize(argv[1]);
		if (!url) {
			log_error("shim: bad socks server, %s", argv[1]);
			return 0;
		}
		if (url->port < 0)
			url->port = 1080;

		if (!evutil_ascii_strcasecmp(url->scheme, "socks4"))
			socksv = SOCKS_4;
		else if (!evutil_ascii_strcasecmp(url->scheme, "socks4a"))
			socksv = SOCKS_4a;
		else {
			log_error("shim: unknown socks version, %s",
				  url->scheme);
			return 0;
		}

		if (conn_set_socks_server(url->host, url->port, socksv) < 0)
			return 0;
	
		url_free(url);	
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(8888);

	proxy_init(base, dns, (struct sockaddr *)&sin, sizeof(sin));

	event_base_dispatch(base);

	return 0;	
}
