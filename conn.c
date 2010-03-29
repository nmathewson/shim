#include "netheaders.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/dns.h>

#include "config.h"
#include "conn.h"
#include "util.h"
#include "log.h"

struct conninfo {
	enum socks_ver socks;
	struct bufferevent *bev;
	void *cbarg;
	int connecting;
	conn_connectcb on_connect;
	/* for socks... */
	char *host;
	int port;
	struct sockaddr_storage addr;
	int addr_len;
};

static enum socks_ver use_socks = SOCKS_NONE;
static struct sockaddr_storage socks_addr;
static int socks_addr_len = sizeof(socks_addr);
static char *conn_error_string = NULL;

static void
finish_connection(struct conninfo *info, int ok, const char *reason)
{
	mem_free(conn_error_string);
	conn_error_string = NULL;
	if (!ok)
		conn_error_string = mem_strdup(reason);
	bufferevent_disable(info->bev, EV_READ);
	bufferevent_setcb(info->bev, NULL, NULL, NULL, NULL);
	info->on_connect(info->bev, ok, info->cbarg);
	mem_free(info->host);
	mem_free(info);
}

static void
write_socks_request(struct conninfo *info)
{
	if (info->socks == SOCKS_4) {
		struct sockaddr_in *sin = (struct sockaddr_in*)&info->addr;

		if (info->addr.ss_family != AF_INET) {
			finish_connection(info, 0,
				"SOCKS 4 can't handle ipv6!");
		}

		/* connection request */
		bufferevent_write(info->bev, "\x04\x01", 2);
		bufferevent_write(info->bev, &sin->sin_port,
				  sizeof(sin->sin_port));
		bufferevent_write(info->bev, &sin->sin_addr.s_addr,
				  sizeof(sin->sin_addr.s_addr));
		bufferevent_write(info->bev, "xx", 3);
	} else {
		ev_uint16_t port = htons(info->port);

		assert(info->host != NULL);
		bufferevent_write(info->bev, "\x04\x01", 2);
		bufferevent_write(info->bev, &port, sizeof(port));
		bufferevent_write(info->bev, "\x00\x00\x00\xff", 4);
		bufferevent_write(info->bev, "xx", 3);
		bufferevent_write(info->bev, info->host, strlen(info->host)+1);
	}

	bufferevent_enable(info->bev, EV_READ);
}

static void
conn_errorcb(struct bufferevent *bev, short what, void *arg)
{
	struct conninfo *info = arg;

	if (info->connecting) {
		info->connecting = 0;
		if (what & BEV_EVENT_CONNECTED) {
			if (info->socks != SOCKS_NONE)
				write_socks_request(info);
			else
				finish_connection(info, 1, NULL);
		} else {
			// XXX need better err msg
			const char *msg = "Connection failed";
			if (info->socks != SOCKS_NONE)
				msg = "Connection to proxy server failed";
			finish_connection(info, 0, msg);
		}
	} else {
		finish_connection(info, 0, "SOCKS I/O error");
	}
}

static const char *
socks4_error_to_string(unsigned char err)
{
	switch (err) {
	case 0x5b:
		return "SOCKS 4: request failed";
	case 0x5c:
		return "SOCKS 4: client is not running identd";
	case 0x5d: 
		return "SOCKS 4: invalid user ID";
	}

	return "SOCKS 4: unknown error";
}

static void
conn_readcb(struct bufferevent *bev, void *arg)
{
	struct conninfo *info = arg;
	struct evbuffer *inbuf = bufferevent_get_input(bev);
	unsigned char *data;
	unsigned char code;

	/* socks4 and socks4a both have an 8 byte response */
	if (evbuffer_get_length(inbuf) < 8) {
		log_debug("conn: waiting for full socks response");
		return;
	}

	data = evbuffer_pullup(inbuf, 8);
	code = data[1];
	evbuffer_drain(inbuf, 8);

	if (code != 0x5a) {
		finish_connection(info, 0, socks4_error_to_string(code));
	} else {
		finish_connection(info, 1, NULL);
	}
}

void socks_resolvecb(int result, struct evutil_addrinfo *ai, void *arg)
{
	struct conninfo *info = arg;

	if (result) {
		char buf[256];
		evutil_snprintf(buf, sizeof(buf), "DNS Failure: %s",
				evutil_gai_strerror(result));
		finish_connection(info, 0, buf);
	} else {
		log_debug("conn: socks resolve %s",
			  format_addr(ai->ai_addr));
		assert(ai->ai_addrlen <= sizeof(info->addr));
		memcpy(&info->addr, ai->ai_addr, ai->ai_addrlen);
		info->addr_len = ai->ai_addrlen;
		bufferevent_socket_connect(info->bev,
					   (struct sockaddr*)&socks_addr,
					   socks_addr_len);
	}

	if (ai)
		evutil_freeaddrinfo(ai);
}

int
conn_connect_bufferevent(struct bufferevent *bev, struct evdns_base *dns,
			 int family, const char *name, int port,
			 conn_connectcb conncb, void *arg)
{
	struct conninfo *info;
	int rv = -1;
	

	info = mem_calloc(1, sizeof(*info));
	info->bev = bev;
	info->on_connect = conncb;
	info->cbarg = arg;
	info->connecting = 1;
	info->socks = use_socks;

	bufferevent_setcb(bev, conn_readcb, NULL, conn_errorcb, info);
	if (use_socks != SOCKS_NONE) {
		info->host = mem_strdup(name);
		info->port = port;
		if (use_socks == SOCKS_4a) {
			rv = bufferevent_socket_connect(bev,
					(struct sockaddr*)&socks_addr,
					socks_addr_len);
			return rv;
		}
#ifndef DISABLE_DIRECT_CONNECTIONS
		else {
			struct evutil_addrinfo hint;
			char portstr[NI_MAXSERV];

			evutil_snprintf(portstr, sizeof(portstr), "%d", port);
			memset(&hint, 0, sizeof(hint));
			hint.ai_family = AF_INET;
			hint.ai_protocol = IPPROTO_TCP;
			hint.ai_socktype = SOCK_STREAM;

			evdns_getaddrinfo(dns, name, portstr, &hint,
				          socks_resolvecb, info);
			return 0;
		}
#endif
	}
#ifdef DISABLE_DIRECT_CONNECTIONS
	{
		const char *msg;
		msg = "Direct connections disabled, but I have no SOCKS 4a "
		      "proxy to connect to!";
		log_error("conn: %s", msg);
		finish_connection(info, 0, msg);
	}
#else
	rv =  bufferevent_socket_connect_hostname(bev, dns, family, name, port);
#endif

	return rv;
}

int
conn_set_socks_server(const char *name, int port, enum socks_ver ver)
{
	int ret;
	int rv = -1;	
	struct evutil_addrinfo *ai = NULL;
	struct evutil_addrinfo hint;
	char portstr[NI_MAXSERV];

	assert(ver != SOCKS_NONE);

	evutil_snprintf(portstr, sizeof(portstr), "%d", port);
	memset(&hint, 0, sizeof(hint));
	hint.ai_family = AF_UNSPEC;
	hint.ai_protocol = IPPROTO_TCP;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_flags = EVUTIL_AI_ADDRCONFIG;

	ret = evutil_getaddrinfo(name, portstr, &hint, &ai);
	if (!ret) {
		rv = 0;
		memset(&socks_addr, 0, sizeof(socks_addr));
		memcpy(&socks_addr, ai->ai_addr, ai->ai_addrlen);
		socks_addr_len = ai->ai_addrlen;
		use_socks = ver;
		log_notice("conn: socks server set to %s",
			   format_addr((struct sockaddr*)&socks_addr));
	} else {
		log_error("conn: can't resolve socks server %s: %s",
			  name, evutil_gai_strerror(ret));
	}
	
	if (ai)
		evutil_freeaddrinfo(ai);

	return rv;
}

const char *
conn_get_connect_error(void)
{
	return conn_error_string;
}

#ifdef TEST_CONN
void do_connect(struct bufferevent *bev, int ok, void *arg)
{
	if (!ok) {
		log_notice("conn: failed: %s", conn_get_connect_error());
	} else {
		log_notice("conn: conn OK!");
	}
	bufferevent_free(bev);
}

int main(int argc, char **argv)
{
	struct evdns_base *dns;
	struct event_base *base;
	struct bufferevent *bev;
	struct url *socks, *host;
	int s4;

	base = event_base_new();
	dns = evdns_base_new(base, 1);
	
	log_set_file(NULL);
	log_set_min_level(LOG_DEBUG);
	if (argc >= 3) {
		socks = url_tokenize(argv[2]);
		s4 = !evutil_ascii_strcasecmp("socks4", socks->scheme);
		if (conn_set_socks_server(socks->host, socks->port, s4?
				SOCKS_4 : SOCKS_4a) < 0)
			return 0;
	}
	
	host = url_connect_tokenize(argv[1]);

	bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);

	conn_connect_bufferevent(bev, dns, AF_INET, host->host, host->port,
				 do_connect, NULL);

	event_base_dispatch(base);

	return 0;
}
#endif
