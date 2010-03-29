#include "netheaders.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "util.h"
#include "log.h"

void *
mem_calloc(size_t nmemb, size_t size)
{
	void *ret;

	ret = calloc(nmemb, size);
	if (!ret)
		log_fatal("mem_calloc: alloc failed");

	return ret;
}

void *
mem_malloc(size_t size)
{
	void *ret;

	ret = malloc(size);
	if (!ret)
		log_fatal("mem_malloc: alloc failed");

	return ret;
}

char *
mem_strdup(const char *str)
{
	char *ret;

	ret = strdup(str);
	if (!ret)
		log_fatal("mem_strdup: alloc failed");

	return ret;
}

char *
mem_strdup_n(const char *str, size_t n)
{
	char *ret;
	
	ret = mem_calloc(1, n + 1);
	if (!ret)
		log_fatal("mem_strdup: alloc failed");
	memcpy(ret, str, n);

	return ret;
}

void
mem_free(void *buf)
{
	if (buf)
		free(buf);
}

static void
add_token(const char *buf, size_t len, struct token_list *tokens)
{
	struct token *token;

	token = mem_calloc(1, sizeof(*token));
	token->token = mem_strdup_n(buf, len);
	TAILQ_INSERT_TAIL(tokens, token, next);
}

/* this isn't very fast, but this thing is meant for a single user anyhow */
size_t
tokenize(const char *buf, const char *sep, int lim,
	 struct token_list *tokens)
{
	char *p;
	size_t ntok;
	size_t len;

	ntok = 0;

	while ((lim < 0 || ntok < (size_t)lim) && (p = strpbrk(buf, sep))) {
		len = p - buf;
		add_token(buf, len, tokens);
		buf += len + 1;
		ntok++;
	}

	/* add any remaining */
	if (*buf) {
		add_token(buf, strlen(buf), tokens);
		ntok++;
	}

	return ntok;
}

void
token_list_clear(struct token_list *tokens)
{
	struct token *token;

	while ((token = TAILQ_FIRST(tokens))) {
		TAILQ_REMOVE(tokens, token, next);
		if (token->token)
			mem_free(token->token);
		mem_free(token);
	}
}

ev_int64_t
get_int(const char *buf, int base)
{
	char *endp;
	ev_int64_t rv;

	rv = evutil_strtoll(buf, &endp, base);
	// XXX
	//
	
	return rv;
}

static int
get_port(const char *str)
{
	long port;
	char *endp;

	errno = 0;
	port = strtol(str, &endp, 10);
	if (errno == ERANGE || !endp || *endp != '\0' ||
	    port < 1 || port > 0xffff)
		return -1;

	return port;
}

// tokenize a CONNECT host:port request
struct url *
url_connect_tokenize(const char *str)
{
	struct url *url;
	char *p;
	int port;

	url = mem_calloc(1, sizeof(*url));

	p = strrchr(str, ':');
	if (!p || p == str)
		goto fail;
	port = get_port(p + 1);
	if (port < 0)
		goto fail;	

	url->host = mem_strdup_n(str, p - str);
	url->port = port;

	return url;	

fail:
	url_free(url);

	return NULL;
}

// XXX should this do more to sanitize the url?
struct url *
url_tokenize(const char *str)
{
	struct url *url;
	size_t ntokens;
	char *p;
	struct token_list tokens;
	struct token *scheme, *slash, *hostport, *path;
	size_t len;
	int port = -1;
	char *pathstr;

	url = NULL;	
	TAILQ_INIT(&tokens);

	ntokens = tokenize(str, "/", 3, &tokens);

	/* just a path? */
	if (ntokens >= 1 && TAILQ_FIRST(&tokens)->token[0] == '\0') {
		url = mem_calloc(1, sizeof(*url));
		url->path = mem_strdup(str);
		goto out;
	}

	if (ntokens < 3)
		goto out;

	scheme = TAILQ_FIRST(&tokens);
	len = strlen(scheme->token);
	if (len	< 2 || scheme->token[len - 1] != ':')
		goto out;
	scheme->token[len - 1] = '\0';

	slash = TAILQ_NEXT(scheme, next);	
	if (slash->token[0] != '\0')
		goto out;

	hostport = TAILQ_NEXT(slash, next);
	if (hostport->token[0] == '\0')
		goto out;
	// XXX this could break IPv6 addresses
	p = strrchr(hostport->token, ':');
	if (p == hostport->token)
		goto out;
	if (p && p[1] != '\0') {
		*p++ = '\0';
		port = get_port(p);
		if (port < 0)
			goto out;
	}

	if (ntokens > 3) {
		// XXX maybe urlencode?
		assert(ntokens == 4);
		path = TAILQ_NEXT(hostport, next);
		len = strlen(path->token);
		pathstr = mem_calloc(1, 2 + len);
		pathstr[0] = '/';
		memcpy(pathstr + 1, path->token, len);
	} else
		pathstr = mem_strdup("/");
	

	url = mem_calloc(1, sizeof(*url));
	url->scheme = scheme->token;
	url->host = hostport->token;
	url->port = port;
	url->path = pathstr;

	scheme->token = NULL;
	hostport->token = NULL;

out:
	token_list_clear(&tokens);

	return url;
}	

void
url_free(struct url *url)
{
	if (!url)
		return;

	mem_free(url->scheme);
	mem_free(url->host);
	mem_free(url->path);
	mem_free(url);
}

const char *
format_addr(const struct sockaddr *addr)
{
	const char *r = NULL;
	static char buf[256];
	char tmp[256];

	if (addr->sa_family == AF_INET) {	
		struct sockaddr_in *sin = (struct sockaddr_in *)addr;
		r = evutil_inet_ntop(AF_INET, &sin->sin_addr, tmp,
		            	     sizeof(tmp));
		if (r) {
			if (sin->sin_port)
				evutil_snprintf(buf, sizeof(buf), "%s:%hu",
						tmp, ntohs(sin->sin_port));
			else
				strcpy(buf, tmp);
		}
	} else if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
		r = evutil_inet_ntop(AF_INET6, &sin6->sin6_addr, tmp,
				     sizeof(tmp));
		if (r) {
			if (sin6->sin6_port)
				evutil_snprintf(buf, sizeof(buf), "[%s]:%hu",
						tmp, ntohs(sin6->sin6_port));
			else
				strcpy(buf, tmp);
		}
	}

	if (!r)
		strcpy(buf, "???");
	
	return buf;
}

const char *
socket_error_string(evutil_socket_t s)
{
	return evutil_socket_error_to_string(evutil_socket_geterror(s));
}

#ifdef TEST_UTIL
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	struct url *url;

	url = url_tokenize(argv[1]);
	if (!url) {
		printf("bad url!\n");
		return 0;
	}	
	printf("%s, %s, %d, %s\n",
		url->scheme, url->host, url->port, url->path);
	url_free(url);

	return 0;
}
#endif
