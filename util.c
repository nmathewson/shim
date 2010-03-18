#include <stdlib.h>
#include <string.h>
#include "util.h"

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

void
log_debug(const char *msg, ...)
{
}

void
log_notice(const char *msg, ...)
{
}

void
log_warn(const char *msg, ...)
{
}

void
log_error(const char *msg, ...)
{
}

void
log_fatal(const char *msg, ...)
{
	// XXX
	abort();
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

	while ((lim < 0 || ntok < (unsigned)lim) && (p = strpbrk(buf, sep))) {
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

struct url *
url_tokenize(const char *str)
{
	struct url *url;
	char *p;

#define DUP(dst, src, len) 			\
	do { 					\
		if (len == 0) 			\
			goto fail; 		\
		dst = mem_strdup_n(src, len); 	\
	} while (0)

	url = mem_calloc(1, sizeof(*url));
	url->port = -1;

	p = strstr(str, "://");
	if (!p) {
		if (*str != '/')
			goto fail;
		else
			DUP(url->query, str, strlen(str));
		return url;
	}
	
	DUP(url->scheme, str, p - str);
	str = p + 3;
	
	p = strchr(str, ':');
	if (p) {
		long port;

		DUP(url->host, str, p - str);
		port = strtol(p + 1, &p, 10);
		if (port < 1 || port > 0xffff)
			goto fail;
		if (p) {
			if (*p == '\0')
				p = NULL;
			else if (*p != '/')
				goto fail;
		}
		url->port = port;
	} else {
		p = strchr(str, '/');
		if (p)
			DUP(url->host, str, p - str);
		else
			DUP(url->host, str, strlen(str));
	}

	if (p)
		DUP(url->query, p, strlen(p));
	else
		url->query = mem_strdup("/");

#undef DUP

	return url;

fail:
	url_free(url);
	return NULL;
}

void
url_free(struct url *url)
{
	if (!url)
		return;

	mem_free(url->scheme);
	mem_free(url->host);
	mem_free(url->query);
	mem_free(url);
}

#ifdef TEST_UTIL
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	struct url *url;

	url = url_tokenize(argv[1]);
	if (url) {
		printf("%s://%s:%d%s\n", url->scheme, url->host, url->port, url->query);
		url_free(url);
	} else {
		printf("BAD URL!\n");
	}
	
	return 0;
}
#endif
