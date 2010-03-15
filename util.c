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

void
mem_free(void *buf)
{
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
	token->token = mem_malloc(len + 1);
	memcpy(token->token, buf, len);
	token->token[len] = '\0';
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
free_token_list(struct token_list *tokens)
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
parse_int(const char *buf, int base)
{
	char *endp;
	ev_int64_t rv;

	rv = evutil_strtoll(buf, &endp, base);
	// XXX
	//
	
	return rv;
}

#ifdef TEST_UTIL
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	struct token_list tokens;
	struct token *token;
	int n;
	
	TAILQ_INIT(&tokens);

	n = tokenize(argv[1], argv[2], atoi(argv[3]), &tokens);

	printf("ntokens %d\n", n);
	TAILQ_FOREACH(token, &tokens, next) {
		printf("tok: '%s'\n", token->token);
	}

	free_token_list(&tokens);
	
	return 0;
}
#endif
