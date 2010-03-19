#ifndef _UTIL_H_
#define _UTIL_H_

#include <sys/queue.h>
#include <event2/util.h>

void *mem_calloc(size_t nmemb, size_t size);
void *mem_malloc(size_t size);
char *mem_strdup(const char *str);
char *mem_strdup_n(const char *str, size_t n);
void mem_free(void *buf);

struct token {
	TAILQ_ENTRY(token) next;
	char *token;
};
TAILQ_HEAD(token_list, token) token;

size_t tokenize(const char *buf, const char *sep, int lim,
		struct token_list *tokens);
void token_list_clear(struct token_list *tokens);

ev_int64_t get_int(const char *buf, int base);

struct url {
	char *scheme;
	char *host;
	int port;
	char *query;
};
struct url *url_tokenize(const char *str);
void url_free(struct url *url);

struct sockaddr;

const char *format_addr(const struct sockaddr *addr);
const char *socket_error_string(evutil_socket_t s);

#endif
