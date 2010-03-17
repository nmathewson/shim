#ifndef _UTIL_H_
#define _UTIL_H_

#include <sys/queue.h>
#include <event2/util.h>

void *mem_calloc(size_t nmemb, size_t size);
void *mem_malloc(size_t size);
char *mem_strdup(const char *str);
char *mem_strdup_n(const char *str, size_t n);
void mem_free(void *buf);

void log_debug(const char *msg, ...);
void log_notice(const char *msg, ...);
void log_warn(const char *msg, ...);
void log_error(const char *msg, ...);
void log_fatal(const char *msg, ...);

struct token {
	TAILQ_ENTRY(token) next;
	char *token;
};
TAILQ_HEAD(token_list, token) token;

size_t tokenize(const char *buf, const char *sep, int lim,
		struct token_list *tokens);
void free_token_list(struct token_list *tokens);

ev_int64_t get_int(const char *buf, int base);

struct url {
	char *scheme;
	char *host;
	int port;
	char *query;
};
struct url *tokenize_url(const char *str);
void free_url(struct url *url);

#endif
