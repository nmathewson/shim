#ifndef _UTIL_H_
#define _UTIL_H_

#include <sys/queue.h>

void *mem_calloc(size_t nmemb, size_t size);
void *mem_malloc(size_t size);
char *mem_strdup(const char *str);
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

#endif
