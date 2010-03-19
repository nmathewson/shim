#ifndef _HEADERS_H_
#define _HEADERS_H_

#include <sys/queue.h>

/* Use a list of strings to preserve any folding. */ 
struct val_line {
	TAILQ_ENTRY(val_line) next;
	size_t len;
	char str[0];
};
TAILQ_HEAD(val_line_list, val_line);

struct header {
	TAILQ_ENTRY(header) next;
	size_t val_len;
	struct val_line_list val;
	char key[0];
};
TAILQ_HEAD(header_list, header);

struct evbuffer;

void headers_add_key(struct header_list *headers, const char *key, size_t n);
void headers_add_val(struct header_list *headers, const char *val, size_t n);
void headers_add_key_val(struct header_list *headers, const char *key,
			 const char *val);
void headers_dump(struct header_list *headers, struct evbuffer *buf);
int headers_load(struct header_list *headers, struct evbuffer *buf);
char *headers_find(struct header_list *headers, const char *key);
int headers_remove(struct header_list *headers, const char *key);
void headers_clear(struct header_list *headers);

#endif
