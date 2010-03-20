#include <assert.h>
#include <string.h>
#include <event2/buffer.h>

#include "util.h"
#include "headers.h"

void
headers_add_key(struct header_list *headers, const char *key, size_t n)
{
	struct header *h;

	h = mem_calloc(1, sizeof(*h) + n + 1);
	TAILQ_INIT(&h->val);
	memcpy(h->key, key, n);	
	TAILQ_INSERT_TAIL(headers, h, next);
}

void
headers_add_val(struct header_list *headers, const char *val, size_t n)
{
	struct header *h;
	struct val_line *line;

	h = TAILQ_LAST(headers, header_list);
	assert(h != NULL);

	line = mem_calloc(1, sizeof(*line) + n + 1);
	memcpy(line->str, val, n);
	line->len = n;
	TAILQ_INSERT_TAIL(&h->val, line, next);
	h->val_len += n;
}

void
headers_add_key_val(struct header_list *headers, const char *key,
	const char *val)
{
	headers_add_key(headers, key, strlen(key));
	headers_add_val(headers, val, strlen(val));
}

void
headers_dump(struct header_list *headers, struct evbuffer *buf)
{
	struct header *h;
	struct val_line *line;
	
	TAILQ_FOREACH(h, headers, next) {
		evbuffer_add_printf(buf, "%s: ", h->key);
		TAILQ_FOREACH(line, &h->val, next) {
			evbuffer_add_printf(buf, "%s\r\n", line->str);
		}
	}

	evbuffer_add(buf, "\r\n", 2);
}

/* return: -1 error, 0 need more data, 1 finished. */
int
headers_load(struct header_list *headers, struct evbuffer *buf)
{
	char *line, *p;
	
	while ((line = evbuffer_readln(buf, NULL, EVBUFFER_EOL_CRLF))) {
		if (*line == '\0') {
			mem_free(line);
			return 1;
		}

		p = line;

		if (*line != ' ' && *line != '\t') {
			p = strchr(line, ':');
			if (!p || line == p) {
				mem_free(line);
				return -1;
			}
			headers_add_key(headers, line, p - line);
			++p;
			p += strspn(p, " \t");
		}
		
		if (!TAILQ_LAST(headers, header_list)) {
			mem_free(line);
			return -1;
		}

		headers_add_val(headers, p, strlen(p));
		mem_free(line);
	}

	return 0;
}

/* caller must free result; returns NULL if key not found. */
char *
headers_find(struct header_list *headers, const char *key)
{
	struct header *h;
	struct val_line *line;
	char *ret, *p;
	size_t len;
	
	TAILQ_FOREACH(h, headers, next) {
		if (evutil_ascii_strcasecmp(h->key, key))
			continue;

		len = h->val_len;

		/* XXX Some of this space is wasted if we trim any leading WS
 		   from value lines */
		ret = mem_calloc(1, len + 1);
		p = ret;

		TAILQ_FOREACH(line, &h->val, next) {
			len = strspn(line->str, " \t");
			/* after the first line, translate leading WS to
 		 	   a single SP */
			if (p != ret)
				*p++ = ' ';
			memcpy(p, line->str + len, line->len - len);
			p += line->len - len;
		}
	
		return ret;	
	}

	return NULL;
}

static void
remove_one(struct header_list *headers, struct header *h)
{
	struct val_line *line;

	TAILQ_REMOVE(headers, h, next);
	while ((line = TAILQ_FIRST(&h->val))) {
		TAILQ_REMOVE(&h->val, line, next);
		mem_free(line);	
	}
	mem_free(h);	
}

void
headers_clear(struct header_list *headers)
{
	struct header *h;

	while ((h = TAILQ_FIRST(headers)))
		remove_one(headers, h);
}

int
headers_remove(struct header_list *headers, const char *key)
{
	int count;
	struct header *h, *next;
	
	count = 0;
	for (h = TAILQ_FIRST(headers); h != NULL; h = next) {
		next = TAILQ_NEXT(h, next);
		if (!evutil_ascii_strcasecmp(h->key, key)) {
			count++;
			remove_one(headers, h);
		}
	}

	return count;
}

#ifdef TEST_HEADERS
#include <stdio.h>
int main(int argc, char **argv)
{
	struct evbuffer *buf, *buf2;
	struct header_list headers;
	char line[256];

	buf = evbuffer_new();
	buf2 = evbuffer_new();
	TAILQ_INIT(&headers);

	while (fgets(line, sizeof(line), stdin)) {
		evbuffer_add(buf, line, strlen(line));
	}

	headers_load(&headers, buf);
	headers_dump(&headers, buf2);

	printf("buf1..\n");
	fwrite(evbuffer_pullup(buf, evbuffer_get_length(buf)), evbuffer_get_length(buf), 1, stdout);
	printf("\nbuf2..\n");
	fwrite(evbuffer_pullup(buf2, evbuffer_get_length(buf2)), evbuffer_get_length(buf2), 1, stdout);

	if (argc > 1) {
		int i;
		printf("\nfinding stuffs...\n");
		for (i = 1; i < argc; ++i) {
			char *buf = headers_find(&headers, argv[i]);
			printf("%s? %s\n", argv[i], buf? buf : "NOT FOUND");
			if (buf) {
				mem_free(buf);
				headers_remove(&headers, argv[i]);
			}
		}
	}

	evbuffer_free(buf);
	evbuffer_free(buf2);

	return 0;
}
#endif
