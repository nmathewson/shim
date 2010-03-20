#include <stdio.h>
#include <stdlib.h>
#include "log.h"

static enum log_level min_log_level = LOG_NOTICE;
static FILE *log_file = NULL;

void
log_debug(const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	log_msg_va(LOG_DEBUG, msg, ap);
	va_end(ap);
}

void
log_info(const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	log_msg_va(LOG_INFO, msg, ap);
	va_end(ap);
}

void
log_notice(const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	log_msg_va(LOG_NOTICE, msg, ap);
	va_end(ap);
}

void
log_warn(const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	log_msg_va(LOG_WARN, msg, ap);
	va_end(ap);
}

void
log_error(const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	log_msg_va(LOG_ERROR, msg, ap);
	va_end(ap);
}

void
log_fatal(const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	log_msg_va(LOG_FATAL, msg, ap);
	va_end(ap);
}

void
log_msg_va(enum log_level lvl, const char *msg, va_list ap)
{
	if (lvl >= min_log_level) {
		vfprintf(log_file, msg, ap);
		fputs("\n", log_file);
		fflush(log_file);
		if (lvl >= LOG_FATAL)
			abort();
	}
}

void
log_set_min_level(enum log_level lvl)
{
	min_log_level = lvl;
}

enum log_level
log_get_min_level(void)
{
	return min_log_level;
}

void
log_set_file(FILE *fp)
{
	if (!fp)
		log_file = stderr;
	else
		log_file = fp;
}
