AUTOMAKE_OPTIONS = foreign

SUBDIRS = .

noinst_HEADERS = conn.h headers.h httpconn.h log.h proxy.h util.h
shim_SOURCES = main.c proxy.c httpconn.c conn.c headers.c log.c util.c
shim_CFLAGS = -I$(srcdir)/compat $(LIBEVENT_CFLAGS)
shim_LDADD = $(LIBEVENT_LIBS)
bin_PROGRAMS = shim
