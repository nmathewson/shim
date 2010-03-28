AUTOMAKE_OPTIONS = foreign

SUBDIRS = .

shim_SOURCES = main.c proxy.c httpconn.c conn.c headers.c log.c util.c
shim_CFLAGS = $(LIBEVENT_CFLAGS)
shim_LDADD = $(LIBEVENT_LIBS)
bin_PROGRAMS = shim
