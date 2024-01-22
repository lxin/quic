man7_MANS		= quic.7
EXTRA_DIST		= $(man7_MANS)

lib_LTLIBRARIES		= libquic.la
libquic_la_SOURCES	= connection.c connection.h crypto.c
libquic_la_CFLAGS	= -Werror -Wall $(LIBGNUTLS_CFLAGS)
libquic_la_LIBADD	= $(LIBGNUTLS_LIBS)

libcnetinetdir		= $(includedir)/netinet
libcnetinet_HEADERS	= netinet/quic.h

pkgconfigdir		= $(libdir)/pkgconfig
pkgconfig_DATA		= libquic.pc
DISTCLEANFILES		= libquic.pc
