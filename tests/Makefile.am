EXTRA_DIST		= keys runtest.sh msquic_test.c

noinst_PROGRAMS		= func_test perf_test sample_test ticket_test alpn_test

AM_CPPFLAGS		= -I$(top_builddir)/libquic/ -I$(top_builddir)/modules/include/uapi/
AM_CFLAGS		= -Werror -Wall -Wformat-signedness $(LIBGNUTLS_CFLAGS)
LDADD			= $(top_builddir)/libquic/libquic.la $(LIBGNUTLS_LIBS)

func_test_SOURCE	= func_test.c
perf_test_SOURCE	= perf_test.c
ticket_test_SOURCE	= ticket_test.c
alpn_test_SOURCE	= alpn_test.c
sample_test_SOURCE	= sample_test.c

msquic_test: msquic_test.c
	$(CXX) $^ -o $@ -lmsquic -Wl,-rpath=/usr/local/lib -Wall
http3_test: http3_test.c
	$(LIBTOOL) --mode=link $(CC) $^  -o $@ -lnghttp3 \
		$(LDADD) $(AM_CPPFLAGS) $(AM_CFLAGS)

check:
	./runtest.sh $(tests)

CLEANFILES		= msquic_test http3_test
DISTCLEANFILES		= keys/*.pem keys/*.ext keys/*.txt
MAINTAINERCLEANFILES	= Makefile.in
