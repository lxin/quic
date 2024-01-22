EXTRA_DIST		= keys runtest.sh

noinst_PROGRAMS		= func_test perf_test sample_test ticket_test

AM_CPPFLAGS		= -I$(top_builddir)/handshake/
AM_CFLAGS		= -Werror -Wall $(LIBGNUTLS_CFLAGS)
LDADD			= $(top_builddir)/handshake/libquic.la

func_test_SOURCE	= func_test.c
func_test_LDADD		= $(LDADD) $(LIBGNUTLS_LIBS)
perf_test_SOURCE	= perf_test.c
perf_test_LDADD		= $(LDADD) $(LIBGNUTLS_LIBS)

sample_test_SOURCE	= sample_test.c
ticket_test_SOURCE	= ticket_test.c

msquic_test: msquic_test.c
	$(CXX) $^ -o $@ -lmsquic -Wl,-rpath=/usr/local/lib -Wall
run:
	./runtest.sh
CLEANFILES		= msquic_test
DISTCLEANFILES		= keys/*.pem keys/*.ext
