EXTRA_DIST		= keys runtest.sh test_mtls.sh

noinst_PROGRAMS		= func_test perf_test sample_test ticket_test alpn_test pto_test mtls_test

AM_CPPFLAGS		= -I$(top_builddir)/libquic/ -I$(top_builddir)/modules/include/uapi/
AM_CFLAGS		= -Werror -Wall -Wformat-signedness $(LIBGNUTLS_CFLAGS)
LDADD			= $(top_builddir)/libquic/libquic.la $(LIBGNUTLS_LIBS)

func_test_SOURCE	= func_test.c
perf_test_SOURCE	= perf_test.c
alpn_test_SOURCE	= alpn_test.c
ticket_test_SOURCE	= ticket_test.c
sample_test_SOURCE	= sample_test.c
pto_test_SOURCE		= pto_test.c
mtls_test_SOURCES	= mtls_test.c

http3_test: http3_test.c
	$(LIBTOOL) --mode=link $(CC) $^  -o $@ -lnghttp3 \
		$(LDADD) $(AM_CPPFLAGS) $(AM_CFLAGS)

check: $(noinst_PROGRAMS)
	@case " $(tests) " in \
		*" mtls "*) $(srcdir)/test_mtls.sh ./mtls_test ;; \
		"  ")       ./runtest.sh && $(srcdir)/test_mtls.sh ./mtls_test ;; \
		*)          ./runtest.sh $(tests) ;; \
	esac

CLEANFILES		= http3_test
DISTCLEANFILES		= keys/*.pem keys/*.ext keys/*.txt
MAINTAINERCLEANFILES	= Makefile.in
