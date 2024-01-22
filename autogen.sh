GEN="compile config.guess config.sub depcomp install-sh \
     missing aclocal.m4 configure config.h.in autom4te.cache ltmain.sh \
     ar-lib Makefile.in handshake/Makefile.in tests/Makefile.in INSTALL"

rm -rf $GEN

[ "$1" = "clean" ] && exit 0

libtoolize --force --copy
aclocal
autoheader
automake --add-missing --copy --gnu
autoconf

exit 0
