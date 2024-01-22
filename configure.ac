AC_INIT([quic], [1.0], [lucien.xin@gmail.com])
AM_INIT_AUTOMAKE([foreign])

AC_PROG_CC
AM_PROG_AR
AC_PROG_LIBTOOL

PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= 3.3.0])
AC_SUBST([LIBGNUTLS_CFLAGS])
AC_SUBST([LIBGNUTLS_LIBS])

AC_SUBST([with_kernel], [`uname -r`])
AC_SUBST([with_kernel_mod], [/lib/modules/$with_kernel/extra])
AC_SUBST([KERNEL_SRC], [/lib/modules/$with_kernel/build])
AC_SUBST([KERNEL_MOD], [$with_kernel_mod])
AC_CHECK_FILE([/lib/modules/$with_kernel/build/Makefile],
	      [], [AC_MSG_ERROR(no kernel-devel found)])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
	Makefile
	handshake/Makefile
	handshake/libquic.pc
	tests/Makefile
])
AC_OUTPUT
