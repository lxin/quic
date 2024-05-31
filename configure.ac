AC_INIT([quic], [1.0], [lucien.xin@gmail.com])
AM_INIT_AUTOMAKE([foreign])

AC_PROG_CC
AM_PROG_AR
LT_INIT

PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= 3.7.0])
AC_SUBST([LIBGNUTLS_CFLAGS])
AC_SUBST([LIBGNUTLS_LIBS])

AC_SUBST([kernel], [/lib/modules/`uname -r`])
AC_CHECK_FILE([$kernel/kernel/net/quic],
	      [AC_MSG_NOTICE(quic module with kernel found and skip building it)
	       AC_CHECK_FILE([/usr/include/linux/quic.h], [], [AC_MSG_ERROR([no kernel-headers found])])],
	      [AC_SUBST([MODULES], [modules])
	       AC_SUBST([KERNEL_BUILD], [$kernel/build])
	       AC_SUBST([KERNEL_EXTRA], [$kernel/extra])
	       AC_CHECK_FILE([$kernel/build/Makefile], [], [AC_MSG_ERROR(no kernel-devel found)])
	       AC_CONFIG_FILES([modules/Makefile])])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile libquic/Makefile libquic/libquic.pc tests/Makefile])
AC_OUTPUT
