AC_INIT([quic], [1.0], [lucien.xin@gmail.com])
AM_INIT_AUTOMAKE([foreign])

AC_PROG_CC
AM_PROG_AR
LT_INIT

PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= 3.7.0])
AC_SUBST([LIBGNUTLS_CFLAGS])
AC_SUBST([LIBGNUTLS_LIBS])

AC_ARG_WITH([modules], AS_HELP_STRING([--without-modules], [skip building kernel modules]))

if test "x$with_modules" != "xno"; then
	kernel="/lib/modules/`uname -r`"
	if test -d "$kernel/kernel/net/quic" && test "x$with_modules" != "xyes" ; then
		BUILTIN_MODULES=yes
		AC_MSG_NOTICE([quic module found in kernel, skipping build])
		test -f /usr/include/linux/quic.h || AC_MSG_ERROR([no kernel-headers found])
	else
		AC_SUBST([MODULES], [modules])
		AC_SUBST([KERNEL_BUILD], [$kernel/build])
		AC_SUBST([KERNEL_EXTRA], [$kernel/extra])
		test -f "$kernel/build/Makefile" || AC_MSG_ERROR([no kernel-devel found])
		AC_CONFIG_FILES([modules/Makefile])
	fi
else
	AC_MSG_NOTICE([--without-modules specified, skipping kernel module build])
fi

AM_CONDITIONAL([BUILTIN_MODULES], [test "x$BUILTIN_MODULES" = "xyes"])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile libquic/Makefile libquic/libquic.pc tests/Makefile])
AC_OUTPUT
