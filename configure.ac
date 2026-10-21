AC_INIT([quic], [1.0], [lucien.xin@gmail.com])
AM_INIT_AUTOMAKE([foreign])

AC_DEFUN([CHECK_KSYMS], [
	AS_IF([grep -q "$1" $kernel/build/$2],
	      [test "x$3" != "x" && kcflags=$kcflags"-DLINUX_KERNEL_NO_$3= "],
	      [test "x$4" != "x" && kcflags=$kcflags"-DLINUX_KERNEL_NO_$4= "])
])

AC_PROG_CC
AM_PROG_AR
LT_INIT

PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= 3.7.2])
AC_SUBST([LIBGNUTLS_CFLAGS])
AC_SUBST([LIBGNUTLS_LIBS])

AC_ARG_WITH([modules], AS_HELP_STRING([--without-modules], [skip building kernel modules]))

if test "x$with_modules" != "xno"; then
	kernel="/lib/modules/`uname -r`"
	if test -d "$kernel/kernel/net/quic" && test "x$with_modules" != "xyes" ; then
		AC_MSG_NOTICE([quic module found in kernel, skipping build])
	else
		AC_SUBST([MODULES], [modules])
		AC_SUBST([KERNEL_BUILD], [$kernel/build])
		AC_SUBST([KERNEL_EXTRA], [$kernel/extra])
		test -f "$kernel/build/Makefile" || AC_MSG_ERROR([no kernel-devel found])

		kcflags=""
		CHECK_KSYMS([release(struct sock ], [include/net/udp_tunnel.h], [], [944bfc1b1c6f])
		CHECK_KSYMS([sock(.*struct sock ], [include/net/udp_tunnel.h], [], [2cba193628fe])
		CHECK_KSYMS([proto_memory], [include/net/proto_memory.h], [], [f3d93817fba3])
		CHECK_KSYMS([ip6cb_flags], [include/net/udp_tunnel.h], [], [f78c75d84fe8])
		CHECK_KSYMS([ipv6_pinfo_offset], [include/net/sock.h], [], [f5f80e32de12])
		CHECK_KSYMS([ipv6_fl_list], [include/net/inet_sock.h], [], [1c17f4373d4d])
		CHECK_KSYMS([unaligned], [include/linux/unaligned.h], [], [5f60d5f6bbc1])
		CHECK_KSYMS([ipcb_flags], [include/net/udp_tunnel.h], [], [e3411e326fa4])
		CHECK_KSYMS([proto_accept_arg], [include/net/sock.h], [], [92ef0fd55ac8])
		CHECK_KSYMS([sockaddr_unsized], [include/net/sock.h], [], [449f68f8fffa])
		CHECK_KSYMS([\*addr_len], [include/net/sock.h], [8341c989ac77], [])
		CHECK_KSYMS([karg], [include/net/sock.h], [], [e1d001fa5b47])
		CHECK_KSYMS([rps], [include/net/rps.h], [], [490a79faf95e])
		CHECK_KSYMS([inet_sk_get_local_port_range], [Module.symvers], [], [91d0b78c5177])
		CHECK_KSYMS([inet6_sock_destruct], [Module.symvers], [], [1651951ebea5])
		CHECK_KSYMS([hrtimer_setup], [Module.symvers], [], [908a1d775422])
		CHECK_KSYMS([timer_delete], [Module.symvers], [], [bb663f0f3c39])
		AC_SUBST([KCFLAGS], [$kcflags])

		AC_CONFIG_FILES([modules/Makefile])
	fi
else
	AC_MSG_NOTICE([--without-modules specified, skipping kernel module build])
fi

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile libquic/Makefile libquic/libquic.pc tests/Makefile])
AC_OUTPUT
