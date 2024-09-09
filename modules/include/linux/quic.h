/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#ifndef __linux_quic_h__
#define __linux_quic_h__

#include <uapi/linux/quic.h>

int quic_sock_setopt(struct sock *sk, int optname, void *optval, unsigned int optlen);
int quic_sock_getopt(struct sock *sk, int optname, void *optval, unsigned int *optlen);

#endif
