/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#ifndef _LINUX_QUIC_H
#define _LINUX_QUIC_H

#include <uapi/linux/quic.h>

int quic_kernel_setsockopt(struct sock *sk, int optname, void *optval, unsigned int optlen);
int quic_kernel_getsockopt(struct sock *sk, int optname, void *optval, unsigned int *optlen);

#endif
