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

#include <linux/sockptr.h>
#include <uapi/linux/quic.h>

int quic_do_setsockopt(struct sock *sk, int optname, sockptr_t optval, unsigned int optlen);
int quic_do_getsockopt(struct sock *sk, int optname, sockptr_t optval, sockptr_t optlen);

#endif
