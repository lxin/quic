// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is the userspace handshake part for the QUIC kernel implementation
 *
 * Initialization/cleanup for QUIC protocol support.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include <gnutls/abstract.h>
#include <sys/socket.h>
#include <linux/quic.h>

/* Socket option layer for QUIC */
#ifndef SOL_QUIC
#define SOL_QUIC		288
#endif

#ifndef IPPROTO_QUIC
#define IPPROTO_QUIC		261
#endif

#define QUIC_PRIORITY \
	"NORMAL:-VERS-ALL:+VERS-TLS1.3:+PSK:+ECDHE-PSK:-CIPHER-ALL:+AES-128-GCM:+AES-256-GCM:" \
	"+CHACHA20-POLY1305:+AES-128-CCM:-GROUP-ALL:+GROUP-SECP256R1:" \
	"+GROUP-X25519:+GROUP-SECP384R1:+GROUP-SECP521R1:" \
	"%DISABLE_TLS13_COMPAT_MODE"

int quic_client_handshake(int sockfd, const char *pkey_file,
			  const char *hostname, const char *alpns);
int quic_server_handshake(int sockfd, const char *pkey_file,
			  const char *cert_file, const char *alpns);

enum quic_handshake_step_op {
	QUIC_HANDSHAKE_STEP_OP_SENDMSG = 1,
	QUIC_HANDSHAKE_STEP_OP_RECVMSG,
};

struct quic_handshake_step_sendmsg {
	const struct msghdr *msg;
	int flags;
	ssize_t retval;
};

struct quic_handshake_step_recvmsg {
	struct msghdr *msg;
	int flags;
	ssize_t retval;
};

struct quic_handshake_step {
	enum quic_handshake_step_op op;

	union {
		struct quic_handshake_step_sendmsg s_sendmsg;
		struct quic_handshake_step_recvmsg s_recvmsg;
	};
};

int quic_handshake_init(gnutls_session_t session,
			struct quic_handshake_step **pstep);
int quic_handshake_step(gnutls_session_t session,
			struct quic_handshake_step **pstep);
void quic_handshake_deinit(gnutls_session_t session);

int quic_handshake(gnutls_session_t session);

int quic_session_get_data(gnutls_session_t session,
			  void *data, size_t *size);
int quic_session_set_data(gnutls_session_t session,
			  const void *data, size_t size);

int quic_session_get_alpn(gnutls_session_t session,
			  void *data, size_t *size);
int quic_session_set_alpn(gnutls_session_t session,
			  const void *data, size_t size);

ssize_t quic_sendmsg(int sockfd, const void *msg, size_t len,
		     int64_t sid, uint32_t flags);
ssize_t quic_recvmsg(int sockfd, void *msg, size_t len,
		     int64_t *sid, uint32_t *flags);

typedef void (*quic_set_log_func_t)(int level, const char *msg);
quic_set_log_func_t quic_set_log_func(quic_set_log_func_t func);
int quic_set_log_level(int level);
