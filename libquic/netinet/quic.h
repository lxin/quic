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

struct quic_handshake_parms {
	uint32_t		timeout;	/* handshake timeout in milliseconds */

	gnutls_privkey_t	privkey;	/* private key for x509 handshake */
	gnutls_pcert_st		*cert;		/* certificate for x509 handshake */
	char			*cafile;	/* system ca is used if not set */
	char			*peername;	/* - server name for client side x509 handshake or,
						 * - psk identity name chosen during PSK handshake
						 */
	char			*names[10];	/* psk identifies in PSK handshake */
	gnutls_datum_t		keys[10];	/* - psk keys in PSK handshake, or,
						 * - certificates received in x509 handshake
						 */
	uint32_t		num_keys;	/* keys total numbers */
};

int quic_client_handshake_parms(int sockfd, struct quic_handshake_parms *parms);
int quic_server_handshake_parms(int sockfd, struct quic_handshake_parms *parms);

int quic_client_handshake(int sockfd, char *pkey_file, char *cert_file);
int quic_server_handshake(int sockfd, char *pkey_file, char *cert_file);

ssize_t quic_sendmsg(int sockfd, const void *msg, size_t len, uint64_t sid, uint32_t flag);
ssize_t quic_recvmsg(int sockfd, void *msg, size_t len, uint64_t *sid, uint32_t *flag);

void quic_set_log_level(int level);
typedef void (*quic_log_func)(char const *fmt, ...);
void quic_set_log_funcs(quic_log_func debug, quic_log_func warn, quic_log_func error);
