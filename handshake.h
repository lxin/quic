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

struct quic_handshake_parms {
	uint32_t		timeout;	/* handshake timeout in seconds */

	gnutls_privkey_t	privkey;	/* private key for x509 handshake */
	gnutls_pcert_st		*cert;		/* certificate for x509 handshake */
	char 			*peername;	/* - server name for client side x509 handshake or,
						 * - psk identity name chosen during PSK handshake
						 */
	char			*names[10];	/* psk identifies in PSK handshake */
	gnutls_datum_t		keys[10];	/* - psk keys in PSK handshake, or,
						 * - certificates received in x509 handshake
						 */
	uint32_t		num_keys;	/* keys total numbers */
};

int quic_client_x509_tlshd(int sockfd, struct sockaddr *ra, struct quic_handshake_parms *parms);
int quic_server_x509_tlshd(int sockfd, struct quic_handshake_parms *parms);

int quic_client_psk_tlshd(int sockfd, struct sockaddr *ra, struct quic_handshake_parms *parms);
int quic_server_psk_tlshd(int sockfd, struct quic_handshake_parms *parms);

int quic_client_x509_handshake(int sockfd, struct sockaddr *ra);
int quic_server_x509_handshake(int sockfd, char *pkey, char *cert);

int quic_client_psk_handshake(int sockfd, struct sockaddr *ra, char *psk);
int quic_server_psk_handshake(int sockfd, char *psk);

int quic_sendmsg(int sockfd, const void *msg, size_t len, uint32_t sid, uint32_t flag);
int quic_recvmsg(int sockfd, void *msg, size_t len, uint32_t *sid, uint32_t *flag);
