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

#include <sys/socket.h>
#include <linux/quic.h>

int quic_client_x509_handshake(int sockfd, struct sockaddr_in *ra);
int quic_server_x509_handshake(int sockfd, char *pkey, char *cert);

int quic_client_psk_handshake(int sockfd, struct sockaddr_in *ra, char *psk);
int quic_server_psk_handshake(int sockfd, char *psk);

int quic_sendmsg(int sockfd, const void *msg, size_t len, uint32_t sid, uint32_t flag);
int quic_recvmsg(int sockfd, void *msg, size_t len, uint32_t *sid, uint32_t *flag);
