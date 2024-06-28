/*
 * Generic definitions and forward declarations for libquic.
 *
 * Copyright (c) 2024 Red Hat, Inc.
 *
 * libquic is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "netinet/quic.h"

#define QUIC_MAX_DATA_LEN	4096
#define QUIC_MAX_ALPNS_LEN	128

struct quic_msg {
	struct quic_msg *next;
	uint8_t data[QUIC_MAX_DATA_LEN];
	uint32_t len;
	uint8_t level;
};

struct quic_conn {
	struct quic_handshake_parms *parms;
	char alpns[QUIC_MAX_ALPNS_LEN];
	uint8_t ticket[QUIC_MAX_DATA_LEN];
	uint32_t ticket_len;
	uint32_t cipher;
	int sockfd;

	gnutls_session_t session;
	uint8_t recv_ticket:1;
	uint8_t completed:1;
	uint8_t cert_req:2;
	uint8_t is_serv:1;
	uint32_t errcode;
	timer_t timer;

	struct quic_msg *send_list;
	struct quic_msg *send_last;
	struct quic_msg recv_msg;
};

extern struct quic_conn *quic_conn_create(int sockfd, struct quic_handshake_parms *parms);
extern int quic_conn_configure_session(struct quic_conn *conn);
extern int quic_conn_start_handshake(struct quic_conn *conn);
extern void quic_conn_destroy(struct quic_conn *conn);

extern void quic_log_debug(char const *fmt, ...);
extern void quic_log_error(char const *fmt, ...);
extern void quic_log_notice(char const *fmt, ...);
extern void quic_log_gnutls_error(int error);

extern int quic_file_read_psk(char *file, char *identity[], gnutls_datum_t *pkey);
extern int quic_file_read_pkey(char *file, gnutls_privkey_t *privkey);
extern int quic_file_read_cert(char *file, gnutls_pcert_st **cert);
