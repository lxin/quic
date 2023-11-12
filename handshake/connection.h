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

#include <gnutls/crypto.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <linux/tls.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include "quic.h"

struct quic_data {
	uint8_t data[144];
	uint32_t datalen;
};

#define MAX_BUFLEN	2048
struct quic_buf {
	uint32_t buflen;
	uint8_t buf[MAX_BUFLEN];
};

struct quic_key {
	gnutls_cipher_algorithm_t cipher_type;
	gnutls_cipher_algorithm_t aead_type;
	gnutls_mac_algorithm_t prf_type;
	gnutls_aead_cipher_hd_t aead;
	gnutls_cipher_hd_t cipher;
	struct quic_data secret;
	struct quic_data key;
	struct quic_data iv;
	struct quic_data hp_key;
};

struct quic_frame {
	struct quic_frame *next;
	struct quic_buf data;
	uint32_t offset;
	uint32_t number;
};

struct quic_pktns {
	struct quic_frame *send_list;
	struct quic_frame *send_last;
	struct quic_frame *sent_list;
	struct quic_frame *sent_last;
	struct quic_frame *recv_list;
	struct quic_frame *recv_last;
	uint32_t send_offset;
	uint32_t send_number;
	uint32_t recv_offset;
	uint32_t recv_number;
	uint32_t number_base;
	uint32_t number_map;
	uint8_t ack_needed;
};

struct quic_pkthd {
	struct quic_data token;
	struct quic_data scid;
	struct quic_data dcid;

	struct quic_pktns *pktns;
	struct quic_key *key;

	/* pkt = packet->buf + offset */
	/* pkt_len = length + num_offset */
	/* payload_len = length - numlen */
	uint32_t len_offset;
	uint32_t length;
	uint32_t num_offset;
	uint32_t number;
	uint32_t numlen;

	uint32_t fr_offset;
	uint32_t offset;
	uint32_t hdlen;
	uint8_t type;
};

struct quic_conn {
	struct quic_pktns in_pktns;
	struct quic_pktns hs_pktns;
	struct quic_key in_key[2];
	struct quic_key hs_key[2];

	struct quic_handshake_parms *parms;
	struct quic_data priority;
	struct quic_data token;
	struct quic_data alpn;
	uint32_t cipher;
	int sockfd;

	gnutls_session_t session;
	struct timeval tv;
	timer_t timer;
	uint8_t errcode;
	uint8_t state;
	uint8_t version;

	struct quic_connection_id orig;
	struct quic_context context;
	struct quic_buf ctxdata;
	struct quic_buf packet;
	struct quic_pkthd hd;
};

enum {
	QUIC_CONN_HANDSHAKE_STATE_CLOSED,
	QUIC_CONN_HANDSHAKE_STATE_COMPLETED,
	QUIC_CONN_HANDSHAKE_STATE_CONFIRMED,
};

static inline int quic_conn_handshake_completed(struct quic_conn *conn)
{
	return conn->state == QUIC_CONN_HANDSHAKE_STATE_CONFIRMED;
}

static inline int quic_packet_send_more(struct quic_conn *conn)
{
	return conn->hs_pktns.send_list || conn->in_pktns.send_list;
}

#define DEBUG 0

static inline void print_debug(char const *fmt, ...)
{
	va_list arg;
	if (!DEBUG)
		return;
	printf("[DEBUG] ");
	va_start(arg, fmt);
	vprintf(fmt, arg);
	va_end(arg);
}

static inline void print_warn(char const *fmt, ...)
{
	va_list arg;
	printf("[WARN] ");
	va_start(arg, fmt);
	vprintf(fmt, arg);
	va_end(arg);
}

static inline void print_error(char const *fmt, ...)
{
	va_list arg;
	printf("[ERROR] ");
	va_start(arg, fmt);
	vprintf(fmt, arg);
	va_end(arg);
}

static inline void quic_dump_key(char *str, const uint8_t key[], int len)
{
	int i;

	printf("[DEBUG]   [%s](%d): ", str, len);
	for (i = 0; i < len; i ++)
		printf("%02x", key[i]);
	printf("\n");
}

static inline void quic_debug_dump_data(char *str, struct quic_data *data)
{
	quic_dump_key(str, data->data, data->datalen);
}

static inline void quic_debug_dump_key(struct quic_key *key)
{
	if (!DEBUG)
		return;

	quic_debug_dump_data("SECRET", &key->secret);
	quic_debug_dump_data("KEY", &key->key);
	quic_debug_dump_data("IV", &key->iv);
	quic_debug_dump_data("HPKEY", &key->hp_key);
}

int quic_crypto_derive_initial_keys(struct quic_conn *conn, uint8_t *data, uint32_t datalen);
int quic_crypto_read_write_crypto_data(struct quic_conn *conn, uint8_t encryption_level,
				       const uint8_t *data, size_t datalen);
int quic_crypto_encrypt(struct quic_conn *conn, struct quic_buf *packet, struct quic_pkthd *hd);
int quic_crypto_decrypt(struct quic_conn *conn, struct quic_buf *packet, struct quic_pkthd *hd);
int quic_crypto_client_set_x509_session(struct quic_conn *conn);
int quic_crypto_server_set_x509_session(struct quic_conn *conn);
int quic_crypto_client_set_psk_session(struct quic_conn *conn);
int quic_crypto_server_set_psk_session(struct quic_conn *conn);

int quic_packet_encode_transport_params(struct quic_conn *conn, uint8_t *dest, uint32_t destlen);
int quic_packet_decode_transport_params(struct quic_conn *conn, const uint8_t *data, uint32_t datalen);
int quic_packet_create(struct quic_conn *conn, struct quic_buf *packet);
int quic_packet_process(struct quic_conn *conn, struct quic_buf *packet);
void quic_packet_sent_timeout(struct quic_conn *conn);
void quic_packet_purge_lists(struct quic_conn *conn);
int64_t quic_packet_get_num(const uint8_t *p, size_t pkt_numlen);
