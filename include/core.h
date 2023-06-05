#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2.h>
#include <gnutls/crypto.h>

#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

#include <pthread.h>
#include <ev.h>

#include "list.h"
#include "quic.h"
#include "kernel.h"
#include "debug.h"

enum {
	QUIC_STATE_CLOSED,
	QUIC_STATE_CONNECTING,
	QUIC_STATE_CONNECTED,
};

struct quic_endpoint {
	struct list_head conns;
	struct sockaddr_in a;
	int sockfd;

	char private_key[100];
	char certificate[100];
	uint8_t is_serv:1,
		is_kern:1;

	struct ev_loop *loop;
	struct ev_async aev;
	struct ev_io rev;
	pthread_t thread;
};

struct quic_key {
	uint8_t key[64];
	uint8_t keylen;
};

struct quic_connection {
	struct list_head list;
	struct quic_endpoint *ep;
	uint8_t state;
	uint8_t is_read:1,
		is_ready:1,
		is_accept:1;
	int sockfd;

	gnutls_certificate_credentials_t cred;
	ngtcp2_crypto_conn_ref conn_ref;
	ngtcp2_sockaddr_in la, ra;
	gnutls_session_t session;
	ngtcp2_conn *conn;
	uint32_t connecting_ts, connected_ts;

	struct quic_key secret[2];

	struct ev_async aev;

	struct list_head sndq, rcvq;
};

struct quic_message {
	struct list_head list;
	uint8_t *data;
	uint32_t datalen;
	uint64_t stream_id;
	uint32_t flags;
	uint64_t offset;
};

/* endpoint.c */
struct quic_connection *quic_endpoint_accept_conn(struct quic_endpoint *ep);
void quic_endpoint_add_conn(struct quic_endpoint *ep, struct quic_connection *conn);
void quic_endpoint_read_cb(struct ev_loop *loop, ev_io *e, int events);
void quic_endpoint_async_cb(struct ev_loop *loop, ev_async *e, int events);

/* connection.c */
int quic_connection_write(struct quic_connection *conn);
struct quic_connection *quic_connection_new(struct quic_endpoint *ep, struct sockaddr_in *a,
					    ngtcp2_pkt_hd *hd);

/* message.c */
struct quic_message *quic_message_sndq_dequeue(struct quic_connection *conn);
void quic_message_rcvq_enqueue(struct quic_connection *conn, struct quic_message *msg);
struct quic_message *quic_message_new(const uint8_t *data, uint32_t datalen, uint64_t stream_id,
				      uint32_t flags, uint64_t offset);

/* ngtcp2_conn.c */
int quic_ngtcp2_conn_init(struct quic_connection *conn, ngtcp2_pkt_hd *hd);

/* callbacks.c */
void quic_ngtcp2_conn_callbacks_init(ngtcp2_callbacks *callbacks);

/* kernel.c */
int quic_kernel_socket_setup(struct quic_connection *conn, uint8_t reuse);
