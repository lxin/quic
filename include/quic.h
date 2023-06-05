#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "kernel.h"

#ifdef IN_KERNEL_QUIC
#define IS_KERN 1
#else
#define IS_KERN 0
#endif

enum {
	QUIC_CONFIG_PRIVATE_KEY,
	QUIC_CONFIG_CERTIFICATE,
};

struct quic_endpoint *quic_create_endpoint(char *ip, uint16_t port, uint8_t is_serv,
					   uint8_t is_kern);
int quic_config_endpoint(struct quic_endpoint *ep, uint8_t optname, char *opt, int len);

struct quic_connection *quic_start_connection(struct quic_endpoint *ep, char *ip, uint16_t port);
struct quic_connection *quic_accept_connection(struct quic_endpoint *ep);
int quic_connection_sockfd(struct quic_connection *conn);

int quic_close_connection(struct quic_connection *conn);
int quic_release_endpoint(struct quic_endpoint *ep);

int quic_send_message(struct quic_connection *conn, int64_t *stream_id, char *data, size_t datalen);
int quic_recv_message(struct quic_connection *conn, int64_t *stream_id, char *data, size_t datalen);

int quic_kernel_sendmsg(int sockfd, const void *msg, size_t len, uint32_t stream_id,
			uint32_t stream_flag);
int quic_kernel_recvmsg(int sockfd, void *msg, size_t len, uint32_t *stream_id,
			uint32_t *stream_flag);
