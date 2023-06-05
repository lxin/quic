#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "quic.h"

#define PKEY_FILE "keys/pkey.key"
#define CERT_FILE "keys/cert.crt"

#define MSG_LEN 2048
char msg[MSG_LEN + 1];

int main(void)
{
	struct quic_connection *conn;
	struct quic_endpoint *ep;
	int64_t stream_id;
	int ret, sockfd;

	ep = quic_create_endpoint("127.0.0.1", 1234, 1, IS_KERN);
	if (!ep) {
		printf("socket failed\n");
		return -1;
	}

	ret = quic_config_endpoint(ep, QUIC_CONFIG_PRIVATE_KEY,
				   PKEY_FILE, strlen(PKEY_FILE) + 1);
	if (ret) {
		printf("config private key failed\n");
		return -1;
	}

	ret = quic_config_endpoint(ep, QUIC_CONFIG_CERTIFICATE,
				   CERT_FILE, strlen(CERT_FILE) + 1);
	if (ret) {
		printf("config certificate failed\n");
		return -1;
	}

	conn = quic_accept_connection(ep);
	if (!conn)
		return -1;
	if (IS_KERN) { /* in-kernel quic (up-call handshake) */
		int flag = 0, sid = 0, len = 0;

		sockfd = quic_connection_sockfd(conn);
		if (sockfd < 0)
			return -1;
		/* sockfd can be passed to kernel by 'handshake' netlink for NFS use */
		printf("setup kernel quic done %d\n", sockfd);

		while (1) {
			ret = quic_kernel_recvmsg(sockfd, &msg[len], sizeof(msg) - len,
						  &sid, &flag);
			if (ret == -1) {
				printf("recv error %d\n", ret, errno);
				return 1;
			}
			len += ret;
			if (flag & QUIC_STREAM_FLAG_FIN)
				break;
		}
		printf("recv: \"%s\", len: %d, stream_id: %d.\n", msg, ret, sid);

		sid = 1;
		flag = QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN;
		strcpy(msg, "I don't know!");
		ret = quic_kernel_sendmsg(sockfd, msg, strlen(msg), sid, flag);
		if (ret == -1) {
			printf("send %d %d\n", ret, errno);
			return -1;
		}
		return 0;
	}
	ret = quic_recv_message(conn, &stream_id, msg, sizeof(msg));
	if (ret < 0) {
		printf("recv failed\n");
		return -1;
	}
	printf("recv %d: %d %s\n", ret, stream_id, msg);

	quic_close_connection(conn);
	quic_release_endpoint(ep);
	return 0;
}
