#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include "quic.h"
#include <sys/socket.h>
#include <arpa/inet.h>

#define MSG_LEN 4096
char msg[MSG_LEN + 1];

int main(int argc, char *argv[])
{
	struct quic_connection *conn;
	struct quic_endpoint *ep;
	int64_t stream_id;
	int ret, sockfd;

	if (argc != 5) {
		printf("%s <LOCAL ADDR> <LOCAL PORT> <PRIVATE_KEY_FILE> <CERTIFICATE_FILE>\n", argv[0]);
		return 0;
	}

	ep = quic_create_endpoint(argv[1], atoi(argv[2]), 1, IS_KERN);
	if (!ep) {
		printf("socket failed\n");
		return -1;
	}

	ret = quic_config_endpoint(ep, QUIC_CONFIG_PRIVATE_KEY,
				   argv[3], strlen(argv[3]) + 1);
	if (ret) {
		printf("config private key failed\n");
		return -1;
	}

	ret = quic_config_endpoint(ep, QUIC_CONFIG_CERTIFICATE,
				   argv[4], strlen(argv[4]) + 1);
	if (ret) {
		printf("config certificate failed\n");
		return -1;
	}

	conn = quic_accept_connection(ep);
	if (!conn)
		return -1;
	if (IS_KERN) { /* in-kernel quic (up-call handshake) */
		int flag = 0, sid = 0;
		uint64_t len = 0;

		sockfd = quic_connection_sockfd(conn);
		if (sockfd < 0)
			return -1;
		/* sockfd can be passed to kernel by 'handshake' netlink for NFS use */
		printf("setup kernel quic done %d\n", sockfd);

		while (1) {
			ret = quic_kernel_recvmsg(sockfd, &msg, sizeof(msg),
						  &sid, &flag);
			if (ret == -1) {
				printf("recv error %d\n", ret, errno);
				return 1;
			}
			len += ret;
			if (len == MSG_LEN * 5) { /* do connection migration with bind port changed */
				struct sockaddr_in a = {};

				a.sin_family = AF_INET;
				a.sin_port = htons(atoi(argv[2]) + 1);
				inet_pton(AF_INET, argv[1], &a.sin_addr.s_addr);
				if (setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_MIGRATION, &a, sizeof(a)))
					return -1;
			}
			printf("recv len: %lld, stream_id: %d.\n", len, sid);
			if (flag & QUIC_STREAM_FLAG_FIN)
				break;
		}

		sid = 1;
		flag = QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN;
		strcpy(msg, "recv done");
		ret = quic_kernel_sendmsg(sockfd, msg, strlen(msg), sid, flag);
		if (ret == -1) {
			printf("send %d %d\n", ret, errno);
			return -1;
		}
		sleep(1);
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
