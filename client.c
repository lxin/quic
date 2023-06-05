#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include "quic.h"

#define MSG_LEN	4096
#define TOT_LEN	204800000
char msg[MSG_LEN + 1];

int main(int argc, char *argv[])
{
	struct quic_connection *conn;
	struct quic_endpoint *ep;
	int64_t stream_id = -1;
	int ret, sockfd;

	if (argc != 3 && argc != 5) {
		printf("%s <PEER ADDR> <PEER PORT> [<PRIVATE_KEY_FILE> <CERTIFICATE_FILE>]\n", argv[0]);
		return 0;
	}

	ep = quic_create_endpoint(NULL, 0, 0, IS_KERN);
	if (!ep) {
		printf("socket failed\n");
		return -1;
	}

	if (argc == 7) {
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
	}

	conn = quic_start_connection(ep, argv[1], atoi(argv[2]));
	if (!conn)
		return -1;

	if (IS_KERN) { /* in-kernel QUIC (up-call handshake) */
		int flag = QUIC_STREAM_FLAG_NEW;
		uint64_t len = 0;
		int sid = 0, i;

		sockfd = quic_connection_sockfd(conn);
		if (sockfd < 0)
			return -1;
		/* sockfd can be passed to kernel by 'handshake' netlink for NFS use */
		printf("setup kernel quic done %d\n", sockfd);

		for (i = 0; i < MSG_LEN; i++)
			msg[i] = i % 10 + 48;
		msg[i] = '\0';
		while (1) {
			if (len) {
				flag = 0;
				if (len == TOT_LEN - MSG_LEN)
					flag = QUIC_STREAM_FLAG_FIN;
			}
			ret = quic_kernel_sendmsg(sockfd, msg, strlen(msg), sid, flag);
			if (ret == -1) {
				printf("send %d %d\n", ret, errno);
				return -1;
			}
			len += ret;
			printf("send %d %lld\n", ret, len);
			if (len >= TOT_LEN)
				break;
		}
		printf("send done\n");

		memset(msg, 0, sizeof(msg));
		ret = quic_kernel_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
		if (ret == -1) {
			printf("recv error %d %d\n", ret, errno);
			return 1;
		}
		printf("recv: \"%s\", len: %d, stream_id: %d, flag: %d\n", msg, ret, sid, flag);
		return 0;
	}
	strcpy(msg, "hello quic");
	ret = quic_send_message(conn, &stream_id, msg, strlen(msg) + 1);
	if (ret < 0) {
		printf("send failed\n");
		return -1;
	}
	printf("send %d\n", ret);
	sleep(3);

	quic_close_connection(conn);
	quic_release_endpoint(ep);
	return 0;
}
