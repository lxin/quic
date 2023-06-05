#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include "quic.h"

#define MSG_LEN	2048
char msg[MSG_LEN + 1];

int main(void)
{
	struct quic_connection *conn;
	struct quic_endpoint *ep;
	int64_t stream_id = -1;
	int ret, sockfd;

	ep = quic_create_endpoint("127.0.0.1", 4321, 0, IS_KERN);
	if (!ep) {
		printf("socket failed\n");
		return -1;
	}

	conn = quic_start_connection(ep, "127.0.0.1", 1234);
	if (!conn)
		return -1;

	if (IS_KERN) { /* in-kernel QUIC (up-call handshake) */
		int flag = QUIC_STREAM_FLAG_NEW;
		int sid = 0, len = 0;

		sockfd = quic_connection_sockfd(conn);
		if (sockfd < 0)
			return -1;
		/* sockfd can be passed to kernel by 'handshake' netlink for NFS use */
		printf("setup kernel quic done %d\n", sockfd);

		strcpy(msg, "hello quic, ");
		ret = quic_kernel_sendmsg(sockfd, msg, strlen(msg), sid, flag);
		if (ret == -1) {
			printf("send %d %d\n", ret, errno);
			return -1;
		}
		flag = 0;
		strcpy(msg, "this is sctp, ");
		ret = quic_kernel_sendmsg(sockfd, msg, strlen(msg), sid, flag);
		if (ret == -1) {
			printf("send %d %d\n", ret, errno);
			return -1;
		}
		flag = QUIC_STREAM_FLAG_FIN;
		strcpy(msg, "where is tcp?");
		ret = quic_kernel_sendmsg(sockfd, msg, strlen(msg), sid, flag);
		if (ret == -1) {
			printf("send %d %d\n", ret, errno);
			return -1;
		}

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
