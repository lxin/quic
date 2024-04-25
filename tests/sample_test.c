#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <netinet/quic.h>

static int do_client(int argc, char *argv[])
{
	struct sockaddr_in ra = {};
	char msg[50], *alpn;
	int ret, sockfd;

	if (argc < 4) {
		printf("%s client <PEER ADDR> <PEER PORT> [ALPN]\n", argv[0]);
		return 0;
	}

	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
	if (sockfd < 0) {
		printf("socket create failed\n");
		return -1;
	}

	alpn = argv[4];
	if (alpn && setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_ALPN, alpn, strlen(alpn))) {
		printf("socket setsockopt alpn failed\n");
		return -1;
	}

	ra.sin_family = AF_INET;
	ra.sin_port = htons(atoi(argv[3]));
	inet_pton(AF_INET, argv[2], &ra.sin_addr.s_addr);

	if (connect(sockfd, (struct sockaddr *)&ra, sizeof(ra))) {
		printf("socket connect failed\n");
		return -1;
	}

	if (quic_client_handshake(sockfd, NULL, NULL))
		return -1;

	/* NOTE: quic_send/recvmsg() allows get/setting stream id and flags,
	 * comparing to send/recv():
	 * sid = 0;
	 * flag = QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN;
	 * quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	 * quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	 */
	strcpy(msg, "hello quic server!");
	ret = send(sockfd, msg, strlen(msg), MSG_SYN | MSG_FIN);
	if (ret == -1) {
		printf("send error %d %d\n", ret, errno);
		return -1;
	}
	printf("send %d\n", ret);

	memset(msg, 0, sizeof(msg));
	ret = recv(sockfd, msg, sizeof(msg), 0);
	if (ret == -1) {
		printf("recv error %d %d\n", ret, errno);
		return 1;
	}
	printf("recv: \"%s\", len: %d\n", msg, ret);

	close(sockfd);
	return 0;
}

static int do_server(int argc, char *argv[])
{
	struct sockaddr_in sa = {};
	int listenfd, sockfd, ret;
	unsigned int addrlen;
	char msg[50], *alpn;

	if (argc < 6) {
		printf("%s server <LOCAL ADDR> <LOCAL PORT> <PRIVATE_KEY_FILE> <CERTIFICATE_FILE> [ALPN]\n", argv[0]);
		return 0;
	}

	sa.sin_family = AF_INET;
	sa.sin_port = htons(atoi(argv[3]));
	inet_pton(AF_INET, argv[2], &sa.sin_addr.s_addr);
	listenfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
	if (listenfd < 0) {
		printf("socket create failed\n");
		return -1;
	}
	if (bind(listenfd, (struct sockaddr *)&sa, sizeof(sa))) {
		printf("socket bind failed\n");
		return -1;
	}
	alpn = argv[6];
	if (alpn && setsockopt(listenfd, SOL_QUIC, QUIC_SOCKOPT_ALPN, alpn, strlen(alpn))) {
		printf("socket setsockopt alpn failed\n");
		return -1;
	}
	if (listen(listenfd, 1)) {
		printf("socket listen failed\n");
		return -1;
	}
	addrlen = sizeof(sa);
	sockfd = accept(listenfd, (struct sockaddr *)&sa, &addrlen);
	if (sockfd < 0) {
		printf("socket accept failed %d %d\n", errno, sockfd);
		return -1;
	}

	if (quic_server_handshake(sockfd, argv[4], argv[5]))
		return -1;

	memset(msg, 0, sizeof(msg));
	ret = recv(sockfd, msg, sizeof(msg), 0);
	if (ret == -1) {
		printf("recv error %d %d\n", ret, errno);
		return 1;
	}
	printf("recv: \"%s\", len: %d\n", msg, ret);

	strcpy(msg, "hello quic client!");
	ret = send(sockfd, msg, strlen(msg), MSG_SYN | MSG_FIN);
	if (ret == -1) {
		printf("send error %d %d\n", ret, errno);
		return -1;
	}
	printf("send %d\n", ret);

	close(sockfd);
	close(listenfd);
	return 0;
}

int main(int argc, char *argv[])
{
	if (argc < 2 || (strcmp(argv[1], "server") && strcmp(argv[1], "client"))) {
		printf("%s server|client ...\n", argv[0]);
		return 0;
	}

	if (!strcmp(argv[1], "client"))
		return do_client(argc, argv);

	return do_server(argc, argv);
}
