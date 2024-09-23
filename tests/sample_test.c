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
	char msg[50], *psk, *host;
	unsigned int flags;
	int ret, sockfd;
	int64_t sid;

	if (argc < 6) {
		printf("%s client <PEER ADDR> <PEER PORT> <PSK_FILE | 'none'> "
		       "<HOSTNAME | 'none'> [ALPN]\n", argv[0]);
		return 0;
	}

	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
	if (sockfd < 0) {
		printf("socket create failed\n");
		return -1;
	}

	ra.sin_family = AF_INET;
	ra.sin_port = htons(atoi(argv[3]));
	inet_pton(AF_INET, argv[2], &ra.sin_addr.s_addr);

	if (connect(sockfd, (struct sockaddr *)&ra, sizeof(ra))) {
		printf("socket connect failed\n");
		return -1;
	}

	psk  = strcmp(argv[4], "none") ? argv[4] : NULL;
	host = strcmp(argv[5], "none") ? argv[5] : NULL;
	if (quic_client_handshake(sockfd, psk, host, argv[6]))
		return -1;

	/* set MSG_STREAM_NEW flag to open a stream while sending first data
	 * or call getsockopt(QUIC_SOCKOPT_STREAM_OPEN) to open a stream.
	 * set MSG_STREAM_FIN to mark the last data on this stream.
	 */
	strcpy(msg, "hello quic server!");
	sid = QUIC_STREAM_TYPE_UNI_MASK;
	flags = MSG_STREAM_NEW | MSG_STREAM_FIN;
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d %d\n", ret, errno);
		return -1;
	}
	printf("send '%s' on stream %d\n", msg, (int)sid);

	flags = 0;
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg) - 1, &sid, &flags);
	if (ret == -1) {
		printf("recv error %d %d\n", ret, errno);
		return 1;
	}
	printf("recv '%s' on stream %d\n", msg, (int)sid);

	close(sockfd);
	return 0;
}

static int do_server(int argc, char *argv[])
{
	unsigned int addrlen, flags;
	struct sockaddr_in sa = {};
	char msg[50], *alpn, *cert;
	int listenfd, sockfd, ret;
	int64_t sid;

	if (argc < 6) {
		printf("%s server <LOCAL ADDR> <LOCAL PORT> <PRIVATE_KEY_FILE | PSK_FILE> "
		       "<CERTIFICATE_FILE | 'none'> [ALPN]\n", argv[0]);
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
	alpn = argv[6]; /* For kernel ALPN match */
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

	cert = strcmp(argv[5], "none") ? argv[5] : NULL;
	if (quic_server_handshake(sockfd, argv[4], cert, argv[6]))
		return -1;

	flags = 0;
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg) - 1, &sid, &flags);
	if (ret == -1) {
		printf("recv error %d %d\n", ret, errno);
		return 1;
	}
	printf("recv '%s' on stream %d\n", msg, (int)sid);

	strcpy(msg, "hello quic client!");
	sid = QUIC_STREAM_TYPE_SERVER_MASK;
	flags = MSG_STREAM_NEW | MSG_STREAM_FIN;
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d %d\n", ret, errno);
		return -1;
	}
	printf("send '%s' on stream %d\n", msg, (int)sid);

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
