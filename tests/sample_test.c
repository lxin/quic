#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/quic.h>
#include <sys/syslog.h>

static const char *parse_address(
	char const *address, char const *port, struct sockaddr_storage *sas)
{
	struct addrinfo hints = {0};
	struct addrinfo *res;
	int rc;

	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	rc = getaddrinfo(address, port, &hints, &res);
	if (rc != 0)
		return gai_strerror(rc);
	memcpy(sas, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return NULL;
}

static int do_client(int argc, char *argv[])
{
	struct sockaddr_storage ra = {};
	char msg[50], *psk, *host;
	unsigned int flags;
	int ret, sockfd;
	const char *rc;
	int64_t sid;

	if (argc < 6) {
		printf("%s client <PEER ADDR> <PEER PORT> <PSK_FILE | 'none'> "
		       "<HOSTNAME | 'none'> [ALPN]\n", argv[0]);
		return 0;
	}

	rc = parse_address(argv[2], argv[3], &ra);
	if (rc != NULL) {
		printf("parse address failed: %s\n", rc);
		return -1;
	}
	sockfd = socket(ra.ss_family, SOCK_DGRAM, IPPROTO_QUIC);
	if (sockfd < 0) {
		printf("socket create failed\n");
		return -1;
	}

	if (connect(sockfd, (struct sockaddr *)&ra, sizeof(ra))) {
		printf("socket connect failed\n");
		return -1;
	}

	psk  = strcmp(argv[4], "none") ? argv[4] : NULL;
	host = strcmp(argv[5], "none") ? argv[5] : NULL;
	if (quic_client_handshake(sockfd, psk, host, argv[6]))
		return -1;

	/* set MSG_QUIC_STREAM_NEW flag to open a stream while sending first data
	 * or call getsockopt(QUIC_SOCKOPT_STREAM_OPEN) to open a stream.
	 * set MSG_QUIC_STREAM_FIN to mark the last data on this stream.
	 */
	strcpy(msg, "hello quic server!");
	sid = QUIC_STREAM_TYPE_UNI_MASK;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
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
	struct sockaddr_storage sa = {};
	char msg[50], *alpn, *cert;
	int listenfd, sockfd, ret;
	const char *rc;
	int64_t sid;

	if (argc < 6) {
		printf("%s server <LOCAL ADDR> <LOCAL PORT> <PRIVATE_KEY_FILE | PSK_FILE> "
		       "<CERTIFICATE_FILE | 'none'> [ALPN]\n", argv[0]);
		return 0;
	}

	rc = parse_address(argv[2], argv[3], &sa);
	if (rc != NULL) {
		printf("parse address failed: %s\n", rc);
		return -1;
	}
	listenfd = socket(sa.ss_family, SOCK_DGRAM, IPPROTO_QUIC);
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
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d %d\n", ret, errno);
		return -1;
	}
	printf("send '%s' on stream %d\n", msg, (int)sid);

	flags = 0;
	quic_recvmsg(sockfd, msg, sizeof(msg) - 1, &sid, &flags);

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

	quic_set_log_level(LOG_NOTICE);

	if (!strcmp(argv[1], "client"))
		return do_client(argc, argv);

	return do_server(argc, argv);
}
