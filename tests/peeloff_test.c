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

static const char *parse_address(char *address, char const *port, struct sockaddr_storage *sas)
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
	struct quic_stream_peeloff pinfo = {};
	struct quic_stream_info sinfo = {};
	struct sockaddr_storage ra = {};
	int ret, sockfd, strmfd;
	unsigned int optlen;
	const char *rc;
	char msg[50];

	if (argc < 3) {
		printf("%s client <PEER ADDR> <PEER PORT>\n", argv[0]);
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

	if (quic_client_handshake(sockfd, NULL, NULL, NULL))
		return -1;

	/* open a unidirectional stream */
	optlen = sizeof(sinfo);
	sinfo.stream_id = -1;
	sinfo.stream_flags = MSG_STREAM_UNI;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &sinfo, &optlen);
	if (ret) {
		printf("getsockopt stream_open failed\n");
		return -1;
	}

	/* peel off the stream */
	optlen = sizeof(pinfo);
	pinfo.stream_id = sinfo.stream_id;
	strmfd = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_PEELOFF, &pinfo, &optlen);
	if (strmfd < 0) {
		printf("getsockopt stream_peeloff failed %d\n", strmfd);
		return -1;
	}

	/* send data on the peeled off stream */
	strcpy(msg, "hello quic server!");
	ret = send(strmfd, msg, strlen(msg), 0);
	if (ret == -1) {
		printf("send error %d %d\n", ret, errno);
		return -1;
	}
	printf("send '%s' on stream %d\n", msg, (int)pinfo.stream_id);
	close(strmfd);

	recv(sockfd, NULL, 0, 0);
	close(sockfd);
	return 0;
}

static int do_server(int argc, char *argv[])
{
	struct quic_stream_peeloff pinfo = {};
	unsigned int addrlen, flags, optlen;
	int listenfd, sockfd, strmfd, ret;
	struct sockaddr_storage sa = {};
	struct quic_event_option event;
	union quic_event *ev;
	const char *rc;
	char msg[50];

	if (argc < 5) {
		printf("%s server <LOCAL ADDR> <LOCAL PORT> <PRIVATE_KEY_FILE> "
		       "<CERTIFICATE_FILE>\n", argv[0]);
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

	if (quic_server_handshake(sockfd, argv[4], argv[5], NULL))
		return -1;

	/* enable stream update event */
	event.type = QUIC_EVENT_STREAM_UPDATE;
	event.on = 1;
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_EVENT, &event, sizeof(event));
	if (ret == -1) {
		printf("socket setsockopt event error %d\n", errno);
		return -1;
	}

	while (1) {
		/* wait for stream update event for new recv stream */
		flags = 0;
		memset(msg, 0, sizeof(msg));
		ret = quic_recvmsg(sockfd, msg, sizeof(msg) - 1, NULL, &flags);
		if (ret == -1) {
			printf("recv error %d %d\n", ret, errno);
			return 1;
		}
		if (!(flags & MSG_NOTIFICATION) || msg[0] != QUIC_EVENT_STREAM_UPDATE)
			continue;
		ev = (union quic_event *)&msg[1];
		if (ev->update.state != QUIC_STREAM_RECV_STATE_RECV)
			continue;

		/* peel off the stream */
		optlen = sizeof(pinfo);
		pinfo.stream_id = ev->update.id;
		strmfd = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_PEELOFF, &pinfo, &optlen);
		if (strmfd < 0) {
			printf("getsockopt stream_peeloff failed %d\n", ret);
			return -1;
		}

		/* read data from the peeled off stream */
		memset(msg, 0, sizeof(msg));
		ret = recv(strmfd, msg, sizeof(msg) - 1, 0);
		if (ret == -1) {
			printf("recv error %d %d\n", ret, errno);
			return 1;
		}
		printf("recv '%s' on stream %d\n", msg, (int)pinfo.stream_id);
		close(strmfd);
		break;
	}

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
