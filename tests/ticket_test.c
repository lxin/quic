#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <netinet/quic.h>

static uint8_t ticket[4096];
static uint8_t token[256];

static int do_client(int argc, char *argv[])
{
	unsigned int ticket_len, param_len, token_len, addr_len;
	struct quic_transport_param param = {};
	struct sockaddr_in ra = {}, la = {};
	int ret, sockfd;
	char msg[50];

	if (argc < 3) {
		printf("%s client <PEER ADDR> <PEER PORT>\n", argv[0]);
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

	param.receive_session_ticket = 1;
	param_len = sizeof(param);
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, param_len);
	if (ret == -1)
		return -1;

	if (quic_client_handshake(sockfd, NULL, NULL))
		return -1;

	/* get ticket and param after handshake (you can save it somewhere) */
	ticket_len = sizeof(ticket);
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_SESSION_TICKET, ticket, &ticket_len);
	if (ret == -1 || !ticket_len) {
		printf("socket getsockopt session ticket\n");
		return -1;
	}

	param_len = sizeof(param);
	param.remote = 1;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, &param_len);
	if (ret == -1) {
		printf("socket getsockopt remote transport param\n");
		return -1;
	}

	/* get token and local address (needed when peer validate_address is set) */
	token_len = sizeof(token);
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TOKEN, &token, &token_len);
	if (ret == -1) {
		printf("socket getsockopt regular token\n");
		return -1;
	}

	addr_len = sizeof(la);
	ret = getsockname(sockfd, (struct sockaddr *)&la, &addr_len);
	if (ret == -1) {
		printf("getsockname local address and port used\n");
		return -1;
	}

	printf("get the session ticket %d and transport param %d and token %d, save it\n",
	       ticket_len, param_len, token_len);

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

	printf("start new connection with the session ticket used...\n");
	sleep(2);

	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
	if (sockfd < 0) {
		printf("socket create failed\n");
		return -1;
	}

	/* bind previous address and port and set token for address validation */
	if (bind(sockfd, (struct sockaddr *)&la, addr_len)) {
		printf("socket bind failed\n");
		return -1;
	}
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TOKEN, token, token_len);
	if (ret == -1) {
		printf("socket setsockopt token\n");
		return -1;
	}

	ra.sin_family = AF_INET;
	ra.sin_port = htons(atoi(argv[3]));
	inet_pton(AF_INET, argv[2], &ra.sin_addr.s_addr);

	if (connect(sockfd, (struct sockaddr *)&ra, sizeof(ra))) {
		printf("socket connect failed\n");
		return -1;
	}

	/* set the ticket and remote param and early data into the socket for handshake */
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_SESSION_TICKET, ticket, ticket_len);
	if (ret == -1) {
		printf("socket setsockopt session ticket\n");
		return -1;
	}
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, param_len);
	if (ret == -1) {
		printf("socket setsockopt remote transport param\n");
		return -1;
	}
	strcpy(msg, "hello quic server, I'm back!");
	ret = send(sockfd, msg, strlen(msg), MSG_SYN | MSG_FIN);
	if (ret == -1) {
		printf("send error %d %d\n", ret, errno);
		return -1;
	}
	printf("send %d\n", ret);

	if (quic_client_handshake(sockfd, NULL, NULL))
		return -1;

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
	struct quic_transport_param param = {};
	struct sockaddr_in sa = {};
	int listenfd, sockfd, ret;
	unsigned int addrlen;
	char msg[50];

	if (argc < 5) {
		printf("%s server <LOCAL ADDR> <LOCAL PORT> <PRIVATE_KEY_FILE> <CERTIFICATE_FILE>\n", argv[0]);
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
	if (listen(listenfd, 1)) {
		printf("socket listen failed\n");
		return -1;
	}
	param.validate_peer_address = 1;
	if (setsockopt(listenfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, sizeof(param)))
		return -1;
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

	printf("wait for the client next connection...\n");

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

	strcpy(msg, "hello quic client! welcome back!");
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
