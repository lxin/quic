#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "example/tlshd_fake.h"

#define MSG_LEN 4096
#define TOT_LEN 2048000000
char msg[MSG_LEN + 1];

static int do_server(int argc, char *argv[])
{
	struct quic_handshake_parms parms = {};
	struct sockaddr_in la = {}, ra = {};
	int ret, sockfd, listenfd, addrlen;
	struct quic_connection *conn;
	struct quic_endpoint *ep;
	int flag = 0, sid = 0;
	uint64_t len;

	if (argc != 4 && argc != 5) {
		printf("%s server <LOCAL ADDR> <LOCAL PORT> <PSK_FILE> | <PRIVATE_KEY_FILE> <CERTIFICATE_FILE>\n", argv[0]);
		return 0;
	}

	la.sin_family = AF_INET;
	la.sin_port = htons(atoi(argv[2]));
	inet_pton(AF_INET, argv[1], &la.sin_addr.s_addr);
	listenfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
	if (listenfd < 0) {
		printf("socket create failed\n");
		return -1;
	}
	if (bind(listenfd, (struct sockaddr *)&la, sizeof(la))) {
		printf("socket bind failed\n");
		return -1;
	}
	if (listen(listenfd, 1)) {
		printf("socket listen failed\n");
		return -1;
	}
loop:
	len = 0;
        printf("waiting for new socket...\n");
	addrlen = sizeof(ra);
	sockfd = accept(listenfd, (struct sockaddr *)&ra, &addrlen);
	if (sockfd < 0) {
		printf("socket accept failed %d %d\n", errno, sockfd);
		return -1;
	}
	parms.timeout = 15;
	parms.alpn = "sample";
	if (argc == 4)  {
		ret = read_psk_file(argv[3], parms.names, parms.keys);
		if (ret <= 0)
			return -1;
		parms.num_keys = ret;
		if (quic_server_psk_tlshd(sockfd, &parms))
			return -1;
		printf("psk identity chosen: '%s'\n", parms.peername);
	}
	if (argc == 5) {
		gnutls_pcert_st cert;
		parms.cert = &cert;
		if (read_pkey_file(argv[3], &parms.privkey) ||
		    read_cert_file(argv[4], &parms.cert))
			return -1;
		if (quic_server_x509_tlshd(sockfd, &parms))
			return -1;
		printf("received cert number: '%d'\n", parms.num_keys);
	}
	/* sockfd can be passed to kernel by 'handshake' netlink for NFS use */
	printf("handshake done %d\n", sockfd);

	while (1) {
		ret = quic_recvmsg(sockfd, &msg, sizeof(msg), &sid, &flag);
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
		printf("recv len: %lld, stream_id: %d, flag: %d.\n", len, sid, flag);
		if (flag & QUIC_STREAM_FLAG_FIN)
			break;
	}

	flag = QUIC_STREAM_FLAG_FIN;
	strcpy(msg, "recv done");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	if (ret == -1) {
		printf("send %d %d\n", ret, errno);
		return -1;
	}
	sleep(1);
	close(sockfd);
	goto loop;
	return 0;
}

static int do_client(int argc, char *argv[])
{
	struct quic_handshake_parms parms = {};
        struct sockaddr_in ra = {};
	struct quic_endpoint *ep;
	int sid = 0, flag, i;
	uint64_t len = 0;
	int ret, sockfd;

	if (argc != 3 && argc != 4 && argc != 5 && argc != 6) {
		printf("%s client <PEER ADDR> <PEER PORT> [<PSK file> | [<PRIVATE_KEY_FILE> <CERTIFICATE_FILE> [<SERVER_NAME>]]]\n", argv[0]);
		return 0;
	}

	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
	if (sockfd < 0) {
		printf("socket create failed\n");
		return -1;
	}

        ra.sin_family = AF_INET;
        ra.sin_port = htons(atoi(argv[2]));
        inet_pton(AF_INET, argv[1], &ra.sin_addr.s_addr);

	if (connect(sockfd, (struct sockaddr *)&ra, sizeof(ra))) {
		printf("socket connect failed\n");
		return -1;
	}

	parms.timeout = 15;
	parms.alpn = "sample";
	if (argc == 4)  {
		ret = read_psk_file(argv[3], parms.names, parms.keys);
		if (ret <= 0)
			return -1;
		parms.num_keys = ret;
		if (quic_client_psk_tlshd(sockfd, &parms))
			return -1;
		printf("psk identity chosen: '%s'\n", parms.peername);
	}
	if (argc == 3) {
		if (quic_client_x509_tlshd(sockfd, &parms))
			return -1;
		printf("received cert number: '%d'\n", parms.num_keys);
	}
	if (argc >= 5) {
		gnutls_pcert_st cert;
		parms.cert = &cert;

		if (read_pkey_file(argv[3], &parms.privkey) ||
		    read_cert_file(argv[4], &parms.cert))
			return -1;
		if (argc == 6)
			parms.peername = argv[5];
		if (quic_client_x509_tlshd(sockfd, &parms))
			return -1;
		printf("received cert number: '%d'\n", parms.num_keys);
	}
	/* sockfd can be passed to kernel by 'handshake' netlink for NFS use */
	printf("handshake done %d\n", sockfd);

	/* for the congestion control testing setup:
	 * 'system("tc qdisc add dev lo root netem loss 50%")'
	 */
	for (i = 0; i < MSG_LEN; i++)
		msg[i] = i % 10 + 48;
	flag = QUIC_STREAM_FLAG_NEW;
	msg[i] = '\0';
	while (1) {
		if (len) {
			flag = 0;
			if (len == TOT_LEN - MSG_LEN)
				flag = QUIC_STREAM_FLAG_FIN;
		}
		ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
		if (ret == -1) {
			printf("send %d %d\n", ret, errno);
			return -1;
		}
		len += ret;
		printf("send len: %lld, stream_id: %lld, flag: %d.\n", len, sid, flag);
		if (len >= TOT_LEN)
			break;
	}
	printf("send done!\n");

	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d %d\n", ret, errno);
		return 1;
	}
	printf("recv: \"%s\", len: %d, stream_id: %d, flag: %d.\n", msg, ret, sid, flag);
	return 0;
}

int main(int argc, char *argv[])
{
	if (argc < 2 || (strcmp(argv[1], "client") && strcmp(argv[1], "server"))) {
		printf("%s client | server ... \n", argv[0]);
		return 0;
	}
	if (!strcmp(argv[1], "client")) {
		argc--;
		argv[1] = argv[0];
		return do_client(argc, &argv[1]);
	}
	argc--;
	argv[1] = argv[0];
	return do_server(argc, &argv[1]);
}
