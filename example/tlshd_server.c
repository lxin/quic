#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "tlshd_fake.h"

#define MSG_LEN 4096
char msg[MSG_LEN + 1];

int main(int argc, char *argv[])
{
	struct quic_handshake_parms parms = {};
	struct sockaddr_in la = {}, ra = {};
	int ret, sockfd, listenfd, addrlen;
	struct quic_connection *conn;
	struct quic_endpoint *ep;
	int flag = 0, sid = 0;
	uint64_t len = 0;

	if (argc != 4 && argc != 5) {
		printf("%s <LOCAL ADDR> <LOCAL PORT> <PSK_FILE> | <PRIVATE_KEY_FILE> <CERTIFICATE_FILE>\n", argv[0]);
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

	sid = 1;
	flag = QUIC_STREAM_FLAG_NEW | QUIC_STREAM_FLAG_FIN;
	strcpy(msg, "recv done");
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flag);
	if (ret == -1) {
		printf("send %d %d\n", ret, errno);
		return -1;
	}
	sleep(1);
	return 0;
}
