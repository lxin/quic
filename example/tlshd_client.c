#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "tlshd_fake.h"

#define MSG_LEN	4096
#define TOT_LEN	20480000
char msg[MSG_LEN + 1];

int main(int argc, char *argv[])
{
	struct quic_handshake_parms parms = {};
        struct sockaddr_in ra = {};
	struct quic_endpoint *ep;
	int sid = 0, flag, i;
	uint64_t len = 0;
	int ret, sockfd;

	if (argc != 3 && argc != 4 && argc != 5 && argc != 6) {
		printf("%s <PEER ADDR> <PEER PORT> [<PSK file> | [<PRIVATE_KEY_FILE> <CERTIFICATE_FILE> [<SERVER_NAME>]]]\n", argv[0]);
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

	parms.timeout = 15000;
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
		printf("send %d %lld\n", ret, len);
		if (len == TOT_LEN / 2) { /* do rekeying */
			if (setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_KEY_UPDATE, NULL, 0))
				return -1;
		}
		if (len >= TOT_LEN)
			break;
	}
	printf("send done\n");

	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flag);
	if (ret == -1) {
		printf("recv error %d %d\n", ret, errno);
		return 1;
	}
	printf("recv: \"%s\", len: %d, stream_id: %d, flag: %d\n", msg, ret, sid, flag);
	return 0;
}
