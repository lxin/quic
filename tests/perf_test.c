#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <linux/tls.h>
#include <arpa/inet.h>
#include <netinet/quic.h>

#define SND_MSG_LEN	4096
#define RCV_MSG_LEN	4096 * 16
#define ALPN_LEN	20
#define TOT_LEN		1 * 1024 * 1024 * 1024

char snd_msg[SND_MSG_LEN];
char rcv_msg[RCV_MSG_LEN];
char alpn[ALPN_LEN] = "sample";

static int read_datum(const char *file, gnutls_datum_t *data)
{
	struct stat statbuf;
	unsigned int size;
	int ret = -1;
	void *buf;
	int fd;

	fd = open(file, O_RDONLY);
	if (fd == -1)
		return -1;
	if (fstat(fd, &statbuf))
		goto out;
	if (statbuf.st_size < 0 || statbuf.st_size > INT_MAX)
		goto out;
	size = (unsigned int)statbuf.st_size;
	buf = malloc(size);
	if (!buf)
		goto out;
	if (read(fd, buf, size) == -1) {
		free(buf);
		goto out;
	}
	data->data = buf;
	data->size = size;
	ret = 0;
out:
	close(fd);
	return ret;
}

static int read_pkey_file(char *file, gnutls_privkey_t *privkey)
{
	gnutls_datum_t data;
	int ret;

	if (read_datum(file, &data))
		return -1;

	ret = gnutls_privkey_init(privkey);
	if (ret)
		goto out;

	ret = gnutls_privkey_import_x509_raw(*privkey, &data, GNUTLS_X509_FMT_PEM, NULL, 0);
out:
        free(data.data);
	return ret;
}

static int read_cert_file(char *file, gnutls_pcert_st **cert)
{
	gnutls_datum_t data;
	int ret;

	if (read_datum(file, &data))
		return -1;

	ret = gnutls_pcert_import_x509_raw(*cert, &data, GNUTLS_X509_FMT_PEM, 0);
	free(data.data);

	return ret;
}

static int do_server(int argc, char *argv[])
{
	struct quic_handshake_parms parms = {};
	struct quic_transport_param param = {};
	int ret, sockfd, listenfd, addrlen;
	struct sockaddr_storage ra = {};
	struct sockaddr_in la = {};
	uint64_t len = 0,  sid = 0;
	char *mode, *pkey, *cert;
	gnutls_pcert_st gcert;
	struct addrinfo *rp;
	int flag = 0;

	if (argc != 6) {
		printf("%s server <LOCAL ADDR> <LOCAL PORT> <-pkey_file:PRIVATE_KEY_FILE> <-cert_file:CERTIFICATE_FILE>\n", argv[0]);
		return 0;
	}

	if (getaddrinfo(argv[2], argv[3], NULL, &rp)) {
		printf("getaddrinfo error\n");
		return -1;
	}

	if (rp->ai_family == AF_INET6) {
		struct sockaddr_in6 la = {};

		la.sin6_family = AF_INET6;
		la.sin6_port = htons(atoi(argv[3]));
		inet_pton(AF_INET6, argv[2], &la.sin6_addr);
		listenfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_QUIC);
		if (listenfd < 0) {
			printf("socket create failed\n");
			return -1;
		}
		if (bind(listenfd, (struct sockaddr *)&la, sizeof(la))) {
			printf("socket bind failed\n");
			return -1;
		}
		param.max_udp_payload_size = 1400;
		param.cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
		if (setsockopt(listenfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM,
			       &param, sizeof(param)))
			return -1;
		goto listen;
	}

	la.sin_family = AF_INET;
	la.sin_port = htons(atoi(argv[3]));
	inet_pton(AF_INET, argv[2], &la.sin_addr.s_addr);
	listenfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
	if (listenfd < 0) {
		printf("socket create failed\n");
		return -1;
	}
	if (bind(listenfd, (struct sockaddr *)&la, sizeof(la))) {
		printf("socket bind failed\n");
		return -1;
	}

	param.validate_address = 1; /* trigger retry packet sending */
	param.grease_quic_bit = 1;
	param.cert_request = 1;
	if (setsockopt(listenfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, sizeof(param)))
		return -1;

listen:
	if (listen(listenfd, 1)) {
		printf("socket listen failed\n");
		return -1;
	}

	mode = strtok(argv[4], ":");
	if (strcmp(mode, "-pkey_file"))
		return -1;
	pkey = strtok(NULL, ":");

	mode = strtok(argv[5], ":");
	if (strcmp(mode, "-cert_file"))
		return -1;
	cert = strtok(NULL, ":");

loop:
	printf("Waiting for New Socket...\n");
	addrlen = sizeof(ra);
	sockfd = accept(listenfd, (struct sockaddr *)&ra, &addrlen);
	if (sockfd < 0) {
		printf("socket accept failed %d %d\n", errno, sockfd);
		return -1;
	}

	printf("accept %d\n", sockfd);
	if (setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_ALPN, alpn, strlen(alpn) + 1))
		return -1;

	/* start doing handshake with tlshd API */
	parms.cert = &gcert;
	if (read_pkey_file(pkey, &parms.privkey) || read_cert_file(cert, &parms.cert)) {
		printf("parse prikey or cert files failed\n");
		return -1;
	}
	parms.timeout = 15000;
	if (quic_server_handshake_parms(sockfd, &parms))
		return -1;

	printf("HANDSHAKE DONE: received cert number: '%d'\n", parms.num_keys);

	while (1) {
		ret = quic_recvmsg(sockfd, &rcv_msg, RCV_MSG_LEN, &sid, &flag);
		if (ret == -1) {
			printf("recv error %d\n", ret, errno);
			return 1;
		}
		len += ret;
		usleep(20);
		if (flag & QUIC_STREAM_FLAG_FIN)
			break;
		printf("  recv len: %lld, stream_id: %lld, flag: %d.\n", len, sid, flag);
	}

	printf("RECV DONE: tot_len %lld, stream_id: %lld, flag: %d.\n", len, sid, flag);

	flag = QUIC_STREAM_FLAG_FIN;
	strcpy(snd_msg, "recv done");
	ret = quic_sendmsg(sockfd, snd_msg, strlen(snd_msg), sid, flag);
	if (ret == -1) {
		printf("send %d %d\n", ret, errno);
		return -1;
	}
	sleep(1);
	close(sockfd);
	printf("CLOSE DONE\n");

	len = 0;
	goto loop;
	return 0;
}

static int do_client(int argc, char *argv[])
{
	char *mode, *pkey = NULL, *cert = NULL;
	struct quic_handshake_parms parms = {};
	struct sockaddr_in ra = {};
	uint64_t len = 0, sid = 0;
	gnutls_pcert_st gcert;
	int ret, sockfd, flag;
	struct addrinfo *rp;
	time_t start, end;

	if (argc != 4 && argc != 6) {
		printf("%s client <PEER ADDR> <PEER PORT> [<-pkey_file:PRIVATE_KEY_FILE> <-cert_file:CERTIFICATE_FILE>]\n", argv[0]);
		return 0;
	}

	if (getaddrinfo(argv[2], argv[3], NULL, &rp)) {
		printf("getaddrinfo error\n");
		return -1;
	}

	if (rp->ai_family == AF_INET6) {
		struct quic_transport_param param = {};
		struct sockaddr_in6 ra = {};

		sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_QUIC);
		if (sockfd < 0) {
			printf("socket create failed\n");
			return -1;
		}

		ra.sin6_family = AF_INET6;
		ra.sin6_port = htons(atoi(argv[3]));
		inet_pton(AF_INET6, argv[2], &ra.sin6_addr);

		param.version = 5; /* invalid version to trigger version negotiation */
		param.recv_session_ticket = 1;
		param.cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
		if (setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM,
			       &param, sizeof(param)))
			return -1;

		if (connect(sockfd, (struct sockaddr *)&ra, sizeof(ra))) {
			printf("socket connect failed\n");
			return -1;
		}
		goto handshake;
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

handshake:
	if (setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_ALPN, alpn, strlen(alpn) + 1))
		return -1;

	/* start doing handshake with tlshd API */
	if (argc == 6) {
		parms.cert = &gcert;

		mode = strtok(argv[4], ":");
		if (strcmp(mode, "-pkey_file"))
			return -1;
		pkey = strtok(NULL, ":");

		mode = strtok(argv[5], ":");
		if (strcmp(mode, "-cert_file"))
			return -1;
		cert = strtok(NULL, ":");

		if (read_pkey_file(pkey, &parms.privkey) || read_cert_file(cert, &parms.cert)) {
			printf("parse prikey or cert files failed\n");
			return -1;
		}
	}
	parms.timeout = 15000;
	if (quic_client_handshake_parms(sockfd, &parms))
		return -1;

	printf("HANDSHAKE DONE: received cert number: '%d'.\n", parms.num_keys);

	time(&start);
	flag = QUIC_STREAM_FLAG_NEW; /* open stream when send first msg */
	ret = quic_sendmsg(sockfd, snd_msg, SND_MSG_LEN, sid, flag);
	if (ret == -1) {
		printf("send %d %d\n", ret, errno);
		return -1;
	}
	len += ret;
	flag = 0;
	while (1) {
		ret = quic_sendmsg(sockfd, snd_msg, SND_MSG_LEN, sid, flag);
		if (ret == -1) {
			printf("send %d %d\n", ret, errno);
			return -1;
		}
		len += ret;
		if (!(len % (SND_MSG_LEN * 1024)))
			printf("  send len: %lld, stream_id: %lld, flag: %d.\n", len, sid, flag);
		if (len > TOT_LEN - SND_MSG_LEN)
			break;
	}
	flag = QUIC_STREAM_FLAG_FIN; /* close stream when send last msg */
	ret = quic_sendmsg(sockfd, snd_msg, SND_MSG_LEN, sid, flag);
	if (ret == -1) {
		printf("send %d %d\n", ret, errno);
		return -1;
	}
	len += ret;
	printf("SEND DONE: tot_len: %lld, stream_id: %lld, flag: %d.\n", len, sid, flag);

	memset(rcv_msg, 0, sizeof(rcv_msg));
	ret = quic_recvmsg(sockfd, rcv_msg, RCV_MSG_LEN, &sid, &flag);
	if (ret == -1) {
		printf("recv error %d %d\n", ret, errno);
		return 1;
	}
	time(&end);
	start = end - start;
	printf("ALL RECVD: %u MBytes/Sec\n", TOT_LEN/1024/1024/start);

	close(sockfd);
	return 0;
}

int main(int argc, char *argv[])
{
	if (argc < 2 || (strcmp(argv[1], "client") && strcmp(argv[1], "server"))) {
		printf("%s client|server ... \n", argv[0]);
		return 0;
	}

	if (!strcmp(argv[1], "client"))
		return do_client(argc, argv);

	return do_server(argc, argv);
}
