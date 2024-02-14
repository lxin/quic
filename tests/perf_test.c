#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
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

struct options {
	char *pkey;
	char *cert;
	char *addr;
	char *port;
	uint8_t is_serv;
	uint64_t tot_len;
	uint64_t msg_len;
};

static struct option long_options[] = {
	{"addr",	required_argument,	0,	'a'},
	{"port",	required_argument,	0,	'p'},
	{"pkey",	required_argument,	0,	'k'},
	{"cert",	required_argument,	0,	'c'},
	{"msg_len",	required_argument,	0,	'm'},
	{"tot_len",	required_argument,	0,	't'},
	{"listen",	no_argument,		0,	'l'},
	{"help",	no_argument,		0,	'h'},
	{0,		0,			0,	 0 }
};

static void print_usage(char *cmd)
{
	printf("%s:\n\n", cmd);
	printf("    --listen/-l:            work as a server\n");
	printf("    --addr/-a <a>:          server IP address\n");
	printf("    --port/-p <p>:          server port\n");
	printf("    --pkey/-k <k>:          private key\n");
	printf("    --cert/-c <c>:          certificate\n");
	printf("    --help/-h <h>:          show help\n");
	printf("    --msg_len/-m <m>:       msg_len to send\n");
	printf("    --tot_len/-t <t>:       tot_len to send\n\n");
}

static int parse_options(int argc, char *argv[], struct options *opts)
{
	int c, option_index = 0;

	while (1) {
		c = getopt_long(argc, argv, "la:p:m:t:k:c:h", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'l':
			opts->is_serv = 1;
			break;
		case 'a':
			opts->addr = optarg;
			break;
		case 'p':
			opts->port = optarg;
			break;
		case 'c':
			opts->cert = optarg;
			break;
		case 'k':
			opts->pkey = optarg;
			break;
		case 'm':
			opts->msg_len = atoi(optarg);
			if (opts->msg_len > SND_MSG_LEN)
				return -1;
			break;
		case 't':
			opts->tot_len = atoll(optarg);
			if (opts->tot_len > TOT_LEN)
				return -1;
			break;
		case 'h':
			print_usage(argv[0]);
			return 1;
		default:
			return -1;
		}
	}

	if (opts->is_serv && (!opts->cert || !opts->pkey))
		return -1;
	return 0;
}

static int do_server(struct options *opts)
{
	struct quic_handshake_parms parms = {};
	struct quic_transport_param param = {};
	struct sockaddr_storage ra = {};
	struct sockaddr_in la = {};
	uint32_t flag = 0, addrlen;
	uint64_t len = 0,  sid = 0;
	int ret, sockfd, listenfd;
	gnutls_pcert_st gcert;
	struct addrinfo *rp;

	if (getaddrinfo(opts->addr, opts->port, NULL, &rp)) {
		printf("getaddrinfo error\n");
		return -1;
	}

	if (rp->ai_family == AF_INET6) {
		struct sockaddr_in6 la = {};

		la.sin6_family = AF_INET6;
		la.sin6_port = htons(atoi(opts->port));
		inet_pton(AF_INET6, opts->addr, &la.sin6_addr);
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
		param.payload_cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
		if (setsockopt(listenfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM,
			       &param, sizeof(param)))
			return -1;
		goto listen;
	}

	la.sin_family = AF_INET;
	la.sin_port = htons(atoi(opts->port));
	inet_pton(AF_INET, opts->addr, &la.sin_addr.s_addr);
	listenfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
	if (listenfd < 0) {
		printf("socket create failed\n");
		return -1;
	}
	if (bind(listenfd, (struct sockaddr *)&la, sizeof(la))) {
		printf("socket bind failed\n");
		return -1;
	}

	param.validate_peer_address = 1; /* trigger retry packet sending */
	param.grease_quic_bit = 1;
	param.certificate_request = 1;
	param.stateless_reset = 1;
	param.plpmtud_probe_timeout = 1000000;
	if (setsockopt(listenfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, sizeof(param)))
		return -1;

listen:
	if (listen(listenfd, 1)) {
		printf("socket listen failed\n");
		return -1;
	}

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
	if (read_pkey_file(opts->pkey, &parms.privkey) ||
	    read_cert_file(opts->cert, &parms.cert)) {
		printf("parse prikey or cert files failed\n");
		return -1;
	}
	parms.timeout = 15000;
	if (quic_server_handshake_parms(sockfd, &parms))
		return -1;

	printf("HANDSHAKE DONE: received cert number: '%d'\n", parms.num_keys);

	while (1) {
		ret = quic_recvmsg(sockfd, &rcv_msg, opts->msg_len * 16, &sid, &flag);
		if (ret == -1) {
			printf("recv error %d %d\n", ret, errno);
			return 1;
		}
		len += ret;
		usleep(20);
		if (flag & QUIC_STREAM_FLAG_FIN)
			break;
		printf("  recv len: %lu, stream_id: %lu, flag: %u.\n", len, sid, flag);
	}

	printf("RECV DONE: tot_len %lu, stream_id: %lu, flag: %u.\n", len, sid, flag);

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

static int do_client(struct options *opts)
{
	struct quic_handshake_parms parms = {};
	struct sockaddr_in ra = {};
	uint64_t len = 0, sid = 0;
	gnutls_pcert_st gcert;
	struct addrinfo *rp;
	time_t start, end;
	int ret, sockfd;
	uint32_t flag;

	if (getaddrinfo(opts->addr, opts->port, NULL, &rp)) {
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
		ra.sin6_port = htons(atoi(opts->port));
		inet_pton(AF_INET6, opts->addr, &ra.sin6_addr);

		param.version = 5; /* invalid version to trigger version negotiation */
		param.receive_session_ticket = 1;
		param.payload_cipher_type = TLS_CIPHER_CHACHA20_POLY1305;
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
        ra.sin_port = htons(atoi(opts->port));
        inet_pton(AF_INET, opts->addr, &ra.sin_addr.s_addr);

	if (connect(sockfd, (struct sockaddr *)&ra, sizeof(ra))) {
		printf("socket connect failed\n");
		return -1;
	}

handshake:
	if (setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_ALPN, alpn, strlen(alpn) + 1))
		return -1;

	/* start doing handshake with tlshd API */
	if (opts->pkey && opts->cert) {
		parms.cert = &gcert;
		if (read_pkey_file(opts->pkey, &parms.privkey) ||
		    read_cert_file(opts->cert, &parms.cert)) {
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
	ret = quic_sendmsg(sockfd, snd_msg, opts->msg_len, sid, flag);
	if (ret == -1) {
		printf("send %d %d\n", ret, errno);
		return -1;
	}
	len += ret;
	flag = 0;
	while (1) {
		ret = quic_sendmsg(sockfd, snd_msg, opts->msg_len, sid, flag);
		if (ret == -1) {
			printf("send %d %d\n", ret, errno);
			return -1;
		}
		len += ret;
		if (!(len % (opts->msg_len * 1024)))
			printf("  send len: %lu, stream_id: %lu, flag: %u.\n", len, sid, flag);
		if (len > opts->tot_len - opts->msg_len)
			break;
	}
	flag = QUIC_STREAM_FLAG_FIN; /* close stream when send last msg */
	ret = quic_sendmsg(sockfd, snd_msg, opts->msg_len, sid, flag);
	if (ret == -1) {
		printf("send %d %d\n", ret, errno);
		return -1;
	}
	len += ret;
	printf("SEND DONE: tot_len: %lu, stream_id: %lu, flag: %u.\n", len, sid, flag);

	memset(rcv_msg, 0, sizeof(rcv_msg));
	ret = quic_recvmsg(sockfd, rcv_msg, opts->msg_len * 16, &sid, &flag);
	if (ret == -1) {
		printf("recv error %d %d\n", ret, errno);
		return 1;
	}
	time(&end);
	start = end - start;
	if (opts->tot_len/1024/start < 1024)
		printf("ALL RECVD: %lu KBytes/Sec\n", opts->tot_len/1024/start);
	else
		printf("ALL RECVD: %lu MBytes/Sec\n", opts->tot_len/1024/1024/start);

	close(sockfd);
	return 0;
}

int main(int argc, char *argv[])
{
	struct options opts = {};
	int ret;

	opts.msg_len = SND_MSG_LEN;
	opts.tot_len = TOT_LEN;
	opts.addr = "0.0.0.0";
	opts.port = "1234";

	ret = parse_options(argc, argv, &opts);
	if (ret) {
		if (ret < 0)
			printf("parse options error\n");
		return -1;
	}

	if (!opts.is_serv)
		return do_client(&opts);

	return do_server(&opts);
}
