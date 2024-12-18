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

#define SECONDS		1000000

char snd_msg[SND_MSG_LEN];
char rcv_msg[RCV_MSG_LEN];
char alpn[ALPN_LEN] = "sample";

struct options {
	char *pkey;
	char *cert;
	char *psk;
	char *ca;
	char *addr;
	char *port;
	uint8_t is_serv;
	uint8_t no_crypt;
	uint64_t tot_len;
	uint64_t msg_len;
};

static struct option long_options[] = {
	{"addr",	required_argument,	0,	'a'},
	{"port",	required_argument,	0,	'p'},
	{"pkey",	required_argument,	0,	'k'},
	{"cert",	required_argument,	0,	'c'},
	{"psk",		required_argument,	0,	'i'},
	{"ca",		required_argument,	0,	's'},
	{"msg_len",	required_argument,	0,	'm'},
	{"tot_len",	required_argument,	0,	't'},
	{"listen",	no_argument,		0,	'l'},
	{"no_crypt",	no_argument,		0,	'x'},
	{"help",	no_argument,		0,	'h'},
	{0,		0,			0,	 0 }
};

static void print_usage(char *cmd)
{
	printf("%s:\n\n", cmd);
	printf("    --listen/-l:            work as a server\n");
	printf("    --addr/-a <a>:          server IP address\n");
	printf("    --port/-p <p>:          server port\n");
	printf("    --pkey/-k <k>:          private key file\n");
	printf("    --cert/-c <c>:          certificate file\n");
	printf("    --psk/-i <i>:           pre-shared key file\n");
	printf("    --ca/-s <s>:            ca file\n");
	printf("    --help/-h <h>:          show help\n");
	printf("    --msg_len/-m <m>:       msg_len to send\n");
	printf("    --tot_len/-t <t>:       tot_len to send\n");
	printf("    --no_crypt/-x <x>:      disable 1rtt encryption\n\n");
}

static int parse_options(int argc, char *argv[], struct options *opts)
{
	int c, option_index = 0;

	while (1) {
		c = getopt_long(argc, argv, "la:p:m:t:k:c:s:i:xh", long_options, &option_index);
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
		case 's':
			opts->ca = optarg;
			break;
		case 'i':
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
		case 'x':
			opts->no_crypt = 1;
			break;
		case 'h':
			print_usage(argv[0]);
			return 1;
		default:
			return -1;
		}
	}

	if (opts->is_serv && (!opts->cert && !opts->pkey))
		return -1;
	return 0;
}

static int do_server(struct options *opts)
{
	struct quic_transport_param param = {};
	uint32_t flags = 0, addrlen, len = 0;
	struct sockaddr_storage ra = {};
	struct sockaddr_in la = {};
	int ret, sockfd, listenfd;
	struct addrinfo *rp;
	int64_t sid = 0;

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

listen:
	param.grease_quic_bit = 1;
	param.stateless_reset = 1;
	param.max_idle_timeout = 120 * SECONDS;
	param.disable_1rtt_encryption = opts->no_crypt;
	if (setsockopt(listenfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, sizeof(param))) {
		printf("socket setsockopt transport param failed\n");
		return -1;
	}
	if (setsockopt(listenfd, SOL_QUIC, QUIC_SOCKOPT_ALPN, alpn, strlen(alpn))) {
		printf("socket setsockopt alpn failed\n");
		return -1;
	}

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

	if (quic_server_handshake(sockfd, opts->pkey, opts->cert, alpn))
		return -1;

	printf("HANDSHAKE DONE\n");

	while (1) {
		ret = quic_recvmsg(sockfd, &rcv_msg, opts->msg_len * 16, &sid, &flags);
		if (ret == -1) {
			printf("recv error %d %d\n", ret, errno);
			return 1;
		}
		len += ret;
		usleep(20);
		if (flags & MSG_STREAM_FIN)
			break;
		printf("  recv len: %u, stream_id: %d, flags: %u.\n", len, (int)sid, flags);
	}

	printf("RECV DONE: tot_len %u, stream_id: %d, flags: %u.\n", len, (int)sid, flags);

	flags = MSG_STREAM_FIN;
	strcpy(snd_msg, "recv done");
	ret = quic_sendmsg(sockfd, snd_msg, strlen(snd_msg), sid, flags);
	if (ret == -1) {
		printf("send %d %d\n", ret, errno);
		return -1;
	}

	flags = 0;
	quic_recvmsg(sockfd, &rcv_msg, sizeof(rcv_msg), &sid, &flags);

	close(sockfd);
	printf("CLOSE DONE\n");

	len = 0;
	goto loop;
	return 0;
}

static uint64_t get_now_time()
{
	struct timespec t ;
	clock_gettime ( CLOCK_REALTIME , & t ) ;
	return t.tv_sec * 1000 + ( t.tv_nsec + 500000 ) / 1000000 ;
}

static int do_client(struct options *opts)
{
	struct quic_transport_param param = {};
	struct sockaddr_in ra = {};
	uint32_t len = 0, flags;
	struct addrinfo *rp;
	uint64_t start, end;
	int ret, sockfd;
	int64_t sid = 0;
	float rate;

	if (getaddrinfo(opts->addr, opts->port, NULL, &rp)) {
		printf("getaddrinfo error\n");
		return -1;
	}

	if (rp->ai_family == AF_INET6) {
		struct sockaddr_in6 ra = {};

		sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_QUIC);
		if (sockfd < 0) {
			printf("socket create failed\n");
			return -1;
		}

		param.max_idle_timeout = 120 * SECONDS;
		param.disable_1rtt_encryption = opts->no_crypt;
		if (setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, sizeof(param))) {
			printf("socket setsockopt transport param failed\n");
			return -1;
		}

		ra.sin6_family = AF_INET6;
		ra.sin6_port = htons(atoi(opts->port));
		inet_pton(AF_INET6, opts->addr, &ra.sin6_addr);

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

	param.max_idle_timeout = 120 * SECONDS;
	param.disable_1rtt_encryption = opts->no_crypt;
	if (setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, sizeof(param))) {
		printf("socket setsockopt transport param failed\n");
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
	if (quic_client_handshake(sockfd, opts->pkey, NULL, alpn))
		return -1;

	printf("HANDSHAKE DONE.\n");

	start = get_now_time();
	flags = MSG_STREAM_NEW; /* open stream when send first msg */
	ret = quic_sendmsg(sockfd, snd_msg, opts->msg_len, sid, flags);
	if (ret == -1) {
		printf("send %d %d\n", ret, errno);
		return -1;
	}
	len += ret;
	flags = 0;
	while (1) {
		ret = quic_sendmsg(sockfd, snd_msg, opts->msg_len, sid, flags);
		if (ret == -1) {
			printf("send %d %d\n", ret, errno);
			return -1;
		}
		len += ret;
		if (!(len % (opts->msg_len * 1024)))
			printf("  send len: %u, stream_id: %d, flags: %u.\n", len, (int)sid, flags);
		if (len > opts->tot_len - opts->msg_len)
			break;
	}
	flags = MSG_STREAM_FIN; /* close stream when send last msg */
	ret = quic_sendmsg(sockfd, snd_msg, opts->msg_len, sid, flags);
	if (ret == -1) {
		printf("send %d %d\n", ret, errno);
		return -1;
	}
	len += ret;
	printf("SEND DONE: tot_len: %u, stream_id: %d, flags: %u.\n", len, (int)sid, flags);

	memset(rcv_msg, 0, sizeof(rcv_msg));
	ret = quic_recvmsg(sockfd, rcv_msg, opts->msg_len * 16, &sid, &flags);
	if (ret == -1) {
		printf("recv error %d %d\n", ret, errno);
		return 1;
	}
	end = get_now_time();
	start = end - start;
	rate = ((float)opts->tot_len * 8 * 1000) / 1024 / start;
	if (rate < 1024)
		printf("ALL RECVD: %.1f Kbits/Sec\n", rate);
	else
		printf("ALL RECVD: %.1f Mbits/Sec\n", rate / 1024);

	close(sockfd);
	return 0;
}

int main(int argc, char *argv[])
{
	struct options opts = {};
	int ret;

	opts.msg_len = SND_MSG_LEN;
	opts.tot_len = TOT_LEN;
	opts.addr = "::";
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
