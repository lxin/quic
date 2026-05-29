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
#include <sys/syslog.h>

#define SND_MSG_LEN	4096
#define RCV_MSG_LEN	4096 * 16
#define REQ_MSG_LEN	1024
#define RSP_MSG_LEN	1024
#define ALPN_LEN	20
#define TOT_LEN		1 * 1024 * 1024 * 1024
#define NUM_REQUESTS	100000

#define SECONDS		1000000

enum test_mode {
	MODE_THROUGHPUT = 0,
	MODE_REQRSP = 1,
};

char snd_msg[SND_MSG_LEN];
char rcv_msg[RCV_MSG_LEN];
char req_msg[REQ_MSG_LEN];
char rsp_msg[RSP_MSG_LEN];
char alpn[ALPN_LEN] = "sample";

struct options {
	char *pkey;
	char *cert;
	char *psk;
	char *ca;
	char *addr;
	char *port;
	uint8_t mode;
	uint8_t is_serv;
	uint8_t no_crypt;
	uint64_t tot_len;
	uint64_t msg_len;
	uint64_t num_reqs;
	uint64_t req_len;
	uint64_t rsp_len;
};

static struct option long_options[] = {
	{"addr",	required_argument,	0,	'a'},
	{"port",	required_argument,	0,	'p'},
	{"pkey",	required_argument,	0,	'k'},
	{"cert",	required_argument,	0,	'c'},
	{"psk",		required_argument,	0,	'i'},
	{"ca",		required_argument,	0,	's'},
	{"mode",	required_argument,	0,	'd'},
	{"msg_len",	required_argument,	0,	'm'},
	{"tot_len",	required_argument,	0,	't'},
	{"req_len",	required_argument,	0,	'q'},
	{"rsp_len",	required_argument,	0,	'r'},
	{"num_reqs",	required_argument,	0,	'n'},
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
	printf("    --mode/-d <d>:          0=throughput (default), 1=request/response\n");
	printf("    --help/-h <h>:          show help\n");
	printf("    --no_crypt/-x <x>:      disable 1rtt encryption\n\n");
	printf("  Throughput mode (--mode 0):\n");
	printf("    --msg_len/-m <m>:       message length to send (default: %d)\n", SND_MSG_LEN);
	printf("    --tot_len/-t <t>:       total length to send (default: %d)\n\n", TOT_LEN);
	printf("  Request/Response mode (--mode 1):\n");
	printf("    --req_len/-q <q>:       request message length (default: %d)\n", REQ_MSG_LEN);
	printf("    --rsp_len/-r <r>:       response message length (default: %d)\n", RSP_MSG_LEN);
	printf("    --num_reqs/-n <n>:      number of requests (default: %d)\n\n", NUM_REQUESTS);
}

static int parse_options(int argc, char *argv[], struct options *opts)
{
	int c, option_index = 0;

	while (1) {
		c = getopt_long(argc, argv, "la:p:d:m:t:q:r:n:k:c:s:i:xh",
				long_options, &option_index);
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
		case 'd':
			opts->mode = atoi(optarg);
			if (opts->mode > 1)
				return -1;
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
		case 'q':
			opts->req_len = atoi(optarg);
			if (opts->req_len > REQ_MSG_LEN)
				return -1;
			break;
		case 'r':
			opts->rsp_len = atoi(optarg);
			if (opts->rsp_len > RSP_MSG_LEN)
				return -1;
			break;
		case 'n':
			opts->num_reqs = atoll(optarg);
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

static int do_server_throughput(struct options *opts, int sockfd)
{
	uint32_t flags = 0, len = 0;
	int64_t sid = 0;
	int ret;

	printf("Running in THROUGHPUT mode\n");

	while (1) {
		ret = quic_recvmsg(sockfd, &rcv_msg, opts->msg_len * 16, &sid, &flags);
		if (ret == -1) {
			printf("recv error %d %d\n", ret, errno);
			return 1;
		}
		len += ret;
		usleep(20);
		if (flags & MSG_QUIC_STREAM_FIN)
			break;
		printf("  recv len: %u, stream_id: %d, flags: %u.\n", len, (int)sid, flags);
	}

	printf("RECV DONE: tot_len %u, stream_id: %d, flags: %u.\n", len, (int)sid, flags);

	flags = MSG_QUIC_STREAM_FIN;
	strcpy(snd_msg, "recv done");
	ret = quic_sendmsg(sockfd, snd_msg, strlen(snd_msg), sid, flags);
	if (ret == -1) {
		printf("send %d %d\n", ret, errno);
		return -1;
	}

	flags = 0;
	quic_recvmsg(sockfd, &rcv_msg, sizeof(rcv_msg), &sid, &flags);

	return 0;
}

static int do_server_reqrsp(struct options *opts, int sockfd)
{
	uint32_t flags = 0;
	uint64_t count = 0;
	int64_t sid = -1;
	int ret;

	printf("Running in REQUEST/RESPONSE mode\n");

	while (1) {
		flags = 0;
		ret = quic_recvmsg(sockfd, req_msg, sizeof(req_msg), &sid, &flags);
		if (ret == -1) {
			printf("recv error %d %d\n", ret, errno);
			break;
		}
		if (ret == 0) {
			printf("Connection closed\n");
			break;
		}

		count++;

		/* Check if this is a FIN indicating end of requests */
		if (flags & MSG_QUIC_STREAM_FIN) {
			printf("Received FIN, closing stream\n");
			break;
		}

		/* Send response on the same stream */
		flags = 0;
		ret = quic_sendmsg(sockfd, rsp_msg, opts->rsp_len, sid, flags);
		if (ret == -1) {
			printf("send error %d %d\n", ret, errno);
			break;
		}

		if (!(count % 1000))
			printf("  Processed %llu requests\n", (unsigned long long)count);
	}

	printf("DONE: Processed %llu requests total\n", (unsigned long long)count);

	return 0;
}

static int do_server(struct options *opts)
{
	struct quic_transport_param param = {};
	struct sockaddr_storage ra = {};
	int sockfd, listenfd, ret = 0;
	struct sockaddr_in la = {};
	struct addrinfo *rp;
	uint32_t addrlen;

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

	while (ret >= 0) {
		printf("Waiting for New Connection...\n");
		addrlen = sizeof(ra);
		sockfd = accept(listenfd, (struct sockaddr *)&ra, &addrlen);
		if (sockfd < 0) {
			printf("socket accept failed %d %d\n", errno, sockfd);
			return -1;
		}

		printf("Accept: sockfd=%d\n", sockfd);

		if (quic_server_handshake(sockfd, opts->pkey, opts->cert, alpn))
			return -1;

		printf("HANDSHAKE DONE\n");

		if (opts->mode == MODE_THROUGHPUT)
			ret = do_server_throughput(opts, sockfd);
		else
			ret = do_server_reqrsp(opts, sockfd);

		close(sockfd);
		printf("CLOSE DONE\n");
	}

	return ret;
}

static uint64_t get_now_time_ms(void)
{
	struct timespec t;

	clock_gettime(CLOCK_REALTIME, &t);
	return t.tv_sec * 1000 + (t.tv_nsec + 500000) / 1000000;
}

static uint64_t get_now_time_us(void)
{
	struct timespec t;

	clock_gettime(CLOCK_REALTIME, &t);
	return t.tv_sec * 1000000ULL + t.tv_nsec / 1000;
}

static int do_client_throughput(struct options *opts, int sockfd)
{
	uint32_t len = 0, flags;
	uint64_t start, end;
	int64_t sid = 0;
	float rate;
	int ret;

	printf("Running in THROUGHPUT mode\n");
	printf("Starting throughput test: sending %llu bytes\n", (unsigned long long)opts->tot_len);

	start = get_now_time_ms();
	flags = MSG_QUIC_STREAM_NEW; /* open stream when send first msg */
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
	flags = MSG_QUIC_STREAM_FIN; /* close stream when send last msg */
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
	end = get_now_time_ms();
	start = end - start;
	rate = ((float)opts->tot_len * 8 * 1000) / 1024 / start;

	printf("\n=== Throughput Results ===\n");
	printf("Total sent:       %u bytes\n", len);
	printf("Message size:     %llu bytes\n", (unsigned long long)opts->msg_len);
	printf("Total time:       %llu ms (%.3f sec)\n", (unsigned long long)start, start / 1000.0);
	if (rate < 1024)
		printf("Throughput:       %.1f Kbits/sec\n", rate);
	else
		printf("Throughput:       %.1f Mbits/sec\n", rate / 1024);

	return 0;
}

static int do_client_reqrsp(struct options *opts, int sockfd)
{
	uint32_t flags;
	uint64_t start, end, total_time;
	int64_t sid;
	uint64_t i;
	double avg_latency, req_per_sec;
	uint64_t min_latency = UINT64_MAX, max_latency = 0;
	uint64_t latency;
	int ret;

	printf("Running in REQUEST/RESPONSE mode\n");
	printf("Starting request/response test with %llu requests\n",
	       (unsigned long long)opts->num_reqs);

	total_time = 0;
	sid = 0;

	/* Open the stream with first request */
	flags = MSG_QUIC_STREAM_NEW;
	ret = quic_sendmsg(sockfd, req_msg, opts->req_len, sid, flags);
	if (ret == -1) {
		printf("send error at request 0: %d %d\n", ret, errno);
		return -1;
	}

	/* Receive first response */
	flags = 0;
	ret = quic_recvmsg(sockfd, rsp_msg, sizeof(rsp_msg), &sid, &flags);
	if (ret == -1) {
		printf("recv error at request 0: %d %d\n", ret, errno);
		return -1;
	}

	/* Perform request/response cycles on the same stream */
	for (i = 0; i < opts->num_reqs; i++) {
		start = get_now_time_us();

		/* Send request on the same stream */
		flags = 0;
		ret = quic_sendmsg(sockfd, req_msg, opts->req_len, sid, flags);
		if (ret == -1) {
			printf("send error at request %llu: %d %d\n",
			       (unsigned long long)i, ret, errno);
			return -1;
		}

		/* Receive response */
		flags = 0;
		ret = quic_recvmsg(sockfd, rsp_msg, sizeof(rsp_msg), &sid, &flags);
		if (ret == -1) {
			printf("recv error at request %llu: %d %d\n",
			       (unsigned long long)i, ret, errno);
			return -1;
		}

		end = get_now_time_us();
		latency = end - start;
		total_time += latency;

		if (latency < min_latency)
			min_latency = latency;
		if (latency > max_latency)
			max_latency = latency;

		if ((i + 1) % 1000 == 0)
			printf("  Completed %llu requests\n", (unsigned long long)i + 1);
	}

	/* Close the stream */
	flags = MSG_QUIC_STREAM_FIN;
	ret = quic_sendmsg(sockfd, req_msg, 0, sid, flags);
	if (ret == -1) {
		printf("send FIN error: %d %d\n", ret, errno);
		return -1;
	}

	printf("\n=== Request/Response Results ===\n");
	printf("Total requests:   %llu\n", (unsigned long long)opts->num_reqs);
	printf("Request size:     %llu bytes\n", (unsigned long long)opts->req_len);
	printf("Response size:    %llu bytes\n", (unsigned long long)opts->rsp_len);

	avg_latency = (double)total_time / opts->num_reqs;
	req_per_sec = (double)opts->num_reqs * 1000000.0 / total_time;

	printf("\nLatency:\n");
	printf("  Average:        %.2f us (%.3f ms)\n", avg_latency, avg_latency / 1000.0);
	printf("  Minimum:        %llu us (%.3f ms)\n",
	       (unsigned long long)min_latency, min_latency / 1000.0);
	printf("  Maximum:        %llu us (%.3f ms)\n",
	       (unsigned long long)max_latency, max_latency / 1000.0);
	printf("\nThroughput:\n");
	printf("  Requests/sec:   %.2f\n", req_per_sec);
	printf("  Total time:     %.3f sec\n", total_time / 1000000.0);

	return 0;
}

static int do_client(struct options *opts)
{
	struct quic_transport_param param = {};
	struct sockaddr_in ra = {};
	struct addrinfo *rp;
	int ret, sockfd;

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
		if (setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param,
			       sizeof(param))) {
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

	if (opts->mode == MODE_THROUGHPUT)
		ret = do_client_throughput(opts, sockfd);
	else
		ret = do_client_reqrsp(opts, sockfd);

	close(sockfd);
	return ret;
}

int main(int argc, char *argv[])
{
	struct options opts = {};
	int ret;

	opts.msg_len = SND_MSG_LEN;
	opts.tot_len = TOT_LEN;
	opts.req_len = REQ_MSG_LEN;
	opts.rsp_len = RSP_MSG_LEN;
	opts.num_reqs = NUM_REQUESTS;
	opts.addr = "::";
	opts.port = "1234";
	opts.mode = MODE_THROUGHPUT;

	ret = parse_options(argc, argv, &opts);
	if (ret) {
		if (ret < 0)
			printf("parse options error\n");
		return -1;
	}

	quic_set_log_level(LOG_NOTICE);

	if (!opts.is_serv)
		return do_client(&opts);

	return do_server(&opts);
}
