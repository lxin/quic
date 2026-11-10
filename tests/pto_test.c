// SPDX-License-Identifier: GPL-2.0-or-later
/* Check that no Handshake packet is sent once the handshake is confirmed.
 *
 * rfc9001#section-4.9.2: an endpoint MUST discard its Handshake keys when
 * the TLS handshake is confirmed, and a peer that has done so drops any
 * Handshake packet it receives.  Clients and a server talk through UDP relays
 * that play such a peer: after the first request and response, each counts
 * and drops every datagram that starts with a Handshake packet, in either
 * direction, and it holds ACKs of
 * the client so that they reach the server as its loss timer expires.  A
 * timer that has expired then may run after the ACK has emptied the flight.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/quic.h>
#include <sys/syslog.h>
#include <sys/time.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <poll.h>
#include <time.h>

#define CONNS		8
#define REQUESTS	2000	/* Per connection */
#define MSG_LEN		64
#define TIMEOUT_SEC	5
#define ACK_DELAY_US	2000	/* max_ack_delay of the clients */
#define PAUSE_MS	15	/* Longer than a held ACK: the client ACKs alone */
#define STEADY		4	/* ACKs that pass at once between held ones */
#define STEP_US		5

static atomic_int dropped[2]; /* Handshake packets dropped: 0 from clients, 1 from server */
static atomic_int failed;

static const char *server_psk = "keys/server-psk.txt";
static const char *client_psk = "keys/client-psk.txt";

/* rfc9000#section-17.2: a long header, of type Handshake in QUIC v1 */
static int is_handshake(const unsigned char *b, ssize_t n)
{
	return n > 0 && (b[0] & 0xf0) == 0xe0;
}

static int64_t now_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
}

struct conn {
	struct sockaddr_in server;
	struct sockaddr_in front_addr;
	struct sockaddr_in client;
	int front;			/* Relay socket bound for the client */
	int back;			/* Relay socket connected to the server */
	atomic_int confirmed;
};

/* Relay the datagrams of a connection, and hold one ACK of the client in every
 * STEADY + 1 that follow a response.  The others pass at once, so that the RTT
 * of the server settles before the next held one.  The held one passes extra
 * microseconds after the response, a time that searches for and then tracks
 * the PTO of the server: shorter if the server sent a probe meanwhile, longer
 * if not.
 */
static void *do_relay(void *arg)
{
	int64_t sent = 0, extra = 0, step = 1000, deadline = 0;
	int i, timeout, acks = 0, held = 0, probed = 0, last = 0;
	unsigned char b[65536], ack[MSG_LEN];
	struct conn *c = arg;
	struct pollfd fds[2] = {
		{ .fd = c->front, .events = POLLIN },
		{ .fd = c->back, .events = POLLIN },
	};
	socklen_t alen;
	ssize_t n;

	for (;;) {
		timeout = -1;
		if (held)
			timeout = deadline > now_us() ? (deadline - now_us() + 999) / 1000 : 0;
		if (poll(fds, 2, timeout) < 0)
			break;
		if (held && now_us() >= deadline) {
			send(c->back, ack, held, 0);
			if (probed != last) /* Search for it, then track it. */
				step = step / 2 > STEP_US ? step / 2 : STEP_US;
			last = probed;
			extra += probed ? -step : step;
			held = 0;
		}
		for (i = 0; i < 2; i++) {
			if (!(fds[i].revents & POLLIN))
				continue;
			alen = sizeof(c->client);
			n = i ? recv(c->back, b, sizeof(b), 0) :
				recvfrom(c->front, b, sizeof(b), 0,
					 (struct sockaddr *)&c->client, &alen);
			if (n <= 0)
				continue;
			if (atomic_load(&c->confirmed) && is_handshake(b, n)) {
				atomic_fetch_add(&dropped[i], 1);
				continue;
			}
			if (i) {
				if (held)
					probed = 1;
				else if (atomic_load(&c->confirmed) && n >= MSG_LEN)
					sent = now_us();
				sendto(c->front, b, n, 0, (struct sockaddr *)&c->client,
				       sizeof(c->client));
				continue;
			}
			if (held) { /* Keep the order of the datagrams. */
				send(c->back, ack, held, 0);
				held = 0;
			}
			if (sent && n < MSG_LEN) {
				if (acks++ % (STEADY + 1) == STEADY) {
					memcpy(ack, b, n);
					held = n;
					probed = 0;
					deadline = sent + extra;
				}
				sent = 0;
				if (held)
					continue;
			}
			send(c->back, b, n, 0);
		}
	}
	return NULL;
}

static void set_timeout(int sockfd)
{
	struct timeval tv = { .tv_sec = TIMEOUT_SEC };

	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static void *do_echo(void *arg)
{
	int sockfd = (intptr_t)arg, ret;
	char msg[MSG_LEN];
	unsigned int flags;
	int64_t sid;

	if (quic_server_handshake(sockfd, server_psk, NULL, NULL)) {
		printf("server handshake failed\n");
		goto out;
	}
	set_timeout(sockfd);
	for (;;) { /* Echo each request on its stream. */
		flags = 0;
		ret = quic_recvmsg(sockfd, msg, sizeof(msg), &sid, &flags);
		if (ret <= 0)
			break;
		if (quic_sendmsg(sockfd, msg, ret, sid, 0) != ret)
			break;
	}
out:
	close(sockfd);
	return NULL;
}

static void *do_server(void *arg)
{
	int listenfd = *(int *)arg, sockfd;
	pthread_t echo;

	for (;;) {
		sockfd = accept(listenfd, NULL, NULL);
		if (sockfd < 0)
			break;
		pthread_create(&echo, NULL, do_echo, (void *)(intptr_t)sockfd);
		pthread_detach(echo);
	}
	return NULL;
}

static int request(int sockfd, int64_t sid, unsigned int flags)
{
	char msg[MSG_LEN] = "ping";
	int ret, len = 0;

	if (quic_sendmsg(sockfd, msg, sizeof(msg), sid, flags) != sizeof(msg))
		return -1;
	while (len < (int)sizeof(msg)) {
		flags = 0;
		ret = quic_recvmsg(sockfd, msg, sizeof(msg) - len, &sid, &flags);
		if (ret <= 0)
			return -1;
		len += ret;
	}
	return 0;
}

static int bind_loopback(int sockfd, struct sockaddr_in *sa)
{
	socklen_t len = sizeof(*sa);

	sa->sin_family = AF_INET;
	sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa->sin_port = 0;
	if (bind(sockfd, (struct sockaddr *)sa, sizeof(*sa)))
		return -1;
	return getsockname(sockfd, (struct sockaddr *)sa, &len);
}

static int run_client(struct conn *c)
{
	struct timespec ts = { .tv_nsec = PAUSE_MS * 1000000L };
	struct quic_transport_param param = { .max_ack_delay = ACK_DELAY_US };
	pthread_t relay;
	int sockfd, i;

	c->front = socket(AF_INET, SOCK_DGRAM, 0);
	c->back = socket(AF_INET, SOCK_DGRAM, 0);
	if (c->front < 0 || c->back < 0 || bind_loopback(c->front, &c->front_addr) ||
	    connect(c->back, (struct sockaddr *)&c->server, sizeof(c->server))) {
		printf("relay socket failed %d\n", errno);
		return -1;
	}
	pthread_create(&relay, NULL, do_relay, c);
	pthread_detach(relay);

	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
	if (sockfd < 0 ||
	    connect(sockfd, (struct sockaddr *)&c->front_addr, sizeof(c->front_addr)) ||
	    setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, sizeof(param))) {
		printf("client socket failed %d\n", errno);
		return -1;
	}
	if (quic_client_handshake(sockfd, client_psk, NULL, NULL)) {
		printf("client handshake failed\n");
		return -1;
	}
	set_timeout(sockfd);

	/* After a response, the server has the Finished of the client, and so
	 * both ends have confirmed the handshake.
	 */
	if (request(sockfd, 0, MSG_QUIC_STREAM_NEW)) {
		printf("first request failed %d\n", errno);
		return -1;
	}
	atomic_store(&c->confirmed, 1);

	for (i = 0; i < REQUESTS; i++) {
		nanosleep(&ts, NULL);
		if (request(sockfd, 0, 0)) {
			printf("request %d stalled %d\n", i, errno);
			return -1;
		}
		if (atomic_load(&dropped[0]) || atomic_load(&dropped[1]))
			break;
	}
	close(sockfd);
	return 0;
}

static void *do_client(void *arg)
{
	if (run_client(arg))
		atomic_store(&failed, 1);
	return NULL;
}

int main(void)
{
	int listenfd, i;
	struct sockaddr_in sa;
	pthread_t server, clients[CONNS];
	static struct conn c[CONNS];

	quic_set_log_level(LOG_NOTICE);

	listenfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
	if (listenfd < 0 || bind_loopback(listenfd, &sa) || listen(listenfd, CONNS)) {
		printf("server socket failed %d\n", errno);
		return 1;
	}
	pthread_create(&server, NULL, do_server, &listenfd);

	for (i = 0; i < CONNS; i++) {
		c[i].server = sa;
		pthread_create(&clients[i], NULL, do_client, &c[i]);
	}
	for (i = 0; i < CONNS; i++)
		pthread_join(clients[i], NULL);

	printf("handshake packets after confirmation: %d from clients, %d from server\n",
	       atomic_load(&dropped[0]), atomic_load(&dropped[1]));
	if (atomic_load(&dropped[0]) || atomic_load(&dropped[1]))
		atomic_store(&failed, 1);
	printf("%s\n", atomic_load(&failed) ? "FAIL" : "PASS");
	return atomic_load(&failed);
}
