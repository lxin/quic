#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/quic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <unistd.h>

#define ALPN_NAME "sample"
#define TEST_MSG  "hello quic mtls!"

static int parse_addr(const char *ip, uint16_t port, struct sockaddr_storage *ss,
		      socklen_t *slen)
{
	memset(ss, 0, sizeof(*ss));

	if (strchr(ip, ':')) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;

		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(port);
		if (inet_pton(AF_INET6, ip, &sin6->sin6_addr) != 1)
			return -EINVAL;
		*slen = sizeof(*sin6);
	} else {
		struct sockaddr_in *sin = (struct sockaddr_in *)ss;

		sin->sin_family = AF_INET;
		sin->sin_port = htons(port);
		if (inet_pton(AF_INET, ip, &sin->sin_addr) != 1)
			return -EINVAL;
		*slen = sizeof(*sin);
	}
	return 0;
}

static int run_server(const char *ip, uint16_t port, const char *pkey_file,
		      const char *cert_file, const char *ca_file, int require_mtls)
{
	struct sockaddr_storage ss;
	socklen_t slen;
	int listenfd, sockfd, ret;
	char buf[256] = {};
	uint32_t flags = 0;
	int64_t sid = 0;
	ssize_t n;

	if (parse_addr(ip, port, &ss, &slen) < 0) {
		fprintf(stderr, "Invalid server IP address: %s\n", ip);
		return 1;
	}

	listenfd = socket(ss.ss_family, SOCK_DGRAM, IPPROTO_QUIC);
	if (listenfd < 0) {
		perror("socket");
		return 1;
	}

	if (bind(listenfd, (struct sockaddr *)&ss, slen) < 0) {
		perror("bind");
		close(listenfd);
		return 1;
	}

	if (listen(listenfd, 5) < 0) {
		perror("listen");
		close(listenfd);
		return 1;
	}

	sockfd = accept(listenfd, NULL, NULL);
	if (sockfd < 0) {
		perror("accept");
		close(listenfd);
		return 1;
	}

	if (require_mtls)
		ret = quic_server_handshake_mtls(sockfd, pkey_file, cert_file,
						 ca_file, ALPN_NAME);
	else
		ret = quic_server_handshake(sockfd, pkey_file, cert_file, ALPN_NAME);

	if (ret < 0) {
		fprintf(stderr, "Server handshake failed: %d\n", ret);
		close(sockfd);
		close(listenfd);
		return 1;
	}

	n = quic_recvmsg(sockfd, buf, sizeof(buf) - 1, &sid, &flags);
	if (n <= 0) {
		fprintf(stderr, "Server quic_recvmsg failed: %zd (errno=%d)\n", n, errno);
		close(sockfd);
		close(listenfd);
		return 1;
	}

	printf("Server received (stream %lld): %s\n", (long long)sid, buf);

	n = quic_sendmsg(sockfd, buf, (size_t)n, sid, MSG_QUIC_STREAM_FIN);
	if (n < 0) {
		fprintf(stderr, "Server quic_sendmsg failed: %zd (errno=%d)\n", n, errno);
		close(sockfd);
		close(listenfd);
		return 1;
	}

	/* Wait for peer connection close before tearing down socket */
	flags = 0;
	(void)quic_recvmsg(sockfd, buf, sizeof(buf) - 1, &sid, &flags);

	close(sockfd);
	close(listenfd);
	return 0;
}

static int run_client(const char *ip, uint16_t port, const char *hostname,
		      const char *ca_file, const char *cert_file,
		      const char *pkey_file)
{
	struct sockaddr_storage ss;
	socklen_t slen;
	int sockfd, ret;
	char buf[256] = {};
	uint32_t flags = 0;
	int64_t sid = 0;
	ssize_t n;

	if (parse_addr(ip, port, &ss, &slen) < 0) {
		fprintf(stderr, "Invalid target IP address: %s\n", ip);
		return 1;
	}

	sockfd = socket(ss.ss_family, SOCK_DGRAM, IPPROTO_QUIC);
	if (sockfd < 0) {
		perror("socket");
		return 1;
	}

	if (connect(sockfd, (struct sockaddr *)&ss, slen) < 0) {
		perror("connect");
		close(sockfd);
		return 1;
	}

	ret = quic_client_handshake_mtls(sockfd, ca_file, cert_file, pkey_file,
					 hostname, ALPN_NAME);
	if (ret < 0) {
		fprintf(stderr, "Client handshake failed: %d\n", ret);
		close(sockfd);
		return 1;
	}

	n = quic_sendmsg(sockfd, TEST_MSG, strlen(TEST_MSG), 0,
			 MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN);
	if (n < 0) {
		fprintf(stderr, "Client quic_sendmsg failed: %zd (errno=%d)\n", n, errno);
		close(sockfd);
		return 1;
	}

	n = quic_recvmsg(sockfd, buf, sizeof(buf) - 1, &sid, &flags);
	if (n <= 0) {
		fprintf(stderr, "Client quic_recvmsg failed: %zd (errno=%d)\n", n, errno);
		close(sockfd);
		return 1;
	}

	printf("Client received echo (stream %lld): %s\n", (long long)sid, buf);
	if (strcmp(buf, TEST_MSG) != 0) {
		fprintf(stderr, "Echo mismatch: got '%s', expected '%s'\n", buf, TEST_MSG);
		close(sockfd);
		return 1;
	}

	close(sockfd);
	return 0;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s server <ip> <port> <server.key> <server.crt> [ca.crt]\n"
		"  %s client <ip> <port> <hostname> <ca.crt> [client.crt client.key]\n",
		prog, prog);
}

int main(int argc, char *argv[])
{
	quic_set_log_level(LOG_ERR);

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "server") == 0) {
		if (argc < 6 || argc > 7) {
			usage(argv[0]);
			return 1;
		}
		return run_server(argv[2], (uint16_t)atoi(argv[3]),
				  argv[4], argv[5],
				  (argc == 7) ? argv[6] : NULL,
				  (argc == 7) ? 1 : 0);
	}

	if (strcmp(argv[1], "client") == 0) {
		if (argc != 6 && argc != 8) {
			usage(argv[0]);
			return 1;
		}
		return run_client(argv[2], (uint16_t)atoi(argv[3]),
				  argv[4], argv[5],
				  (argc == 8) ? argv[6] : NULL,
				  (argc == 8) ? argv[7] : NULL);
	}

	usage(argv[0]);
	return 1;
}
