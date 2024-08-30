#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <netinet/quic.h>

static int do_client_alpn(char *ip, int port, char *alpn, int preferred_port)
{
	struct sockaddr_in sa = {};
	unsigned int len;
	int ret, sockfd;
	char msg[50];

	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
	if (sockfd < 0) {
		printf("socket create failed\n");
		return -1;
	}

	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	inet_pton(AF_INET, ip, &sa.sin_addr.s_addr);

	if (connect(sockfd, (struct sockaddr *)&sa, sizeof(sa))) {
		printf("socket connect failed\n");
		return -1;
	}

	if (quic_client_handshake(sockfd, NULL, NULL, alpn))
		return -1;

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

	len = sizeof(sa);
	ret = getpeername(sockfd, (struct sockaddr *)&sa, &len);
	if (ret == -1) {
		printf("socket getpeername error %d\n", errno);
		return -1;
	}

	printf("PEER PORT: %d\n", ntohs(sa.sin_port));
	if (ntohs(sa.sin_port) != preferred_port) {
		printf("preferred port: %d\n", preferred_port);
		return -1;
	}
	/* do not close(sockfd) on purpose */
	return 0;
}

static int do_client(int argc, char *argv[])
{
	char *ip;
	int port;

	if (argc < 3) {
		printf("%s client <PEER ADDR> <PEER PORT>\n", argv[0]);
		return 0;
	}

	port = atoi(argv[3]);
	ip = argv[2];
	if (do_client_alpn(ip, port, "smbd", port + 1))
		return -1;
	if (do_client_alpn(ip, port, "h3", port + 2))
		return -1;
	if (do_client_alpn(ip, port, "ksmbd", port + 3))
		return -1;

	return 0;
}

static int server_handshake(int sockfd, const char *pkey, const char *cert,
			    const char *alpns, char *alpn, size_t *alpn_len)
{
	gnutls_certificate_credentials_t cred;
	gnutls_session_t session;
	int ret;

	ret = gnutls_certificate_allocate_credentials(&cred);
	if (ret)
		goto err;
	ret = gnutls_certificate_set_x509_system_trust(cred);
	if (ret < 0)
		goto err_cred;
	ret = gnutls_certificate_set_x509_key_file(cred, cert, pkey, GNUTLS_X509_FMT_PEM);
	if (ret)
		goto err_cred;
	ret = gnutls_init(&session, GNUTLS_SERVER | GNUTLS_NO_AUTO_SEND_TICKET);
	if (ret)
		goto err_cred;
	ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);
	if (ret)
		goto err_session;

	ret = gnutls_priority_set_direct(session, QUIC_PRIORITY, NULL);
	if (ret)
		goto err_session;

	if (alpns) {
		ret = quic_session_set_alpn(session, alpns, strlen(alpns));
		if (ret)
			goto err_session;
	}

	gnutls_transport_set_int(session, sockfd);

	ret = quic_handshake(session);
	if (ret)
		goto err_session;

	if (alpns)
		ret = quic_session_get_alpn(session, alpn, alpn_len);

err_session:
	gnutls_deinit(session);
err_cred:
	gnutls_certificate_free_credentials(cred);
err:
	return ret;
}

static int do_server(int argc, char *argv[])
{
	char alpns[20] = "smbd, h3, ksmbd";
	int listenfd, sockfd, ret, i = 0;
	struct sockaddr_in sa = {};
	unsigned int addrlen, len;
	int preferred_port;
	char msg[50] = {};

	if (argc < 5) {
		printf("%s server <LOCAL ADDR> <LOCAL PORT> <PRIVATE_KEY_FILE> "
		       "<CERTIFICATE_FILE>\n", argv[0]);
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
	len = strlen(alpns);
	if (setsockopt(listenfd, SOL_QUIC, QUIC_SOCKOPT_ALPN, alpns, len)) {
		printf("socket setsockopt alpn failed %d\n", len);
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
	while (i++ < 3) {
		char alpn[20] = {};
		size_t alpn_len;

		addrlen = sizeof(sa);
		sockfd = accept(listenfd, (struct sockaddr *)&sa, &addrlen);
		if (sockfd < 0) {
			printf("socket accept failed %d %d\n", errno, sockfd);
			return -1;
		}

		/* call setsockopt(QUIC_SOCKOPT_CONNECTION_MIGRATION) before handshake
		 * to set up the preferred_address transport param.
		 */
		ret = getsockname(sockfd, (struct sockaddr *)&sa, &addrlen);
		if (ret == -1) {
			printf("socket getsockname error %d\n", errno);
			return -1;
		}
		preferred_port = ntohs(sa.sin_port) + i;
		sa.sin_port = htons(preferred_port); /* you can also change sa.sin_addr */
		ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONNECTION_MIGRATION, &sa, addrlen);
		if (ret == -1) {
			printf("socket setsockopt migration error %d\n", errno);
			return -1;
		}

		alpn_len = sizeof(alpn) - 1;
		if (server_handshake(sockfd, argv[4], argv[5], alpns, alpn, &alpn_len))
			return -1;

		printf("ALPN: %s\n", alpn);

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
		ret = getsockname(sockfd, (struct sockaddr *)&sa, &addrlen);
		if (ret == -1) {
			printf("socket getsockname error %d\n", errno);
			return -1;
		}
		printf("LOCAL PORT %d\n", ntohs(sa.sin_port));
		if (preferred_port != ntohs(sa.sin_port)) {
			printf("preferred port: %d\n", preferred_port);
			return -1;
		}
		/* do not close(sockfd) on purpose */
	}
	sleep(1);
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
