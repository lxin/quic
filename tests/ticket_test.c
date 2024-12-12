#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/quic.h>

static uint8_t ticket[4096];

static const char *parse_address(
	char const *address, char const *port, struct sockaddr_storage *sas)
{
	struct addrinfo hints = {0};
	struct addrinfo *res;
	int rc;

	hints.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	rc = getaddrinfo(address, port, &hints, &res);
	if (rc != 0)
		return gai_strerror(rc);
	memcpy(sas, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return NULL;
}

static int client_handshake(int sockfd, const char *alpns, const char *host,
			    const uint8_t *ticket_in, size_t ticket_in_len,
			    uint8_t *ticket_out, size_t *ticket_out_len)
{
	gnutls_certificate_credentials_t cred;
	gnutls_session_t session;
	size_t alpn_len;
	char alpn[64];
	int ret;

	ret = gnutls_certificate_allocate_credentials(&cred);
	if (ret)
		goto err;
	ret = gnutls_certificate_set_x509_system_trust(cred);
	if (ret < 0)
		goto err_cred;

	ret = gnutls_init(&session, GNUTLS_CLIENT |
				    GNUTLS_ENABLE_EARLY_DATA | GNUTLS_NO_END_OF_EARLY_DATA);
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

	if (host) {
		ret = gnutls_server_name_set(session, GNUTLS_NAME_DNS, host, strlen(host));
		if (ret)
			goto err_session;
	}

	gnutls_transport_set_int(session, sockfd);

	if (ticket_in) {
		ret = quic_session_set_data(session, ticket_in, ticket_in_len);
		if (ret)
			goto err_session;
	}

	ret = quic_handshake(session);
	if (ret)
		goto err_session;

	if (alpns) {
		alpn_len = sizeof(alpn);
		ret = quic_session_get_alpn(session, alpn, &alpn_len);
		if (ret)
			goto err_session;
	}

	if (ticket_out) {
		sleep(1);
		ret = quic_session_get_data(session, ticket_out, ticket_out_len);
		if (ret)
			goto err_session;
	}

err_session:
	gnutls_deinit(session);
err_cred:
	gnutls_certificate_free_credentials(cred);
err:
	return ret;
}

static int do_client(int argc, char *argv[])
{
	struct quic_transport_param param = {};
	unsigned int param_len, flags;
	struct sockaddr_storage ra = {};
	char msg[50], *alpn;
	size_t ticket_len;
	int ret, sockfd;
	const char *rc;
	int64_t sid;

	if (argc < 3) {
		printf("%s client <PEER ADDR> <PEER PORT> [ALPN]\n", argv[0]);
		return 0;
	}

	rc = parse_address(argv[2], argv[3], &ra);
	if (rc != NULL) {
		printf("parse address failed: %s\n", rc);
		return -1;
	}

	sockfd = socket(ra.ss_family, SOCK_DGRAM, IPPROTO_QUIC);
	if (sockfd < 0) {
		printf("socket create failed\n");
		return -1;
	}

	if (connect(sockfd, (struct sockaddr *)&ra, sizeof(ra))) {
		printf("socket connect failed\n");
		return -1;
	}

	/* get session ticket, remote tranaport param for session resumption */
	alpn = argv[4];
	ticket_len = sizeof(ticket);
	if (client_handshake(sockfd, alpn, NULL, NULL, 0, ticket, &ticket_len))
		return -1;

	param_len = sizeof(param);
	param.remote = 1;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, &param_len);
	if (ret == -1) {
		printf("socket getsockopt remote transport param\n");
		return -1;
	}

	printf("get the session ticket %u and transport param %u, save it\n",
	       (unsigned int)ticket_len, param_len);

	strcpy(msg, "hello quic server!");
	sid = QUIC_STREAM_TYPE_UNI_MASK;
	flags = MSG_STREAM_NEW | MSG_STREAM_FIN;
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d %d\n", ret, errno);
		return -1;
	}
	printf("send '%s' on stream %d\n", msg, (int)sid);

	flags = 0;
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg) - 1, &sid, &flags);
	if (ret == -1) {
		printf("recv error %d %d\n", ret, errno);
		return 1;
	}
	printf("recv '%s' on stream %d\n", msg, (int)sid);

	close(sockfd);

	printf("start new connection with the session ticket used...\n");
	sleep(2);

	rc = parse_address(argv[2], argv[3], &ra);
	if (rc != NULL) {
		printf("parse address failed: %s\n", rc);
		return -1;
	}

	sockfd = socket(ra.ss_family, SOCK_DGRAM, IPPROTO_QUIC);
	if (sockfd < 0) {
		printf("socket create failed\n");
		return -1;
	}

	if (connect(sockfd, (struct sockaddr *)&ra, sizeof(ra))) {
		printf("socket connect failed\n");
		return -1;
	}

	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, param_len);
	if (ret == -1) {
		printf("socket setsockopt remote transport param\n");
		return -1;
	}

	/* send early data before handshake */
	strcpy(msg, "hello quic server, I'm back!");
	sid = QUIC_STREAM_TYPE_UNI_MASK;
	flags = MSG_STREAM_NEW | MSG_STREAM_FIN;
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d %d\n", ret, errno);
		return -1;
	}
	printf("send '%s' on stream %d\n", msg, (int)sid);

	if (client_handshake(sockfd, alpn, NULL, ticket, ticket_len, NULL, NULL))
		return -1;

	flags = 0;
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg) - 1, &sid, &flags);
	if (ret == -1) {
		printf("recv error %d %d\n", ret, errno);
		return 1;
	}
	printf("recv '%s' on stream %d\n", msg, (int)sid);

	close(sockfd);
	return 0;
}

static int server_handshake(int sockfd, const char *pkey, const char *cert, const char *alpns,
			    uint8_t *key, unsigned int keylen)
{
	gnutls_certificate_credentials_t cred;
	gnutls_datum_t skey = {key, keylen};
	gnutls_session_t session;
	size_t alpn_len;
	char alpn[64];
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
	ret = gnutls_init(&session, GNUTLS_SERVER | GNUTLS_NO_AUTO_SEND_TICKET |
				    GNUTLS_ENABLE_EARLY_DATA | GNUTLS_NO_END_OF_EARLY_DATA);
	if (ret)
		goto err_cred;
	ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);
	if (ret)
		goto err_session;

	ret = gnutls_session_ticket_enable_server(session, &skey);
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

	if (alpns) {
		alpn_len = sizeof(alpn);
		ret = quic_session_get_alpn(session, alpn, &alpn_len);
	}

err_session:
	gnutls_deinit(session);
err_cred:
	gnutls_certificate_free_credentials(cred);
err:
	return ret;
}

static int do_server(int argc, char *argv[])
{
	unsigned int addrlen, keylen, flags;
	struct sockaddr_storage sa = {};
	int listenfd, sockfd, ret;
	char msg[50], *alpn;
	uint8_t key[64];
	const char *rc;
	int64_t sid;

	if (argc < 5) {
		printf("%s server <LOCAL ADDR> <LOCAL PORT> <PRIVATE_KEY_FILE> "
		       "<CERTIFICATE_FILE>\n", argv[0]);
		return 0;
	}

	rc = parse_address(argv[2], argv[3], &sa);
	if (rc != NULL) {
		printf("parse address failed: %s\n", rc);
		return -1;
	}

	listenfd = socket(sa.ss_family, SOCK_DGRAM, IPPROTO_QUIC);
	if (listenfd < 0) {
		printf("socket create failed\n");
		return -1;
	}
	if (bind(listenfd, (struct sockaddr *)&sa, sizeof(sa))) {
		printf("socket bind failed\n");
		return -1;
	}
	alpn = argv[6];
	if (alpn && setsockopt(listenfd, SOL_QUIC, QUIC_SOCKOPT_ALPN, alpn, strlen(alpn))) {
		printf("socket setsockopt alpn failed\n");
		return -1;
	}

	if (listen(listenfd, 1)) {
		printf("socket listen failed\n");
		return -1;
	}

	addrlen = sizeof(sa);
	sockfd = accept(listenfd, (struct sockaddr *)&sa, &addrlen);
	if (sockfd < 0) {
		printf("socket accept failed %d %d\n", errno, sockfd);
		return -1;
	}

	keylen = sizeof(key);
	if (getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_SESSION_TICKET, key, &keylen)) {
		printf("socket getsockopt session ticket error %d", errno);
		return -1;
	}

	if (server_handshake(sockfd, argv[4], argv[5], alpn, key, keylen))
		return -1;

	flags = 0;
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg) - 1, &sid, &flags);
	if (ret == -1) {
		printf("recv error %d %d\n", ret, errno);
		return 1;
	}
	printf("recv '%s' on stream %d\n", msg, (int)sid);

	strcpy(msg, "hello quic client!");
	sid = QUIC_STREAM_TYPE_SERVER_MASK;
	flags = MSG_STREAM_NEW | MSG_STREAM_FIN;
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d %d\n", ret, errno);
		return -1;
	}
	printf("send '%s' on stream %d\n", msg, (int)sid);

	close(sockfd);

	printf("wait for the client next connection...\n");

	addrlen = sizeof(sa);
	sockfd = accept(listenfd, (struct sockaddr *)&sa, &addrlen);
	if (sockfd < 0) {
		printf("socket accept failed %d %d\n", errno, sockfd);
		return -1;
	}

	if (server_handshake(sockfd, argv[4], argv[5], alpn, key, keylen))
		return -1;

	flags = 0;
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg) - 1, &sid, &flags);
	if (ret == -1) {
		printf("recv error %d %d\n", ret, errno);
		return 1;
	}
	printf("recv '%s' on stream %d\n", msg, (int)sid);

	strcpy(msg, "hello quic client! welcome back!");
	sid = QUIC_STREAM_TYPE_SERVER_MASK;
	flags = MSG_STREAM_NEW | MSG_STREAM_FIN;
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d %d\n", ret, errno);
		return -1;
	}
	printf("send '%s' on stream %d\n", msg, (int)sid);

	flags = 0;
	quic_recvmsg(sockfd, msg, sizeof(msg) - 1, &sid, &flags);

	close(sockfd);
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
