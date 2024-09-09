#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <netinet/quic.h>

static uint8_t ticket[4096];
static uint8_t token[256];

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
	unsigned int param_len, token_len, addr_len, flags;
	struct quic_transport_param param = {};
	struct sockaddr_in ra = {}, la = {};
	char msg[50], *alpn;
	size_t ticket_len;
	int ret, sockfd;
	int64_t sid;

	if (argc < 3) {
		printf("%s client <PEER ADDR> <PEER PORT> [ALPN]\n", argv[0]);
		return 0;
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

	/* get session ticket, remote tranaport param, token for session resumption */
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

	token_len = sizeof(token);
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TOKEN, &token, &token_len);
	if (ret == -1) {
		printf("socket getsockopt regular token\n");
		return -1;
	}

	addr_len = sizeof(la);
	ret = getsockname(sockfd, (struct sockaddr *)&la, &addr_len);
	if (ret == -1) {
		printf("getsockname local address and port used\n");
		return -1;
	}

	printf("get the session ticket %lu and transport param %u and token %u, save it\n",
	       ticket_len, param_len, token_len);

	strcpy(msg, "hello quic server!");
	sid = QUIC_STREAM_TYPE_UNI_MASK;
	flags = MSG_STREAM_NEW | MSG_STREAM_FIN;
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d %d\n", ret, errno);
		return -1;
	}
	printf("send '%s' on stream %ld\n", msg, sid);

	flags = 0;
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg) - 1, &sid, &flags);
	if (ret == -1) {
		printf("recv error %d %d\n", ret, errno);
		return 1;
	}
	printf("recv '%s' on stream %ld\n", msg, sid);

	close(sockfd);

	printf("start new connection with the session ticket used...\n");
	sleep(2);

	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
	if (sockfd < 0) {
		printf("socket create failed\n");
		return -1;
	}

	/* bind previous address and port and set token for address validation */
	if (bind(sockfd, (struct sockaddr *)&la, addr_len)) {
		printf("socket bind failed\n");
		return -1;
	}

	ra.sin_family = AF_INET;
	ra.sin_port = htons(atoi(argv[3]));
	inet_pton(AF_INET, argv[2], &ra.sin_addr.s_addr);

	if (connect(sockfd, (struct sockaddr *)&ra, sizeof(ra))) {
		printf("socket connect failed\n");
		return -1;
	}

	/* set session ticket, remote tranaport param, token for session resumption */
	ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TOKEN, token, token_len);
	if (ret == -1) {
		printf("socket setsockopt token\n");
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
	printf("send '%s' on stream %ld\n", msg, sid);

	if (client_handshake(sockfd, alpn, NULL, ticket, ticket_len, NULL, NULL))
		return -1;

	flags = 0;
	memset(msg, 0, sizeof(msg));
	ret = quic_recvmsg(sockfd, msg, sizeof(msg) - 1, &sid, &flags);
	if (ret == -1) {
		printf("recv error %d %d\n", ret, errno);
		return 1;
	}
	printf("recv '%s' on stream %ld\n", msg, sid);

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
	struct quic_config config = {};
	struct sockaddr_in sa = {};
	int listenfd, sockfd, ret;
	char msg[50], *alpn;
	uint8_t key[64];
	int64_t sid;

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
	config.validate_peer_address = 1; /* trigger retry packet sending */
	if (setsockopt(listenfd, SOL_QUIC, QUIC_SOCKOPT_CONFIG, &config, sizeof(config)))
		return -1;

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
	printf("recv '%s' on stream %ld\n", msg, sid);

	strcpy(msg, "hello quic client!");
	sid = QUIC_STREAM_TYPE_SERVER_MASK;
	flags = MSG_STREAM_NEW | MSG_STREAM_FIN;
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d %d\n", ret, errno);
		return -1;
	}
	printf("send '%s' on stream %ld\n", msg, sid);

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
	printf("recv '%s' on stream %ld\n", msg, sid);

	strcpy(msg, "hello quic client! welcome back!");
	sid = QUIC_STREAM_TYPE_SERVER_MASK;
	flags = MSG_STREAM_NEW | MSG_STREAM_FIN;
	ret = quic_sendmsg(sockfd, msg, strlen(msg), sid, flags);
	if (ret == -1) {
		printf("send error %d %d\n", ret, errno);
		return -1;
	}
	printf("send '%s' on stream %ld\n", msg, sid);

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
