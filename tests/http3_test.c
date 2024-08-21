#include <nghttp3/nghttp3.h>
#include <netinet/quic.h>
#include <sys/syslog.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>

static int http_log_level = LOG_INFO;

static void http_log_debug(char const *fmt, ...)
{
	char msg[128];
	va_list arg;

	if (http_log_level < LOG_DEBUG)
		return;

	va_start(arg, fmt);
	vsnprintf(msg, sizeof(msg), fmt, arg);
	va_end(arg);

	printf("[DEBUG] %s", msg);
}

static void http_log_info(char const *fmt, ...)
{
	char msg[128];
	va_list arg;

	if (http_log_level < LOG_INFO)
		return;

	va_start(arg, fmt);
	vsnprintf(msg, sizeof(msg), fmt, arg);
	va_end(arg);

	printf("%s", msg);
}

static void http_log_error(char const *fmt, ...)
{
	char msg[128];
	va_list arg;

	if (http_log_level < LOG_ERR)
		return;

	va_start(arg, fmt);
	vsnprintf(msg, sizeof(msg), fmt, arg);
	va_end(arg);

	printf("[ERROR] %s", msg);
}

struct http_request {
	char		method[8];
	char		scheme[8];
	char		host[128];
	char		port[16];
	char		path[128];
	char		user_agent[32];

	uint8_t		done;
	uint32_t	len;
	uint8_t		*data;
	int64_t		stream_id;
};

static int http_acked_stream_data(nghttp3_conn *conn, int64_t stream_id, uint64_t datalen,
				  void *user_data, void *stream_user_data)
{
	http_log_debug("%s\n", __func__);
	return 0;
}

static int http_stream_close(nghttp3_conn *conn, int64_t stream_id, uint64_t app_error_code,
			     void *conn_user_data, void *stream_user_data)
{
	http_log_debug("%s\n", __func__);
	return 0;
}

static int http_deferred_consume(nghttp3_conn *conn, int64_t stream_id, size_t nconsumed,
				 void *user_data, void *stream_user_data)
{
	http_log_debug("%s\n", __func__);
	return 0;
}

static int http_begin_headers(nghttp3_conn *conn, int64_t stream_id, void *user_data,
			      void *stream_user_data)
{
	http_log_debug("%s\n", __func__);
	return 0;
}

static int http_recv_header(nghttp3_conn *conn, int64_t stream_id, int32_t token,
			    nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
			    void *user_data, void *stream_user_data)
{
	http_log_debug("%s\n", __func__);
	return 0;
}

static int http_end_headers(nghttp3_conn *conn, int64_t stream_id, int fin, void *user_data,
			    void *stream_user_data)
{
	http_log_debug("%s\n", __func__);
	return 0;
}

static int http_begin_trailers(nghttp3_conn *conn, int64_t stream_id, void *user_data,
			       void *stream_user_data)
{
	http_log_debug("%s\n", __func__);
	return 0;
}

static int http_recv_trailer(nghttp3_conn *conn, int64_t stream_id, int32_t token,
			     nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
			     void *user_data, void *stream_user_data)
{
	http_log_debug("%s\n", __func__);
	return 0;
}

static int http_end_trailers(nghttp3_conn *conn, int64_t stream_id, int fin,
			     void *user_data, void *stream_user_data)
{
	http_log_debug("%s\n", __func__);
	return 0;
}

static int http_stop_sending(nghttp3_conn *conn, int64_t stream_id, uint64_t app_error_code,
			     void *user_data, void *stream_user_data)
{
	http_log_debug("%s\n", __func__);
	return 0;
}

static int http_reset_stream(nghttp3_conn *conn, int64_t stream_id, uint64_t app_error_code,
			     void *user_data, void *stream_user_data)
{
	http_log_debug("%s\n", __func__);
	return 0;
}

static int http_recv_settings(nghttp3_conn *conn, const nghttp3_settings *settings,
			      void *conn_user_data)
{
	http_log_debug("%s\n", __func__);
	return 0;
}

static int http_shutdown(nghttp3_conn *conn, int64_t id, void *conn_user_data)
{
	http_log_debug("%s\n", __func__);
	return 0;
}

static int http_recv_data(nghttp3_conn *conn, int64_t stream_id, const uint8_t *data,
			  size_t datalen, void *user_data, void *stream_user_data)
{
	static size_t total;
	int i;

	for (i = 0; i < datalen; i++)
		http_log_info("%c", data[i]);

	total += datalen;
	http_log_debug("\n");
	http_log_debug("%s: %lu\n", __func__, total);
	return 0;
}

static int http_client_end_stream(nghttp3_conn *conn, int64_t stream_id, void *user_data,
				  void *stream_user_data)
{
	struct http_request *req = user_data;

	http_log_info("\n");
	req->done = 1;
	return 0;
}

static int http_parse_url(const char *url, struct http_request *req)
{
	char *colon_pos, *slash_pos;

	req->done = 0;
	strcpy(req->method, "GET");
	strcpy(req->user_agent, "nghttp3/quic client");
	if (!strncmp(url, "https://", 8)) {
		strcpy(req->scheme, "https");
		url += 8;
	} else if (!strncmp(url, "http://", 7)) {
		strcpy(req->scheme, "http");
		url += 7;
	} else {
		return -1;
	}

	colon_pos = strchr(url, ':');
	slash_pos = strchr(url, '/');

	if (colon_pos && (slash_pos == NULL || colon_pos < slash_pos)) {
		strncpy(req->host, url, colon_pos - url);
		req->host[colon_pos - url] = '\0';
		if (slash_pos) {
			strncpy(req->port, colon_pos + 1, slash_pos - colon_pos - 1);
			req->port[slash_pos - colon_pos - 1] = '\0';
			strcpy(req->path, slash_pos);
		} else {
			strcpy(req->port, colon_pos + 1);
			strcpy(req->path, "/");
		}
	} else {
		if (slash_pos) {
			strncpy(req->host, url, slash_pos - url);
			req->host[slash_pos - url] = '\0';
			strcpy(req->path, slash_pos);
		} else {
			strcpy(req->host, url);
			strcpy(req->path, "/");
		}
		strcpy(req->port, "443");
	}
	return 0;
}

static int http_client_setup_socket(char *host, char *port)
{
	struct quic_transport_param param = {};
	struct addrinfo *rp, *res;
	char *alpn = "h3, h3-29";
	int sockfd;

	if (getaddrinfo(host, port, NULL, &res)) {
		http_log_error("getaddrinfo error\n");
		return -1;
	}

	for (rp = res; rp != NULL; rp = rp->ai_next) {
		if (rp->ai_family == AF_INET)
			break;
	}

	if (!rp) {
		http_log_error("ai_family doesn't support\n");
		goto err_free;
	}

	sockfd = socket(rp->ai_family, SOCK_DGRAM, IPPROTO_QUIC);
	if (sockfd < 0) {
		http_log_error("socket create failed\n");
		goto err_free;
	}

	param.grease_quic_bit = 1;
	if (setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, sizeof(param))) {
		http_log_error("socket setsockopt transport_param failed\n");
		goto err_close;
	}

	if (connect(sockfd, rp->ai_addr, rp->ai_addrlen)) {
		http_log_error("socket connect failed\n");
		goto err_close;
	}

	if (quic_client_handshake(sockfd, NULL, host, alpn))
		goto err_close;

	http_log_debug("HANDSHAKE DONE\n");
	freeaddrinfo(res);
	return sockfd;

err_close:
	close(sockfd);
err_free:
	freeaddrinfo(res);
	return -1;
}

static int http_client_create_conn(nghttp3_conn **httpconn, int sockfd, struct http_request *req)
{
	int64_t ctrl_stream_id, qpack_enc_stream_id, qpack_dec_stream_id;
	const nghttp3_mem *mem = nghttp3_mem_default();
	nghttp3_callbacks callbacks = {
		http_acked_stream_data,
		http_stream_close,
		http_recv_data,
		http_deferred_consume,
		http_begin_headers,
		http_recv_header,
		http_end_headers,
		http_begin_trailers,
		http_recv_trailer,
		http_end_trailers,
		http_stop_sending,
		http_client_end_stream,
		http_reset_stream,
		http_shutdown,
		http_recv_settings,
	};
	struct quic_stream_info sinfo;
	socklen_t len = sizeof(sinfo);
	nghttp3_settings settings;
	int ret;

	nghttp3_settings_default(&settings);
	settings.qpack_blocked_streams = 100;
	settings.qpack_max_dtable_capacity = 4096;

	ret = nghttp3_conn_client_new(httpconn, &callbacks, &settings, mem, req);
	if (ret)
		return -1;

	sinfo.stream_id = -1;
	sinfo.stream_flags = MSG_STREAM_UNI;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &sinfo, &len);
	if (ret) {
		http_log_error("socket getsockopt stream_open ctrl failed\n");
		return -1;
	}
	ctrl_stream_id = sinfo.stream_id;
	ret = nghttp3_conn_bind_control_stream(*httpconn, ctrl_stream_id);
	if (ret)
		return -1;
	http_log_debug("%s ctrl_stream_id %llu\n", __func__, ctrl_stream_id);

	sinfo.stream_id = -1;
	sinfo.stream_flags = MSG_STREAM_UNI;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &sinfo, &len);
	if (ret) {
		http_log_error("socket getsockopt stream_open enc failed\n");
		return -1;
	}
	qpack_enc_stream_id = sinfo.stream_id;
	http_log_debug("%s qpack_enc_stream_id %llu\n", __func__, qpack_enc_stream_id);

	sinfo.stream_id = -1;
	sinfo.stream_flags = MSG_STREAM_UNI;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &sinfo, &len);
	if (ret) {
		http_log_error("socket getsockopt stream_open dec failed\n");
		return -1;
	}
	qpack_dec_stream_id = sinfo.stream_id;
	http_log_debug("%s qpack_dec_stream_id %llu\n", __func__, qpack_dec_stream_id);
	ret = nghttp3_conn_bind_qpack_streams(*httpconn, qpack_enc_stream_id,
					      qpack_dec_stream_id);
	if (ret)
		return -1;

	return 0;
}

static int http_write_data(nghttp3_conn *httpconn, int sockfd)
{
	int ret, i, flags = 0, fin = 0, sent;
	int64_t stream_id = -1;
	nghttp3_vec vec[16];
	nghttp3_ssize cnt;

	while (1) {
		cnt = nghttp3_conn_writev_stream(httpconn, &stream_id, &fin, vec, 16);
		if (cnt <= 0)
			return cnt;
		sent = 0;
		for (i = 0; i < cnt; i++) {
			if (i == cnt - 1 && fin)
				flags |= MSG_STREAM_FIN;
			http_log_debug("%s: %d %ld %d\n", __func__, vec[i].len, stream_id, flags);
			ret = quic_sendmsg(sockfd, vec[i].base, vec[i].len, stream_id, flags);
			if (ret < 0)
				return -1;
			sent += ret;
		}
		ret = nghttp3_conn_add_write_offset(httpconn, stream_id, sent);
		if (ret)
			return -1;
	}
	return 0;
}

static int http_read_data(nghttp3_conn *httpconn, int sockfd)
{
	int64_t stream_id = -1;
	uint32_t flags = 0;
	uint8_t buf[2048];
	int ret;

	while (1) {
		flags |= MSG_DONTWAIT;
		ret = quic_recvmsg(sockfd, &buf, sizeof(buf), &stream_id, &flags);
		if (ret <= 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return 0;
			return -1;
		}
		http_log_debug("%s: %d %ld %d\n", __func__, ret, stream_id, flags);
		ret = nghttp3_conn_read_stream(httpconn, stream_id, buf, ret,
					       flags & MSG_STREAM_FIN);
		if (ret < 0)
			return -1;
	}
	return 0;
}

static void http_make_nv(nghttp3_nv *nv, char *name, char *value)
{
	nv->name = (uint8_t *)name;
	nv->value = (uint8_t *)value;
	nv->namelen = strlen(name);
	nv->valuelen = strlen(value);
	nv->flags = NGHTTP3_NV_FLAG_NONE;
}

static int http_submit_request(nghttp3_conn *httpconn, int sockfd, struct http_request *req)
{
	struct quic_stream_info sinfo;
	socklen_t len = sizeof(sinfo);
	nghttp3_nv nva[5];
	int i, ret;

	sinfo.stream_id = -1;
	sinfo.stream_flags = 0;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &sinfo, &len);
	if (ret) {
		http_log_error("socket getsockopt stream_open bidi failed\n");
		return -1;
	}

	http_make_nv(&nva[0], ":method", req->method);
	http_make_nv(&nva[1], ":scheme", req->scheme);
	http_make_nv(&nva[2], ":authority", req->host);
	http_make_nv(&nva[3], ":path", req->path);
	http_make_nv(&nva[4], "user-agent", req->user_agent);

	for (i = 0; i < 5; i++)
		http_log_debug("%s: %s -> %s\n", __func__, nva[i].name, nva[i].value);

	ret = nghttp3_conn_submit_request(httpconn, sinfo.stream_id, nva, 5, NULL, NULL);
	if (ret)
		return -1;

	return http_write_data(httpconn, sockfd);
}

static int http_run_loop(nghttp3_conn *httpconn, int sockfd, struct http_request *req)
{
	struct timeval tv;
	fd_set readfds;
	int ret;

	while (!req->done) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);

		ret = select(sockfd + 1, &readfds, NULL,  NULL, &tv);
		if (ret < 0)
			return -1;
		ret = http_read_data(httpconn, sockfd);
		if (ret < 0)
			return -1;
		ret = http_write_data(httpconn, sockfd);
		if (ret < 0)
			return -1;
	}
	return 0;
}

static void http_conn_free(nghttp3_conn *httpconn, int sockfd)
{
	close(sockfd);
	nghttp3_conn_del(httpconn);
}

static int do_client(const char *url)
{
	nghttp3_conn *httpconn = NULL;
	struct http_request req;
	int sockfd, ret;

	ret = http_parse_url(url, &req);
	if (ret)
		return -1;

	sockfd = http_client_setup_socket(req.host, req.port);
	if (sockfd < 0)
		return -1;

	ret = http_client_create_conn(&httpconn, sockfd, &req);
	if (ret)
		goto out;

	ret = http_submit_request(httpconn, sockfd, &req);
	if (ret)
		goto out;

	ret = http_run_loop(httpconn, sockfd, &req);

out:
	http_conn_free(httpconn, sockfd);
	return ret;
}

static int http_server_setup_socket(char *host, char *port)
{
	struct quic_transport_param param = {};
	struct addrinfo *rp, *res;
	char *alpn = "h3, h3-29";
	int listenfd;

	if (getaddrinfo(host, port, NULL, &res)) {
		http_log_error("getaddrinfo error\n");
		return -1;
	}

	for (rp = res; rp != NULL; rp = rp->ai_next) {
		if (rp->ai_family == AF_INET)
			break;
	}

	if (!rp) {
		http_log_error("ai_family doesn't support\n");
		goto err_free;
	}

	listenfd = socket(rp->ai_family, SOCK_DGRAM, IPPROTO_QUIC);
	if (listenfd < 0) {
		http_log_error("socket create failed\n");
		goto err_free;
	}
	if (bind(listenfd, rp->ai_addr, rp->ai_addrlen)) {
		http_log_error("socket bind failed\n");
		goto err_close;
	}

	param.grease_quic_bit = 1;
	if (setsockopt(listenfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, sizeof(param))) {
		http_log_error("socket setsockopt transport_param failed\n");
		goto err_close;
	}

	if (setsockopt(listenfd, SOL_QUIC, QUIC_SOCKOPT_ALPN, alpn, strlen(alpn))) {
		http_log_error("socket setsockopt alpn failed\n");
		goto err_close;
	}

	if (listen(listenfd, 1)) {
		http_log_error("socket listen failed\n");
		goto err_close;
	}

	freeaddrinfo(res);
	return listenfd;

err_close:
	close(listenfd);
err_free:
	freeaddrinfo(res);
	return -1;
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

static int http_server_accept_socket(int listenfd, const char *pkey_file, const char *cert_file)
{
	char *alpn = "h3, h3-29";
	unsigned int keylen;
	uint8_t key[64];
	int sockfd;

	sockfd = accept(listenfd, NULL, NULL);
	if (sockfd < 0) {
		http_log_error("socket accept failed %d %d\n", errno, sockfd);
		return -1;
	}

	keylen = sizeof(key);
	if (getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_SESSION_TICKET, key, &keylen)) {
		printf("socket getsockopt session ticket error %d", errno);
		return -1;
	}

	if (server_handshake(sockfd, pkey_file, cert_file, alpn, key, keylen))
		return -1;

	http_log_debug("HANDSHAKE DONE\n");
	return sockfd;
}

static int http_server_begin_headers(nghttp3_conn *conn, int64_t stream_id, void *user_data,
				     void *stream_user_data)
{
	struct http_request *req = user_data;

	req->stream_id = stream_id;
	http_log_debug("%s: %llu\n", __func__, stream_id);
	return 0;
}

static int http_server_recv_header(nghttp3_conn *conn, int64_t stream_id, int32_t token,
				   nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
				   void *user_data, void *stream_user_data)
{
	nghttp3_vec v = nghttp3_rcbuf_get_buf(value);
	struct http_request *req = user_data;

	if (req->stream_id != stream_id) {
		http_log_error("%s: %llu %llu\n", __func__, req->stream_id, stream_id);
		return -1;
	}

	switch (token) {
	case NGHTTP3_QPACK_TOKEN__PATH:
		memcpy(req->path, v.base, v.len);
		http_log_debug("%s: path %s\n", __func__, req->path);
		break;
	case NGHTTP3_QPACK_TOKEN__METHOD:
		memcpy(req->method, v.base, v.len);
		http_log_debug("%s: method %s\n", __func__, req->method);
		break;
	case NGHTTP3_QPACK_TOKEN__AUTHORITY:
		memcpy(req->host, v.base, v.len);
		http_log_debug("%s: host %s\n", __func__, req->host);
		break;
	}
	return 0;
}

static nghttp3_ssize http_content_data(nghttp3_conn *conn, int64_t stream_id, nghttp3_vec *vec,
				       size_t veccnt, uint32_t *pflags, void *user_data,
				       void *stream_user_data)
{
	struct http_request *req = user_data;

	vec[0].base = req->data;
	vec[0].len = req->len;

	*pflags |= NGHTTP3_DATA_FLAG_EOF;
	return 1;
}

static int http_server_end_stream(nghttp3_conn *conn, int64_t stream_id, void *user_data,
				  void *stream_user_data)
{
	struct http_request *req = user_data;
	char len[10], status[] = "200";
	nghttp3_data_reader dr = {};
	char path[128] = {};
	nghttp3_nv nva[4];
	struct stat st;
	int ret, fd;

	if (!strcmp(req->path, "/")) {
		req->len = 14;
		req->data = malloc(req->len);
		if (!req->data)
			return -1;
		memcpy(req->data, "Hello, HTTP/3!", req->len);
		goto send;
	}

	path[0] = '.';
	strcpy(&path[1], req->path);
	http_log_debug("%s: %s\n", __func__, path);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		req->len = 16;
		strcpy(status, "404");
		req->data = malloc(req->len);
		if (!req->data)
			return -1;
		memcpy(req->data, "Sorry, Not Found", req->len);
		goto send;
	}
	ret = fstat(fd, &st);
	if (ret < 0)
		return -1;
	req->len = st.st_size;
	req->data = malloc(req->len);
	if (!req->data)
		return -1;
	ret = read(fd, req->data, req->len);
	if (ret < 0)
		goto err;

send:
	ret = sprintf(len, "%d", req->len);
	if (ret < 0)
		goto err;

	http_make_nv(&nva[0], ":status", status);
	http_make_nv(&nva[1], "server", "nghttp3/quic server");
	http_make_nv(&nva[2], "content-type", "text/plain");
	http_make_nv(&nva[3], "content-length", len);

	dr.read_data = http_content_data;
	return nghttp3_conn_submit_response(conn, stream_id, nva, 4, &dr);
err:
	free(req->data);
	req->data = NULL;
	return -1;
}

static int http_server_create_conn(nghttp3_conn **httpconn, int sockfd, struct http_request *req)
{
	int64_t ctrl_stream_id, qpack_enc_stream_id, qpack_dec_stream_id;
	const nghttp3_mem *mem = nghttp3_mem_default();
	struct quic_transport_param param = {};
	nghttp3_callbacks callbacks = {
		http_acked_stream_data,
		http_stream_close,
		http_recv_data,
		http_deferred_consume,
		http_server_begin_headers,
		http_server_recv_header,
		http_end_headers,
		http_begin_trailers,
		http_recv_trailer,
		http_end_trailers,
		http_stop_sending,
		http_server_end_stream,
		http_reset_stream,
		http_shutdown,
		http_recv_settings,
	};
	struct quic_stream_info sinfo;
	socklen_t len = sizeof(sinfo);
	nghttp3_settings settings;
	unsigned int param_len;
	int ret;

	memset(req, 0, sizeof(*req));
	nghttp3_settings_default(&settings);
	settings.qpack_blocked_streams = 100;
	settings.qpack_max_dtable_capacity = 4096;

	ret = nghttp3_conn_server_new(httpconn, &callbacks, &settings, mem, req);
	if (ret)
		return -1;

	param_len = sizeof(param);
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, &param_len);
	if (ret == -1) {
		http_log_error("socket getsockopt remote transport param\n");
		return -1;
	}
	nghttp3_conn_set_max_client_streams_bidi(*httpconn, param.max_streams_bidi);

	sinfo.stream_id = -1;
	sinfo.stream_flags = MSG_STREAM_UNI;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &sinfo, &len);
	if (ret) {
		http_log_error("socket getsockopt stream_open ctrl failed\n");
		return -1;
	}
	ctrl_stream_id = sinfo.stream_id;
	ret = nghttp3_conn_bind_control_stream(*httpconn, ctrl_stream_id);
	if (ret)
		return -1;
	http_log_debug("%s ctrl_stream_id %llu\n", __func__, ctrl_stream_id);

	sinfo.stream_id = -1;
	sinfo.stream_flags = MSG_STREAM_UNI;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &sinfo, &len);
	if (ret) {
		http_log_error("socket getsockopt stream_open enc failed\n");
		return -1;
	}
	qpack_enc_stream_id = sinfo.stream_id;
	http_log_debug("%s qpack_enc_stream_id %llu\n", __func__, qpack_enc_stream_id);

	sinfo.stream_id = -1;
	sinfo.stream_flags = MSG_STREAM_UNI;
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &sinfo, &len);
	if (ret) {
		http_log_error("socket getsockopt stream_open dec failed\n");
		return -1;
	}
	qpack_dec_stream_id = sinfo.stream_id;
	http_log_debug("%s qpack_dec_stream_id %llu\n", __func__, qpack_dec_stream_id);
	ret = nghttp3_conn_bind_qpack_streams(*httpconn, qpack_enc_stream_id,
					      qpack_dec_stream_id);
	if (ret)
		return -1;

	return 0;
}

static int do_server(char *host, const char *pkey_file, const char *cert_file)
{
	nghttp3_conn *httpconn = NULL;
	int ret, listenfd, sockfd;
	struct http_request req;
	char *port;

	host = strtok_r(host, ":", &port);
	if (!host || !port)
		return -1;

	listenfd = http_server_setup_socket(host, port);
	if (listenfd < 0)
		return -1;

	while (1) {
		sockfd = http_server_accept_socket(listenfd, pkey_file, cert_file);
		if (sockfd < 0)
			break;

		ret = http_server_create_conn(&httpconn, sockfd, &req);
		if (ret)
			goto free;

		http_run_loop(httpconn, sockfd, &req);

free:
		http_conn_free(httpconn, sockfd);
	}

	close(listenfd);
	return 0;
}

int main(int argc, char *argv[])
{
	if (argc < 2)
		goto err;

	if (!strcmp(argv[1], "-c")) {
		if (argc < 3) {
			http_log_info("\n  %s -c <URI>\n", argv[0]);
			http_log_info("\n    e.g. %s -c https://www.google.com/\n", argv[0]);
			http_log_info("\n");
			return -1;
		}
		return do_client(argv[2]);
	}

	if (!strcmp(argv[1], "-s")) {
		if (argc < 5) {
			http_log_info("\n  %s -s <ADDR:PORT> <PKEY_FILE> <CERT_FILE>\n", argv[0]);
			http_log_info("\n    e.g. %s -s 127.0.0.1:443 "
				      "./keys/server-key.pem ./keys/server-cert.pem\n", argv[0]);
			http_log_info("\n");
			return -1;
		}
		return do_server(argv[2], argv[3], argv[4]);
	}

err:
	http_log_info("\n  %s <-c | -s> ...\n", argv[0]);
	http_log_info("\n");
	return -1;
}
