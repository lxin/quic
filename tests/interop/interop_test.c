#include <nghttp3/nghttp3.h>
#include <netinet/quic.h>
#include <sys/syslog.h>
#include <linux/tls.h>
#include <sys/stat.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>

static int http_log_level = LOG_INFO;

#define QUIC_PRIORITY_CHACHA20 \
	"NORMAL:-VERS-ALL:+VERS-TLS1.3:+PSK:+ECDHE-PSK:-CIPHER-ALL:" \
	"+CHACHA20-POLY1305:-GROUP-ALL:+GROUP-SECP256R1:" \
	"+GROUP-X25519:+GROUP-SECP384R1:+GROUP-SECP521R1:" \
	"%DISABLE_TLS13_COMPAT_MODE"

#define IOP_CHACHA20				1
#define IOP_HANDSHAKE				2
#define IOP_HTTP3				3
#define IOP_KEYUPDATE				4
#define IOP_MULTICONNECT			5
#define IOP_RESUMPTION				6
#define IOP_RETRY				7
#define IOP_TRANSFER				8
#define IOP_VERSIONNEGOTIATION			9
#define IOP_ZERORTT				10
#define IOP_V2					11
#define IOP_ECN					12

struct http_req {
	char			user_agent[32];
	char			path[512];
	char			method[8];
	char			scheme[8];
	char			host[128];
	char			port[16];

	int			fd;
	uint32_t		len;
	uint8_t			*data;
};

struct http_ctx {
	char			user_agent[32];
	char			path[512];
	char			method[8];
	char			scheme[8];
	char			host[128];
	char			port[16];

	struct http_req		reqs[2048];
	uint8_t			buf[4096];
	uint32_t		req_cnt;
	uint8_t			complete;
	uint8_t			is_serv;
	char			root[32];
	int			sockfd;
	int			errcode;

	char			*pkey_file;
	char			*cert_file;
	int			testcase;
};

struct http_thread {
	struct http_ctx		*ctx;
	pthread_t		thread;
};

static void http_log_debug(char const *fmt, ...)
{
	char msg[512];
	va_list arg;

	if (http_log_level < LOG_DEBUG)
		return;

	va_start(arg, fmt);
	vsnprintf(msg, sizeof(msg), fmt, arg);
	va_end(arg);

	printf("[DEBUG] %s", msg);
}

static void http_log_error(char const *fmt, ...)
{
	char msg[512];
	va_list arg;

	if (http_log_level < LOG_ERR)
		return;

	va_start(arg, fmt);
	vsnprintf(msg, sizeof(msg), fmt, arg);
	va_end(arg);

	printf("[ERROR] %s", msg);
}

/* common nghttp3 callback functions s */
static int http3_acked_stream_data(nghttp3_conn *conn, int64_t stream_id, uint64_t datalen,
				   void *user_data, void *stream_user_data)
{
	http_log_debug("%s\n", __func__);
	return 0;
}

static int http3_stream_close(nghttp3_conn *conn, int64_t stream_id, uint64_t app_error_code,
			      void *conn_user_data, void *stream_user_data)
{
	http_log_debug("%s\n", __func__);
	return 0;
}

static int http3_deferred_consume(nghttp3_conn *conn, int64_t stream_id, size_t nconsumed,
				  void *user_data, void *stream_user_data)
{
	http_log_debug("%s\n", __func__);
	return 0;
}

static int http3_begin_headers(nghttp3_conn *conn, int64_t stream_id, void *user_data,
			       void *stream_user_data)
{
	http_log_debug("%s\n", __func__);
	return 0;
}

static int http3_recv_header(nghttp3_conn *conn, int64_t stream_id, int32_t token,
			     nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
			     void *user_data, void *stream_user_data)
{
	http_log_debug("%s\n", __func__);
	return 0;
}

static int http3_end_headers(nghttp3_conn *conn, int64_t stream_id, int fin, void *user_data,
			     void *stream_user_data)
{
	http_log_debug("%s\n", __func__);
	return 0;
}

static int http3_begin_trailers(nghttp3_conn *conn, int64_t stream_id, void *user_data,
			        void *stream_user_data)
{
	http_log_debug("%s\n", __func__);
	return 0;
}

static int http3_recv_trailer(nghttp3_conn *conn, int64_t stream_id, int32_t token,
			      nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
			      void *user_data, void *stream_user_data)
{
	http_log_debug("%s\n", __func__);
	return 0;
}

static int http3_end_trailers(nghttp3_conn *conn, int64_t stream_id, int fin,
			      void *user_data, void *stream_user_data)
{
	http_log_debug("%s\n", __func__);
	return 0;
}

static int http3_stop_sending(nghttp3_conn *conn, int64_t stream_id, uint64_t app_error_code,
			      void *user_data, void *stream_user_data)
{
	http_log_debug("%s\n", __func__);
	return 0;
}

static int http3_reset_stream(nghttp3_conn *conn, int64_t stream_id, uint64_t app_error_code,
			      void *user_data, void *stream_user_data)
{
	http_log_debug("%s\n", __func__);
	return 0;
}

static int http3_recv_settings(nghttp3_conn *conn, const nghttp3_settings *settings,
			       void *conn_user_data)
{
	http_log_debug("%s\n", __func__);
	return 0;
}

static int http3_shutdown(nghttp3_conn *conn, int64_t id, void *conn_user_data)
{
	http_log_debug("%s\n", __func__);
	return 0;
}


static int http_read_file(const char *filename, uint8_t *buf, size_t *buf_len)
{
	struct stat st;
	int ret, fd;

	*buf_len = 0;

	ret = stat(filename, &st);
	if (ret || !st.st_size)
		return 0;

	fd= open(filename, O_RDONLY);
	if (fd == -1) {
		http_log_error("open file %s failed for read\n", filename);
		return -1;
	}

	ret = read(fd, buf, st.st_size);
	if (ret == -1) {
		http_log_error("write file %s failed\n", filename);
		goto out;
	}

	*buf_len = ret;
out:
	close(fd);
	return ret;
}

static int http_write_file(const char *filename, uint8_t *buf, size_t buf_len)
{
	int ret, fd;

	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd == -1) {
		http_log_error("open file %s failed for write\n", filename);
		return -1;
	}

	ret = write(fd, buf, buf_len);
	if (ret == -1) {
		http_log_error("write file %s failed\n", filename);
		close(fd);
		return -1;
	}

	close(fd);
	return ret;
}

/* http common functions */
static int http_client_handshake(int sockfd, const char *alpns, const char *host, uint8_t *buf,
				 const char *sess_file, int testcase)
{
	gnutls_certificate_credentials_t cred;
	char alpn[64], *prio = QUIC_PRIORITY;
	size_t buf_len, alpn_len;
	gnutls_session_t session;
	int ret, count = 0;

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

	if (testcase == IOP_CHACHA20)
		prio = QUIC_PRIORITY_CHACHA20;

	ret = gnutls_priority_set_direct(session, prio, NULL);
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

	if (testcase == IOP_RESUMPTION || testcase == IOP_ZERORTT) { /* load session ticket */
		if (http_read_file(sess_file, buf, &buf_len) < 0)
			goto err_session;
		if (buf_len) {
			ret = quic_session_set_data(session, buf, buf_len);
			if (ret)
				goto err_session;
		}
	}

	ret = quic_handshake(session);
	if (ret)
		goto err_session;

	if (alpns) {
		alpn_len = sizeof(alpn);
		ret = quic_session_get_alpn(session, alpn, &alpn_len);
	}

	if (testcase == IOP_RESUMPTION || testcase == IOP_ZERORTT) { /* save session ticket */
		while (1) {
			buf_len = 4096;
			ret = quic_session_get_data(session, buf, &buf_len);
			if (ret)
				break;
			if (buf_len) {
				if (http_write_file(sess_file, buf, buf_len) <= 0)
					ret = -errno;
				break;
			}
			if (count++ == 3) { /* wait for session ticket up to 3 secs */
				ret = -EINVAL;
				break;
			}
			sleep(1);
		}
	}

err_session:
	gnutls_deinit(session);
err_cred:
	gnutls_certificate_free_credentials(cred);
err:
	return ret;
}

static int http_client_setup_socket(char *host, char *port, int testcase)
{
	struct quic_transport_param param = {};
	struct addrinfo *rp = NULL, *res, *p;
	struct quic_config config = {};
	int sockfd;

	if (getaddrinfo(host, port, NULL, &res)) {
		http_log_error("getaddrinfo error\n");
		return -1;
	}

	for (p = res; p != NULL; p = p->ai_next) {
		if (p->ai_family == AF_INET) {
			rp = p;
			break;
		}
		if (p->ai_family == AF_INET6)
			rp = p;
	}

	if (!rp) {
		errno = EINVAL;
		http_log_error("ai_family doesn't support\n");
		goto err_free;
	}

	sockfd = socket(rp->ai_family, SOCK_DGRAM, IPPROTO_QUIC);
	if (sockfd < 0) {
		http_log_error("socket create failed\n");
		goto err_free;
	}

	if (testcase == IOP_VERSIONNEGOTIATION)
		config.version = 123;

	config.initial_smoothed_rtt = 100000;
	if (setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CONFIG, &config, sizeof(config))) {
		http_log_error("socket setsockopt config failed\n");
		goto err_close;
	}

	param.grease_quic_bit = 1;
	param.max_idle_timeout = 180000000;
	if (setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, sizeof(param))) {
		http_log_error("socket setsockopt transport_param failed\n");
		goto err_close;
	}

	if (connect(sockfd, rp->ai_addr, rp->ai_addrlen)) {
		http_log_error("socket connect failed\n");
		goto err_close;
	}

	freeaddrinfo(res);
	return sockfd;

err_close:
	close(sockfd);
err_free:
	freeaddrinfo(res);
	return -1;
}

static int http_server_setup_socket(char *host, char *port, char *alpn, int testcase)
{
	struct quic_transport_param param = {};
	struct addrinfo *rp = NULL, *res, *p;
	struct quic_config config = {};
	int listenfd;

	if (getaddrinfo(host, port, NULL, &res)) {
		http_log_error("getaddrinfo error\n");
		return -1;
	}

	for (p = res; p != NULL; p = p->ai_next) {
		if (p->ai_family == AF_INET) {
			rp = p;
			break;
		}
		if (p->ai_family == AF_INET6)
			rp = p;
	}

	if (!rp) {
		errno = EINVAL;
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

	if (testcase == IOP_RETRY)
		config.validate_peer_address = 1;
	if (testcase == IOP_V2)
		config.version = QUIC_VERSION_V2;

	config.initial_smoothed_rtt = 100000;
	if (setsockopt(listenfd, SOL_QUIC, QUIC_SOCKOPT_CONFIG, &config, sizeof(config))) {
		http_log_error("socket setsockopt config failed\n");
		goto err_close;
	}

	param.grease_quic_bit = 1;
	param.max_idle_timeout = 180000000;
	if (setsockopt(listenfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, sizeof(param))) {
		http_log_error("socket setsockopt transport_param failed\n");
		goto err_close;
	}

	if (setsockopt(listenfd, SOL_QUIC, QUIC_SOCKOPT_ALPN, alpn, strlen(alpn))) {
		http_log_error("socket setsockopt alpn failed\n");
		goto err_close;
	}

	if (listen(listenfd, 64)) {
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

static int http_server_handshake(int sockfd, const char *pkey, const char *cert, const char *alpns,
				 uint8_t *key, unsigned int keylen, int testcase)
{
	gnutls_certificate_credentials_t cred;
	char alpn[64], *prio = QUIC_PRIORITY;
	gnutls_datum_t skey = {key, keylen};
	gnutls_session_t session;
	size_t alpn_len;
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

	ret = gnutls_record_set_max_early_data_size(session, 0xffffffffu);
	if (ret)
		goto err_session;

	if (testcase == IOP_CHACHA20)
		prio = QUIC_PRIORITY_CHACHA20;

	ret = gnutls_priority_set_direct(session, prio, NULL);
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

static int http_server_accept_socket(int sockfd, const char *pkey_file, const char *cert_file,
				     char *alpn, int testcase)
{
	unsigned int keylen;
	uint8_t key[64];
	int ret;

	keylen = sizeof(key);
	if (getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_SESSION_TICKET, key, &keylen)) {
		http_log_error("socket getsockopt session ticket error %d", errno);
		return -1;
	}

	ret = http_server_handshake(sockfd, pkey_file, cert_file, alpn, key, keylen, testcase);
	if (ret) {
		errno = -ret;
		return -1;
	}

	http_log_debug("HANDSHAKE DONE\n");
	return 0;
}

static int http_open_stream(int sockfd, int64_t stream_id)
{
	struct quic_stream_info sinfo = {};
	socklen_t len = sizeof(sinfo);

	sinfo.stream_id = stream_id;
	if (getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN, &sinfo, &len)) {
		http_log_error("socket getsockopt stream_open bidi failed\n");
		return -1;
	}
	return 0;
}

static int http_parse_url(const char *url, struct http_ctx *ctx)
{
	char *colon_pos, *slash_pos;

	strcpy(ctx->method, "GET");
	strcpy(ctx->user_agent, "nghttp3/quic client");
	if (!strncmp(url, "https://", 8)) {
		strcpy(ctx->scheme, "https");
		url += 8;
	} else if (!strncmp(url, "http://", 7)) {
		strcpy(ctx->scheme, "http");
		url += 7;
	} else {
		return -1;
	}

	colon_pos = strchr(url, ':');
	slash_pos = strchr(url, '/');

	if (colon_pos && (slash_pos == NULL || colon_pos < slash_pos)) {
		strncpy(ctx->host, url, colon_pos - url);
		ctx->host[colon_pos - url] = '\0';
		if (slash_pos) {
			strncpy(ctx->port, colon_pos + 1, slash_pos - colon_pos - 1);
			ctx->port[slash_pos - colon_pos - 1] = '\0';
			strcpy(ctx->path, slash_pos);
		} else {
			strcpy(ctx->port, colon_pos + 1);
			strcpy(ctx->path, "/");
		}
	} else {
		if (slash_pos) {
			strncpy(ctx->host, url, slash_pos - url);
			ctx->host[slash_pos - url] = '\0';
			strcpy(ctx->path, slash_pos);
		} else {
			strcpy(ctx->host, url);
			strcpy(ctx->path, "/");
		}
		strcpy(ctx->port, "443");
	}
	return 0;
}

static int http_parse_path(const char *url, struct http_ctx *ctx, int64_t stream_id)
{
	struct http_req *req = &ctx->reqs[stream_id >> 2];
	int ret;

	ret = http_parse_url(url, ctx);
	if (ret)
		return ret;

	strcpy(req->path, ctx->path);
	strcpy(req->port, ctx->port);
	strcpy(req->host, ctx->host);
	strcpy(req->method, ctx->method);
	strcpy(req->scheme, ctx->scheme);
	strcpy(req->user_agent, ctx->user_agent);

	return 0;
}

/* http3 functions */
static int http3_write_data(struct http_ctx *ctx, nghttp3_conn *httpconn, int sockfd)
{
	int ret, i, flags, fin = 0, sent;
	int64_t stream_id = -1;
	nghttp3_vec vec[16];
	nghttp3_ssize cnt;

	while (1) {
		flags = 0;
		ret = nghttp3_conn_writev_stream(httpconn, &stream_id, &fin, vec, 16);
		if (ret <= 0) {
			errno = -ret;
			return ret;
		}
		cnt = ret;
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
		if (ret) {
			errno = -ret;
			return -1;
		}
	}
	return 0;
}

static int http3_read_data(struct http_ctx *ctx, nghttp3_conn *httpconn, int sockfd)
{
	int64_t stream_id = -1;
	uint32_t flags = 0;
	int ret;

	while (1) {
		flags |= MSG_DONTWAIT;
		ret = quic_recvmsg(sockfd, ctx->buf, sizeof(ctx->buf), &stream_id, &flags);
		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return 0;
			return -1;
		}
		http_log_debug("%s: %d %ld %d\n", __func__, ret, stream_id, flags);
		ret = nghttp3_conn_read_stream(httpconn, stream_id, ctx->buf, ret,
					       flags & MSG_STREAM_FIN);
		if (ret < 0) {
			errno = -ret;
			return -1;
		}
	}
	return 0;
}

static void http3_make_nv(nghttp3_nv *nv, char *name, char *value)
{
	nv->name = (uint8_t *)name;
	nv->value = (uint8_t *)value;
	nv->namelen = strlen(name);
	nv->valuelen = strlen(value);
	nv->flags = NGHTTP3_NV_FLAG_NONE;
}

static int http3_submit_request(nghttp3_conn *httpconn, struct http_ctx *ctx, int64_t stream_id)
{
	struct http_req *req = &ctx->reqs[stream_id >> 2];
	int sockfd = ctx->sockfd;
	nghttp3_nv nva[5];
	int i, ret;

	http3_make_nv(&nva[0], ":method", req->method);
	http3_make_nv(&nva[1], ":scheme", req->scheme);
	http3_make_nv(&nva[2], ":authority", req->host);
	http3_make_nv(&nva[3], ":path", req->path);
	http3_make_nv(&nva[4], "user-agent", req->user_agent);

	for (i = 0; i < 5; i++)
		http_log_debug("%s: %s -> %s\n", __func__, nva[i].name, nva[i].value);

	ret = nghttp3_conn_submit_request(httpconn, stream_id, nva, 5, NULL, NULL);
	if (ret) {
		errno = -ret;
		return -1;
	}

	return http3_write_data(ctx, httpconn, sockfd);
}

static int http3_client_recv_data(nghttp3_conn *conn, int64_t stream_id, const uint8_t *data,
				  size_t datalen, void *user_data, void *stream_user_data)
{
	struct http_ctx *ctx = user_data;
	struct http_req *req;

	req = &ctx->reqs[stream_id >> 2];
	if (write(req->fd, data, datalen) == -1)
		http_log_error("can not write file\n");
	return 0;
}

static int http3_client_end_stream(nghttp3_conn *conn, int64_t stream_id, void *user_data,
				   void *stream_user_data)
{
	struct http_ctx *ctx = user_data;
	struct http_req *req;

	req = &ctx->reqs[stream_id >> 2];
	close(req->fd);

	http_log_debug("%s %d\n", __func__, ctx->req_cnt);

	ctx->req_cnt--;
	if (!ctx->req_cnt)
		ctx->complete = 1;
	return 0;
}

static int http3_client_end_headers(nghttp3_conn *conn, int64_t stream_id, int fin, void *user_data,
				    void *stream_user_data)
{
	struct http_ctx *ctx = user_data;
	struct http_req *req;
	char *path;
	int ret;

	req = &ctx->reqs[stream_id >> 2];
	ret = asprintf(&path, "%s%s", ctx->root, req->path);
	if (ret < 0)
		return -1;
	http_log_debug("%s: %s\n", __func__, path);

	req->fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (req->fd < 0) {
		http_log_error("can not open file %s\n", path);
		free(path);
		return 0;
	}

	http_log_debug("%s\n", __func__);
	free(path);
	return 0;
}

static int http3_client_create_conn(nghttp3_conn **httpconn, struct http_ctx *ctx)
{
	int64_t ctrl_stream_id, qpack_enc_stream_id, qpack_dec_stream_id;
	const nghttp3_mem *mem = nghttp3_mem_default();
	nghttp3_callbacks callbacks = {
		http3_acked_stream_data,
		http3_stream_close,
		http3_client_recv_data,
		http3_deferred_consume,
		http3_begin_headers,
		http3_recv_header,
		http3_client_end_headers,
		http3_begin_trailers,
		http3_recv_trailer,
		http3_end_trailers,
		http3_stop_sending,
		http3_client_end_stream,
		http3_reset_stream,
		http3_shutdown,
		http3_recv_settings,
	};
	struct quic_stream_info sinfo;
	socklen_t len = sizeof(sinfo);
	nghttp3_settings settings;
	int sockfd = ctx->sockfd;
	int ret;

	nghttp3_settings_default(&settings);
	settings.qpack_blocked_streams = 100;
	settings.qpack_max_dtable_capacity = 4096;

	ret = nghttp3_conn_client_new(httpconn, &callbacks, &settings, mem, ctx);
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
	if (ret) {
		errno = -ret;
		return -1;
	}
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
	if (ret) {
		errno = -ret;
		return -1;
	}

	return 0;
}

static int http3_run_loop(nghttp3_conn *httpconn, struct http_ctx *ctx)
{
	int sockfd = ctx->sockfd;
	struct timeval tv;
	fd_set readfds;
	int ret;

	while (!ctx->complete) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);

		ret = select(sockfd + 1, &readfds, NULL,  NULL, &tv);
		if (ret < 0)
			return -1;
		ret = http3_read_data(ctx, httpconn, sockfd);
		if (ret < 0) {
			if (ctx->is_serv && errno == ENOTCONN)
				return 0;
			return -1;
		}
		ret = http3_write_data(ctx, httpconn, sockfd);
		if (ret < 0)
			return -1;
	}
	return 0;
}

static void http3_conn_free(nghttp3_conn *httpconn)
{
	nghttp3_conn_del(httpconn);
}

static int http3_server_recv_data(nghttp3_conn *conn, int64_t stream_id, const uint8_t *data,
				  size_t datalen, void *user_data, void *stream_user_data)
{
	http_log_debug("%s: %llu\n", __func__, stream_id);
	return 0;
}

static int http3_server_begin_headers(nghttp3_conn *conn, int64_t stream_id, void *user_data,
				      void *stream_user_data)
{
	http_log_debug("%s: %llu\n", __func__, stream_id);
	return 0;
}

static int http3_server_recv_header(nghttp3_conn *conn, int64_t stream_id, int32_t token,
				    nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
				    void *user_data, void *stream_user_data)
{
	nghttp3_vec v = nghttp3_rcbuf_get_buf(value);
	struct http_ctx *ctx = user_data;
	struct http_req *req;

	req = &ctx->reqs[stream_id >> 2];
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

static nghttp3_ssize http3_content_data(nghttp3_conn *conn, int64_t stream_id, nghttp3_vec *vec,
				        size_t veccnt, uint32_t *pflags, void *user_data,
				        void *stream_user_data)
{
	struct http_ctx *ctx = user_data;
	struct http_req *req;

	req = &ctx->reqs[stream_id >> 2];
	vec[0].base = req->data;
	vec[0].len = req->len;

	http_log_debug("%s: %lld %u\n", __func__, stream_id, vec[0].len);
	*pflags |= NGHTTP3_DATA_FLAG_EOF;
	return 1;
}

static int http3_server_end_stream(nghttp3_conn *conn, int64_t stream_id, void *user_data,
				   void *stream_user_data)
{
	struct http_ctx *ctx = user_data;
	char len[10], status[] = "200";
	nghttp3_data_reader dr = {};
	struct http_req *req;
	char *path;
	nghttp3_nv nva[4];
	struct stat st;
	int ret, fd;

	req = &ctx->reqs[stream_id >> 2];
	if (!strcmp(req->path, "/")) {
		req->len = 14;
		req->data = malloc(req->len);
		if (!req->data)
			return -1;
		memcpy(req->data, "Hello, HTTP/3!", req->len);
		goto send;
	}

	ret = asprintf(&path, "%s%s", ctx->root, req->path);
	if (ret < 0)
		return -1;
	http_log_debug("%s: %s\n", __func__, path);

	fd = open(path, O_RDONLY);
	free(path);
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
	close(fd);

send:
	ret = sprintf(len, "%u", req->len);
	if (ret < 0)
		goto err;

	http_log_debug("%s: %s, %lld\n", __func__, len, stream_id);

	http3_make_nv(&nva[0], ":status", status);
	http3_make_nv(&nva[1], "server", "nghttp3/quic server");
	http3_make_nv(&nva[2], "content-type", "text/plain");
	http3_make_nv(&nva[3], "content-length", len);

	dr.read_data = http3_content_data;
	return nghttp3_conn_submit_response(conn, stream_id, nva, 4, &dr);
err:
	free(req->data);
	req->data = NULL;
	return -1;
}

static int http3_server_create_conn(nghttp3_conn **httpconn, struct http_ctx *ctx)
{
	int64_t ctrl_stream_id, qpack_enc_stream_id, qpack_dec_stream_id;
	const nghttp3_mem *mem = nghttp3_mem_default();
	struct quic_transport_param param = {};
	nghttp3_callbacks callbacks = {
		http3_acked_stream_data,
		http3_stream_close,
		http3_server_recv_data,
		http3_deferred_consume,
		http3_server_begin_headers,
		http3_server_recv_header,
		http3_end_headers,
		http3_begin_trailers,
		http3_recv_trailer,
		http3_end_trailers,
		http3_stop_sending,
		http3_server_end_stream,
		http3_reset_stream,
		http3_shutdown,
		http3_recv_settings,
	};
	struct quic_stream_info sinfo;
	socklen_t len = sizeof(sinfo);
	nghttp3_settings settings;
	int sockfd = ctx->sockfd;
	unsigned int param_len;
	int ret;

	nghttp3_settings_default(&settings);
	settings.qpack_blocked_streams = 100;
	settings.qpack_max_dtable_capacity = 4096;

	ret = nghttp3_conn_server_new(httpconn, &callbacks, &settings, mem, ctx);
	if (ret) {
		errno = -ret;
		return -1;
	}

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
	if (ret) {
		errno = -ret;
		return -1;
	}
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
	if (ret) {
		errno = -ret;
		return -1;
	}

	return 0;
}

static int http3_client(char *urls, const char *root, int testcase)
{
	char *p, *url = strtok_r(urls, " ", &p);
	struct quic_stream_info sinfo = {};
	nghttp3_conn *httpconn = NULL;
	socklen_t len = sizeof(sinfo);
	struct http_ctx *ctx;
	int sockfd, ret = 0;
	int64_t stream_id;

	ctx = malloc(sizeof(*ctx));
	if (!ctx)
		return -ENOMEM;
	memset(ctx, 0, sizeof(*ctx));

	ret = http_parse_url(url, ctx);
	if (ret) {
		ret = -EINVAL;
		goto out;
	}

	sockfd = http_client_setup_socket(ctx->host, ctx->port, testcase);
	if (sockfd < 0) {
		ret = -errno;
		goto out;
	}

	if (http_client_handshake(sockfd, "h3", ctx->host, NULL, NULL, testcase)) {
		ret = errno;
		goto free;
	}
	http_log_debug("HANDSHAKE DONE\n");

	if (testcase == IOP_KEYUPDATE) {
		if (setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_KEY_UPDATE, NULL, 0)) {
			http_log_error("socket setsockopt key update failed\n");
			ret = -errno;
			goto free;
		}
	}

	ctx->sockfd = sockfd;
	if (http3_client_create_conn(&httpconn, ctx)) {
		ret = -errno;
		goto free;
	}

	strcpy(ctx->root, root);
	while (url) {
		stream_id = (ctx->req_cnt << 2);
		if (http_parse_path(url, ctx, stream_id)) {
			ret = -EINVAL;
			goto free;
		}

		if (http_open_stream(sockfd, stream_id)) {
			ret = -errno;
			goto free;
		}

		if (http3_submit_request(httpconn, ctx, stream_id)) {
			ret = -errno;
			goto free;
		}

		ctx->req_cnt++;
		url = strtok_r(NULL, " ", &p);
	}

	if (http3_run_loop(httpconn, ctx))
		ret = -errno;
free:
	http3_conn_free(httpconn);
	close(sockfd);
out:
	free(ctx);
	return ret;
}

static void *http3_process(void *arg)
{
	nghttp3_conn *httpconn = NULL;
	struct http_ctx *ctx = arg;
	long ret;

	ret = http_server_accept_socket(ctx->sockfd, ctx->pkey_file, ctx->cert_file,
					"h3", ctx->testcase);
	if (ret < 0) {
		ret = -errno;
		goto out;
	}

	if (http3_server_create_conn(&httpconn, ctx)) {
		ret = -errno;
		goto out;
	}

	if (http3_run_loop(httpconn, ctx))
		ret = -errno;

out:
	http3_conn_free(httpconn);
	return (void *)ret;
}

static int http3_server(char *host, char *pkey_file, char *cert_file,
			const char *root, int testcase)
{
	int listenfd, sockfd, ret = 0, count = 0, i;
	struct http_thread threads[128] = {};
	struct http_ctx *ctx;
	void *retval;
	char *port;

	port = strrchr(host, ':');
	if (!port) {
		ret = -EINVAL;
		return ret;
	}
	*port++ = '\0';

	listenfd = http_server_setup_socket(host, port, "h3", testcase);
	if (listenfd < 0) {
		ret = -errno;
		return ret;
	}

	while (1) {
		sockfd = accept(listenfd, NULL, NULL);
		if (sockfd < 0) {
			http_log_error("socket accept failed %d %d\n", errno, sockfd);
			ret = -errno;
			break;
		}

		ctx = malloc(sizeof(*ctx));
		if (!ctx) {
			close(sockfd);
			ret = -ENOMEM;
			break;
		}

		memset(ctx, 0, sizeof(*ctx));
		strcpy(ctx->root, root);
		ctx->is_serv = 1;
		ctx->sockfd = sockfd;
		ctx->pkey_file = pkey_file;
		ctx->cert_file = cert_file;
		ctx->testcase = testcase;
		threads[count].ctx = ctx;

		if (pthread_create(&threads[count].thread, NULL, http3_process, ctx)) {
			ret = -errno;
			http_log_error("thread create failed %d %d\n", errno, count);
			break;
		}
		count++;
	}

	for (i = 0; i < count; i++) {
		pthread_join(threads[i].thread, &retval);
		close(threads[i].ctx->sockfd);
		free(threads[i].ctx);
	}

	close(listenfd);
	return ret;
}

/* http/0.9 functions */
static int http09_submit_request(struct http_ctx *ctx, int64_t stream_id)
{
	struct http_req *req = &ctx->reqs[stream_id >> 2];
	uint32_t flags = MSG_STREAM_FIN;
	int ret, sockfd = ctx->sockfd;
	char *data;

	ret = asprintf(&data, "GET %s%s", req->path, "\r\n");
	if (ret < 0)
		return -1;
	http_log_debug("%s: %s\n", __func__, data);

	ret = quic_sendmsg(sockfd, data, strlen(data), stream_id, flags);
	free(data);
	if (ret < 0)
		return -1;
	return 0;
}

static int http09_client_recv_data(struct http_ctx *ctx, int64_t stream_id, uint32_t flags,
				   const uint8_t *data, size_t datalen)
{
	struct http_req *req = &ctx->reqs[stream_id >> 2];
	static size_t total;

	if (!req->fd) {
		char *path;
		int ret;

		ret = asprintf(&path, "%s%s", ctx->root, req->path);
		if (ret < 0)
			return -1;
		http_log_debug("%s: %s\n", __func__, path);

		req->fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (req->fd < 0) {
			http_log_error("can not open file %s\n", path);
			free(path);
			return -1;
		}
		free(path);
	}

	if (write(req->fd, data, datalen) == -1) {
		close(req->fd);
		http_log_error("can not write file %s\n", req->path);
		return -1;
	}

	if (flags & MSG_STREAM_FIN) {
		ctx->req_cnt--;
		if (!ctx->req_cnt)
			ctx->complete = 1;

		close(req->fd);
	}

	total += datalen;
	http_log_debug("%s: %lu\n", __func__, total);
	return 0;
}

static int http09_server_recv_data(struct http_ctx *ctx, int64_t stream_id, uint32_t flags,
				   const uint8_t *data, size_t datalen)
{
	struct http_req *req = &ctx->reqs[stream_id >> 2];
	int sockfd = ctx->sockfd;
	struct stat st;
	int ret, fd;
	char *path;

	strncat(req->path, (const char *)data, datalen);
	if (!(flags & MSG_STREAM_FIN))
		return 0;

	datalen = strlen(req->path);
	if (datalen < 6) {
		errno = EINVAL;
		return -1;
	}
	datalen -= 6; /* 4 header chars "/GET " + 2 tailer chars "\n\r" */

	memmove(req->path, &req->path[4], datalen); /* do not use strcpy here! */
	req->path[datalen] = '\0';
	http_log_debug("%s: %s\n", __func__, req->path);

	if (!strcmp(req->path, "/")) {
		req->len = 14;
		req->data = malloc(req->len);
		if (!req->data)
			return -1;
		memcpy(req->data, "Hello, HTTP/3!", req->len);
		goto send;
	}

	ret = asprintf(&path, "%s%s", ctx->root, req->path);
	if (ret < 0)
		return -1;
	http_log_debug("%s: %s\n", __func__, path);

	fd = open(path, O_RDONLY);
	free(path);
	if (fd < 0) {
		req->len = 16;
		req->data = malloc(req->len);
		if (!req->data)
			return -1;
		memcpy(req->data, "Sorry, Not Found", req->len);
		goto send;
	}
	ret = fstat(fd, &st);
	if (ret < 0) {
		close(fd);
		return -1;
	}
	req->len = st.st_size;
	req->data = malloc(req->len);
	if (!req->data) {
		close(fd);
		return -1;
	}
	ret = read(fd, req->data, req->len);
	if (ret < 0) {
		close(fd);
		goto out;
	}
	close(fd);
send:
	ret = quic_sendmsg(sockfd, req->data, req->len, stream_id, MSG_STREAM_FIN);
	if (ret > 0)
		ret = 0;
out:
	free(req->data);
	req->data = NULL;
	return ret;
}

static int http09_run_loop(struct http_ctx *ctx)
{
	int sockfd = ctx->sockfd;
	int64_t stream_id = -1;
	uint32_t flags = 0;
	struct timeval tv;
	fd_set readfds;
	int ret;

	while (!ctx->complete) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);

		ret = select(sockfd + 1, &readfds, NULL,  NULL, &tv);
		if (ret < 0)
			return -1;
		while (1) {
			flags = MSG_DONTWAIT;
			ret = quic_recvmsg(sockfd, ctx->buf, sizeof(ctx->buf), &stream_id, &flags);
			if (ret < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					break;
				if (ctx->is_serv && errno == ENOTCONN)
					return 0;
				return -1;
			}
			if (ctx->is_serv)
				ret = http09_server_recv_data(ctx, stream_id, flags, ctx->buf, ret);
			else
				ret = http09_client_recv_data(ctx, stream_id, flags, ctx->buf, ret);
			if (ret) {
				http_log_error("%s: %d %ld %d\n", __func__, errno,
					       stream_id, flags);
				return -1;
			}
			http_log_debug("%s: %d %ld %d\n", __func__, errno, stream_id, flags);
		}
	}
	return 0;
}

static int http09_client(char *urls, const char *sess_file, const char *tp_file,
			 const char *root, int testcase)
{
	char *p, *url = strtok_r(urls, " ", &p);
	struct quic_transport_param param;
	unsigned int param_len;
	struct http_ctx *ctx;
	int sockfd, ret = 0;
	int64_t stream_id;
	size_t buf_len;

	ctx = malloc(sizeof(*ctx));
	if (!ctx)
		return -ENOMEM;
	memset(ctx, 0, sizeof(*ctx));

	ret = http_parse_url(url, ctx);
	if (ret) {
		ret = -EINVAL;
		goto out;
	}

	sockfd = http_client_setup_socket(ctx->host, ctx->port, testcase);
	if (sockfd < 0) {
		ret = -errno;
		goto out;
	}

	strcpy(ctx->root, root);
	ctx->sockfd = sockfd;
	if (testcase == IOP_ZERORTT) { /* load remote transport param */
		if (http_read_file(tp_file, ctx->buf, &buf_len) < 0) {
			ret = -errno;
			goto free;
		}
		if (buf_len) {
			param_len = sizeof(param);
			if (param_len != buf_len) {
				ret = -EINVAL;
				goto free;
			}
			memcpy(&param, ctx->buf, param_len);
			ret = setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM,
					 &param, param_len);
			if (ret == -1) {
				printf("socket setsockopt remote transport param\n");
				ret = -errno;
				goto free;
			}

			while (url) { /* send early data */
				stream_id = (ctx->req_cnt << 2);
				if (http_parse_path(url, ctx, stream_id)) {
					ret = -EINVAL;
					goto free;
				}

				if (http_open_stream(sockfd, stream_id)) {
					ret = -errno;
					goto free;
				}

				if (http09_submit_request(ctx, stream_id)) {
					ret = -errno;
					goto free;
				}

				ctx->req_cnt++;
				url = strtok_r(NULL, " ", &p);
			}
		}
	}

	if (http_client_handshake(sockfd, "hq-interop", ctx->host, ctx->buf, sess_file, testcase)) {
		ret = -errno;
		goto free;
	}
	http_log_debug("HANDSHAKE DONE %s\n", url);

	if (testcase == IOP_ZERORTT) { /* save remote transport param */
		param_len = sizeof(param);
		param.remote = 1;
		ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM,
				 &param, &param_len);
		if (ret == -1) {
			printf("socket getsockopt remote transport param\n");
			ret = -errno;
			goto free;
		}
		if (param_len) {
			buf_len = param_len;
			memcpy(ctx->buf, &param, buf_len);
			if (http_write_file(tp_file, ctx->buf, buf_len) <= 0) {
				ret = -errno;
				goto free;
			}
		}
	}

	if (testcase == IOP_KEYUPDATE) {
		if (setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_KEY_UPDATE, NULL, 0)) {
			http_log_error("socket setsockopt key update failed\n");
			ret = -errno;
			goto free;
		}
	}

	while (url) {
		stream_id = (ctx->req_cnt << 2);
		if (http_parse_path(url, ctx, stream_id)) {
			ret = -EINVAL;
			goto free;
		}

		if (http_open_stream(sockfd, stream_id)) {
			ret = -errno;
			goto free;
		}

		if (http09_submit_request(ctx, stream_id)) {
			ret = -errno;
			goto free;
		}

		ctx->req_cnt++;
		url = strtok_r(NULL, " ", &p);
	}

	if (http09_run_loop(ctx))
		ret = -errno;
free:
	close(sockfd);
out:
	free(ctx);
	return ret;
}

static void *http09_process(void *arg)
{
	struct http_ctx *ctx = arg;
	long ret;

	if (ctx->testcase == IOP_ZERORTT)
		usleep(500000);

	ret = http_server_accept_socket(ctx->sockfd, ctx->pkey_file, ctx->cert_file,
					"hq-interop", ctx->testcase);
	if (ret < 0) {
		ret = -errno;
		goto out;
	}

	ret = http09_run_loop(ctx);
	if (ret < 0)
		ret = -errno;

out:
	return (void *)ret;
}

static int http09_server(char *host, char *pkey_file, char *cert_file,
			 const char *root, int testcase)
{
	int listenfd, sockfd, ret = 0, count = 0, i;
	struct http_thread threads[128] = {};
	struct http_ctx *ctx;
	void *retval;
	char *port;

	port = strrchr(host, ':');
	if (!port) {
		ret = -EINVAL;
		return ret;
	}
	*port++ = '\0';

	listenfd = http_server_setup_socket(host, port, "hq-interop", testcase);
	if (listenfd < 0) {
		ret = -errno;
		return ret;
	}

	while (1) {
		sockfd = accept(listenfd, NULL, NULL);
		if (sockfd < 0) {
			http_log_error("socket accept failed %d %d\n", errno, sockfd);
			ret = -errno;
			break;
		}

		ctx = malloc(sizeof(*ctx));
		if (!ctx) {
			close(sockfd);
			ret = -ENOMEM;
			break;
		}
		memset(ctx, 0, sizeof(*ctx));
		strcpy(ctx->root, root);
		ctx->is_serv = 1;
		ctx->sockfd = sockfd;
		ctx->pkey_file = pkey_file;
		ctx->cert_file = cert_file;
		ctx->testcase = testcase;
		threads[count].ctx = ctx;

		if (pthread_create(&threads[count].thread, NULL, http09_process, ctx)) {
			ret = -errno;
			http_log_error("thread create failed %d %d\n", errno, count);
			break;
		}
		count++;
	}

	for (i = 0; i < count; i++) {
		pthread_join(threads[i].thread, &retval);
		close(threads[i].ctx->sockfd);
		free(threads[i].ctx);
	}

	close(listenfd);
	return ret;
}

/* iop functions */
static int iop_get_testcase(char *testcase)
{
	if (!testcase)
		return 0;
	if(!strcmp(testcase, "chacha20"))
		return IOP_CHACHA20;
	if(!strcmp(testcase, "handshake"))
		return IOP_HANDSHAKE;
	if(!strcmp(testcase, "http3"))
		return IOP_HTTP3;
	if(!strcmp(testcase, "keyupdate"))
		return IOP_KEYUPDATE;
	if(!strcmp(testcase, "multiconnect"))
		return IOP_MULTICONNECT;
	if(!strcmp(testcase, "resumption"))
		return IOP_RESUMPTION;
	if(!strcmp(testcase, "retry"))
		return IOP_RETRY;
	if(!strcmp(testcase, "transfer"))
		return IOP_TRANSFER;
	if (!strcmp(testcase, "versionnegotiation"))
		return IOP_VERSIONNEGOTIATION;
	if(!strcmp(testcase, "zerortt"))
		return IOP_ZERORTT;
	if(!strcmp(testcase, "v2"))
		return IOP_V2;
	if(!strcmp(testcase, "ecn"))
		return IOP_ECN;
	return 0;
}

static void iop_print_usage(void)
{
	http_log_error("usage: interop_test -c -D rootdir -S sessfile -t tpfile url\n");
	http_log_error("       interop_test -s -D rootdir -C certfile -P pkeyfile address:port\n");
}

int main(int argc, char *argv[])
{
	char *sessfile = "./session.bin", *tpfile = "./tp.bin", *root = "./";
	char *certfile = NULL, *pkeyfile = NULL, *test = NULL;
	int server = 0, client = 0, testcase = 0;
	int ch;

	while ((ch = getopt(argc, argv, "C:D:E:P:S:T:cs")) != -1) {
		switch (ch) {
		case 'C':
			certfile = optarg;
			break;
		case 'P':
			pkeyfile = optarg;
			break;
		case 'S':
			sessfile = optarg;
			break;
		case 'T':
			tpfile = optarg;
			break;
		case 'D':
			root = optarg;
			break;
		case 'E':
			test = optarg;
			break;
		case 'c':
			client = 1;
			break;
		case 's':
			server = 1;
			break;
		default:
			iop_print_usage();
			return 255;
		}
	}
	argc -= optind;
	argv += optind;

	testcase = iop_get_testcase(test);
	if (!testcase) {
		http_log_error("unknown test case\n");
		return 127;
	}

	if (argc != 1 || (!client && !server) || (server && (!certfile || !pkeyfile))) {
		iop_print_usage();
		return 255;
	}

	quic_set_log_level(http_log_level);
	gnutls_global_set_log_level(http_log_level);

	if (client) {
		if (testcase == IOP_HTTP3)
			return http3_client(argv[0], root, testcase);
		return http09_client(argv[0], sessfile, tpfile, root, testcase);
	}

	if (testcase == IOP_HTTP3)
		return http3_server(argv[0], pkeyfile, certfile, root, testcase);
	return http09_server(argv[0], pkeyfile, certfile, root, testcase);
}
