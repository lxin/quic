/*
 * Provide APIs for QUIC handshake.
 *
 * Copyright (c) 2024 Red Hat, Inc.
 *
 * libquic is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <sys/syslog.h>
#include <linux/tls.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include "libquic.h"

static int quic_read_datum(const char *file, gnutls_datum_t *data)
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

static void quic_timer_handler(union sigval arg)
{
	struct quic_conn *conn = arg.sival_ptr;

	quic_log_error("conn timeout error %d", ETIMEDOUT);
	conn->errcode = ETIMEDOUT;
}

static int quic_conn_setup_timer(struct quic_conn *conn)
{
	uint64_t msec = conn->parms->timeout;
	struct itimerspec its = {};
	struct sigevent sev = {};

	sev.sigev_notify = SIGEV_THREAD;
	sev.sigev_notify_function = quic_timer_handler;
	sev.sigev_value.sival_ptr = conn;
	if (timer_create(CLOCK_REALTIME, &sev, &conn->timer)) {
		quic_log_error("timer creation error %d", errno);
		return -1;
	}

	its.it_value.tv_sec  = msec / 1000;
	its.it_value.tv_nsec = (msec % 1000) * 1000000;
	if (timer_settime(conn->timer, 0, &its, NULL)) {
		quic_log_error("timer setup error %d", errno);
		return -1;
	}
	return 0;
}

static void quic_conn_delete_timer(struct quic_conn *conn)
{
	timer_delete(conn->timer);
}

static uint32_t quic_get_tls_cipher_type(gnutls_cipher_algorithm_t cipher)
{
	switch (cipher) {
	case GNUTLS_CIPHER_AES_128_GCM:
		return TLS_CIPHER_AES_GCM_128;
	case GNUTLS_CIPHER_AES_128_CCM:
		return TLS_CIPHER_AES_CCM_128;
	case GNUTLS_CIPHER_AES_256_GCM:
		return TLS_CIPHER_AES_GCM_256;
	case GNUTLS_CIPHER_CHACHA20_POLY1305:
		return TLS_CIPHER_CHACHA20_POLY1305;
	default:
		quic_log_notice("%s: %d", __func__, cipher);
		return 0;
	}
}

static enum quic_crypto_level quic_get_crypto_level(gnutls_record_encryption_level_t level)
{
	switch (level) {
	case GNUTLS_ENCRYPTION_LEVEL_INITIAL:
		return QUIC_CRYPTO_INITIAL;
	case GNUTLS_ENCRYPTION_LEVEL_HANDSHAKE:
		return QUIC_CRYPTO_HANDSHAKE;
	case GNUTLS_ENCRYPTION_LEVEL_APPLICATION:
		return QUIC_CRYPTO_APP;
	case GNUTLS_ENCRYPTION_LEVEL_EARLY:
		return QUIC_CRYPTO_EARLY;
	default:
		quic_log_notice("%s: %d", __func__, level);
		return QUIC_CRYPTO_MAX;
	}
}

static int quic_secret_func(gnutls_session_t session, gnutls_record_encryption_level_t level,
			    const void *rx_secret, const void *tx_secret, size_t secretlen)
{
	struct quic_conn *conn = gnutls_session_get_ptr(session);
	gnutls_cipher_algorithm_t type  = gnutls_cipher_get(session);
	struct quic_crypto_secret secret = {};
	int sockfd, ret, len = sizeof(secret);

	if (conn->completed)
		return 0;

	if (level == GNUTLS_ENCRYPTION_LEVEL_EARLY)
		type = gnutls_early_cipher_get(session);

	sockfd = conn->sockfd;
	secret.level = quic_get_crypto_level(level);
	secret.type = quic_get_tls_cipher_type(type);
	if (tx_secret) {
		secret.send = 1;
		memcpy(secret.secret, tx_secret, secretlen);
		if (setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CRYPTO_SECRET, &secret, len)) {
			quic_log_error("socket setsockopt tx secret error %d %u", errno, level);
			return -1;
		}
	}
	if (rx_secret) {
		secret.send = 0;
		memcpy(secret.secret, rx_secret, secretlen);
		if (setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_CRYPTO_SECRET, &secret, len)) {
			quic_log_error("socket setsockopt rx secret error %d %u", errno, level);
			return -1;
		}
		if (secret.level == QUIC_CRYPTO_APP) {
			if (conn->is_serv) {
				ret = gnutls_session_ticket_send(session, 1, 0);
				if (ret) {
					quic_log_gnutls_error(ret);
					return ret;
				}
			}
			if (!conn->recv_ticket)
				conn->completed = 1;
		}
	}
	quic_log_debug("  Secret func: %u %u %u", secret.level, !!tx_secret, !!rx_secret);
	return 0;
}

static int quic_alert_read_func(gnutls_session_t session,
				gnutls_record_encryption_level_t gtls_level,
				gnutls_alert_level_t alert_level,
				gnutls_alert_description_t alert_desc)
{
	quic_log_notice("%s: %u %u %u %u", __func__,
			!!session, gtls_level, alert_level, alert_desc);
	return 0;
}

static int quic_tp_recv_func(gnutls_session_t session, const uint8_t *buf, size_t len)
{
	struct quic_conn *conn = gnutls_session_get_ptr(session);
	int sockfd = conn->sockfd;

	if (setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT, buf, len)) {
		quic_log_error("socket setsockopt transport_param_ext error %d", errno);
		return -1;
	}
	return 0;
}

static int quic_tp_send_func(gnutls_session_t session, gnutls_buffer_t extdata)
{
	struct quic_conn *conn = gnutls_session_get_ptr(session);
	int ret, sockfd = conn->sockfd;
	uint8_t buf[256];
	unsigned int len;

	len = sizeof(buf);
	if (getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT, buf, &len)) {
		quic_log_error("socket getsockopt transport_param_ext error %d", errno);
		return -1;
	}

	ret = gnutls_buffer_append_data(extdata, buf, len);
	if (ret) {
		quic_log_gnutls_error(ret);
		return ret;
	}

	return 0;
}

static int quic_read_func(gnutls_session_t session, gnutls_record_encryption_level_t level,
			  gnutls_handshake_description_t htype, const void *data, size_t datalen)
{
	struct quic_conn *conn = gnutls_session_get_ptr(session);
	struct quic_msg *msg;
	uint32_t len = datalen;

	if (htype == GNUTLS_HANDSHAKE_KEY_UPDATE)
		return 0;

	msg = malloc(sizeof(*msg));
	if (!msg) {
		quic_log_error("msg malloc error %d", ENOMEM);
		return -1;
	}
	memset(msg, 0, sizeof(*msg));
	msg->len = len;
	memcpy(msg->data, data, msg->len);

	msg->level = quic_get_crypto_level(level);
	if (!conn->send_list)
		conn->send_list = msg;
	else
		conn->send_last->next = msg;
	conn->send_last = msg;

	quic_log_debug("  Read func: %u %u %u", level, htype, datalen);
	return 0;
}

static char quic_priority[] =
	"%DISABLE_TLS13_COMPAT_MODE:NORMAL:-VERS-ALL:+VERS-TLS1.3:+PSK:-CIPHER-ALL:+";

static int quic_session_set_priority(gnutls_session_t session, uint32_t cipher)
{
	char p[136] = {};

	memcpy(p, quic_priority, strlen(quic_priority));
	switch (cipher) {
	case TLS_CIPHER_AES_GCM_128:
		strcat(p, "AES-128-GCM");
		break;
	case TLS_CIPHER_AES_GCM_256:
		strcat(p, "AES-256-GCM");
		break;
	case TLS_CIPHER_AES_CCM_128:
		strcat(p, "AES-128-CCM");
		break;
	case TLS_CIPHER_CHACHA20_POLY1305:
		strcat(p, "CHACHA20-POLY1305");
		break;
	default:
		strcat(p, "AES-128-GCM:+AES-256-GCM:+AES-128-CCM:+CHACHA20-POLY1305");
	}

	return gnutls_priority_set_direct(session, p, NULL);
}

static int quic_session_set_alpns(gnutls_session_t session, char *alpn_data)
{
	gnutls_datum_t alpns[QUIC_MAX_ALPNS_LEN / 2];
	char *alpn = strtok(alpn_data, ",");
	int count = 0;

	while (alpn) {
		while (*alpn == ' ')
			alpn++;
		alpns[count].data = (unsigned char *)alpn;
		alpns[count].size = strlen(alpn);
		count++;
		alpn = strtok(NULL, ",");
	}

	return gnutls_alpn_set_protocols(session, alpns, count, GNUTLS_ALPN_MANDATORY);
}

static gnutls_record_encryption_level_t quic_get_encryption_level(uint8_t level)
{
	switch (level) {
	case QUIC_CRYPTO_INITIAL:
		return GNUTLS_ENCRYPTION_LEVEL_INITIAL;
	case QUIC_CRYPTO_HANDSHAKE:
		return GNUTLS_ENCRYPTION_LEVEL_HANDSHAKE;
	case QUIC_CRYPTO_APP:
		return GNUTLS_ENCRYPTION_LEVEL_APPLICATION;
	case QUIC_CRYPTO_EARLY:
		return GNUTLS_ENCRYPTION_LEVEL_EARLY;
	default:
		quic_log_notice("%s: %d", __func__, level);
		return GNUTLS_ENCRYPTION_LEVEL_APPLICATION + 1;
	}
}

static int quic_conn_get_transport_param(struct quic_conn *conn)
{
	struct quic_transport_param param = {};
	int sockfd = conn->sockfd;
	unsigned int len;

	len = sizeof(conn->alpns);
	if (getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_ALPN, conn->alpns, &len)) {
		quic_log_error("socket getsockopt alpn error %d", errno);
		return -1;
	}
	len = sizeof(conn->ticket);
	if (getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_SESSION_TICKET, conn->ticket, &len)) {
		quic_log_error("socket getsockopt session ticket error %d", errno);
		return -1;
	}
	conn->ticket_len = len;
	len = sizeof(param);
	if (getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, &len)) {
		quic_log_error("socket getsockopt transport param error %d", errno);
		return -1;
	}
	conn->recv_ticket = param.receive_session_ticket;
	conn->cert_req = param.certificate_request;
	conn->cipher = param.payload_cipher_type;
	return 0;
}

static int quic_handshake_sendmsg(int sockfd, struct quic_msg *msg)
{
	char outcmsg[CMSG_SPACE(sizeof(struct quic_handshake_info))];
	struct quic_handshake_info *info;
	struct msghdr outmsg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	int flags = 0;

	outmsg.msg_name = NULL;
	outmsg.msg_namelen = 0;
	outmsg.msg_iov = &iov;
	iov.iov_base = (void *)msg->data;
	iov.iov_len = msg->len;
	outmsg.msg_iovlen = 1;

	outmsg.msg_control = outcmsg;
	outmsg.msg_controllen = sizeof(outcmsg);
	outmsg.msg_flags = 0;
	if (msg->next)
		flags = MSG_MORE;

	cmsg = CMSG_FIRSTHDR(&outmsg);
	cmsg->cmsg_level = IPPROTO_QUIC;
	cmsg->cmsg_type = QUIC_HANDSHAKE_INFO;
	cmsg->cmsg_len = CMSG_LEN(sizeof(*info));

	info = (struct quic_handshake_info *)CMSG_DATA(cmsg);
	info->crypto_level = msg->level;

	return sendmsg(sockfd, &outmsg, flags);
}

static int quic_handshake_recvmsg(int sockfd, struct quic_msg *msg)
{
	char incmsg[CMSG_SPACE(sizeof(struct quic_handshake_info))];
	struct quic_handshake_info info;
	struct cmsghdr *cmsg = NULL;
	struct msghdr inmsg;
	struct iovec iov;
	int ret;

	msg->len = 0;
	memset(&inmsg, 0, sizeof(inmsg));

	iov.iov_base = msg->data;
	iov.iov_len = sizeof(msg->data);

	inmsg.msg_name = NULL;
	inmsg.msg_namelen = 0;
	inmsg.msg_iov = &iov;
	inmsg.msg_iovlen = 1;
	inmsg.msg_control = incmsg;
	inmsg.msg_controllen = sizeof(incmsg);

	ret = recvmsg(sockfd, &inmsg, MSG_DONTWAIT);
	if (ret < 0)
		return ret;
	msg->len = ret;

	for (cmsg = CMSG_FIRSTHDR(&inmsg); cmsg != NULL; cmsg = CMSG_NXTHDR(&inmsg, cmsg))
		if (IPPROTO_QUIC == cmsg->cmsg_level && QUIC_HANDSHAKE_INFO == cmsg->cmsg_type)
			break;
	if (cmsg) {
		memcpy(&info, CMSG_DATA(cmsg), sizeof(info));
		msg->level = info.crypto_level;
	}

	return ret;
}

static int quic_handshake_completed(struct quic_conn *conn)
{
	return conn->completed || conn->errcode;
}

static int quic_handshake_crypto_data(struct quic_conn *conn, uint8_t level,
				      const uint8_t *data, size_t datalen)
{
	gnutls_session_t session = conn->session;
	int ret;

	level = quic_get_encryption_level(level);
	if (datalen > 0) {
		ret = gnutls_handshake_write(session, level, data, datalen);
		if (ret != 0) {
			if (!gnutls_error_is_fatal(ret))
				return 0;
			goto err;
		}
	}

	ret = gnutls_handshake(session);
	if (ret < 0) {
		if (!gnutls_error_is_fatal(ret))
			return 0;
		goto err;
	}
	return 0;
err:
	gnutls_alert_send_appropriate(session, ret);
	quic_log_gnutls_error(ret);
	return ret;
}

/**
 * quic_conn_create - Create a context for QUIC handshake
 * @conn_p: pointer to accept the QUIC handshake context created
 * @sockfd: socket descriptor
 * @parms: handshake parameters
 *
 * Return values:
 * - On success, a new conn is returned.
 * - On error, NULL is returned and errno is set to indicate the error.
 */
struct quic_conn *quic_conn_create(int sockfd, struct quic_handshake_parms *parms)
{
	struct quic_conn *conn;
	int ret;

	conn = malloc(sizeof(*conn));
	if (!conn) {
		quic_log_error("conn malloc error %d", ENOMEM);
		errno = ENOMEM;
		return NULL;
	}

	memset(conn, 0, sizeof(*conn));
	conn->parms = parms;
	conn->sockfd = sockfd;

	if (quic_conn_get_transport_param(conn)) {
		ret = -errno;
		goto err;
	}

	if (quic_conn_setup_timer(conn)) {
		ret = -errno;
		goto err;
	}

	return conn;
err:
	quic_conn_destroy(conn);
	errno = -ret;
	return NULL;
}

/**
 * quic_conn_destroy - Destroy a context for QUIC handshake
 * @conn: QUIC handshake context to destroy
 *
 */
void quic_conn_destroy(struct quic_conn *conn)
{
	struct quic_msg *msg = conn->send_list;

	while (msg) {
		conn->send_list = msg->next;
		free(msg);
		msg = conn->send_list;
	}

	quic_conn_delete_timer(conn);
	gnutls_deinit(conn->session);
	free(conn);
}

#define QUIC_TLSEXT_TP_PARAM	0x39u

/**
 * quic_conn_configure_session - Configure a handshake session
 * @session: TLS session to configure
 * @alpns: multiple ALPNs split by ','
 * @cipher: cipher perferred
 *
 * Return values:
 * - On success, GNUTLS_E_SUCCESS (0) is returned.
 * - On error, a negative error value is returned.
 */
int quic_conn_configure_session(struct quic_conn *conn)
{
	gnutls_session_t session = conn->session;
	int ret;

	ret = quic_session_set_priority(session, conn->cipher);
	if (ret)
		return ret;

	if (conn->alpns[0]) {
		ret = quic_session_set_alpns(session, conn->alpns);
		if (ret)
			return ret;
	}

	gnutls_handshake_set_secret_function(session, quic_secret_func);
	gnutls_handshake_set_read_function(session, quic_read_func);
	gnutls_alert_set_read_function(session, quic_alert_read_func);

	return gnutls_session_ext_register(
		session, "QUIC Transport Parameters", QUIC_TLSEXT_TP_PARAM,
		GNUTLS_EXT_TLS, quic_tp_recv_func, quic_tp_send_func, NULL, NULL, NULL,
		GNUTLS_EXT_FLAG_TLS | GNUTLS_EXT_FLAG_CLIENT_HELLO | GNUTLS_EXT_FLAG_EE);
}

/**
 * quic_conn_start_handshake - Drive the handshake interaction
 * @conn: QUIC handshake context
 *
 * Return values:
 * - On success, 0 is returned.
 * - On error, a negative error value is returned.
 */
int quic_conn_start_handshake(struct quic_conn *conn)
{
	int ret, sockfd = conn->sockfd;
	struct quic_msg *msg;
	struct timeval tv;
	fd_set readfds;

	if (!conn->is_serv) {
		ret = quic_handshake_crypto_data(conn, QUIC_CRYPTO_INITIAL, NULL, 0);
		if (ret)
			return ret;

		msg = conn->send_list;
		while (msg) {
			quic_log_debug("< Handshake SEND: %d %d", msg->len, msg->level);
			ret = quic_handshake_sendmsg(sockfd, msg);
			if (ret < 0) {
				quic_log_error("socket sendmsg error %d", errno);
				return -errno;
			}
			conn->send_list = msg->next;
			free(msg);
			msg = conn->send_list;
		}
	}

	while (!quic_handshake_completed(conn)) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);

		ret = select(sockfd + 1, &readfds, NULL,  NULL, &tv);
		if (ret < 0) {
			quic_log_error("socket select error %d", errno);
			return -errno;
		}
		msg = &conn->recv_msg;
		while (!quic_handshake_completed(conn)) {
			ret = quic_handshake_recvmsg(sockfd, msg);
			if (ret <= 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					break;
				quic_log_error("socket recvmsg error %d", errno);
				return -errno;
			}
			quic_log_debug("> Handshake RECV: %u %u", msg->len, msg->level);
			ret = quic_handshake_crypto_data(conn, msg->level, msg->data, msg->len);
			if (ret)
				return ret;
		}

		msg = conn->send_list;
		while (msg) {
			quic_log_debug("< Handshake SEND: %u %u", msg->len, msg->level);
			ret = quic_handshake_sendmsg(sockfd, msg);
			if (ret < 0) {
				quic_log_error("socket sendmsg error %d", errno);
				return -errno;
			}
			conn->send_list = msg->next;
			free(msg);
			msg = conn->send_list;
		}
	}

	return -conn->errcode;
}

static int quic_log_level = LOG_NOTICE;
static void (*quic_log_func)(int level, const char *msg);

/**
 * quic_log_debug - log msg with debug level
 *
 */
void quic_log_debug(char const *fmt, ...)
{
	char msg[128];
	va_list arg;

	if (quic_log_level < LOG_DEBUG)
		return;

	va_start(arg, fmt);
	vsnprintf(msg, sizeof(msg), fmt, arg);
	va_end(arg);

	if (quic_log_func) {
		quic_log_func(LOG_DEBUG, msg);
		return;
	}
	printf("[DEBUG] %s\n", msg);
}

/**
 * quic_log_notice - log msg with notice level
 *
 */
void quic_log_notice(char const *fmt, ...)
{
	char msg[128];
	va_list arg;

	if (quic_log_level < LOG_NOTICE)
		return;

	va_start(arg, fmt);
	vsnprintf(msg, sizeof(msg), fmt, arg);
	va_end(arg);

	if (quic_log_func) {
		quic_log_func(LOG_NOTICE, msg);
		return;
	}
	printf("[NOTICE] %s\n", msg);
}

/**
 * quic_log_error - log msg with error level
 *
 */
void quic_log_error(char const *fmt, ...)
{
	char msg[128];
	va_list arg;

	if (quic_log_level < LOG_ERR)
		return;

	va_start(arg, fmt);
	vsnprintf(msg, sizeof(msg), fmt, arg);
	va_end(arg);

	if (quic_log_func) {
		quic_log_func(LOG_ERR, msg);
		return;
	}
	printf("[ERROR] %s\n", msg);
}

/**
 * quic_log_gnutls_error - log msg with error level and gnutls strerror converted
 * @error: the error code returned from gnutls APIs
 *
 */
void quic_log_gnutls_error(int error)
{
	quic_log_error("gnutls: %s (%d)", gnutls_strerror(error), error);
}

/**
 * quic_file_read_pkey - read private key from a file
 * @file: the key file to read
 * @privkey: the pointer to receive the key
 *
 * Return values:
 * - On success, GNUTLS_E_SUCCESS (0) is returned.
 * - On error, a negative error value is returned.
 */
int quic_file_read_pkey(char *file, gnutls_privkey_t *privkey)
{
	gnutls_datum_t data;
	int ret;

	if (quic_read_datum(file, &data))
		return -EINVAL;

	ret = gnutls_privkey_init(privkey);
	if (ret)
		goto out;

	ret = gnutls_privkey_import_x509_raw(*privkey, &data, GNUTLS_X509_FMT_PEM, NULL, 0);
out:
	free(data.data);
	return ret;
}

/**
 * quic_file_read_cert - read certificate from a file
 * @file: the cert file to read
 * @cert: the pointer to receive the cert
 *
 * Return values:
 * - On success, GNUTLS_E_SUCCESS (0).
 * - On error, a negative error value.
 */
int quic_file_read_cert(char *file, gnutls_pcert_st **cert)
{
	gnutls_datum_t data;
	int ret;

	if (quic_read_datum(file, &data))
		return -EINVAL;

	ret = gnutls_pcert_import_x509_raw(*cert, &data, GNUTLS_X509_FMT_PEM, 0);
	free(data.data);

	return ret;
}

/**
 * quic_file_read_psk - read PSKs from a file
 * @file: the PSK file to read
 * @identity: the pointer to receive the PSK identities
 * @pkey: the pointer to receive the PSK keys
 *
 * Return values:
 * - On success, the count of PSKs read is returned.
 * - On error, -1 is returned.
 */
int quic_file_read_psk(char *file, char *identity[], gnutls_datum_t *pkey)
{
	unsigned char *end, *key, *buf;
	int fd, err = -1, i = 0;
	struct stat statbuf;
	gnutls_datum_t gkey;
	unsigned int size;

	fd = open(file, O_RDONLY);
	if (fd == -1)
		return -1;
	if (fstat(fd, &statbuf))
		goto out;

	size = (unsigned int)statbuf.st_size;
	buf = malloc(size);
	if (!buf)
		goto out;
	if (read(fd, buf, size) == -1) {
		free(buf);
		goto out;
	}

	end = buf + size - 1;
	do {
		key = (unsigned char *)strchr((char *)buf, ':');
		if (!key)
			goto out;
		*key = '\0';
		identity[i] = (char *)buf;

		key++;
		gkey.data = key;

		buf = (unsigned char *)strchr((char *)key, '\n');
		if (!buf) {
			gkey.size = end - gkey.data;
			buf = end;
			goto decode;
		}
		*buf = '\0';
		buf++;
		gkey.size = strlen((char *)gkey.data);
decode:
		if (gnutls_hex_decode2(&gkey, &pkey[i]))
			goto out;
		i++;
	} while (buf < end);

	err = i;
out:
	close(fd);
	return err;
}

/**
 * quic_set_log_level - change the log_level
 * @level: the level it changes to (LOG_XXX from sys/syslog.h)
 *
 */
void quic_set_log_level(int level)
{
	quic_log_level = level;
}

/**
 * quic_set_log_func - change the log func
 * @func: the log func it changes to
 *
 */
void quic_set_log_func(void (*func)(int level, const char *msg))
{
	quic_log_func = func;
}

/**
 * quic_recvmsg - receive msg and also get stream ID and flag
 * @sockfd: IPPROTO_QUIC type socket
 * @msg: msg buffer
 * @len: msg buffer length
 * @sid: stream ID got from kernel
 * @flag: stream flag got from kernel
 *
 * Return values:
 * - On success, the number of bytes received is returned.
 * - On error, -1 is returned, and errno is set to indicate the error.
 */
ssize_t quic_recvmsg(int sockfd, void *msg, size_t len, int64_t *sid, uint32_t *flags)
{
	char incmsg[CMSG_SPACE(sizeof(struct quic_stream_info))];
	struct quic_stream_info info;
	struct cmsghdr *cmsg = NULL;
	struct msghdr inmsg;
	struct iovec iov;
	int error;

	memset(&inmsg, 0, sizeof(inmsg));

	iov.iov_base = msg;
	iov.iov_len = len;

	inmsg.msg_name = NULL;
	inmsg.msg_namelen = 0;
	inmsg.msg_iov = &iov;
	inmsg.msg_iovlen = 1;
	inmsg.msg_control = incmsg;
	inmsg.msg_controllen = sizeof(incmsg);

	error = recvmsg(sockfd, &inmsg, *flags);
	if (error < 0)
		return error;

	if (!sid)
		return error;

	for (cmsg = CMSG_FIRSTHDR(&inmsg); cmsg != NULL; cmsg = CMSG_NXTHDR(&inmsg, cmsg))
		if (IPPROTO_QUIC == cmsg->cmsg_level && QUIC_STREAM_INFO == cmsg->cmsg_type)
			break;
	*flags = inmsg.msg_flags;
	if (cmsg) {
		memcpy(&info, CMSG_DATA(cmsg), sizeof(struct quic_stream_info));
		*sid = info.stream_id;
		*flags |= info.stream_flags;
	}
	return error;
}

/**
 * quic_sendmsg - send msg with stream ID and flag
 * @sockfd: IPPROTO_QUIC type socket
 * @msg: msg to send
 * @len: the length of the msg to send
 * @sid: stream ID
 * @flag: stream flag
 *
 * Return values:
 * - On success, the number of bytes sent is returned.
 * - On error, -1 is returned, and errno is set to indicate the error.
 */
ssize_t quic_sendmsg(int sockfd, const void *msg, size_t len, int64_t sid, uint32_t flags)
{
	char outcmsg[CMSG_SPACE(sizeof(struct quic_stream_info))];
	struct quic_stream_info *info;
	struct msghdr outmsg;
	struct cmsghdr *cmsg;
	struct iovec iov;

	outmsg.msg_name = NULL;
	outmsg.msg_namelen = 0;
	outmsg.msg_iov = &iov;
	iov.iov_base = (void *)msg;
	iov.iov_len = len;
	outmsg.msg_iovlen = 1;

	outmsg.msg_control = outcmsg;
	outmsg.msg_controllen = sizeof(outcmsg);

	cmsg = CMSG_FIRSTHDR(&outmsg);
	cmsg->cmsg_level = IPPROTO_QUIC;
	cmsg->cmsg_type = 0;
	cmsg->cmsg_len = CMSG_LEN(sizeof(*info));

	outmsg.msg_controllen = cmsg->cmsg_len;
	info = (struct quic_stream_info *)CMSG_DATA(cmsg);
	info->stream_id = sid;
	info->stream_flags = flags;

	return sendmsg(sockfd, &outmsg, flags);
}
