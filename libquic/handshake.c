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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <poll.h>

#include "netinet/quic.h"

#define QUIC_TLSEXT_TP_PARAM	0x39u

#define QUIC_MSG_STREAM_FLAGS \
	(MSG_STREAM_NEW | MSG_STREAM_FIN | MSG_STREAM_UNI | MSG_STREAM_DONTWAIT)

struct quic_msg {
	struct quic_msg *next;
	uint8_t *data;
	uint32_t len;
	uint8_t level;
};

struct quic_handshake_ctx {
	struct quic_msg *send_list;
	struct quic_msg *send_last;
	uint8_t data[65536];
	uint8_t completed:1;
	uint8_t is_serv:1;
};

static struct quic_handshake_ctx *quic_handshake_ctx_get(gnutls_session_t session)
{
	return gnutls_db_get_ptr(session);
}

/*
 * The caller needs to opt-in in order
 * to get log messages
 */
static int quic_log_level = -1;
static quic_set_log_func_t quic_log_func;

static void quic_log_error(char const *fmt, ...);

/**
 * quic_log_debug - log msg with debug level
 *
 */
static void quic_log_debug(char const *fmt, ...)
{
	char msg[128];
	va_list arg;
	int rc;

	if (quic_log_level < LOG_DEBUG)
		return;

	va_start(arg, fmt);
	rc = vsnprintf(msg, sizeof(msg), fmt, arg);
	va_end(arg);
	if (rc < 0) {
		quic_log_error("%s: msg size is greater than 128 bytes!",
			       __func__);
		return;
	}

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
static void quic_log_notice(char const *fmt, ...)
{
	char msg[128];
	va_list arg;
	int rc;

	if (quic_log_level < LOG_NOTICE)
		return;

	va_start(arg, fmt);
	rc = vsnprintf(msg, sizeof(msg), fmt, arg);
	va_end(arg);
	if (rc < 0) {
		quic_log_error("%s: msg size is greater than 128 bytes!",
			       __func__);
		return;
	}

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
static void quic_log_error(char const *fmt, ...)
{
	char msg[128];
	va_list arg;
	int rc;

	if (quic_log_level < LOG_ERR)
		return;

	va_start(arg, fmt);
	rc = vsnprintf(msg, sizeof(msg), fmt, arg);
	va_end(arg);
	if (rc < 0) {
		snprintf(msg, sizeof(msg),
			 "%s: msg size is greater than 128 bytes!",
			 __func__);
	}

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
static void quic_log_gnutls_error(int error)
{
	quic_log_error("gnutls: %s (%d)", gnutls_strerror(error), error);
}

/**
 * quic_set_log_level - change the log_level
 * @level: the level it changes to (LOG_XXX from sys/syslog.h)
 *
 * Return values:
 * - The old @level
 */
int quic_set_log_level(int level)
{
	int old = quic_log_level;
	quic_log_level = level;
	return old;
}

/**
 * quic_set_log_func - change the log func
 * @func: the log func it changes to
 *
 * Return values:
 * - The old @func
 */
quic_set_log_func_t quic_set_log_func(quic_set_log_func_t func)
{
	quic_set_log_func_t old = quic_log_func;
	quic_log_func = func;
	return old;
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
	struct quic_stream_info *info;
	struct cmsghdr *cmsg;
	struct msghdr inmsg;
	struct iovec iov;
	ssize_t ret;

	iov.iov_base = msg;
	iov.iov_len = len;

	memset(&inmsg, 0, sizeof(inmsg));
	inmsg.msg_iov = &iov;
	inmsg.msg_iovlen = 1;
	inmsg.msg_control = incmsg;
	inmsg.msg_controllen = sizeof(incmsg);

	ret = recvmsg(sockfd, &inmsg, flags ? (int)*flags : 0);
	if (ret < 0)
		return ret;

	if (flags)
		*flags = inmsg.msg_flags;

	cmsg = CMSG_FIRSTHDR(&inmsg);
	if (!cmsg)
		return ret;

	if (SOL_QUIC == cmsg->cmsg_level &&  QUIC_STREAM_INFO == cmsg->cmsg_type) {
		info = (struct quic_stream_info *)CMSG_DATA(cmsg);
		if (sid)
			*sid = info->stream_id;
		if (flags)
			*flags |= info->stream_flags;
	}
	return ret;
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

	iov.iov_base = (void *)msg;
	iov.iov_len = len;

	memset(&outmsg, 0, sizeof(outmsg));
	outmsg.msg_iov = &iov;
	outmsg.msg_iovlen = 1;
	outmsg.msg_control = outcmsg;
	outmsg.msg_controllen = sizeof(outcmsg);

	cmsg = CMSG_FIRSTHDR(&outmsg);
	cmsg->cmsg_level = SOL_QUIC;
	cmsg->cmsg_type = QUIC_STREAM_INFO;
	cmsg->cmsg_len = CMSG_LEN(sizeof(*info));

	outmsg.msg_controllen = cmsg->cmsg_len;
	info = (struct quic_stream_info *)CMSG_DATA(cmsg);
	info->stream_id = sid;
	info->stream_flags = (flags & QUIC_MSG_STREAM_FLAGS);

	return sendmsg(sockfd, &outmsg, (int)(flags & ~QUIC_MSG_STREAM_FLAGS));
}

static uint32_t quic_tls_cipher_type(gnutls_cipher_algorithm_t cipher)
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

static uint8_t quic_crypto_level(gnutls_record_encryption_level_t level)
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

static gnutls_record_encryption_level_t quic_tls_crypto_level(uint8_t level)
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

static int quic_set_secret(gnutls_session_t session, gnutls_record_encryption_level_t level,
			   const void *rx_secret, const void *tx_secret, size_t secretlen)
{
	gnutls_cipher_algorithm_t type  = gnutls_cipher_get(session);
	struct quic_handshake_ctx *ctx = quic_handshake_ctx_get(session);
	struct quic_crypto_secret secret = {};
	int sockfd, ret, len = sizeof(secret);

	if (!ctx || ctx->completed)
		return 0;

	if (secretlen > QUIC_CRYPTO_SECRET_BUFFER_SIZE) {
		quic_log_error("secretlen[%zu] > %u",
			       secretlen, QUIC_CRYPTO_SECRET_BUFFER_SIZE);
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}

	if (level == GNUTLS_ENCRYPTION_LEVEL_EARLY)
		type = gnutls_early_cipher_get(session);

	sockfd = gnutls_transport_get_int(session);
	secret.level = quic_crypto_level(level);
	secret.type = quic_tls_cipher_type(type);
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
			if (ctx->is_serv) {
				ret = gnutls_session_ticket_send(session, 1, 0);
				if (ret) {
					quic_log_gnutls_error(ret);
					return ret;
				}
			}
			ctx->completed = 1;
		}
	}
	quic_log_debug("  Secret func: %u %u %u", secret.level, !!tx_secret, !!rx_secret);
	return 0;
}

static int quic_alert_read(gnutls_session_t session,
			   gnutls_record_encryption_level_t gtls_level,
			   gnutls_alert_level_t alert_level,
			   gnutls_alert_description_t alert_desc)
{
	quic_log_notice("%s: %u %u %u %u", __func__,
			!!session, gtls_level, alert_level, alert_desc);
	return 0;
}

static int quic_tp_recv(gnutls_session_t session, const uint8_t *buf, size_t len)
{
	int sockfd = gnutls_transport_get_int(session);

	if (setsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT, buf, len)) {
		quic_log_error("socket setsockopt transport_param_ext error %d", errno);
		return -1;
	}
	return 0;
}

static int quic_tp_send(gnutls_session_t session, gnutls_buffer_t extdata)
{
	int ret, sockfd = gnutls_transport_get_int(session);
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

static struct quic_msg *quic_msg_create(const void *data, size_t datalen)
{
	struct quic_msg *msg = malloc(sizeof(*msg));

	if (!msg)
		return NULL;

	memset(msg, 0, sizeof(*msg));
	msg->data = malloc(datalen);
	if (!msg->data) {
		free(msg);
		return NULL;
	}

	msg->len = datalen;
	memcpy(msg->data, data, msg->len);
	return msg;
}

static void quic_msg_destroy(struct quic_msg *msg)
{
	free(msg->data);
	free(msg);
}

static int quic_msg_read(gnutls_session_t session, gnutls_record_encryption_level_t level,
			 gnutls_handshake_description_t htype, const void *data, size_t datalen)
{
	struct quic_handshake_ctx *ctx = quic_handshake_ctx_get(session);
	struct quic_msg *msg;

	if (!ctx || htype == GNUTLS_HANDSHAKE_KEY_UPDATE)
		return 0;

	msg = quic_msg_create(data, datalen);
	if (!msg) {
		quic_log_error("msg create error %d", ENOMEM);
		return -1;
	}

	msg->level = quic_crypto_level(level);
	if (!ctx->send_list)
		ctx->send_list = msg;
	else
		ctx->send_last->next = msg;
	ctx->send_last = msg;

	quic_log_debug("  Read func: %u %u %u", level, htype, datalen);
	return 0;
}

static int quic_handshake_process(gnutls_session_t session, uint8_t level,
				  const uint8_t *data, size_t datalen)
{
	gnutls_record_encryption_level_t l;
	int ret;

	l = quic_tls_crypto_level(level);
	if (datalen > 0) {
		ret = gnutls_handshake_write(session, l, data, datalen);
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

static int quic_handshake_sendmsg(int sockfd, struct quic_msg *msg)
{
	char outcmsg[CMSG_SPACE(sizeof(struct quic_handshake_info))];
	struct quic_handshake_info *info;
	struct msghdr outmsg;
	struct cmsghdr *cmsg;
	struct iovec iov;

	iov.iov_base = (void *)msg->data;
	iov.iov_len = msg->len;

	memset(&outmsg, 0, sizeof(outmsg));
	outmsg.msg_iov = &iov;
	outmsg.msg_iovlen = 1;
	outmsg.msg_control = outcmsg;
	outmsg.msg_controllen = sizeof(outcmsg);

	cmsg = CMSG_FIRSTHDR(&outmsg);
	cmsg->cmsg_level = SOL_QUIC;
	cmsg->cmsg_type = QUIC_HANDSHAKE_INFO;
	cmsg->cmsg_len = CMSG_LEN(sizeof(*info));

	info = (struct quic_handshake_info *)CMSG_DATA(cmsg);
	info->crypto_level = msg->level;

	return sendmsg(sockfd, &outmsg, (msg->next ? MSG_MORE : 0));
}

static int quic_handshake_recvmsg(int sockfd, struct quic_msg *msg)
{
	char incmsg[CMSG_SPACE(sizeof(struct quic_handshake_info))];
	struct quic_handshake_info *info;
	struct cmsghdr *cmsg;
	struct msghdr inmsg;
	struct iovec iov;
	ssize_t ret;

	iov.iov_base = msg->data;
	iov.iov_len = msg->len;

	memset(&inmsg, 0, sizeof(inmsg));
	inmsg.msg_iov = &iov;
	inmsg.msg_iovlen = 1;
	inmsg.msg_control = incmsg;
	inmsg.msg_controllen = sizeof(incmsg);

	ret = recvmsg(sockfd, &inmsg, MSG_DONTWAIT);
	if (ret < 0)
		return ret;
	msg->len = ret;

	cmsg = CMSG_FIRSTHDR(&inmsg);
	if (!cmsg)
		return ret;

	if (SOL_QUIC == cmsg->cmsg_level && QUIC_HANDSHAKE_INFO == cmsg->cmsg_type) {
		info = (struct quic_handshake_info *)CMSG_DATA(cmsg);
		msg->level = info->crypto_level;
	}

	return ret;
}

static int quic_storage_add(void *dbf, time_t exp_time, const gnutls_datum_t *key,
			    const gnutls_datum_t *data)
{
	return 0;
}

static gnutls_anti_replay_t quic_anti_replay;

/**
 * quic_handshake - Drive the handshake interaction with TLS session
 * @session: TLS session
 *
 * Return values:
 * - On success, 0 is returned.
 * - On error, a negative error value is returned.
 */
int quic_handshake(gnutls_session_t session)
{
	int ret, sockfd = gnutls_transport_get_int(session);
	struct quic_msg *msg, _msg = {};
	struct quic_handshake_ctx *ctx;
	unsigned int len;
	uint8_t opt[128];

	ctx = malloc(sizeof(*ctx));
	if (!ctx) {
		quic_log_error("ctx malloc error %d", ENOMEM);
		return -ENOMEM;
	}
	memset(ctx, 0, sizeof(*ctx));

	len = sizeof(opt);
	ret = getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TOKEN, opt, &len);
	ctx->is_serv = !!ret;
	/* gnutls_session_set_ptr() might be used by the caller. */
	gnutls_db_set_ptr(session, ctx);

	gnutls_handshake_set_secret_function(session, quic_set_secret);
	gnutls_handshake_set_read_function(session, quic_msg_read);
	gnutls_alert_set_read_function(session, quic_alert_read);
	ret = gnutls_session_ext_register(
		session, "QUIC Transport Parameters", QUIC_TLSEXT_TP_PARAM,
		GNUTLS_EXT_TLS, quic_tp_recv, quic_tp_send, NULL, NULL, NULL,
		GNUTLS_EXT_FLAG_TLS | GNUTLS_EXT_FLAG_CLIENT_HELLO | GNUTLS_EXT_FLAG_EE);
	if (ret)
		goto out;

	if (ctx->is_serv) {
		if (!quic_anti_replay) {
			ret = gnutls_anti_replay_init(&quic_anti_replay);
			if (ret)
				goto out;
			gnutls_anti_replay_set_add_function(quic_anti_replay, quic_storage_add);
			gnutls_anti_replay_set_ptr(quic_anti_replay, NULL);
		}
		gnutls_anti_replay_enable(session, quic_anti_replay);
	}

	if (!ctx->is_serv) {
		ret = quic_handshake_process(session, QUIC_CRYPTO_INITIAL, NULL, 0);
		if (ret)
			goto out;

		msg = ctx->send_list;
		while (msg) {
			quic_log_debug("< Handshake SEND: %d %d", msg->len, msg->level);
			ret = quic_handshake_sendmsg(sockfd, msg);
			if (ret < 0) {
				quic_log_error("socket sendmsg error %d", errno);
				ret = -errno;
				goto out;
			}
			ctx->send_list = msg->next;
			quic_msg_destroy(msg);
			msg = ctx->send_list;
		}
	}

	while (!ctx->completed) {
		struct pollfd pfd = {
			.fd = sockfd,
			.events = POLLIN,
		};

		ret = poll(&pfd, 1, 1000);
		if (ret < 0) {
			quic_log_error("socket poll() error %d", errno);
			ret = -errno;
			goto out;
		}
		msg = &_msg;
		while (!ctx->completed) {
			msg->data = ctx->data;
			msg->len = sizeof(ctx->data);
			ret = quic_handshake_recvmsg(sockfd, msg);
			if (ret <= 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					break;
				quic_log_error("socket recvmsg error %d", errno);
				ret = -errno;
				goto out;
			}
			quic_log_debug("> Handshake RECV: %u %u", msg->len, msg->level);
			ret = quic_handshake_process(session, msg->level, msg->data, msg->len);
			if (ret)
				goto out;
		}

		msg = ctx->send_list;
		while (msg) {
			quic_log_debug("< Handshake SEND: %u %u", msg->len, msg->level);
			ret = quic_handshake_sendmsg(sockfd, msg);
			if (ret < 0) {
				quic_log_error("socket sendmsg error %d", errno);
				ret = -errno;
				goto out;
			}
			ctx->send_list = msg->next;
			quic_msg_destroy(msg);
			msg = ctx->send_list;
		}
	}

out:
	gnutls_db_set_ptr(session, NULL);

	msg = ctx->send_list;
	while (msg) {
		ctx->send_list = msg->next;
		quic_msg_destroy(msg);
		msg = ctx->send_list;
	}
	free(ctx);
	return ret < 0 ? ret : 0;
}

/**
 * quic_session_get_data - Get session data from a TLS session
 * @session: TLS session
 * @data: pre-allocated buffer to hold session data
 * @size: session data's size
 *
 * Return values:
 * - On success, 0 is returned.
 * - On error, a negative error value is returned.
 */
int quic_session_get_data(gnutls_session_t session, void *data, size_t *size)
{
	int ret, sockfd = gnutls_transport_get_int(session);
	unsigned int len = *size;

	if (getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_SESSION_TICKET, data, &len)) {
		quic_log_error("socket getsockopt session ticket error %d", errno);
		return -errno;
	}
	if (!len) {
		*size = 0;
		return 0;
	}

	ret = quic_handshake_process(session, QUIC_CRYPTO_APP, data, len);
	if (ret)
		return ret;
	return gnutls_session_get_data(session, data, size);
}

/**
 * quic_session_set_data - Set session data to a TLS session
 * @session: TLS session
 * @data: buffer to hold the session
 * @size: session data's size
 *
 * Return values:
 * - On success, 0 is returned.
 * - On error, a negative error value is returned.
 */
int quic_session_set_data(gnutls_session_t session, const void *data, size_t size)
{
	return gnutls_session_set_data(session, data, size);
}

/**
 * quic_session_get_alpn - Get session alpn from a TLS session
 * @session: TLS session
 * @data: pre-allocated string buffer to hold session alpn
 * @size: session alpn's size
 *
 * Return values:
 * - On success, 0 is returned.
 * - On error, a negative error value is returned.
 */
int quic_session_get_alpn(gnutls_session_t session, void *alpn, size_t *size)
{
	gnutls_datum_t alpn_data;
	int ret;

	ret = gnutls_alpn_get_selected_protocol(session, &alpn_data);
	if (ret)
		return ret;

	if (*size < alpn_data.size)
		return -EINVAL;

	memcpy(alpn, alpn_data.data, alpn_data.size);
	*size = alpn_data.size;
	return 0;
}

/**
 * quic_session_set_alpn - Set session alpn to a TLS session
 * @session: TLS session
 * @data: string buffer to hold the session
 * @size: session alpn's size
 *
 * Return values:
 * - On success, 0 is returned.
 * - On error, a negative error value is returned.
 */
int quic_session_set_alpn(gnutls_session_t session, const void *alpns, size_t size)
{
	gnutls_datum_t alpn_data[5];
	char *s, data[64] = {};
	int count = 0;

	if (size >= 64)
		return -EINVAL;

	memcpy(data, alpns, size);
	s = strtok(data, ",");
	while (s) {
		while (*s == ' ')
			s++;
		alpn_data[count].data = (unsigned char *)s;
		alpn_data[count].size = strlen(s);
		count++;
		s = strtok(NULL, ",");
	}

	return gnutls_alpn_set_protocols(session, alpn_data, count,
					 GNUTLS_ALPN_MANDATORY);
}
