// SPDX-License-Identifier: GPL-2.0

#include <linux/genetlink.h>
#include <linux/handshake.h>
#include <sys/socket.h>

#include <linux/quic.h>
#include <linux/tls.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#ifndef IPPROTO_QUIC
#define IPPROTO_QUIC	261
#endif

#ifndef SOL_QUIC
#define SOL_QUIC	288
#endif

#define ADDR4	"127.0.0.1"
#define ADDR6	"::1"
#define PORT	1234

static int family = AF_INET;
static char buf[65536];
static char msg[256];

#define QUIC_MSG_STREAM_FLAGS \
	(MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN | MSG_QUIC_STREAM_UNI | MSG_QUIC_STREAM_DONTWAIT)

static ssize_t send_msg(int sockfd, const void *msg, size_t len, int64_t sid, uint32_t flags)
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

static ssize_t recv_msg(int sockfd, void *msg, size_t len, int64_t *sid, uint32_t *flags)
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

static int send_pass(int sockfd, const void *msg, size_t len, int64_t sid, uint32_t flags)
{
	if (send_msg(sockfd, msg, len, sid, flags) < 0) {
		printf("%s: fail errno=%d sid=%d fl=%u\n", __func__, errno, (int)sid, flags);
		return -1;
	}
	return 0;
}

static int send_fail(int sockfd, const void *msg, size_t len, int64_t sid, uint32_t flags)
{
	if (send_msg(sockfd, msg, len, sid, flags) != -1) {
		printf("%s: success sid=%d fl=%u\n", __func__, (int)sid, flags);
		return -1;
	}
	return 0;
}

static int recv_pass(int sockfd, void *msg, size_t len, int64_t *sid, uint32_t *flags)
{
	if (recv_msg(sockfd, msg, len, sid, flags) < 0) {
		printf("%s: fail errno=%d\n", __func__, errno);
		return -1;
	}
	return 0;
}

static int recv_fail(int sockfd, void *msg, size_t len, int64_t *sid, uint32_t *flags)
{
	if (recv_msg(sockfd, msg, len, sid, flags) != -1) {
		printf("%s: success sid=%d fl=%u\n", __func__, (int)*sid, *flags);
		return -1;
	}
	return 0;
}

static int echo(int connectfd, int acceptfd, int64_t sid, uint32_t flags)
{
	int s = sid;

	if (send_pass(connectfd, msg, sizeof(msg), sid, flags))
		return -1;
	flags = 0;
	if (recv_pass(acceptfd, msg, sizeof(msg), &sid, &flags))
		return -1;
	if (s != -1 && s != sid) {
		printf("%s: sid=%d-%d\n", __func__, (int)s, (int)sid);
		return -1;
	}
	if (sid == -1 ? (flags & MSG_QUIC_STREAM_UNI) : (sid & QUIC_STREAM_TYPE_UNI_MASK))
		return 0;
	if (!(flags & MSG_QUIC_STREAM_FIN))
		return 0;
	s = sid;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (send_pass(acceptfd, msg, sizeof(msg), sid, flags))
		return -1;
	flags = 0;
	if (recv_pass(connectfd, msg, sizeof(msg), &sid, &flags))
		return -1;
	if (s != sid) {
		printf("%s: sid=%d-%d\n", __func__, (int)s, (int)sid);
		return -1;
	}
	return 0;
}

static int recv_event(int sockfd, char *msg, size_t len, int type)
{
	uint32_t flags = 0;

	if (recv_pass(sockfd, msg, len, NULL, &flags) < 0)
		return -1;
	if (!(flags & MSG_QUIC_NOTIFICATION) || msg[0] != type) {
		printf("%s: flags=%u event=%d\n", __func__, flags, msg[0]);
		return -1;
	}
	return 0;
}

static int recv_event_stream_update(int sockfd, int state)
{
	union quic_event *ev;

	if (recv_event(sockfd, msg, sizeof(msg), QUIC_EVENT_STREAM_UPDATE))
		return -1;
	ev = (union quic_event *)&msg[1];
	if (ev->update.state != state) {
		printf("%s: state=%u\n", __func__, ev->update.state);
		return -1;
	}
	return 0;
}

static int recv_event_connection_migration(int sockfd, int local)
{
	union quic_event *ev;

	if (recv_event(sockfd, msg, sizeof(msg), QUIC_EVENT_CONNECTION_MIGRATION))
		return -1;
	ev = (union quic_event *)&msg[1];
	if (ev->local_migration != local) {
		printf("%s: local=%d\n", __func__, ev->local_migration);
		return -1;
	}
	return 0;
}

static int recv_event_key_update(int sockfd, int phase)
{
	union quic_event *ev;

	if (recv_event(sockfd, msg, sizeof(msg), QUIC_EVENT_KEY_UPDATE))
		return -1;
	ev = (union quic_event *)&msg[1];
	if (ev->key_update_phase != phase) {
		printf("%s: phase=%d\n", __func__, ev->key_update_phase);
		return -1;
	}
	return 0;
}

static int recv_event_connection_id(int sockfd, int dest, uint32_t prior_to)
{
	union quic_event *ev;

	if (recv_event(sockfd, msg, sizeof(msg), QUIC_EVENT_CONNECTION_ID))
		return -1;
	ev = (union quic_event *)&msg[1];
	if (ev->info.dest != dest || ev->info.prior_to != prior_to) {
		printf("%s: dest=%d prior_to=%u\n", __func__, dest, ev->info.prior_to);
		return -1;
	}
	return 0;
}

static int recv_event_connection_close(int sockfd, uint32_t errcode, uint8_t frame, char *phrase)
{
	union quic_event *ev;

	if (recv_event(sockfd, msg, sizeof(msg), QUIC_EVENT_CONNECTION_CLOSE))
		return -1;
	ev = (union quic_event *)&msg[1];
	if (ev->close.errcode != errcode || ev->close.frame != frame ||
	    strcmp((char *)ev->close.phrase, phrase)) {
		printf("%s: errcode=%u frame=%d phrase=%s\n", __func__,
		       ev->close.errcode, ev->close.frame, ev->close.phrase);
		return -1;
	}
	return 0;
}

static int setopt_pass(int sockfd, int name, void *val, socklen_t len)
{
	if (setsockopt(sockfd, SOL_QUIC, name, val, len) < 0) {
		printf("%s: fail errno=%d optname=%d\n", __func__, errno, name);
		return -1;
	}
	return 0;
}

static int setopt_fail(int sockfd, int name, void *val, socklen_t len)
{
	if (setsockopt(sockfd, SOL_QUIC, name, val, len) != -1) {
		printf("%s: success optname=%d\n", __func__, name);
		return -1;
	}
	return 0;
}

static int getopt_pass(int sockfd, int name, void *val, socklen_t *len)
{
	if (getsockopt(sockfd, SOL_QUIC, name, val, len) < 0) {
		printf("%s: fail errno=%d optname=%d\n", __func__, errno, name);
		return -1;
	}
	return 0;
}

static int getopt_fail(int sockfd, int name, void *val, socklen_t *len)
{
	if (getsockopt(sockfd, SOL_QUIC, name, val, len) != -1) {
		printf("%s: success optname=%d\n", __func__, errno);
		return -1;
	}
	return 0;
}

static int getopt_connection_id(int sockfd, uint32_t active)
{
	struct quic_connection_id_info info = {};
	unsigned int optlen = sizeof(info);

	if (getopt_pass(sockfd, QUIC_SOCKOPT_CONNECTION_ID, &info, &optlen))
		return -1;
	if (info.active != active) {
		printf("%s: active %u\n", __func__, info.active);
		return -1;
	}
	return 0;
}

static int getopt_session_ticket(int sockfd, unsigned int len)
{
	unsigned int optlen;

	optlen = sizeof(msg);
	if (getopt_pass(sockfd, QUIC_SOCKOPT_SESSION_TICKET, msg, &optlen))
		return -1;
	if (optlen != len) {
		printf("%s: len=%u\n", __func__, optlen);
		return -1;
	}
	return 0;
}

static int getopt_token(int sockfd, int nz)
{
	unsigned int optlen;

	optlen = sizeof(msg);
	if (getopt_pass(sockfd, QUIC_SOCKOPT_TOKEN, msg, &optlen))
		return -1;
	if (nz != !!optlen) {
		printf("%s: len=%u\n", __func__, optlen);
		return -1;
	}
	return 0;
}

static int getopt_port(int sockfd, uint16_t port)
{
	struct sockaddr_storage sa = {};
	unsigned int optlen;
	uint16_t p;

	optlen = sizeof(sa);
	if (getsockname(sockfd, (struct sockaddr *)&sa, &optlen)) {
		printf("getsockname: errno=%d\n", errno);
		return -1;
	}
	p = ntohs(((struct sockaddr_in *)&sa)->sin_port);
	if (port != p) {
		printf("%s: port=%d-%d\n", __func__, p, port);
		return -1;
	}
	return 0;
}

static int getopt_connection_close(int sockfd, uint32_t errcode, uint8_t frame, char *phrase)
{
	struct quic_connection_close *info;
	unsigned int optlen;

	info = (struct quic_connection_close *)msg;
	optlen = sizeof(msg);
	if (getopt_pass(sockfd, QUIC_SOCKOPT_CONNECTION_CLOSE, msg, &optlen))
		return -1;
	if (info->errcode != errcode || info->frame != frame ||
	    strcmp((char *)info->phrase, phrase)) {
		printf("%s: errcode=%u frame=%d phrase=%s\n", __func__,
		       info->errcode, info->frame, info->phrase);
		return -1;
	}
	return 0;
}

static int send_handshake(int sockfd, void *msg, size_t len, uint8_t level, uint32_t flags)
{
	char outcmsg[CMSG_SPACE(sizeof(struct quic_handshake_info))];
	struct quic_handshake_info *info;
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
	cmsg->cmsg_type = QUIC_HANDSHAKE_INFO;
	cmsg->cmsg_len = CMSG_LEN(sizeof(*info));

	info = (struct quic_handshake_info *)CMSG_DATA(cmsg);
	info->crypto_level = level;

	return sendmsg(sockfd, &outmsg, flags);
}

static int recv_handshake(int sockfd, void *msg, size_t len, uint8_t *level, uint32_t flags)
{
	char incmsg[CMSG_SPACE(sizeof(struct quic_handshake_info))];
	struct quic_handshake_info *info;
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

	ret = recvmsg(sockfd, &inmsg, flags);
	if (ret < 0)
		return ret;

	cmsg = CMSG_FIRSTHDR(&inmsg);
	if (!cmsg)
		return ret;

	if (SOL_QUIC == cmsg->cmsg_level && QUIC_HANDSHAKE_INFO == cmsg->cmsg_type) {
		info = (struct quic_handshake_info *)CMSG_DATA(cmsg);
		*level = info->crypto_level;
	}

	return ret;
}

static struct quic_crypto_secret fake_keys[3][2] = {
	{ /* Early */
		{
			.type  = TLS_CIPHER_AES_GCM_128,
			.secret = {
				0x5D, 0x9A, 0x21, 0xF0, 0x3C, 0x88, 0x6B, 0x4E,
				0xD2, 0x11, 0xAF, 0x62, 0xB0, 0x37, 0x8E, 0xC5,
				0x79, 0x0D, 0x54, 0xE1, 0xA3, 0x96, 0x2F, 0xCB,
				0x08, 0x7D, 0x41, 0xFA, 0x13, 0xB8, 0x6E, 0x22,
				0x9F, 0x30, 0xD4, 0x5B, 0xE7, 0x12, 0x8A, 0x61,
				0x04, 0xC9, 0x3E, 0xF6, 0x57, 0xAD, 0x20, 0x89,
			}
		},
		{
			.type  = TLS_CIPHER_AES_GCM_128,
			.secret = {
				0xA1, 0x3F, 0xC6, 0x57, 0x8B, 0x0D, 0xE2, 0x49,
				0x6C, 0xF1, 0x95, 0x2B, 0xD7, 0x40, 0x8E, 0x13,
				0x54, 0x9A, 0x7F, 0xC2, 0x0B, 0x68, 0x31, 0xEA,
				0x05, 0xD9, 0x22, 0x7C, 0xB3, 0x4F, 0x10, 0x8D,
				0xE6, 0x29, 0xF0, 0x57, 0xAD, 0x1C, 0x83, 0x64,
				0xB2, 0x09, 0xC7, 0x3E, 0xF5, 0x61, 0x2A, 0x98,
			}
		}
	},
	{ /* Handshake */
		{
			.type  = TLS_CIPHER_AES_GCM_128,
			.secret = {
				0x7C, 0x12, 0xA9, 0x4F, 0xD0, 0x38, 0xB2, 0xE5,
				0x09, 0x6A, 0xF4, 0x51, 0xC8, 0x23, 0x9D, 0x7E,
				0x10, 0x84, 0xFA, 0x3B, 0x6D, 0x97, 0x0C, 0xE2,
				0x4A, 0xF9, 0x30, 0x11, 0xB6, 0xC5, 0x78, 0x2D,
				0x66, 0x1F, 0xCB, 0x5E, 0x82, 0x90, 0xDA, 0x04,
				0x37, 0xAF, 0x15, 0xE8, 0x63, 0xC1, 0x2B, 0x0D,
			}
		},
		{
			.type  = TLS_CIPHER_AES_GCM_128,
			.secret = {
				0x8F, 0x24, 0xC0, 0x5A, 0x19, 0xE4, 0x72, 0x3D,
				0xB3, 0x0F, 0xA1, 0x68, 0x9C, 0x42, 0xDE, 0x75,
				0xF8, 0x07, 0x6B, 0x11, 0xCD, 0x93, 0x20, 0xEA,
				0x5F, 0x38, 0x14, 0xD1, 0x49, 0xBE, 0x80, 0x23,
				0xAA, 0x6C, 0x12, 0x5D, 0xEF, 0x04, 0x97, 0x31,
				0x6E, 0x1B, 0xC8, 0xF3, 0x50, 0x08, 0xDA, 0x9E,
			}
		}
	},
	{ /* Application */
		{
			.type  = TLS_CIPHER_AES_GCM_128,
			.secret = {
				0x9A, 0x5C, 0xEF, 0x12, 0x68, 0x7D, 0x34, 0xB1,
				0x02, 0xF9, 0xAD, 0x47, 0x6C, 0x03, 0xE5, 0x8F,
				0x1D, 0xA7, 0x60, 0xCB, 0x35, 0x84, 0x9F, 0x22,
				0x71, 0x0B, 0xDC, 0x56, 0xEE, 0x13, 0x42, 0x9C,
				0x5B, 0xF0, 0x28, 0x6D, 0x81, 0x14, 0xC7, 0x3E,
				0xA2, 0x9D, 0x0F, 0x68, 0xB5, 0x7A, 0x11, 0xD3,
			}
		},
		{
			.type  = TLS_CIPHER_AES_GCM_128,
			.secret = {
				0xC1, 0x3E, 0x7F, 0xB4, 0x09, 0x5A, 0xE8, 0x2D,
				0x4C, 0xA7, 0x10, 0xF3, 0x68, 0x9D, 0x21, 0xCB,
				0x57, 0x80, 0x36, 0x1A, 0xF2, 0x4B, 0xC9, 0x05,
				0xE0, 0x6F, 0x93, 0x2A, 0xBD, 0x14, 0x7C, 0x8E,
				0x35, 0xDA, 0x0C, 0x41, 0xF6, 0x92, 0xA0, 0x7B,
				0x18, 0xCB, 0x55, 0xE7, 0x6A, 0x1F, 0xD4, 0x0B,
			}
		}
	}
};

static int set_fake_keys(int sockfd, uint8_t level, uint8_t serv)
{
	struct quic_crypto_secret *s;
	int i;

	switch (level) {
	case QUIC_CRYPTO_EARLY:
		i = 0;
		break;
	case QUIC_CRYPTO_HANDSHAKE:
		i = 1;
		break;
	case QUIC_CRYPTO_APP:
		i = 2;
		break;
	default:
		printf("%s: level=%d\n", __func__, level);
		return -1;
	}

	s = &fake_keys[i][serv];
	s->send = 1;
	s->level = level;
	if (setopt_pass(sockfd, QUIC_SOCKOPT_CRYPTO_SECRET, s, sizeof(*s)))
		return -1;
	s = &fake_keys[i][!serv];
	s->send = 0;
	s->level = level;
	if (setopt_pass(sockfd, QUIC_SOCKOPT_CRYPTO_SECRET, s, sizeof(*s)))
		return -1;
	return 0;
}

static uint8_t fake_ticket[] = {
	0x04, 0x00, 0x00, 0x21, 0x00, 0x01, 0x51, 0x80,
	0xA7, 0x19, 0x32, 0xEF, 0x04, 0xAB, 0xCD, 0xEF,
	0x01, 0x00, 0x10, 0x5E, 0x92, 0x31, 0x7A, 0x88,
	0x44, 0x19, 0x55, 0xE7, 0x02, 0xA5, 0xD1, 0xCC,
	0x90, 0x3F, 0xB2, 0x00, 0x00, 0x01, 0x02, 0x03,
	0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13,
	0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
};

static int send_fake_ticket(int sockfd)
{
	if (send_handshake(sockfd, fake_ticket, sizeof(fake_ticket), QUIC_CRYPTO_APP, 0) < 0) {
		printf("%s: errno=%d\n", __func__, errno);
		return -1;
	}
	return 0;
}

static const uint8_t fake_client_hello[] = { /* ALPN("fake") */
	0x01, 0x00, 0x00, 0x36, 0x03, 0x03, 0x00, 0x01,
	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
	0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
	0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00,
	0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x0B, 0x00,
	0x10, 0x00, 0x07, 0x00, 0x05, 0x04, 0x66, 0x61,
	0x6B, 0x65,
};

static const uint8_t fake_encrypted_extensions[] = {
	0x08, 0x00, 0x00, 0x02, 0x00, 0x00,
};

static int early_data;

static int send_fake_handshake(int sockfd, uint8_t level, uint8_t serv)
{
	unsigned int len;
	char ext[128];

	len = sizeof(msg);
	if ((!serv && level == QUIC_CRYPTO_INITIAL)) {
		len = sizeof(ext);
		if (getopt_pass(sockfd, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT, ext, &len))
			return -1;
		if (early_data && set_fake_keys(sockfd, QUIC_CRYPTO_EARLY, 0))
			return -1;
		/* ClientHello + TP_EXT */
		memcpy(msg, fake_client_hello, sizeof(fake_client_hello));
		memcpy(&msg[sizeof(fake_client_hello)], ext, len);
		len += sizeof(fake_client_hello);
	}

	if (serv && level == QUIC_CRYPTO_HANDSHAKE) {
		len = sizeof(ext);
		if (getopt_pass(sockfd, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT, ext, &len))
			return -1;
		/* EncryptedExtensions + TP_EXT */
		memcpy(msg, fake_encrypted_extensions, sizeof(fake_encrypted_extensions));
		memcpy(&msg[sizeof(fake_encrypted_extensions)], ext, len);
		len += sizeof(fake_encrypted_extensions);
	}

	if (send_handshake(sockfd, msg, len, level, 0) < 0) {
		printf("%s: errno=%d level=%d serv=%d\n", __func__, errno, level, serv);
		return -1;
	}
	return 0;
}

static int recv_fake_handshake(int sockfd, uint8_t level, uint8_t serv)
{
	unsigned int len;
	uint8_t l = 0;
	char *ext;
	int ret;

	len = sizeof(msg);
	ret = recv_handshake(sockfd, msg, len, &l, 0);
	if (ret < 0) {
		printf("%s: errno=%d level=%d serv=%d\n", __func__, errno, level, serv);
		return -1;
	}
	if (l != level) {
		printf("%s: level=%d-%d serv=%d\n", __func__, level, l, serv);
		return -1;
	}

	len = ret;
	if ((serv && level == QUIC_CRYPTO_INITIAL)) {
		ext = &msg[sizeof(fake_client_hello)];
		len -= sizeof(fake_client_hello);
		if (setopt_pass(sockfd, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT, ext, len))
			return -1;
		if (early_data && set_fake_keys(sockfd, QUIC_CRYPTO_EARLY, 1))
			return -1;
	}
	if ((!serv && level == QUIC_CRYPTO_HANDSHAKE)) {
		ext = &msg[sizeof(fake_encrypted_extensions)];
		len -= sizeof(fake_encrypted_extensions);
		if (setopt_pass(sockfd, QUIC_SOCKOPT_TRANSPORT_PARAM_EXT, ext, len))
			return -1;
	}
	return 0;
}

static int send_abnormal_client_hello(int sockfd)
{
	unsigned int len;

	len = sizeof(fake_client_hello);
	memcpy(msg, fake_client_hello, len);
	msg[3] = 0x16; /* wrong length */

	if (send_handshake(sockfd, msg, len, QUIC_CRYPTO_INITIAL, 0) < 0) {
		printf("%s: errno=%d\n", __func__, errno);
		return -1;
	}
	return 0;
}

static void build_address(struct sockaddr_storage *a)
{
	struct sockaddr_in *a4 = (struct sockaddr_in *)a;

	memset(a, 0, sizeof(*a));

	a4->sin_family = family;
	a4->sin_port = htons(PORT);
	if (family == AF_INET) {
		inet_pton(AF_INET, ADDR4, &a4->sin_addr);
		return;
	}
	inet_pton(AF_INET6, ADDR6, &((struct sockaddr_in6 *)a)->sin6_addr);
}

static int change_port(struct sockaddr_storage *a)
{
	struct sockaddr_in *a4 = (struct sockaddr_in *)a;

	a4->sin_port = htons(ntohs(a4->sin_port) + 1);

	return ntohs(a4->sin_port);
}

static int create_listen_socket(char *alpn)
{
	struct sockaddr_storage sa;
	int listenfd;

	build_address(&sa);

	listenfd = socket(family, SOCK_DGRAM, IPPROTO_QUIC);
	if (listenfd < 0) {
		printf("socket: errno=%d\n", errno);
		return -1;
	}
	if (bind(listenfd, (struct sockaddr *)&sa, sizeof(sa))) {
		printf("bind: errno=%d\n", errno);
		return -1;
	}
	if (alpn && setopt_pass(listenfd, QUIC_SOCKOPT_ALPN, alpn, strlen(alpn)))
		return -1;
	if (listen(listenfd, 1)) {
		printf("listen: errno=%d\n", errno);
		return -1;
	}
	return listenfd;
}

static int create_connect_socket(void)
{
	struct sockaddr_storage sa;
	int connectfd;

	build_address(&sa);

	connectfd = socket(family, SOCK_DGRAM, IPPROTO_QUIC);
	if (connectfd < 0) {
		printf("socket: errno=%d\n", errno);
		return -1;
	}
	if (connect(connectfd, (struct sockaddr *)&sa, sizeof(sa))) {
		printf("connect: errno=%d\n", errno);
		return -1;
	}
	return connectfd;
}

static int create_sockets(int *listenfd_p, int *connectfd_p)
{
	int listenfd, connectfd;

	listenfd = create_listen_socket(NULL);
	if (listenfd < 0)
		return -1;
	connectfd = create_connect_socket();
	if (connectfd < 0)
		return -1;

	*connectfd_p = connectfd;
	*listenfd_p = listenfd;
	return 0;
}

static int accept_socket(int listenfd, int connectfd)
{
	int acceptfd;

	if (send_fake_handshake(connectfd, QUIC_CRYPTO_INITIAL, 0))
		return -1;

	acceptfd = accept(listenfd, NULL, NULL);
	if (acceptfd < 0) {
		printf("accept: errno=%d\n", errno);
		return -1;
	}

	close(listenfd);
	return acceptfd;
}

static int do_handshake(int connectfd, int acceptfd)
{
	/* Initial ((CRYPTO)) / Handshake (CRYPTO) <- */
	if (recv_fake_handshake(acceptfd, QUIC_CRYPTO_INITIAL, 1))
		return -1;
	if (set_fake_keys(acceptfd, QUIC_CRYPTO_HANDSHAKE, 1))
		return -1;
	if (send_fake_handshake(acceptfd, QUIC_CRYPTO_INITIAL, 1))
		return -1;
	if (send_fake_handshake(acceptfd, QUIC_CRYPTO_HANDSHAKE, 1))
		return -1;

	/* Handshake (CRYPTO) -> */
	if (recv_fake_handshake(connectfd, QUIC_CRYPTO_INITIAL, 0))
		return -1;
	if (set_fake_keys(connectfd, QUIC_CRYPTO_HANDSHAKE, 0))
		return -1;
	if (recv_fake_handshake(connectfd, QUIC_CRYPTO_HANDSHAKE, 0))
		return -1;
	if (set_fake_keys(connectfd, QUIC_CRYPTO_APP, 0))
		return -1;
	if (send_fake_handshake(connectfd, QUIC_CRYPTO_HANDSHAKE, 0))
		return -1;

	/* DONE */
	if (recv_fake_handshake(acceptfd, QUIC_CRYPTO_HANDSHAKE, 1))
		return -1;
	if (set_fake_keys(acceptfd, QUIC_CRYPTO_APP, 1))
		return -1;
	return 0;
}

static void close_sockets(int connectfd, int acceptfd)
{
	close(connectfd);
	close(acceptfd);
	sleep(1);
}

static void change_fake_keys_type(uint32_t type)
{
	int i;

	for (i = 0; i < 3; i++) {
		fake_keys[0][0].type = type;
		fake_keys[0][1].type = type;
	}
}

static int test_handshake(int *connectfd_p, int *acceptfd_p)
{
	int listenfd, acceptfd, connectfd, sockfd[3];
	struct quic_transport_param param;
	struct sockaddr_storage sa;
	struct quic_config config;
	unsigned int addrlen;
	uint32_t flags;

	printf("=> Handshake Tests\n");
	system("[ -f /proc/sys/net/quic/alpn_demux ] && sysctl -q net.quic.alpn_demux=0");

	if (create_sockets(&listenfd, &connectfd))
		return -1;
	memset(&config, 0, sizeof(config));
	config.validate_peer_address = 1;
	if (setopt_pass(listenfd, QUIC_SOCKOPT_CONFIG, &config, sizeof(config)))
		return -1;
	acceptfd = accept_socket(listenfd, connectfd);
	if (acceptfd < 0)
		return -1;
	if (do_handshake(connectfd, acceptfd))
		return -1;
	close_sockets(connectfd, acceptfd);
	printf("[] Handshake with Retry\n");

	if (create_sockets(&listenfd, &connectfd))
		return -1;
	memset(&config, 0, sizeof(config));
	config.version = QUIC_VERSION_V2;
	if (setopt_pass(listenfd, QUIC_SOCKOPT_CONFIG, &config, sizeof(config)))
		return -1;
	acceptfd = accept_socket(listenfd, connectfd);
	if (acceptfd < 0)
		return -1;
	if (do_handshake(connectfd, acceptfd))
		return -1;
	close_sockets(connectfd, acceptfd);
	printf("[] Handshake with V2\n");

	if (create_sockets(&listenfd, &connectfd))
		return -1;
	memset(&config, 0, sizeof(config));
	config.version = 123;
	if (setopt_pass(connectfd, QUIC_SOCKOPT_CONFIG, &config, sizeof(config)))
		return -1;
	acceptfd = accept_socket(listenfd, connectfd);
	if (acceptfd < 0)
		return -1;
	if (do_handshake(connectfd, acceptfd))
		return -1;
	close_sockets(connectfd, acceptfd);
	printf("[] Handshake with Version Negotiation\n");

	if (create_sockets(&listenfd, &connectfd))
		return -1;
	change_fake_keys_type(TLS_CIPHER_AES_GCM_256);
	acceptfd = accept_socket(listenfd, connectfd);
	if (acceptfd < 0)
		return -1;
	if (do_handshake(connectfd, acceptfd))
		return -1;
	close_sockets(connectfd, acceptfd);
	printf("[] Handshake with TLS_CIPHER_AES_GCM_256\n");

	if (create_sockets(&listenfd, &connectfd))
		return -1;
	change_fake_keys_type(TLS_CIPHER_AES_CCM_128);
	acceptfd = accept_socket(listenfd, connectfd);
	if (acceptfd < 0)
		return -1;
	if (do_handshake(connectfd, acceptfd))
		return -1;
	close_sockets(connectfd, acceptfd);
	printf("[] Handshake with TLS_CIPHER_AES_CCM_128\n");

	if (create_sockets(&listenfd, &connectfd))
		return -1;
	change_fake_keys_type(TLS_CIPHER_CHACHA20_POLY1305);
	acceptfd = accept_socket(listenfd, connectfd);
	if (acceptfd < 0)
		return -1;
	if (do_handshake(connectfd, acceptfd))
		return -1;
	close_sockets(connectfd, acceptfd);
	printf("[] Handshake with TLS_CIPHER_CHACHA20_POLY1305\n");

	if (create_sockets(&listenfd, &connectfd))
		return -1;
	acceptfd = accept_socket(listenfd, connectfd);
	if (acceptfd < 0)
		return -1;
	addrlen = sizeof(sa);
	memset(&sa, 0, sizeof(sa));
	if (getsockname(acceptfd, (struct sockaddr *)&sa, &addrlen)) {
		printf("getsockname: errno=%d\n", errno);
		return -1;
	}
	change_port(&sa);
	if (setopt_pass(acceptfd, QUIC_SOCKOPT_CONNECTION_MIGRATION, &sa, sizeof(sa)))
		return -1;
	if (do_handshake(connectfd, acceptfd))
		return -1;
	close_sockets(connectfd, acceptfd);
	printf("[] Handshake with Preferred Address\n");

	system("sysctl -q net.quic.alpn_demux=1");
	sockfd[0] = create_listen_socket("quic");
	if (sockfd[0] < 0)
		return -1;
	sockfd[1] = create_listen_socket("fake");
	if (sockfd[1] < 0)
		return -1;
	sockfd[2] = create_listen_socket("http3");
	if (sockfd[2] < 0)
		return -1;
	connectfd = create_connect_socket();
	if (connectfd < 0)
		return -1;
	listenfd = sockfd[1];
	acceptfd = accept_socket(listenfd, connectfd);
	if (acceptfd < 0)
		return -1;
	if (do_handshake(connectfd, acceptfd))
		return -1;
	close_sockets(connectfd, acceptfd);
	printf("[] Handshake with ALPN demux\n");

	connectfd = create_connect_socket();
	if (connectfd < 0)
		return -1;
	if (send_abnormal_client_hello(connectfd))
		return -1;
	close_sockets(sockfd[0], sockfd[2]);
	system("sysctl -q net.quic.alpn_demux=0");
	printf("[] Handshake with ALPN demux (abnormal Client Hello)\n");

	if (create_sockets(&listenfd, &connectfd))
		return -1;
	memset(&param, 0, sizeof(param));
	param.disable_1rtt_encryption = 1;
	if (setopt_pass(connectfd, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, sizeof(param)))
		return -1;
	if (setopt_pass(listenfd, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, sizeof(param)))
		return -1;
	acceptfd = accept_socket(listenfd, connectfd);
	if (acceptfd < 0)
		return -1;
	if (do_handshake(connectfd, acceptfd))
		return -1;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (echo(connectfd, acceptfd, -1, flags))
		return -1;
	close_sockets(connectfd, acceptfd);
	printf("[] Handshake with 1RTT Encryption disabled\n");

	if (create_sockets(&listenfd, &connectfd))
		return -1;
	memset(&param, 0, sizeof(param));
	param.max_datagram_frame_size = 1400;
	if (setopt_pass(connectfd, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, sizeof(param)))
		return -1;
	if (setopt_pass(listenfd, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, sizeof(param)))
		return -1;
	acceptfd = accept_socket(listenfd, connectfd);
	if (acceptfd < 0)
		return -1;
	if (do_handshake(connectfd, acceptfd))
		return -1;
	printf("[] Handshake with Datagram enabled\n");

	*connectfd_p = connectfd;
	*acceptfd_p = acceptfd;
	return 0;
}

static int test_stream(int connectfd, int acceptfd)
{
	struct quic_stream_info info;
	struct quic_errinfo errinfo;
	unsigned int optlen;
	uint32_t flags;
	int64_t sid;

	printf("=> Stream Tests\n");

	sid = 0;
	flags = MSG_QUIC_STREAM_FIN;
	if (send_fail(connectfd, msg, sizeof(msg), sid, flags))
		return -1;
	printf("[] Cannot send on non-opened stream\n");

	sid = 4;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	printf("[] Open stream with STREAM_NEW\n");

	sid = 0;
	flags = MSG_QUIC_STREAM_FIN;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	printf("[] Open stream sequentially\n");

	sid = -1; /* 8 */
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	printf("[] Open next bidi stream (sid = -1)\n");

	sid = -1; /* 2 */
	flags = MSG_QUIC_STREAM_UNI | MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	printf("[] Open next uni stream (sid = -1)\n");

	optlen = sizeof(info);
	info.stream_id = 0;
	info.stream_flags = 0;
	if (getopt_fail(connectfd, QUIC_SOCKOPT_STREAM_OPEN, &info, &optlen))
		return -1;
	printf("[] Cannot reopen a closed stream\n");

	optlen = sizeof(info);
	info.stream_id = -1; /* 12 */
	info.stream_flags = 0;
	if (getopt_pass(connectfd, QUIC_SOCKOPT_STREAM_OPEN, &info, &optlen))
		return -1;
	sid = info.stream_id;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	printf("[] Open next bidi stream using STREAM_OPEN\n");

	optlen = sizeof(info);
	info.stream_id = -1; /* 6 */
	info.stream_flags = MSG_QUIC_STREAM_UNI;
	if (getopt_pass(connectfd, QUIC_SOCKOPT_STREAM_OPEN, &info, &optlen))
		return -1;
	sid = info.stream_id;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	printf("[] Open next uni stream using STREAM_OPEN\n");

	optlen = sizeof(info);
	info.stream_id = 10;
	info.stream_flags = 0;
	if (getopt_pass(connectfd, QUIC_SOCKOPT_STREAM_OPEN, &info, &optlen))
		return -1;
	optlen = sizeof(info);
	info.stream_id = 16;
	info.stream_flags = 0;
	if (getopt_pass(connectfd, QUIC_SOCKOPT_STREAM_OPEN, &info, &optlen))
		return -1;
	printf("[] Open multiple streams via STREAM_OPEN\n");

	sid = 10;
	flags = MSG_QUIC_STREAM_FIN;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	sid = 16;
	flags = MSG_QUIC_STREAM_FIN;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	printf("[] Send data on multiple streams\n");

	sid = 14; /* 14 */
	flags = MSG_QUIC_STREAM_NEW;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	flags = MSG_QUIC_STREAM_NEW;
	if (send_fail(connectfd, msg, sizeof(msg), sid, flags))
		return -1;
	printf("[] STREAM_NEW not allowed on already-open stream\n");

	info.stream_id = 14;
	info.stream_flags = 0;
	optlen = sizeof(info);
	if (getopt_fail(connectfd, QUIC_SOCKOPT_STREAM_OPEN, &info, &optlen))
		return -1;
	printf("[] STREAM_OPEN not allowed on already-open stream\n");

	sid = -1;
	flags = MSG_QUIC_STREAM_NEW;
	if (send_fail(connectfd, msg, sizeof(msg), sid, flags))
		return -1;
	printf("[] STREAM_NEW not allowed (sid = -1 already used)\n");

	flags = MSG_QUIC_STREAM_FIN;
	if (send_pass(connectfd, NULL, 0, sid, flags))
		return -1;
	flags = 0;
	if (recv_pass(acceptfd, msg, sizeof(msg), &sid, &flags))
		return -1;
	printf("[] Send FIN-only frame\n");

	sid = 400;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	printf("[] Send with sid > initial max_streams_bidi\n");

	sid = 402;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	printf("[] Send with sid > initial max_streams_uni\n");

	/* 0 4 8 12 16 400 (bidi_closed=6) */
	sid = 424; /* 0 + max_streams (100) * 4 +  bidi_closed (6) * 4 */
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN | MSG_QUIC_STREAM_DONTWAIT;
	if (send_fail(connectfd, msg, sizeof(msg), sid, flags))
		return -1;
	printf("[] Send with sid > current max_streams_bidi\n");

	sid = 404;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	sid = 424;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN | MSG_QUIC_STREAM_DONTWAIT;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	printf("[] Send after max_streams_bidi increased\n");

	/* 2 6 10 14 402 (uni_closed=5) */
	sid = 422; /* 2 + max_streams (100) * 4 +  uni_closed(4) * 5 */
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN | MSG_QUIC_STREAM_DONTWAIT;
	if (send_fail(connectfd, msg, sizeof(msg), sid, flags))
		return -1;
	printf("[] Send with sid > current max_streams_uni\n");

	sid = 406;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	sid = 422;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN | MSG_QUIC_STREAM_DONTWAIT;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	printf("[] Send after max_streams_uni increased\n");

	optlen = sizeof(info);
	info.stream_id = 408;
	info.stream_flags = 0;
	if (getopt_pass(connectfd, QUIC_SOCKOPT_STREAM_OPEN, &info, &optlen))
		return -1;
	sid = info.stream_id;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	printf("[] STREAM_OPEN with sid > initial max_streams_bidi\n");

	optlen = sizeof(info);
	info.stream_id = 410;
	info.stream_flags = 0;
	if (getopt_pass(connectfd, QUIC_SOCKOPT_STREAM_OPEN, &info, &optlen))
		return -1;
	sid = info.stream_id;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	printf("[] STREAM_OPEN with sid > initial max_streams_uni\n");

	/* 0 4 8 12 16 400 404 408 424 (bidi_closed=9) */
	info.stream_id = 436; /* 0 + max_streams (100) * 4 +  bidi_closed (9) * 4 */
	info.stream_flags = MSG_QUIC_STREAM_DONTWAIT;
	optlen = sizeof(info);
	if (getopt_fail(connectfd, QUIC_SOCKOPT_STREAM_OPEN, &info, &optlen))
		return -1;
	printf("[] STREAM_OPEN not allowed (sid > current max_streams_bidi)\n");

	sid = 412;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	info.stream_id = 436;
	info.stream_flags = MSG_QUIC_STREAM_DONTWAIT;
	optlen = sizeof(info);
	if (getopt_pass(connectfd, QUIC_SOCKOPT_STREAM_OPEN, &info, &optlen))
		return -1;
	sid = info.stream_id;
	flags = MSG_QUIC_STREAM_FIN;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	printf("[] Send after max_streams_bidi extended via STREAM_OPEN\n");

	/* 2 6 10 14 402 406 410 422 (uni_closed=8) */
	info.stream_id = 434; /* 2 + max_streams (100) * 4 +  bidi_closed (8) * 4 */
	info.stream_flags = MSG_QUIC_STREAM_DONTWAIT;
	optlen = sizeof(info);
	if (getopt_fail(connectfd, QUIC_SOCKOPT_STREAM_OPEN, &info, &optlen))
		return -1;
	printf("[] STREAM_OPEN not allowed (sid > current max_streams_uni)\n");

	sid = 414;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	info.stream_id = 434;
	info.stream_flags = MSG_QUIC_STREAM_DONTWAIT;
	optlen = sizeof(info);
	if (getopt_pass(connectfd, QUIC_SOCKOPT_STREAM_OPEN, &info, &optlen))
		return -1;
	sid = info.stream_id;
	flags = MSG_QUIC_STREAM_FIN;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	printf("[] Send after max_streams_uni extended via STREAM_OPEN\n");

	optlen = sizeof(errinfo);
	errinfo.stream_id = 414;
	errinfo.errcode = 1;
	if (setopt_fail(connectfd, QUIC_SOCKOPT_STREAM_RESET, &errinfo, optlen))
		return -1;
	printf("[] Cannot reset a closed stream\n");

	optlen = sizeof(errinfo);
	errinfo.stream_id = 444;
	errinfo.errcode = 1;
	if (setopt_fail(connectfd, QUIC_SOCKOPT_STREAM_RESET, &errinfo, optlen))
		return -1;
	printf("[] Cannot reset a non-opened stream\n");

	sid = 418;
	flags = 0;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	optlen = sizeof(errinfo);
	errinfo.stream_id = sid;
	errinfo.errcode = 1;
	if (setopt_fail(acceptfd, QUIC_SOCKOPT_STREAM_RESET, &errinfo, optlen))
		return -1;
	printf("[] Cannot reset a recv-only stream\n");

	optlen = sizeof(errinfo);
	errinfo.stream_id = sid;
	errinfo.errcode = 1;
	if (setopt_pass(connectfd, QUIC_SOCKOPT_STREAM_RESET, &errinfo, optlen))
		return -1;
	printf("[] Reset opened stream\n");

	flags = 0;
	if (send_fail(connectfd, msg, sizeof(msg), sid, flags))
		return -1;
	flags = MSG_QUIC_STREAM_NEW;
	if (send_fail(connectfd, msg, sizeof(msg), sid, flags))
		return -1;
	flags = MSG_QUIC_STREAM_FIN;
	if (send_fail(connectfd, msg, sizeof(msg), sid, flags))
		return -1;
	printf("[] Cannot send on a reset stream\n");

	optlen = sizeof(errinfo);
	errinfo.stream_id = 412;
	errinfo.errcode = 1;
	if (setopt_fail(acceptfd, QUIC_SOCKOPT_STREAM_STOP_SENDING, &errinfo, optlen))
		return -1;
	printf("[] Cannot stop-sending on closed stream\n");

	optlen = sizeof(errinfo);
	errinfo.stream_id = 444;
	errinfo.errcode = 1;
	if (setopt_fail(connectfd, QUIC_SOCKOPT_STREAM_STOP_SENDING, &errinfo, optlen))
		return -1;
	printf("[] Cannot stop-sending on non-opened stream\n");

	sid = 426;
	flags = 0;
	if (send_pass(connectfd, msg, sizeof(msg), sid, flags))
		return -1;

	optlen = sizeof(errinfo);
	errinfo.stream_id = sid;
	errinfo.errcode = 1;
	if (setopt_fail(connectfd, QUIC_SOCKOPT_STREAM_STOP_SENDING, &errinfo, optlen))
		return -1;
	printf("[] Cannot stop-sending on send-only stream\n");

	optlen = sizeof(errinfo);
	errinfo.stream_id = sid;
	errinfo.errcode = 1;
	if (setopt_pass(acceptfd, QUIC_SOCKOPT_STREAM_STOP_SENDING, &errinfo, optlen))
		return -1;
	printf("[] Peer stop-sending accepted\n");

	flags = 0;
	if (send_fail(connectfd, msg, sizeof(msg), sid, flags))
		return -1;
	flags = MSG_QUIC_STREAM_NEW;
	if (send_fail(connectfd, msg, sizeof(msg), sid, flags))
		return -1;
	flags = MSG_QUIC_STREAM_FIN;
	if (send_fail(connectfd, msg, sizeof(msg), sid, flags))
		return -1;
	printf("[] Cannot send after peer stop-sending\n");
	return 0;
}

static int test_connection(int connectfd, int acceptfd)
{
	struct quic_connection_id_info info;
	struct sockaddr_storage sa;
	unsigned int optlen;
	uint32_t flags;
	uint16_t port;
	int64_t sid;

	printf("=> Connection Tests\n");

	/* Connection ID */
	optlen = sizeof(info);
	info.prior_to = 3;
	info.active = 0;
	info.dest = 0;
	if (setopt_pass(connectfd, QUIC_SOCKOPT_CONNECTION_ID, &info, optlen)) /* 3-9 */
		return -1;
	sid = -1;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	if (getopt_connection_id(connectfd, 3))
		return -1;
	printf("[] Retired source CIDs with prior_to=3\n");

	info.prior_to = 5;
	info.active = 2;
	info.dest = 0;
	if (setopt_fail(connectfd, QUIC_SOCKOPT_CONNECTION_ID, &info, optlen))
		return -1;
	printf("[] Reject invalid active source CID (must exist)\n");

	optlen = sizeof(info);
	info.prior_to = 3;
	info.active = 5;
	info.dest = 0;
	if (setopt_fail(connectfd, QUIC_SOCKOPT_CONNECTION_ID, &info, optlen))
		return -1;
	optlen = sizeof(info);
	info.prior_to = 10;
	info.active = 5;
	info.dest = 0;
	if (setopt_fail(connectfd, QUIC_SOCKOPT_CONNECTION_ID, &info, optlen))
		return -1;
	printf("[] Reject source CID retire request: prior_to out of range\n");

	optlen = sizeof(info);
	info.prior_to = 3;
	info.active = 0;
	info.dest = 1;
	if (setopt_pass(connectfd, QUIC_SOCKOPT_CONNECTION_ID, &info, optlen)) /* 3-9 */
		return -1;
	sid = -1;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	if (getopt_connection_id(connectfd, 3))
		return -1;
	printf("[] Retired destination CIDs with prior_to=3\n");

	info.prior_to = 5;
	info.active = 2;
	info.dest = 1;
	if (setopt_fail(connectfd, QUIC_SOCKOPT_CONNECTION_ID, &info, optlen))
		return -1;
	printf("[] Reject invalid active destination CID (must exist)\n");

	optlen = sizeof(info);
	info.prior_to = 3;
	info.active = 5;
	info.dest = 1;
	if (setopt_fail(connectfd, QUIC_SOCKOPT_CONNECTION_ID, &info, optlen))
		return -1;
	optlen = sizeof(info);
	info.prior_to = 10;
	info.active = 5;
	info.dest = 1;
	if (setopt_fail(connectfd, QUIC_SOCKOPT_CONNECTION_ID, &info, optlen))
		return -1;
	printf("[] Reject destination CID retire request: prior_to out of range\n");

	/* Connection Migration */
	optlen = sizeof(sa);
	if (getsockname(connectfd, (struct sockaddr *)&sa, &optlen)) {
		printf("getsockname: errno=%d\n", errno);
		return -1;
	}
	if (setopt_fail(connectfd, QUIC_SOCKOPT_CONNECTION_MIGRATION, &sa, optlen))
		return -1;
	printf("[] Reject migration to same address/port\n");

	if (setopt_fail(connectfd, QUIC_SOCKOPT_CONNECTION_MIGRATION, &sa, optlen - 1))
		return -1;
	printf("[] Reject migration with malformed address (optlen too small)\n");

	port = change_port(&sa);
	if (setopt_pass(connectfd, QUIC_SOCKOPT_CONNECTION_MIGRATION, &sa, optlen))
		return -1;
	change_port(&sa);
	if (setopt_fail(connectfd, QUIC_SOCKOPT_CONNECTION_MIGRATION, &sa, optlen))
		return -1;
	printf("[] Reject migration when another migration already pending\n");

	sid = -1;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	sid = -1;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (echo(acceptfd, connectfd, sid, flags))
		return -1;
	if (getopt_port(connectfd, port))
		return -1;
	printf("[] Connection migration succeeded\n");

	/* Key Update */
	if (setopt_pass(connectfd, QUIC_SOCKOPT_KEY_UPDATE, NULL, 0))
		return -1;
	if (setopt_fail(connectfd, QUIC_SOCKOPT_KEY_UPDATE, NULL, 0))
		return -1;
	printf("[] Reject second key update while one is in progress\n");

	sid = -1;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	sleep(1); /* Wait for last phase key to be freed */
	printf("[] Local key update completed\n");

	sid = -1;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	if (setopt_pass(acceptfd, QUIC_SOCKOPT_KEY_UPDATE, NULL, 0))
		return -1;
	sid = -1;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (echo(acceptfd, connectfd, sid, flags))
		return -1;
	printf("[] Peer key update completed\n");

	/* Token */
	if (setopt_pass(acceptfd, QUIC_SOCKOPT_TOKEN, NULL, 0))
		return -1;
	sid = -1;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (echo(connectfd, acceptfd, sid, flags))
		return -1;
	if (getopt_token(connectfd, 1))
		return -1;
	printf("[] New token received from peer\n");

	if (setopt_fail(connectfd, QUIC_SOCKOPT_TOKEN, NULL, 0))
		return -1;
	printf("[] Reject setting NULL token value\n");

	if (setopt_fail(connectfd, QUIC_SOCKOPT_TOKEN, msg, 121))
		return -1;
	printf("[] Reject setting oversized token (>120 bytes)\n");

	/* Session Ticket */
	if (getopt_session_ticket(connectfd, 0))
		return -1;
	printf("[] No session ticket received yet\n");

	if (getopt_session_ticket(acceptfd, 64))
		return -1;
	printf("[] Retrieve system-generated master key\n");

	if (setopt_fail(acceptfd, QUIC_SOCKOPT_SESSION_TICKET, msg, 63))
		return -1;
	printf("[] Reject too-small session ticket (<64 bytes)\n");

	if (setopt_fail(acceptfd, QUIC_SOCKOPT_SESSION_TICKET, msg, 4097))
		return -1;
	printf("[] Reject too-large session ticket (>4096 bytes)\n");

	if (setopt_pass(acceptfd, QUIC_SOCKOPT_SESSION_TICKET, msg, sizeof(msg)))
		return -1;
	if (getopt_session_ticket(acceptfd, sizeof(msg)))
		return -1;
	printf("[] Session ticket set with user-defined master key\n");

	flags = MSG_QUIC_DATAGRAM;
	if (send_pass(connectfd, msg, sizeof(msg), -1, flags))
		return -1;
	flags = 0;
	if (recv_pass(acceptfd, msg, sizeof(msg), NULL, &flags))
		return -1;
	printf("[] Datagram message received\n");

	flags = MSG_QUIC_DATAGRAM;
	if (send_fail(connectfd, msg, 4096, -1, flags))
		return -1;
	printf("[] Reject datagram larger than max_datagram\n");
	return 0;
}

static int test_notification(int connectfd, int acceptfd)
{
	struct quic_connection_id_info cinfo;
	struct quic_event_option event;
	struct quic_stream_info info;
	struct quic_errinfo errinfo;
	struct sockaddr_storage sa;
	unsigned int optlen;
	uint32_t flags;
	int64_t sid;

	printf("=> Notification Tests\n");

	/* Stream Update */
	event.type = QUIC_EVENT_STREAM_UPDATE;
	event.on = 1;
	if (setopt_pass(connectfd, QUIC_SOCKOPT_EVENT, &event, sizeof(event)))
		return -1;
	event.type = QUIC_EVENT_STREAM_UPDATE;
	event.on = 1;
	if (setopt_pass(acceptfd, QUIC_SOCKOPT_EVENT, &event, sizeof(event)))
		return -1;
	printf("[] Enabled stream-update notifications\n");

	optlen = sizeof(info);
	info.stream_id = -1;
	info.stream_flags = MSG_QUIC_STREAM_UNI;
	if (getopt_pass(connectfd, QUIC_SOCKOPT_STREAM_OPEN, &info, &optlen))
		return -1;
	sid = info.stream_id;
	flags = 0;
	if (send_pass(connectfd, msg, sizeof(msg), sid, flags))
		return -1;
	if (recv_event_stream_update(acceptfd, QUIC_STREAM_RECV_STATE_RECV))
		return -1;
	printf("[] Stream RECV_STATE_RECV\n");

	sid = info.stream_id;
	flags = MSG_QUIC_STREAM_FIN;
	if (send_pass(connectfd, NULL, 0, sid, flags))
		return -1;
	if (recv_event_stream_update(connectfd, QUIC_STREAM_SEND_STATE_RECVD))
		return -1;
	printf("[] Stream SEND_STATE_RECVD\n");

	if (recv_event_stream_update(acceptfd, QUIC_STREAM_RECV_STATE_RECVD))
		return -1;
	flags = 0;
	if (recv_pass(acceptfd, msg, sizeof(msg), &sid, &flags))
		return -1;
	flags = 0;
	if (recv_pass(acceptfd, msg, sizeof(msg), &sid, &flags))
		return -1;
	printf("[] Stream RECV_STATE_RECVD\n");

	optlen = sizeof(info);
	info.stream_id = -1;
	info.stream_flags = MSG_QUIC_STREAM_UNI;
	if (getopt_pass(connectfd, QUIC_SOCKOPT_STREAM_OPEN, &info, &optlen))
		return -1;
	sid = info.stream_id;
	flags = 0;
	if (send_pass(connectfd, msg, sizeof(msg), sid, flags))
		return -1;
	if (recv_event_stream_update(acceptfd, QUIC_STREAM_RECV_STATE_RECV))
		return -1;
	optlen = sizeof(errinfo);
	errinfo.stream_id = info.stream_id;
	errinfo.errcode = 1;
	if (setopt_pass(connectfd, QUIC_SOCKOPT_STREAM_RESET, &errinfo, optlen))
		return -1;
	if (recv_event_stream_update(acceptfd, QUIC_STREAM_RECV_STATE_RESET_RECVD))
		return -1;
	printf("[] Stream RECV_STATE_RESET_RECVD\n");

	flags = 0;
	if (recv_event_stream_update(connectfd, QUIC_STREAM_SEND_STATE_RESET_RECVD))
		return -1;
	printf("[] Stream SEND_STATE_RESET_RECVD\n");

	event.type = QUIC_EVENT_STREAM_UPDATE;
	event.on = 0;
	if (setopt_pass(acceptfd, QUIC_SOCKOPT_EVENT, &event, sizeof(event)))
		return -1;
	event.type = QUIC_EVENT_STREAM_UPDATE;
	event.on = 0;
	if (setopt_pass(connectfd, QUIC_SOCKOPT_EVENT, &event, sizeof(event)))
		return -1;
	printf("[] Disabled stream-update notifications\n");

	/* Connection Migration */
	event.type = QUIC_EVENT_CONNECTION_MIGRATION;
	event.on = 1;
	if (setopt_pass(connectfd, QUIC_SOCKOPT_EVENT, &event, sizeof(event)))
		return -1;
	event.type = QUIC_EVENT_CONNECTION_MIGRATION;
	event.on = 1;
	if (setopt_pass(acceptfd, QUIC_SOCKOPT_EVENT, &event, sizeof(event)))
		return -1;
	printf("[] Enabled connection-migration notifications\n");

	optlen = sizeof(sa);
	if (getsockname(connectfd, (struct sockaddr *)&sa, &optlen)) {
		printf("getsockname: errno=%d\n", errno);
		return -1;
	}
	change_port(&sa);
	if (setopt_pass(connectfd, QUIC_SOCKOPT_CONNECTION_MIGRATION, &sa, optlen))
		return -1;
	sid = -1;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (send_pass(connectfd, msg, strlen(msg), sid, flags))
		return -1;
	sid = -1;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (send_pass(acceptfd, msg, strlen(msg), sid, flags))
		return -1;
	if (recv_event_connection_migration(connectfd, 1))
		return -1;
	flags = 0;
	if (recv_pass(connectfd, msg, sizeof(msg), &sid, &flags))
		return -1;
	printf("[] Migration event (local=1)\n");

	if (recv_event_connection_migration(acceptfd, 0))
		return -1;
	flags = 0;
	if (recv_pass(acceptfd, msg, sizeof(msg), &sid, &flags))
		return -1;
	printf("[] Migration event (local=0)\n");

	event.type = QUIC_EVENT_CONNECTION_MIGRATION;
	event.on = 0;
	if (setopt_pass(acceptfd, QUIC_SOCKOPT_EVENT, &event, sizeof(event)))
		return -1;
	event.type = QUIC_EVENT_CONNECTION_MIGRATION;
	event.on = 0;
	if (setopt_pass(connectfd, QUIC_SOCKOPT_EVENT, &event, sizeof(event)))
		return -1;
	printf("[] Disabled connection-migration notifications\n");

	/* Key Update */
	event.type = QUIC_EVENT_KEY_UPDATE;
	event.on = 1;
	if (setopt_pass(acceptfd, QUIC_SOCKOPT_EVENT, &event, sizeof(event)))
		return -1;
	printf("[] Enabled key-update notifications\n");

	if (setopt_pass(connectfd, QUIC_SOCKOPT_KEY_UPDATE, NULL, 0))
		return -1;
	sid = -1;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (send_pass(connectfd, msg, strlen(msg), sid, flags))
		return -1;
	if (recv_event_key_update(acceptfd, 1))
		return -1;
	flags = 0;
	if (recv_pass(acceptfd, msg, sizeof(msg), &sid, &flags))
		return -1;
	printf("[] Key update phase=1\n");

	event.type = QUIC_EVENT_KEY_UPDATE;
	event.on = 0;
	if (setopt_pass(acceptfd, QUIC_SOCKOPT_EVENT, &event, sizeof(event)))
		return -1;
	printf("[] Disabled key-update notifications\n");

	/* New Token */
	event.type = QUIC_EVENT_NEW_TOKEN;
	event.on = 1;
	if (setopt_pass(connectfd, QUIC_SOCKOPT_EVENT, &event, sizeof(event)))
		return -1;
	printf("[] Enabled new-token notifications\n");

	if (setopt_pass(acceptfd, QUIC_SOCKOPT_TOKEN, NULL, 0))
		return -1;
	if (recv_event(connectfd, msg, sizeof(msg), QUIC_EVENT_NEW_TOKEN))
		return -1;
	printf("[] New token event\n");

	event.type = QUIC_EVENT_NEW_TOKEN;
	event.on = 0;
	if (setopt_pass(connectfd, QUIC_SOCKOPT_EVENT, &event, sizeof(event)))
		return -1;
	printf("[] Disabled new-token notifications\n");

	/* New Session Ticket */
	event.type = QUIC_EVENT_NEW_SESSION_TICKET;
	event.on = 1;
	if (setopt_pass(connectfd, QUIC_SOCKOPT_EVENT, &event, sizeof(event)))
		return -1;
	printf("[] Enabled new-session-ticket notifications\n");

	if (send_fake_ticket(acceptfd))
		return -1;
	if (recv_event(connectfd, msg, sizeof(msg), QUIC_EVENT_NEW_SESSION_TICKET))
		return -1;
	printf("[] New session ticket event\n");

	event.type = QUIC_EVENT_NEW_SESSION_TICKET;
	event.on = 0;
	if (setopt_pass(connectfd, QUIC_SOCKOPT_EVENT, &event, sizeof(event)))
		return -1;
	printf("[] Disabled new-session-ticket notifications\n");

	/* Connection ID */
	event.type = QUIC_EVENT_CONNECTION_ID;
	event.on = 1;
	if (setopt_pass(connectfd, QUIC_SOCKOPT_EVENT, &event, sizeof(event)))
		return -1;
	printf("[] Enabled connection-ID notifications\n");

	optlen = sizeof(cinfo);
	cinfo.prior_to = 0;
	cinfo.active = 0;
	cinfo.dest = 0;
	if (getopt_pass(connectfd, QUIC_SOCKOPT_CONNECTION_ID, &cinfo, &optlen))
		return -1;
	cinfo.prior_to++;
	cinfo.active = 0;
	cinfo.dest = 0;
	if (setopt_pass(connectfd, QUIC_SOCKOPT_CONNECTION_ID, &cinfo, optlen))
		return -1;
	if (recv_event_connection_id(connectfd, 0, cinfo.prior_to))
		return -1;
	printf("[] Connection-ID event (source)\n");

	optlen = sizeof(cinfo);
	cinfo.prior_to = 0;
	cinfo.active = 0;
	cinfo.dest = 1;
	if (getopt_pass(connectfd, QUIC_SOCKOPT_CONNECTION_ID, &cinfo, &optlen))
		return -1;
	cinfo.prior_to++;
	cinfo.active = 0;
	cinfo.dest = 1;
	if (setopt_pass(connectfd, QUIC_SOCKOPT_CONNECTION_ID, &cinfo, optlen))
		return -1;
	if (recv_event_connection_id(connectfd, 1, cinfo.prior_to))
		return -1;
	printf("[] Connection-ID event (dest)\n");

	event.type = QUIC_EVENT_CONNECTION_ID;
	event.on = 0;
	if (setopt_pass(connectfd, QUIC_SOCKOPT_EVENT, &event, sizeof(event)))
		return -1;
	printf("[] Disabled connection-ID notifications\n");

	/* Close: see test_close() */
	return 0;
}

static int test_close(int connectfd, int acceptfd)
{
	struct quic_connection_close *info;
	struct quic_event_option event;

	printf("=> Close Tests\n");

	event.type = QUIC_EVENT_CONNECTION_CLOSE;
	event.on = 1;
	if (setopt_pass(acceptfd, QUIC_SOCKOPT_EVENT, &event, sizeof(event)))
		return -1;
	printf("[] Close event enabled\n");

	info = (struct quic_connection_close *)msg;
	info->errcode = 10;
	info->frame = 1;
	snprintf((char *)info->phrase, sizeof(msg) - sizeof(*info), "this is app err");
	if (setopt_fail(acceptfd, QUIC_SOCKOPT_CONNECTION_CLOSE, info,
			sizeof(*info) + strlen((char *)info->phrase)))
		return -1;
	printf("[] Reject close info: phrase not null-terminated\n");

	info = (struct quic_connection_close *)msg;
	info->errcode = 10;
	info->frame = 1;
	if (setopt_fail(acceptfd, QUIC_SOCKOPT_CONNECTION_CLOSE, info, sizeof(*info) - 1))
		return -1;
	printf("[] Reject close info: buffer too small\n");

	info = (struct quic_connection_close *)msg;
	info->errcode = 10;
	info->frame = 1;
	snprintf((char *)info->phrase, sizeof(msg) - sizeof(*info), "this is app err");
	if (setopt_pass(connectfd, QUIC_SOCKOPT_CONNECTION_CLOSE, info,
			sizeof(*info) + strlen((char *)info->phrase) + 1))
		return -1;
	printf("[] Close info set on local socket\n");

	shutdown(connectfd, SHUT_WR);
	if (recv_event_connection_close(acceptfd, 10, 0, "this is app err"))
		return -1;
	printf("[] Close event received\n");

	if (getopt_connection_close(acceptfd, 10, 0, "this is app err"))
		return -1;
	printf("[] Close info read from peer\n");

	close(connectfd);
	close(acceptfd);
	return 0;
}

static int func_test(char *af)
{
	int acceptfd, connectfd;

	if (!strcmp(af, "6"))
		family = AF_INET6;

	if (test_handshake(&connectfd, &acceptfd))
		return -1;

	if (test_stream(connectfd, acceptfd))
		return -1;

	if (test_connection(connectfd, acceptfd))
		return -1;

	if (test_notification(connectfd, acceptfd))
		return -1;

	if (test_close(connectfd, acceptfd))
		return -1;

	close_sockets(connectfd, acceptfd);
	return 0;
}

static int server_handshake(int sockfd)
{
	if (recv_fake_handshake(sockfd, QUIC_CRYPTO_INITIAL, 1))
		return -1;
	if (set_fake_keys(sockfd, QUIC_CRYPTO_HANDSHAKE, 1))
		return -1;
	if (send_fake_handshake(sockfd, QUIC_CRYPTO_INITIAL, 1))
		return -1;
	if (send_fake_handshake(sockfd, QUIC_CRYPTO_HANDSHAKE, 1))
		return -1;
	if (recv_fake_handshake(sockfd, QUIC_CRYPTO_HANDSHAKE, 1))
		return -1;
	if (set_fake_keys(sockfd, QUIC_CRYPTO_APP, 1))
		return -1;
	if (early_data && send_fake_ticket(sockfd))
		return -1;
	return 0;
}

static int client_handshake(int sockfd)
{
	if (send_fake_handshake(sockfd, QUIC_CRYPTO_INITIAL, 0))
		return -1;
	if (recv_fake_handshake(sockfd, QUIC_CRYPTO_INITIAL, 0))
		return -1;
	if (set_fake_keys(sockfd, QUIC_CRYPTO_HANDSHAKE, 0))
		return -1;
	if (recv_fake_handshake(sockfd, QUIC_CRYPTO_HANDSHAKE, 0))
		return -1;
	if (set_fake_keys(sockfd, QUIC_CRYPTO_APP, 0))
		return -1;
	if (send_fake_handshake(sockfd, QUIC_CRYPTO_HANDSHAKE, 0))
		return -1;
	if (early_data)
		sleep(1); /* Wait for new session ticket msg */
	return 0;
}

static int get_new_fd(void)
{
	struct sockaddr_nl local = { .nl_family = AF_NETLINK };
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (fd < 0) {
		printf("socket: errno=%d\n", errno);
		return -1;
	}
	if (bind(fd, (struct sockaddr *)&local, sizeof(local))) {
		printf("bind: errno=%d\n", errno);
		return -1;
	}
	return fd;
}

static inline uint16_t nla_len(const struct nlattr *nla)
{
	return nla->nla_len - NLA_HDRLEN;
}

static void *nla_data(const struct nlattr *nla)
{
	return (char *)nla + NLA_HDRLEN;
}

static inline uint32_t nla_get_u32(const struct nlattr *nla)
{
	return *(uint32_t *)nla_data(nla);
}

static inline uint16_t nla_get_u16(const struct nlattr *nla)
{
	return *(uint16_t *)nla_data(nla);
}

static struct nlattr *nla_next(const struct nlattr *nla, int *remaining)
{
	unsigned int totlen = NLA_ALIGN(nla->nla_len);

	if (remaining)
		*remaining -= totlen;
	return (struct nlattr *)((char *) nla + totlen);
}

static void nla_put_u32(struct nlattr *nla, int type, uint32_t value)
{
	nla->nla_type = type;
	nla->nla_len  = NLA_HDRLEN + sizeof(uint32_t);
	*(uint32_t *)nla_data(nla) = value;
}

static void nla_put_data(struct nlattr *nla, int type, void *data, int len)
{
	nla->nla_type = type;
	nla->nla_len = NLA_HDRLEN + len;
	memcpy(nla_data(nla), data, len);
}

static int nlmsg_len(const struct nlmsghdr *nlh)
{
	return nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
}

static void *nlmsg_data(const struct nlmsghdr *nlh)
{
	struct genlmsghdr *ghdr = NLMSG_DATA(nlh);

	return (char *)ghdr + GENL_HDRLEN;
}

static void nlmsg_init(struct nlmsghdr *nlh, int family_id, int cmd)
{
	struct genlmsghdr *ghdr = NLMSG_DATA(nlh);

	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 1;
	ghdr->cmd = cmd;
}

#define nlh_for_each_attr(na, nlh, rem) \
	for (na = nlmsg_data(nlh), rem = nlmsg_len(nlh); \
			rem >= (int)NLA_HDRLEN; na = nla_next(na, &rem))

#define nla_for_each_attr(na, nla, rem) \
	for (na = nla_data(nla), rem = nla_len(nla); \
			rem >= (int)NLA_HDRLEN; na = nla_next(na, &rem))

static int get_group_and_family_id(int fd, int *family_id, int *group_id)
{
	struct nlattr *na, *g_na, *i_na, *n_na;
	struct nlmsghdr *nlh;
	int rem, g_rem;

	*family_id = 0;
	*group_id = 0;

	nlh = (struct nlmsghdr *)buf;
	nlmsg_init(nlh, GENL_ID_CTRL, CTRL_CMD_GETFAMILY);
	na = nlmsg_data(nlh);
	nla_put_data(na, CTRL_ATTR_FAMILY_NAME, HANDSHAKE_FAMILY_NAME,
		     strlen(HANDSHAKE_FAMILY_NAME) + 1);
	nlh->nlmsg_len += na->nla_len;

	if (send(fd, buf, nlh->nlmsg_len, 0) < 0) {
		printf("send: errno=%d\n", errno);
		return -1;
	}
	if (recv(fd, buf, sizeof(buf), 0) < 0) {
		printf("recv: errno=%d\n", errno);
		return -1;
	}

	nlh_for_each_attr(na, nlh, rem) {
		if (na->nla_type == CTRL_ATTR_FAMILY_ID)
			*family_id = nla_get_u16(na);

		if (na->nla_type == CTRL_ATTR_MCAST_GROUPS) {
			nla_for_each_attr(g_na, na, g_rem) {
				i_na = nla_data(g_na);
				n_na = nla_next(i_na, NULL);
				if (!strcmp(nla_data(n_na), HANDSHAKE_MCGRP_TLSHD))
					*group_id = nla_get_u32(i_na);
			}
		}
	}

	return (*family_id && *group_id) ? 0 : -1;
}

static int get_accept_fd(int fd, int family_id, int *type)
{
	struct nlmsghdr *nlh;
	int rem, sockfd = -1;
	struct nlattr *na;

	nlh = (struct nlmsghdr *)buf;
	nlmsg_init(nlh, family_id, HANDSHAKE_CMD_ACCEPT);
	na = nlmsg_data(nlh);
	nla_put_u32(na, HANDSHAKE_A_ACCEPT_HANDLER_CLASS, HANDSHAKE_HANDLER_CLASS_TLSHD);
	nlh->nlmsg_len += na->nla_len;

	if (send(fd, buf, nlh->nlmsg_len, 0) < 0) {
		printf("send: errno=%d\n", errno);
		return -1;
	}
	if (recv(fd, buf, sizeof(buf), 0) < 0) {
		printf("recv: errno=%d\n", errno);
		return -1;
	}

	nlh_for_each_attr(na, nlh, rem) {
		if (na->nla_type == HANDSHAKE_A_ACCEPT_SOCKFD)
			sockfd = nla_get_u32(na);
		if (na->nla_type == HANDSHAKE_A_ACCEPT_MESSAGE_TYPE)
			*type = nla_get_u32(na);
	}
	return sockfd;
}

static int put_accept_fd(int fd, int family_id, int sockfd, int ret)
{
	struct nlmsghdr *nlh;
	struct nlattr *na;

	nlh = (struct nlmsghdr *)buf;
	nlmsg_init(nlh, family_id, HANDSHAKE_CMD_DONE);
	na = nlmsg_data(nlh);
	nla_put_u32(na, HANDSHAKE_A_DONE_STATUS, ret);
	nlh->nlmsg_len += na->nla_len;

	na = nla_next(na, NULL);
	nla_put_u32(na, HANDSHAKE_A_DONE_SOCKFD, sockfd);
	nlh->nlmsg_len += na->nla_len;

	if (send(fd, buf, nlh->nlmsg_len, 0) < 0) {
		printf("send: errno=%d\n", errno);
		return -1;
	}
	close(sockfd);
	return 0;
}

static void handle_msg(struct nlmsghdr *nlh, int family_id)
{
	int fd, sockfd, rem, ret, type = 0;
	struct nlattr *na;

	nlh_for_each_attr(na, nlh, rem) {
		if (na->nla_type == HANDSHAKE_A_ACCEPT_HANDLER_CLASS &&
		    nla_get_u32(na) == HANDSHAKE_HANDLER_CLASS_TLSHD) {
			fd = get_new_fd();
			if (fd < 0)
				return;
			sockfd = get_accept_fd(fd, family_id, &type);
			if (sockfd < 0)
				return;
			if (type == HANDSHAKE_MSG_TYPE_SERVERHELLO)
				ret = server_handshake(sockfd);
			else
				ret = client_handshake(sockfd);
			if (put_accept_fd(fd, family_id, sockfd, ret))
				return;
			close(fd);
		}
	}
}

static int fake_tlshd(char *backlog)
{
	int fd, family_id, group_id, i, bl = 1024;
	ssize_t len;

	if (backlog) {
		bl = atoi(backlog);
		if (!bl) {
			printf(" ... [backlog]\n");
			return -1;
		}
	}

	fd = get_new_fd();
	if (fd < 0)
		return -1;
	if (get_group_and_family_id(fd, &family_id, &group_id))
		return -1;
	if (setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group_id, sizeof(group_id))) {
		printf("setsockopt: NETLINK_ADD_MEMBERSHIP errno=%d\n", errno);
		return -1;
	}
	for (i = 0; i < bl; i++) {
		len = recv(fd, buf, sizeof(buf), 0);
		if (len < 0) {
			printf("recv: errno=%d", errno);
			break;
		}
		handle_msg((struct nlmsghdr *)buf, family_id);
	}
	close(fd);
	return 0;
}

static int ticket_server(void)
{
	int listenfd, sockfd;
	uint32_t flags;
	char msg[64];
	int64_t sid;

	listenfd = create_listen_socket(NULL);
	if (listenfd < 0)
		return -1;

	sockfd = accept(listenfd, NULL, NULL);
	if (sockfd < 0) {
		printf("accept: errno=%d\n", errno);
		return -1;
	}

	if (server_handshake(sockfd))
		return -1;

	flags = 0;
	memset(msg, 0, sizeof(msg));
	if (recv_pass(sockfd, msg, sizeof(msg) - 1, &sid, &flags))
		return -1;
	printf("[] recv '%s' on stream %d\n", msg, (int)sid);

	snprintf(msg, sizeof(msg), "hello quic client!");
	sid = QUIC_STREAM_TYPE_SERVER_MASK;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (send_pass(sockfd, msg, strlen(msg), sid, flags))
		return -1;
	printf("[] send '%s' on stream %d\n", msg, (int)sid);

	flags = 0;
	if (recv_fail(sockfd, msg, sizeof(msg) - 1, &sid, &flags))
		return -1;

	close(sockfd);

	sockfd = accept(listenfd, NULL, NULL);
	if (sockfd < 0) {
		printf("accept: errno=%d\n", errno);
		return -1;
	}

	if (server_handshake(sockfd))
		return -1;

	flags = 0;
	memset(msg, 0, sizeof(msg));
	if (recv_pass(sockfd, msg, sizeof(msg) - 1, &sid, &flags))
		return -1;
	printf("[] recv '%s' on stream %d\n", msg, (int)sid);

	snprintf(msg, sizeof(msg), "hello quic client!");
	sid = QUIC_STREAM_TYPE_SERVER_MASK;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (send_pass(sockfd, msg, strlen(msg), sid, flags))
		return -1;
	printf("[] send '%s' on stream %d\n", msg, (int)sid);

	flags = 0;
	if (recv_fail(sockfd, msg, sizeof(msg) - 1, &sid, &flags))
		return -1;

	close(sockfd);
	close(listenfd);
	return 0;
}

static int ticket_client(void)
{
	struct quic_transport_param param = {};
	unsigned int ticket_len, param_len;
	char msg[64], ticket[256];
	uint32_t flags;
	int64_t sid;
	int sockfd;

	sockfd = create_connect_socket();
	if (sockfd < 0)
		return -1;

	if (client_handshake(sockfd))
		return -1;

	sleep(1); /* Wait for new session ticket msg */
	ticket_len = sizeof(ticket);
	if (getopt_pass(sockfd, QUIC_SOCKOPT_SESSION_TICKET, ticket, &ticket_len))
		return -1;

	param_len = sizeof(param);
	param.remote = 1;
	if (getopt_pass(sockfd, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, &param_len))
		return -1;

	printf("[] get the session ticket %u and transport param %u, save it\n",
	       ticket_len, param_len);

	snprintf(msg, sizeof(msg), "hello quic server!");
	sid = QUIC_STREAM_TYPE_UNI_MASK;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (send_pass(sockfd, msg, strlen(msg), sid, flags))
		return -1;
	printf("[] send '%s' on stream %d\n", msg, (int)sid);

	flags = 0;
	memset(msg, 0, sizeof(msg));
	if (recv_pass(sockfd, msg, sizeof(msg) - 1, &sid, &flags))
		return -1;
	printf("[] recv '%s' on stream %d\n", msg, (int)sid);

	close(sockfd);
	sleep(1);
	printf("[] start new connection with the session ticket used...\n");

	sockfd = create_connect_socket();
	if (sockfd < 0)
		return -1;

	if (setopt_pass(sockfd, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, param_len))
		return -1;

	snprintf(msg, sizeof(msg), "hello quic server, I'm back!");
	sid = QUIC_STREAM_TYPE_UNI_MASK;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (send_pass(sockfd, msg, strlen(msg), sid, flags))
		return -1;
	printf("[] send '%s' on stream %d\n", msg, (int)sid);

	if (client_handshake(sockfd))
		return -1;

	flags = 0;
	memset(msg, 0, sizeof(msg));
	if (recv_pass(sockfd, msg, sizeof(msg) - 1, &sid, &flags))
		return -1;
	printf("[] recv '%s' on stream %d\n", msg, (int)sid);

	close(sockfd);
	sleep(1);
	return 0;
}

static int sample_server(void)
{
	int listenfd, sockfd;
	uint32_t flags;
	char msg[64];
	int64_t sid;

	listenfd = create_listen_socket(NULL);
	if (listenfd < 0)
		return -1;

	sockfd = accept(listenfd, NULL, NULL);
	if (sockfd < 0) {
		printf("accept: errno=%d\n", errno);
		return -1;
	}

	if (server_handshake(sockfd))
		return -1;

	flags = 0;
	memset(msg, 0, sizeof(msg));
	if (recv_pass(sockfd, msg, sizeof(msg) - 1, &sid, &flags))
		return -1;
	printf("[] recv '%s' on stream %d\n", msg, (int)sid);

	snprintf(msg, sizeof(msg), "hello quic client!");
	sid = QUIC_STREAM_TYPE_SERVER_MASK;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (send_pass(sockfd, msg, strlen(msg), sid, flags))
		return -1;
	printf("[] send '%s' on stream %d\n", msg, (int)sid);

	flags = 0;
	if (recv_fail(sockfd, msg, sizeof(msg) - 1, &sid, &flags))
		return -1;

	close(sockfd);
	close(listenfd);
	return 0;
}

static int sample_client(void)
{
	uint32_t flags;
	char msg[64];
	int64_t sid;
	int sockfd;

	sockfd = create_connect_socket();
	if (sockfd < 0)
		return -1;

	if (client_handshake(sockfd))
		return -1;

	snprintf(msg, sizeof(msg), "hello quic server!");
	sid = QUIC_STREAM_TYPE_UNI_MASK;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (send_pass(sockfd, msg, strlen(msg), sid, flags))
		return -1;
	printf("[] send '%s' on stream %d\n", msg, (int)sid);

	flags = 0;
	memset(msg, 0, sizeof(msg));
	if (recv_pass(sockfd, msg, sizeof(msg) - 1, &sid, &flags))
		return -1;
	printf("[] recv '%s' on stream %d\n", msg, (int)sid);

	close(sockfd);
	sleep(1);
	return 0;
}

static int sample_test(char *af, char *role)
{
	if (!strcmp(af, "6"))
		family = AF_INET6;

	if (!role)
		goto err;

	if (!strcmp(role, "server"))
		return early_data ? ticket_server() : sample_server();

	if (!strcmp(role, "client"))
		return early_data ? ticket_client() : sample_client();

err:
	printf(" ... <4 | 6> <server | client>\n");
	return -1;
}

static int perf_server(int size)
{
	int listenfd, sockfd, ret, len = 0;
	uint32_t flags;
	int64_t sid;

	listenfd = create_listen_socket(NULL);
	if (listenfd < 0)
		return -1;

	sockfd = accept(listenfd, NULL, NULL);
	if (sockfd < 0) {
		printf("accept: errno=%d\n", errno);
		return -1;
	}

	if (server_handshake(sockfd))
		return -1;

	while (1) {
		flags = 0;
		ret = recv_msg(sockfd, buf, sizeof(buf) - 1, &sid, &flags);
		if (ret < 0) {
			printf("recv_msg: errno=%d len=%d\n", errno, len);
			return -1;
		}
		len += ret;
		if (flags & MSG_QUIC_STREAM_FIN)
			break;
	}
	if (len != size * 1024) {
		printf("%s: size=%d-%d\n", __func__, size * 1024, len);
		return -1;
	}
	printf("[] recv %dK on stream %d\n", size, (int)sid);

	sid = QUIC_STREAM_TYPE_SERVER_MASK;
	flags = MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN;
	if (send_pass(sockfd, msg, sizeof(msg), sid, flags))
		return -1;
	printf("[] recv it on stream %d\n", (int)sid);

	flags = 0;
	if (recv_fail(sockfd, msg, sizeof(msg), &sid, &flags))
		return -1;

	close(sockfd);
	close(listenfd);
	return 0;
}

static int perf_client(int size)
{
	int sockfd, ret, i;
	uint32_t flags;
	int64_t sid;

	sockfd = create_connect_socket();
	if (sockfd < 0)
		return -1;

	if (client_handshake(sockfd))
		return -1;

	sid = QUIC_STREAM_TYPE_UNI_MASK;
	for (i = 0; i < 1024; i++) {
		if (i == 0)
			flags = MSG_QUIC_STREAM_NEW;
		else if (i == 1023)
			flags = MSG_QUIC_STREAM_FIN;
		else
			flags = 0;
		ret = send_msg(sockfd, buf, size, sid, flags);
		if (ret != size) {
			printf("send_msg: errno=%d len=%d\n", errno, ret);
			return -1;
		}
	}
	printf("[] send %dK bytes on stream %d\n", size, (int)sid);

	flags = 0;
	if (recv_pass(sockfd, msg, sizeof(msg), &sid, &flags))
		return -1;
	printf("[] recv it by peer on stream %d\n", (int)sid);

	close(sockfd);
	sleep(1);
	return 0;
}

static int perf_test(char *af, char *role, char *msg_size)
{
	int size;

	if (!strcmp(af, "6"))
		family = AF_INET6;

	if (!role || !msg_size)
		goto err;

	size = atoi(msg_size);
	if (!size || size > 65536)
		goto err;

	if (!strcmp(role, "server"))
		return perf_server(size);

	if (!strcmp(role, "client"))
		return perf_client(size);
err:
	printf(" ... <4 | 6> <server | client> [msg_size]\n");
	return -1;
}

int main(int argc, char *argv[])
{
	if (argc < 3)
		goto err;

	if (!strcmp(argv[1], "func"))
		return func_test(argv[2]);

	if (!strcmp(argv[1], "perf"))
		return perf_test(argv[2], argv[3], argv[4]);

	if (!strcmp(argv[1], "sample"))
		return sample_test(argv[2], argv[3]);

	if (!strcmp(argv[1], "ticket")) {
		early_data = 1;
		return sample_test(argv[2], argv[3]);
	}

	if (!strcmp(argv[1], "tlshd"))
		return fake_tlshd(argv[2]);

err:
	printf("%s <func | perf | sample | ticket | tlshd>\n", argv[0]);
	return -1;
}
