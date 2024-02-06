// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is the userspace handshake part for the QUIC kernel implementation
 *
 * Initialization/cleanup for QUIC protocol support.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include "connection.h"

static int read_psk_file(char *psk, char *identity[], gnutls_datum_t *pkey)
{
	unsigned char *end, *key, *buf;
	int fd, err = -1, i = 0;
	struct stat statbuf;
	gnutls_datum_t gkey;
	unsigned int size;

	fd = open(psk, O_RDONLY);
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

static int read_datum(const char *file, gnutls_datum_t *data)
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

static int read_pkey_file(char *file, gnutls_privkey_t *privkey)
{
	gnutls_datum_t data;
	int ret;

	if (read_datum(file, &data))
		return -1;

	ret = gnutls_privkey_init(privkey);
	if (ret)
		goto out;

	ret = gnutls_privkey_import_x509_raw(*privkey, &data, GNUTLS_X509_FMT_PEM, NULL, 0);
out:
        free(data.data);
	return ret;
}

static int read_cert_file(char *file, gnutls_pcert_st **cert)
{
	gnutls_datum_t data;
	int ret;

	if (read_datum(file, &data))
		return -1;

	ret = gnutls_pcert_import_x509_raw(*cert, &data, GNUTLS_X509_FMT_PEM, 0);
	free(data.data);

	return ret;
}

static void timer_handler(union sigval arg)
{
	struct quic_conn *conn = arg.sival_ptr;

	conn->errcode = ETIMEDOUT;
}

static int set_nonblocking(int sockfd, uint8_t nonblocking)
{
	int flags = fcntl(sockfd, F_GETFL, 0);

	if (flags == -1) {
		print_error("fcntl");
		return -1;
	}

	if (nonblocking)
		flags |= O_NONBLOCK;
	else
		flags &= ~O_NONBLOCK;

	if (fcntl(sockfd, F_SETFL, flags) == -1) {
		print_error("fcntl");
		return -1;
	}
	return 0;
}

static int setup_timer(struct quic_conn *conn)
{
	uint64_t msec = conn->parms->timeout;
	struct itimerspec its = {};
	struct sigevent sev = {};

	if (set_nonblocking(conn->sockfd, 1))
		return -1;

	sev.sigev_notify = SIGEV_THREAD;
	sev.sigev_notify_function = timer_handler;
	sev.sigev_value.sival_ptr = conn;
	timer_create(CLOCK_REALTIME, &sev, &conn->timer);

	its.it_value.tv_sec  = msec / 1000;
	its.it_value.tv_nsec = (msec % 1000) * 1000000;
	timer_settime(conn->timer, 0, &its, NULL);
	return 0;
}

static int delete_timer(struct quic_conn *conn)
{
	set_nonblocking(conn->sockfd, 0);
	timer_delete(conn->timer);
	return 0;
}

static int get_transport_param(struct quic_conn *conn)
{
	struct quic_transport_param param = {};
	int sockfd = conn->sockfd;
	unsigned int len;

	len = sizeof(conn->alpn.data);
	if (getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_ALPN, conn->alpn.data, &len)) {
		print_error("socket getsockopt alpn failed\n");
		return -1;
	}
	conn->alpn.datalen = len;
	len = sizeof(conn->ticket.buf);
	if (getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_SESSION_TICKET, conn->ticket.buf, &len)) {
		printf("socket getsockopt session ticket failed\n");
		return -1;
	}
	conn->ticket.buflen = len;
	len = sizeof(param);
	if (getsockopt(sockfd, SOL_QUIC, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, &len)) {
		printf("socket getsockopt transport param failed\n");
		return -1;
	}
	conn->recv_ticket = param.receive_session_ticket;
	conn->cert_req = param.certificate_request;
	conn->cipher = param.payload_cipher_type;
	conn->sockfd = sockfd;
	return 0;
}

static int quic_conn_destroy(struct quic_conn *conn)
{
	struct quic_frame *frame = conn->send_list;
	int ret;

	while (frame) {
		conn->send_list = frame->next;
		free(frame);
		frame = conn->send_list;
	}
	delete_timer(conn);
	gnutls_deinit(conn->session);
	ret = conn->errcode;
	free(conn);
	return -ret;
}

static struct quic_conn *quic_conn_create(int sockfd, struct quic_handshake_parms *parms, uint8_t server)
{
	struct quic_conn *conn;

	conn = malloc(sizeof(*conn));
	if (!conn)
		return NULL;

	memset(conn, 0, sizeof(*conn));
	conn->parms = parms;
	conn->sockfd = sockfd;

	if (get_transport_param(conn))
		goto err;

	if (setup_timer(conn))
		goto err;

	return conn;
err:
	quic_conn_destroy(conn);
	return NULL;
}

static int quic_conn_sendmsg(int sockfd, struct quic_frame *frame)
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
	iov.iov_base = (void *)frame->data.buf;
	iov.iov_len = frame->data.buflen;
	outmsg.msg_iovlen = 1;

	outmsg.msg_control = outcmsg;
	outmsg.msg_controllen = sizeof(outcmsg);
	outmsg.msg_flags = 0;
	if (frame->next)
		flags = MSG_MORE;

	cmsg = CMSG_FIRSTHDR(&outmsg);
	cmsg->cmsg_level = IPPROTO_QUIC;
	cmsg->cmsg_type = QUIC_HANDSHAKE_INFO;
	cmsg->cmsg_len = CMSG_LEN(sizeof(*info));

	info = (struct quic_handshake_info *)CMSG_DATA(cmsg);
	info->crypto_level = frame->level;

	return sendmsg(sockfd, &outmsg, flags);
}

static int quic_conn_recvmsg(int sockfd, struct quic_frame *frame)
{
	char incmsg[CMSG_SPACE(sizeof(struct quic_handshake_info))];
	struct quic_handshake_info info;
	struct cmsghdr *cmsg = NULL;
	struct msghdr inmsg;
	struct iovec iov;
	int error;

	frame->data.buflen = 0;
	memset(&inmsg, 0, sizeof(inmsg));

	iov.iov_base = frame->data.buf;
	iov.iov_len = sizeof(frame->data.buf);

	inmsg.msg_name = NULL;
	inmsg.msg_namelen = 0;
	inmsg.msg_iov = &iov;
	inmsg.msg_iovlen = 1;
	inmsg.msg_control = incmsg;
	inmsg.msg_controllen = sizeof(incmsg);

	error = recvmsg(sockfd, &inmsg, 0);
	if (error < 0)
		return error;
	frame->data.buflen = error;

	for (cmsg = CMSG_FIRSTHDR(&inmsg); cmsg != NULL; cmsg = CMSG_NXTHDR(&inmsg, cmsg))
		if (IPPROTO_QUIC == cmsg->cmsg_level && QUIC_HANDSHAKE_INFO == cmsg->cmsg_type)
			break;
	if (cmsg) {
		memcpy(&info, CMSG_DATA(cmsg), sizeof(info));
		frame->level = info.crypto_level;
	}

	return error;
}

static void quic_conn_do_handshake(struct quic_conn *conn)
{
	int ret, sockfd = conn->sockfd;
	struct timeval tv = {1, 0};
	struct quic_frame *frame;
	fd_set readfds;

	FD_ZERO(&readfds);
	FD_SET(sockfd, &readfds);

	while (!quic_conn_handshake_completed(conn)) {
		ret = select(sockfd + 1, &readfds, NULL,  NULL, &tv);
		if (ret < 0) {
			conn->errcode = errno;
			return;
		}
		frame = &conn->frame;
		while (!quic_conn_handshake_completed(conn)) {
			ret = quic_conn_recvmsg(sockfd, frame);
			if (ret <= 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					break;
				conn->errcode = errno;
				return;
			}
			print_debug("v %s RECV: %d %d\n", __func__, frame->data.buflen, frame->level);
			ret = quic_crypto_read_write_crypto_data(conn, frame->level, frame->data.buf,
								 frame->data.buflen);
			if (ret) {
				conn->errcode = -ret;
				return;
			}
		}

		frame = conn->send_list;
		while (frame) {
			print_debug("^ %s SEND: %d %d\n", __func__, frame->data.buflen, frame->level);
			ret = quic_conn_sendmsg(sockfd, frame);
			if (ret < 0) {
				conn->errcode = errno;
				return;
			}
			conn->send_list = frame->next;
			free(frame);
			frame = conn->send_list;
		}
	}
}

/**
 * quic_client_handshake_parms - start a QUIC handshake with Certificate or PSK mode from client side
 * @sockfd: IPPROTO_QUIC type socket
 * @parms: parameters for handshake, see struct quic_handshake_parms
 *
 * Return values:
 * - On success, 0.
 * - On error, the error is returned.
 */
int quic_client_handshake_parms(int sockfd, struct quic_handshake_parms *parms)
{
	struct quic_frame *frame;
	struct quic_conn *conn;
	int ret, level;

	conn = quic_conn_create(sockfd, parms, 0);
	if (!conn)
		return -ENOMEM;

	ret = parms->num_keys ? quic_crypto_client_set_psk_session(conn)
			      : quic_crypto_client_set_x509_session(conn);
	if (ret) {
		conn->errcode = -ret;
		goto out;
	}

	level = QUIC_CRYPTO_INITIAL;
	ret = quic_crypto_read_write_crypto_data(conn, level, NULL, 0);
	if (ret) {
		conn->errcode = -ret;
		goto out;
	}

	frame = conn->send_list;
	while (frame) {
		print_debug("^ %s SEND: %d %d\n", __func__, frame->data.buflen, frame->level);
		ret = quic_conn_sendmsg(sockfd, frame);
		if (ret < 0) {
			conn->errcode = errno;
			goto out;
		}
		conn->send_list = frame->next;
		free(frame);
		frame = conn->send_list;
	}

	quic_conn_do_handshake(conn);
out:
	return quic_conn_destroy(conn);
}

/**
 * quic_server_handshake_parms - start a QUIC handshake with Certificate or PSK mode from server side
 * @sockfd: IPPROTO_QUIC type socket
 * @parms: parameters for handshake, see struct quic_handshake_parms
 *
 * Return values:
 * - On success, 0.
 * - On error, the error is returned.
 */
int quic_server_handshake_parms(int sockfd, struct quic_handshake_parms *parms)
{
	struct quic_conn *conn;
	int ret;

	conn = quic_conn_create(sockfd, parms, 1);
	if (!conn)
		return -ENOMEM;

	ret = parms->num_keys ? quic_crypto_server_set_psk_session(conn)
			      : quic_crypto_server_set_x509_session(conn);
	if (ret) {
		conn->errcode = -ret;
		goto out;
	}

	quic_conn_do_handshake(conn);
out:
	return quic_conn_destroy(conn);
}

/**
 * quic_client_handshake - start a QUIC handshake with Certificate or PSK mode from client side
 * @sockfd: IPPROTO_QUIC type socket
 * @pkey_file: private key file (optional) or pre-shared key file
 * @cert_file: certificate file (optional) or null
 *
 * Return values:
 * - On success, 0.
 * - On error, the error is returned.
 */
int quic_client_handshake(int sockfd, char *pkey_file, char *cert_file)
{
	struct quic_handshake_parms parms = {};
	gnutls_pcert_st gcert;
	int ret;

	parms.timeout = 15000;
	if (!cert_file) {
		if (!pkey_file)
			goto start;
		ret = read_psk_file(pkey_file, parms.names, parms.keys);
		if (ret <= 0) {
			print_error("parse psk file failed\n");
			return -1;
		}
		parms.num_keys = ret;
		goto start;
	}

	parms.cert = &gcert;
	if (read_pkey_file(pkey_file, &parms.privkey) ||
	    read_cert_file(cert_file, &parms.cert)) {
		print_error("parse prikey or cert files failed\n");
		return -1;
	}
start:
	return quic_client_handshake_parms(sockfd, &parms);
}

/**
 * quic_server_handshake - start a QUIC handshake with Certificate or PSK mode from server side
 * @sockfd: IPPROTO_QUIC type socket
 * @pkey: private key file or pre-shared key file
 * @cert: certificate file or null
 *
 * Return values:
 * - On success, 0.
 * - On error, the error is returned.
 */
int quic_server_handshake(int sockfd, char *pkey_file, char *cert_file)
{
	struct quic_handshake_parms parms = {};
	gnutls_pcert_st gcert;
	int ret;

	parms.timeout = 15000;
	if (!cert_file) {
		ret = read_psk_file(pkey_file, parms.names, parms.keys);
		if (ret <= 0) {
			print_error("parse psk file failed\n");
			return -1;
		}
		parms.num_keys = ret;
		goto start;
	}

	parms.cert = &gcert;
	if (read_pkey_file(pkey_file, &parms.privkey) ||
	    read_cert_file(cert_file, &parms.cert)) {
		print_error("parse prikey or cert files failed\n");
		return -1;
	}
start:
	return quic_server_handshake_parms(sockfd, &parms);
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
 * - On success, the number of bytes received.
 * - On error, -1 is returned, and errno is set to indicate the error.
 */
int quic_recvmsg(int sockfd, void *msg, size_t len, uint64_t *sid, uint32_t *flag)
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

	error = recvmsg(sockfd, &inmsg, 0);
	if (error < 0)
		return error;

	if (!sid)
		return error;

	for (cmsg = CMSG_FIRSTHDR(&inmsg); cmsg != NULL; cmsg = CMSG_NXTHDR(&inmsg, cmsg))
		if (IPPROTO_QUIC == cmsg->cmsg_level && QUIC_STREAM_INFO == cmsg->cmsg_type)
			break;
	if (cmsg) {
		memcpy(&info, CMSG_DATA(cmsg), sizeof(struct quic_stream_info));
		*sid = info.stream_id;
		*flag = info.stream_flag;
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
 * - On success, return the number of bytes sent.
 * - On error, -1 is returned, and errno is set to indicate the error.
 */
int quic_sendmsg(int sockfd, const void *msg, size_t len, uint64_t sid, uint32_t flag)
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
	outmsg.msg_flags = 0;

	cmsg = CMSG_FIRSTHDR(&outmsg);
	cmsg->cmsg_level = IPPROTO_QUIC;
	cmsg->cmsg_type = 0;
	cmsg->cmsg_len = CMSG_LEN(sizeof(*info));

	outmsg.msg_controllen = cmsg->cmsg_len;
	info = (struct quic_stream_info *)CMSG_DATA(cmsg);
	info->stream_id = sid;
	info->stream_flag = flag;

	return sendmsg(sockfd, &outmsg, 0);
}
