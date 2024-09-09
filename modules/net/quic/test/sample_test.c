// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is kernel test of the QUIC kernel implementation
 *
 * Initialization/cleanup for QUIC protocol support.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include <linux/completion.h>
#include <linux/module.h>
#include <linux/socket.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/quic.h>
#include <linux/inet.h>
#include <linux/net.h>
#include <linux/key.h>

#include <net/handshake.h>
#include <net/sock.h>

#define ROLE_LEN	10
#define IP_LEN		20
#define ALPN_LEN	20

static char role[ROLE_LEN] = "client";
static char alpn[ALPN_LEN] = "sample";
static char ip[IP_LEN] = "127.0.0.1";
static int port = 1234;
static int psk;

static u8 session_data[4096];
static u8 token[256];

static int quic_test_recvmsg(struct socket *sock, void *msg, int len, s64 *sid, int *flags)
{
	char incmsg[CMSG_SPACE(sizeof(struct quic_stream_info))];
	struct quic_stream_info *rinfo = CMSG_DATA(incmsg);
	struct msghdr inmsg;
	struct kvec iov;
	int error;

	iov.iov_base = msg;
	iov.iov_len = len;

	memset(&inmsg, 0, sizeof(inmsg));
	inmsg.msg_control = incmsg;
	inmsg.msg_controllen = sizeof(incmsg);

	error = kernel_recvmsg(sock, &inmsg, &iov, 1, len, *flags);
	if (error < 0)
		return error;

	if (!sid)
		return error;

	*sid = rinfo->stream_id;
	*flags = rinfo->stream_flags | inmsg.msg_flags;
	return error;
}

static int quic_test_sendmsg(struct socket *sock, const void *msg, int len, s64 sid, int flags)
{
	char outcmsg[CMSG_SPACE(sizeof(struct quic_stream_info))];
	struct quic_stream_info *sinfo;
	struct msghdr outmsg;
	struct cmsghdr *cmsg;
	struct kvec iov;

	iov.iov_base = (void *)msg;
	iov.iov_len = len;

	memset(&outmsg, 0, sizeof(outmsg));
	outmsg.msg_control = outcmsg;
	outmsg.msg_controllen = sizeof(outcmsg);
	outmsg.msg_flags = flags;

	cmsg = CMSG_FIRSTHDR(&outmsg);
	cmsg->cmsg_level = IPPROTO_QUIC;
	cmsg->cmsg_type = 0;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct quic_stream_info));

	outmsg.msg_controllen = cmsg->cmsg_len;
	sinfo = (struct quic_stream_info *)CMSG_DATA(cmsg);
	memset(sinfo, 0, sizeof(struct quic_stream_info));
	sinfo->stream_id = sid;
	sinfo->stream_flags = flags;

	return kernel_sendmsg(sock, &outmsg, &iov, 1, len);
}

struct quic_test_priv {
	struct completion sk_handshake_done;
	struct file *filp;
	int status;
};

static void quic_test_handshake_done(void *data, int status, key_serial_t peerid)
{
	struct quic_test_priv *priv = data;

	priv->status = status;
	complete_all(&priv->sk_handshake_done);
}

static int quic_test_client_handshake(struct socket *sock, struct quic_test_priv *priv)
{
	struct tls_handshake_args args = {};
	int err;

	init_completion(&priv->sk_handshake_done);

	args.ta_sock = sock;
	args.ta_done = quic_test_handshake_done;
	args.ta_data = priv;
	args.ta_timeout_ms = 3000;

	if (psk) {
		args.ta_my_peerids[0] = psk;
		args.ta_num_peerids = 1;
		err = tls_client_hello_psk(&args, GFP_KERNEL);
		if (err)
			return err;
		goto wait;
	}

	args.ta_peername = "server.test";
	err = tls_client_hello_x509(&args, GFP_KERNEL);
	if (err)
		return err;
wait:
	err = wait_for_completion_interruptible_timeout(&priv->sk_handshake_done, 5 * HZ);
	if (err <= 0) {
		tls_handshake_cancel(sock->sk);
		return -EINVAL;
	}
	return priv->status;
}

static int quic_test_server_handshake(struct socket *sock, struct quic_test_priv *priv)
{
	struct tls_handshake_args args = {};
	int err;

	init_completion(&priv->sk_handshake_done);

	args.ta_sock = sock;
	args.ta_done = quic_test_handshake_done;
	args.ta_data = priv;
	args.ta_timeout_ms = 3000;

	if (psk) {
		err = tls_server_hello_psk(&args, GFP_KERNEL);
		if (err)
			return err;
		goto wait;
	}

	err = tls_server_hello_x509(&args, GFP_KERNEL);
	if (err)
		return err;
wait:
	err = wait_for_completion_interruptible_timeout(&priv->sk_handshake_done, 5 * HZ);
	if (err <= 0) {
		tls_handshake_cancel(sock->sk);
		return -EINVAL;
	}
	return priv->status;
}

static int quic_test_do_ticket_client(void)
{
	unsigned int param_len, token_len, ticket_len;
	struct quic_transport_param param = {};
	struct sockaddr_in ra = {}, la = {};
	struct quic_test_priv priv = {};
	struct quic_config config = {};
	struct socket *sock;
	int err, flags = 0;
	char msg[64];
	s64 sid;

	err = __sock_create(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_QUIC, &sock, 1);
	if (err < 0)
		return err;
	priv.filp = sock_alloc_file(sock, 0, NULL);
	if (IS_ERR(priv.filp))
		return PTR_ERR(priv.filp);
	err = quic_sock_setopt(sock->sk, QUIC_SOCKOPT_ALPN, alpn, strlen(alpn));
	if (err)
		goto free;

	config.receive_session_ticket = 1;
	err = quic_sock_setopt(sock->sk, QUIC_SOCKOPT_CONFIG, &config, sizeof(config));
	if (err)
		goto free;

	ra.sin_family = AF_INET;
	ra.sin_port = htons((u16)port);
	if (!in4_pton(ip, strlen(ip), (u8 *)&ra.sin_addr.s_addr, -1, NULL))
		goto free;
	err = kernel_connect(sock, (struct sockaddr *)&ra, sizeof(ra), 0);
	if (err < 0)
		goto free;

	err = quic_test_client_handshake(sock, &priv);
	if (err < 0)
		goto free;

	pr_info("quic_test: handshake completed\n");

	ticket_len = sizeof(session_data);
	err = quic_sock_getopt(sock->sk, QUIC_SOCKOPT_SESSION_TICKET, session_data, &ticket_len);
	if (err < 0)
		goto free;

	param_len = sizeof(param);
	param.remote = 1;
	err = quic_sock_getopt(sock->sk, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, &param_len);
	if (err < 0)
		goto free;

	token_len = sizeof(token);
	err = quic_sock_getopt(sock->sk, QUIC_SOCKOPT_TOKEN, token, &token_len);
	if (err < 0)
		goto free;

	err = kernel_getsockname(sock, (struct sockaddr *)&la);
	if (err < 0)
		goto free;

	pr_info("quic_test: save session ticket: %d, transport param %d, token %d for session resumption\n",
		ticket_len, param_len, token_len);

	strscpy(msg, "hello quic server!", sizeof(msg));
	sid = (0 | QUIC_STREAM_TYPE_UNI_MASK);
	flags = MSG_STREAM_NEW | MSG_STREAM_FIN;
	err = quic_test_sendmsg(sock, msg, strlen(msg), sid, flags);
	if (err < 0) {
		pr_info("quic_test: send err: %d\n", err);
		goto free;
	}
	pr_info("quic_test: send '%s' on stream %lld\n", msg, sid);

	memset(msg, 0, sizeof(msg));
	flags = 0;
	err = quic_test_recvmsg(sock, msg, sizeof(msg) - 1, &sid, &flags);
	if (err < 0) {
		pr_info("quic_test: recv err: %d\n", err);
		goto free;
	}
	pr_info("quic_test: recv '%s' on stream %lld\n", msg, sid);

	__fput_sync(priv.filp);
	msleep(100);

	err = __sock_create(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_QUIC, &sock, 1);
	if (err < 0)
		return err;
	priv.filp = sock_alloc_file(sock, 0, NULL);
	if (IS_ERR(priv.filp))
		return PTR_ERR(priv.filp);
	err = quic_sock_setopt(sock->sk, QUIC_SOCKOPT_ALPN, alpn, strlen(alpn));
	if (err)
		goto free;

	err = kernel_bind(sock, (struct sockaddr *)&la, sizeof(la));
	if (err)
		goto free;

	ra.sin_family = AF_INET;
	ra.sin_port = htons((u16)port);
	if (!in4_pton(ip, strlen(ip), (u8 *)&ra.sin_addr.s_addr, -1, NULL))
		goto free;
	err = kernel_connect(sock, (struct sockaddr *)&ra, sizeof(ra), 0);
	if (err < 0)
		goto free;

	err = quic_sock_setopt(sock->sk, QUIC_SOCKOPT_TOKEN, token, token_len);
	if (err)
		goto free;

	err = quic_sock_setopt(sock->sk, QUIC_SOCKOPT_SESSION_TICKET, session_data, ticket_len);
	if (err)
		goto free;

	err = quic_sock_setopt(sock->sk, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, param_len);
	if (err)
		goto free;

	/* send early data before handshake */
	strscpy(msg, "hello quic server! I'm back!", sizeof(msg));
	sid = (0 | QUIC_STREAM_TYPE_UNI_MASK);
	flags = MSG_STREAM_NEW | MSG_STREAM_FIN;
	err = quic_test_sendmsg(sock, msg, strlen(msg), sid, flags);
	if (err < 0) {
		pr_info("quic_test: send err: %d\n", err);
		goto free;
	}
	pr_info("quic_test: send '%s' on stream %lld\n", msg, sid);

	err = quic_test_client_handshake(sock, &priv);
	if (err < 0)
		goto free;

	pr_info("quic_test: handshake completed\n");

	memset(msg, 0, sizeof(msg));
	flags = 0;
	err = quic_test_recvmsg(sock, msg, sizeof(msg) - 1, &sid, &flags);
	if (err < 0) {
		pr_info("quic_test: recv err: %d\n", err);
		goto free;
	}
	pr_info("quic_test: recv '%s' on stream %lld\n", msg, sid);

	err = 0;
free:
	__fput_sync(priv.filp);
	return err;
}

static int quic_test_do_sample_client(void)
{
	struct quic_test_priv priv = {};
	struct sockaddr_in ra = {};
	struct socket *sock;
	int err, flags = 0;
	char msg[64];
	s64 sid;

	err = __sock_create(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_QUIC, &sock, 1);
	if (err < 0)
		return err;
	priv.filp = sock_alloc_file(sock, 0, NULL);
	if (IS_ERR(priv.filp))
		return PTR_ERR(priv.filp);
	err = quic_sock_setopt(sock->sk, QUIC_SOCKOPT_ALPN, alpn, strlen(alpn));
	if (err)
		goto free;
	ra.sin_family = AF_INET;
	ra.sin_port = htons((u16)port);
	if (!in4_pton(ip, strlen(ip), (u8 *)&ra.sin_addr.s_addr, -1, NULL))
		goto free;
	err = kernel_connect(sock, (struct sockaddr *)&ra, sizeof(ra), 0);
	if (err < 0)
		goto free;

	err = quic_test_client_handshake(sock, &priv);
	if (err < 0)
		goto free;

	pr_info("quic_test: handshake completed\n");

	/* set MSG_STREAM_NEW flag to open a stream while sending first data
	 * or call getsockopt(QUIC_SOCKOPT_STREAM_OPEN) to open a stream.
	 * set MSG_STREAM_FIN to mark the last data on this stream.
	 */
	strscpy(msg, "hello quic server!", sizeof(msg));
	sid = (0 | QUIC_STREAM_TYPE_UNI_MASK);
	flags = MSG_STREAM_NEW | MSG_STREAM_FIN;
	err = quic_test_sendmsg(sock, msg, strlen(msg), sid, flags);
	if (err < 0) {
		pr_info("quic_test: send err: %d\n", err);
		goto free;
	}
	pr_info("quic_test: send '%s' on stream %lld\n", msg, sid);

	memset(msg, 0, sizeof(msg));
	flags = 0;
	err = quic_test_recvmsg(sock, msg, sizeof(msg) - 1, &sid, &flags);
	if (err < 0) {
		pr_info("quic_test: recv err: %d\n", err);
		goto free;
	}
	pr_info("quic_test: recv '%s' on stream %lld\n", msg, sid);

	err = 0;
free:
	fput(priv.filp);
	return err;
}

static int quic_test_do_ticket_server(void)
{
	struct quic_test_priv priv = {};
	struct quic_config config = {};
	struct socket *sock, *newsock;
	struct sockaddr_in la = {};
	int err, flags = 0;
	char msg[64];
	s64 sid;

	err = __sock_create(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_QUIC, &sock, 1);
	if (err < 0)
		return err;

	la.sin_family = AF_INET;
	la.sin_port = htons((u16)port);
	if (!in4_pton(ip, strlen(ip), (u8 *)&la.sin_addr.s_addr, -1, NULL))
		goto free;
	err = kernel_bind(sock, (struct sockaddr *)&la, sizeof(la));
	if (err < 0)
		goto free;
	err = quic_sock_setopt(sock->sk, QUIC_SOCKOPT_ALPN, alpn, strlen(alpn));
	if (err)
		goto free;
	err = kernel_listen(sock, 1);
	if (err < 0)
		goto free;
	config.validate_peer_address = 1;
	err = quic_sock_setopt(sock->sk, QUIC_SOCKOPT_CONFIG, &config, sizeof(config));
	if (err)
		goto free;

	err = kernel_accept(sock, &newsock, 0);
	if (err < 0)
		goto free;

	/* attach a file for user space to operate */
	priv.filp = sock_alloc_file(newsock, 0, NULL);
	if (IS_ERR(priv.filp)) {
		err = PTR_ERR(priv.filp);
		goto free;
	}

	/* do handshake with net/handshake APIs */
	err = quic_test_server_handshake(newsock, &priv);
	if (err < 0)
		goto free_flip;

	pr_info("quic_test: handshake completed\n");

	memset(msg, 0, sizeof(msg));
	flags = 0;
	err = quic_test_recvmsg(newsock, msg, sizeof(msg) - 1, &sid, &flags);
	if (err < 0) {
		pr_info("quic_test: recv err: %d\n", err);
		goto free_flip;
	}
	pr_info("quic_test: recv '%s' on stream %lld\n", msg, sid);

	strscpy(msg, "hello quic client!", sizeof(msg));
	sid = (0 | QUIC_STREAM_TYPE_SERVER_MASK);
	flags = MSG_STREAM_NEW | MSG_STREAM_FIN;
	err = quic_test_sendmsg(newsock, msg, strlen(msg), sid, flags);
	if (err < 0) {
		pr_info("quic_test: send err: %d\n", err);
		goto free_flip;
	}
	pr_info("quic_test: send '%s' on stream %lld\n", msg, sid);

	__fput_sync(priv.filp);

	pr_info("quic_test: wait for next connection from client...\n");

	err = kernel_accept(sock, &newsock, 0);
	if (err < 0)
		goto free;

	/* attach a file for user space to operate */
	priv.filp = sock_alloc_file(newsock, 0, NULL);
	if (IS_ERR(priv.filp)) {
		err = PTR_ERR(priv.filp);
		goto free;
	}

	/* do handshake with net/handshake APIs */
	err = quic_test_server_handshake(newsock, &priv);
	if (err < 0)
		goto free_flip;

	pr_info("quic_test: handshake completed\n");

	memset(msg, 0, sizeof(msg));
	flags = 0;
	err = quic_test_recvmsg(newsock, msg, sizeof(msg) - 1, &sid, &flags);
	if (err < 0) {
		pr_info("quic_test: recv err: %d\n", err);
		goto free_flip;
	}
	pr_info("quic_test: recv '%s' on stream %lld\n", msg, sid);

	strscpy(msg, "hello quic client! welcome back!", sizeof(msg));
	sid = (0 | QUIC_STREAM_TYPE_SERVER_MASK);
	flags = MSG_STREAM_NEW | MSG_STREAM_FIN;
	err = quic_test_sendmsg(newsock, msg, strlen(msg), sid, flags);
	if (err < 0) {
		pr_info("quic_test: send err: %d\n", err);
		goto free_flip;
	}
	pr_info("quic_test: send '%s' on stream %lld\n", msg, sid);

	err = 0;
free_flip:
	__fput_sync(priv.filp);
free:
	sock_release(sock);
	return err;
}

static int quic_test_do_sample_server(void)
{
	struct quic_test_priv priv = {};
	struct socket *sock, *newsock;
	struct sockaddr_in la = {};
	int err, flags = 0;
	char msg[64];
	s64 sid;

	err = __sock_create(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_QUIC, &sock, 1);
	if (err < 0)
		return err;

	la.sin_family = AF_INET;
	la.sin_port = htons((u16)port);
	if (!in4_pton(ip, strlen(ip), (u8 *)&la.sin_addr.s_addr, -1, NULL))
		goto free;
	err = kernel_bind(sock, (struct sockaddr *)&la, sizeof(la));
	if (err < 0)
		goto free;
	err = quic_sock_setopt(sock->sk, QUIC_SOCKOPT_ALPN, alpn, strlen(alpn));
	if (err)
		goto free;
	err = kernel_listen(sock, 1);
	if (err < 0)
		goto free;
	err = kernel_accept(sock, &newsock, 0);
	if (err < 0)
		goto free;

	/* attach a file for user space to operate */
	priv.filp = sock_alloc_file(newsock, 0, NULL);
	if (IS_ERR(priv.filp)) {
		err = PTR_ERR(priv.filp);
		goto free;
	}

	/* do handshake with net/handshake APIs */
	err = quic_test_server_handshake(newsock, &priv);
	if (err < 0)
		goto free_flip;

	pr_info("quic_test: handshake completed\n");

	memset(msg, 0, sizeof(msg));
	flags = 0;
	err = quic_test_recvmsg(newsock, msg, sizeof(msg) - 1, &sid, &flags);
	if (err < 0) {
		pr_info("quic_test: recv err %d\n", err);
		goto free_flip;
	}
	pr_info("quic_test: recv '%s' on stream %lld\n", msg, sid);

	strscpy(msg, "hello quic client!", sizeof(msg));
	sid = (0 | QUIC_STREAM_TYPE_SERVER_MASK);
	flags = MSG_STREAM_NEW | MSG_STREAM_FIN;
	err = quic_test_sendmsg(newsock, msg, strlen(msg), sid, flags);
	if (err < 0) {
		pr_info("quic_test: send err: %d\n", err);
		goto free_flip;
	}
	pr_info("quic_test: send '%s' on stream %lld\n", msg, sid);

	err = 0;
free_flip:
	fput(priv.filp);
free:
	sock_release(sock);
	return err;
}

static int quic_test_init(void)
{
	pr_info("quic_test: init\n");
	if (!strcmp(role, "client")) {
		if (!strcmp(alpn, "ticket"))
			return quic_test_do_ticket_client();
		return quic_test_do_sample_client();
	}
	if (!strcmp(role, "server")) {
		if (!strcmp(alpn, "ticket"))
			return quic_test_do_ticket_server();
		return quic_test_do_sample_server();
	}
	return -EINVAL;
}

static void quic_test_exit(void)
{
	pr_info("quic_test: exit\n");
}

module_init(quic_test_init);
module_exit(quic_test_exit);

module_param_string(role, role, ROLE_LEN, 0644);
module_param_string(alpn, alpn, ALPN_LEN, 0644);
module_param_string(ip, ip, IP_LEN, 0644);
module_param_named(port, port, int, 0644);
module_param_named(psk, psk, int, 0644);

MODULE_PARM_DESC(role, "client or server");
MODULE_PARM_DESC(ip, "server address");
MODULE_PARM_DESC(port, "server port");
MODULE_PARM_DESC(alpn, "alpn name");
MODULE_PARM_DESC(psk, "key_serial_t for psk");

MODULE_AUTHOR("Xin Long <lucien.xin@gmail.com>");
MODULE_DESCRIPTION("Test For Support for the QUIC protocol (RFC9000)");
MODULE_LICENSE("GPL");
