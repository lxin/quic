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

/* Receive a message and extract QUIC stream metadata from control message. */
static int quic_test_recvmsg(struct socket *sock, void *msg, int len, s64 *sid, u32 *flags)
{
	char incmsg[CMSG_SPACE(sizeof(struct quic_stream_info))];
	struct quic_stream_info *rinfo;
	struct cmsghdr *cmsg;
	struct msghdr inmsg;
	struct kvec iov;
	int err;

	iov.iov_base = msg;
	iov.iov_len = len;

	memset(&inmsg, 0, sizeof(inmsg));
	inmsg.msg_control = incmsg;
	inmsg.msg_controllen = sizeof(incmsg);

	err = kernel_recvmsg(sock, &inmsg, &iov, 1, len, (int)(*flags));
	if (err < 0)
		return err;

	*flags = inmsg.msg_flags;

	cmsg = (struct cmsghdr *)incmsg;
	if (SOL_QUIC == cmsg->cmsg_level &&  QUIC_STREAM_INFO == cmsg->cmsg_type) {
		rinfo = CMSG_DATA(cmsg);
		*sid = rinfo->stream_id;
		*flags |= rinfo->stream_flags;
	}
	return err;
}

/* Send a message with QUIC stream metadata via control message. */
static int quic_test_sendmsg(struct socket *sock, const void *msg, int len, s64 sid, u32 flags)
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

	cmsg = (struct cmsghdr *)outcmsg;
	cmsg->cmsg_level = SOL_QUIC;
	cmsg->cmsg_type = QUIC_STREAM_INFO;
	cmsg->cmsg_len = CMSG_LEN(sizeof(*sinfo));

	outmsg.msg_controllen = cmsg->cmsg_len;
	sinfo = CMSG_DATA(cmsg);
	sinfo->stream_id = sid;
	sinfo->stream_flags = flags;

	return kernel_sendmsg(sock, &outmsg, &iov, 1, len);
}

struct quic_test_priv {
	struct completion sk_handshake_done;
	struct file *filp;
	int status;
};

/* Callback for handshake completion: stores status and wakes waiting context. */
static void quic_test_handshake_done(void *data, int status, key_serial_t peerid)
{
	struct quic_test_priv *priv = data;

	priv->status = status;
	complete_all(&priv->sk_handshake_done);
}

/* Client handshake logic using the kernel TLS handshake API. */
static int quic_test_client_handshake(struct socket *sock, struct quic_test_priv *priv)
{
	struct tls_handshake_args args = {};
	int err;

	init_completion(&priv->sk_handshake_done);

	args.ta_sock = sock;
	args.ta_done = quic_test_handshake_done;
	args.ta_data = priv;
	args.ta_timeout_ms = 3000;

	if (psk) { /* Use PSK if key_serial_t is configured, otherwise X.509-based handshake. */
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
	/* Wait for handshake completion or timeout. */
	err = wait_for_completion_interruptible_timeout(&priv->sk_handshake_done, HZ * 5UL);
	if (err <= 0) {
		tls_handshake_cancel(sock->sk);
		return -EINVAL;
	}
	return priv->status;
}

/* Server handshake logic using kernel TLS API. Similar to quic_test_client_handshake().*/
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
	err = wait_for_completion_interruptible_timeout(&priv->sk_handshake_done, HZ * 5UL);
	if (err <= 0) {
		tls_handshake_cancel(sock->sk);
		return -EINVAL;
	}
	return priv->status;
}

static int quic_test_do_sample_client(void)
{
	struct quic_test_priv priv = {};
	struct sockaddr_in ra = {};
	struct socket *sock;
	u32 flags = 0;
	char msg[64];
	int err;
	s64 sid;

	err = __sock_create(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_QUIC, &sock, 1);
	if (err < 0)
		return err;
	/* Allocate a file descriptor for the new socket to expose it to userspace. */
	priv.filp = sock_alloc_file(sock, 0, NULL);
	if (IS_ERR(priv.filp))
		return PTR_ERR(priv.filp);
	/* Set ALPN (Application-Layer Protocol Negotiation) on the socket.
	 *
	 * This value will be exposed to userspace via getsockopt(QUIC_SOCKOPT_ALPN)
	 * and used during the TLS handshake (e.g., to select HTTP/3 or custom protocol).
	 *
	 * Setting this here allows the userspace handshake implementation to retrieve
	 * and embed the ALPN value in the ClientHello sent to the server.
	 */
	err = quic_kernel_setsockopt(sock->sk, QUIC_SOCKOPT_ALPN, alpn, strlen(alpn));
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

	/* Send a message on a new unidirectional stream and then receive a response.
	 *
	 * - MSG_STREAM_NEW tells the stack to open a new stream with the given stream ID (sid).
	 *   Alternatively, a stream can be opened via getsockopt(QUIC_SOCKOPT_STREAM_OPEN).
	 *
	 * - MSG_STREAM_FIN marks the end of the stream, signaling no more data will follow.
	 *
	 * We send "hello quic server!" on a unidirectional stream (QUIC_STREAM_TYPE_UNI_MASK),
	 * and expect a response on a peer-initiated stream, which we receive with recvmsg().
	 */
	strscpy(msg, "hello quic server!", sizeof(msg));
	sid = QUIC_STREAM_TYPE_UNI_MASK;
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

static int quic_test_do_ticket_client(void)
{
	struct quic_transport_param param = {};
	unsigned int param_len, ticket_len;
	struct quic_test_priv priv = {};
	struct quic_config config = {};
	struct sockaddr_in ra = {};
	struct socket *sock;
	u32 flags = 0;
	char msg[64];
	int err;
	s64 sid;

	err = __sock_create(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_QUIC, &sock, 1);
	if (err < 0)
		return err;
	priv.filp = sock_alloc_file(sock, 0, NULL);
	if (IS_ERR(priv.filp))
		return PTR_ERR(priv.filp);
	err = quic_kernel_setsockopt(sock->sk, QUIC_SOCKOPT_ALPN, alpn, strlen(alpn));
	if (err)
		goto free;

	/* Instruct the userspace handshake to capture and provide the session ticket
	 * during the handshake process via QUIC_SOCKOPT_SESSION_TICKET socket option.
	 */
	config.receive_session_ticket = 1;
	err = quic_kernel_setsockopt(sock->sk, QUIC_SOCKOPT_CONFIG, &config, sizeof(config));
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

	/* Retrieve the session ticket from userspace (set via
	 * setsockopt(QUIC_SOCKOPT_SESSION_TICKET) during the handshake) and store it in
	 * 'session_data' for later session resumption.
	 */
	ticket_len = sizeof(session_data);
	err = quic_kernel_getsockopt(sock->sk, QUIC_SOCKOPT_SESSION_TICKET, session_data,
				     &ticket_len);
	if (err < 0)
		goto free;

	/* Retrieve and store the server's transport parameters into 'param'.  These are
	 * needed later to enable early data transmission during session resumption.
	 */
	param_len = sizeof(param);
	param.remote = 1;
	err = quic_kernel_getsockopt(sock->sk, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, &param_len);
	if (err < 0)
		goto free;

	pr_info("quic_test: save session ticket: %d, transport param %d for session resumption\n",
		ticket_len, param_len);

	strscpy(msg, "hello quic server!", sizeof(msg));
	sid = QUIC_STREAM_TYPE_UNI_MASK;
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
	err = quic_kernel_setsockopt(sock->sk, QUIC_SOCKOPT_ALPN, alpn, strlen(alpn));
	if (err)
		goto free;

	ra.sin_family = AF_INET;
	ra.sin_port = htons((u16)port);
	if (!in4_pton(ip, strlen(ip), (u8 *)&ra.sin_addr.s_addr, -1, NULL))
		goto free;
	err = kernel_connect(sock, (struct sockaddr *)&ra, sizeof(ra), 0);
	if (err < 0)
		goto free;

	/* Provide the session ticket for resumption. It will be retrieved by userspace via
	 * getsockopt(QUIC_SOCKOPT_SESSION_TICKET) and used during the handshake.
	 */
	err = quic_kernel_setsockopt(sock->sk, QUIC_SOCKOPT_SESSION_TICKET, session_data,
				     ticket_len);
	if (err)
		goto free;

	/* Provide the server's transport parameters for early data transmission. */
	err = quic_kernel_setsockopt(sock->sk, QUIC_SOCKOPT_TRANSPORT_PARAM, &param, param_len);
	if (err)
		goto free;

	/* Queue early application data to be sent before the handshake begins. */
	strscpy(msg, "hello quic server! I'm back!", sizeof(msg));
	sid = QUIC_STREAM_TYPE_UNI_MASK;
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

static int quic_test_do_sample_server(void)
{
	struct quic_test_priv priv = {};
	struct socket *sock, *newsock;
	struct sockaddr_in la = {};
	u32 flags = 0;
	char msg[64];
	int err;
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
	err = quic_kernel_setsockopt(sock->sk, QUIC_SOCKOPT_ALPN, alpn, strlen(alpn));
	if (err)
		goto free;
	err = kernel_listen(sock, 1);
	if (err < 0)
		goto free;
	err = kernel_accept(sock, &newsock, 0);
	if (err < 0)
		goto free;

	priv.filp = sock_alloc_file(newsock, 0, NULL);
	if (IS_ERR(priv.filp)) {
		err = PTR_ERR(priv.filp);
		goto free;
	}

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
	sid = QUIC_STREAM_TYPE_SERVER_MASK;
	flags = MSG_STREAM_NEW | MSG_STREAM_FIN;
	err = quic_test_sendmsg(newsock, msg, strlen(msg), sid, flags);
	if (err < 0) {
		pr_info("quic_test: send err: %d\n", err);
		goto free_flip;
	}
	pr_info("quic_test: send '%s' on stream %lld\n", msg, sid);

	flags = 0;
	quic_test_recvmsg(newsock, msg, sizeof(msg) - 1, &sid, &flags);
	err = 0;
free_flip:
	fput(priv.filp);
free:
	sock_release(sock);
	return err;
}

static int quic_test_do_ticket_server(void)
{
	struct quic_test_priv priv = {};
	struct socket *sock, *newsock;
	struct sockaddr_in la = {};
	u32 flags = 0;
	char msg[64];
	int err;
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
	err = quic_kernel_setsockopt(sock->sk, QUIC_SOCKOPT_ALPN, alpn, strlen(alpn));
	if (err)
		goto free;
	err = kernel_listen(sock, 1);
	if (err < 0)
		goto free;

	err = kernel_accept(sock, &newsock, 0);
	if (err < 0)
		goto free;

	priv.filp = sock_alloc_file(newsock, 0, NULL);
	if (IS_ERR(priv.filp)) {
		err = PTR_ERR(priv.filp);
		goto free;
	}

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
	sid = QUIC_STREAM_TYPE_SERVER_MASK;
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

	priv.filp = sock_alloc_file(newsock, 0, NULL);
	if (IS_ERR(priv.filp)) {
		err = PTR_ERR(priv.filp);
		goto free;
	}

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
	sid = QUIC_STREAM_TYPE_SERVER_MASK;
	flags = MSG_STREAM_NEW | MSG_STREAM_FIN;
	err = quic_test_sendmsg(newsock, msg, strlen(msg), sid, flags);
	if (err < 0) {
		pr_info("quic_test: send err: %d\n", err);
		goto free_flip;
	}
	pr_info("quic_test: send '%s' on stream %lld\n", msg, sid);

	flags = 0;
	quic_test_recvmsg(newsock, msg, sizeof(msg) - 1, &sid, &flags);
	err = 0;
free_flip:
	__fput_sync(priv.filp);
free:
	sock_release(sock);
	return err;
}

static int quic_test_init(void)
{
	pr_info("quic_test: init\n");
	if (!strcmp(role, "client")) { /* Run client-side tests. */
		/* Reuse 'alpn' as test selector: "ticket" triggers the ticket test. */
		if (!strcmp(alpn, "ticket"))
			return quic_test_do_ticket_client();
		/* Otherwise, run sample test. */
		return quic_test_do_sample_client();
	}
	if (!strcmp(role, "server")) { /* Run server-side tests. */
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

MODULE_PARM_DESC(role, "Client or server");
MODULE_PARM_DESC(ip, "Server Address");
MODULE_PARM_DESC(port, "Server Port");
MODULE_PARM_DESC(alpn, "ALPN name");
MODULE_PARM_DESC(psk, "key_serial_t for psk");

MODULE_AUTHOR("Xin Long <lucien.xin@gmail.com>");
MODULE_DESCRIPTION("Test For Support for the QUIC protocol (RFC9000)");
MODULE_LICENSE("GPL");
