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

#include <uapi/linux/quic.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/inet.h>
#include <linux/net.h>
#include <linux/delay.h>
#include <linux/completion.h>
#include <net/handshake.h>
#include <net/sock.h>

#define ROLE_LEN	10
#define IP_LEN		20
#define ALPN_LEN	20

static char role[ROLE_LEN] = "client";
static char ip[IP_LEN] = "127.0.0.1";
static int port = 1234;
static char alpn[ALPN_LEN] = "sample";

#define SND_MSG_LEN	4096
#define RCV_MSG_LEN	(4096 * 16)
#define TOT_LEN		(1 * 1024 * 1024 * 1024)

static char	snd_msg[SND_MSG_LEN];
static char	rcv_msg[RCV_MSG_LEN];

static int quic_test_recvmsg(struct socket *sock, void *msg, int len, u64 *sid, int *flag)
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

	error = kernel_recvmsg(sock, &inmsg, &iov, 1, len, 0);
	if (error < 0)
		return error;

	if (!sid)
		return error;

	*sid = rinfo->stream_id;
	*flag = rinfo->stream_flag;
	return error;
}

static int quic_test_sendmsg(struct socket *sock, const void *msg, int len, u64 sid, int flag)
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

	cmsg = CMSG_FIRSTHDR(&outmsg);
	cmsg->cmsg_level = IPPROTO_QUIC;
	cmsg->cmsg_type = 0;
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct quic_stream_info));

	outmsg.msg_controllen = cmsg->cmsg_len;
	sinfo = (struct quic_stream_info *)CMSG_DATA(cmsg);
	memset(sinfo, 0, sizeof(struct quic_stream_info));
	sinfo->stream_id = sid;
	sinfo->stream_flag = flag;

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

	err = sock_common_setsockopt(sock, SOL_QUIC, QUIC_SOCKOPT_ALPN,
				     KERNEL_SOCKPTR(alpn), strlen(alpn) + 1);
	if (err)
		return err;

	init_completion(&priv->sk_handshake_done);

	args.ta_sock = sock;
	args.ta_done = quic_test_handshake_done;
	args.ta_data = priv;
	args.ta_peername = "server.test";
	args.ta_timeout_ms = 3000;
	err = tls_client_hello_x509(&args, GFP_KERNEL);
	if (err)
		return err;
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

	err = sock_common_setsockopt(sock, SOL_QUIC, QUIC_SOCKOPT_ALPN,
				     KERNEL_SOCKPTR(alpn), strlen(alpn) + 1);
	if (err)
		return err;

	init_completion(&priv->sk_handshake_done);

	args.ta_sock = sock;
	args.ta_done = quic_test_handshake_done;
	args.ta_data = priv;
	args.ta_timeout_ms = 3000;
	err = tls_server_hello_x509(&args, GFP_KERNEL);
	if (err)
		return err;
	err = wait_for_completion_interruptible_timeout(&priv->sk_handshake_done, 5 * HZ);
	if (err <= 0) {
		tls_handshake_cancel(sock->sk);
		return -EINVAL;
	}
	return priv->status;
}

static int quic_test_do_client(void)
{
	struct quic_test_priv priv = {};
	struct sockaddr_in ra = {};
	u64 len = 0, sid = 0;
	struct socket *sock;
	int err, flag = 0;
	u32 start, end;

	err = __sock_create(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_QUIC, &sock, 1);
	if (err < 0)
		return err;
	priv.filp = sock_alloc_file(sock, 0, NULL);
	if (IS_ERR(priv.filp))
		return PTR_ERR(priv.filp);

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

	start = jiffies_to_msecs(jiffies);
	flag = QUIC_STREAM_FLAG_NEW; /* open stream when send first msg */
	err = quic_test_sendmsg(sock, snd_msg, SND_MSG_LEN, sid, flag);
	if (err < 0) {
		pr_info("send %d\n", err);
		goto free;
	}
	len += err;
	flag = 0;
	while (1) {
		err = quic_test_sendmsg(sock, snd_msg, SND_MSG_LEN, sid, flag);
		if (err < 0) {
			pr_info("send %d\n", err);
			goto free;
		}
		len += err;
		if (!(len % (SND_MSG_LEN * 1024)))
			pr_info("  send len: %lld, stream_id: %lld, flag: %d.\n", len, sid, flag);
		if (len > TOT_LEN - SND_MSG_LEN)
			break;
	}
	flag = QUIC_STREAM_FLAG_FIN; /* close stream when send last msg */
	err = quic_test_sendmsg(sock, snd_msg, SND_MSG_LEN, sid, flag);
	if (err < 0) {
		pr_info("send %d\n", err);
		goto free;
	}
	pr_info("SEND DONE: tot_len: %lld, stream_id: %lld, flag: %d.\n", len, sid, flag);

	memset(rcv_msg, 0, sizeof(rcv_msg));
	err = quic_test_recvmsg(sock, rcv_msg, RCV_MSG_LEN, &sid, &flag);
	if (err < 0) {
		pr_info("recv error %d\n", err);
		goto free;
	}
	end = jiffies_to_msecs(jiffies);
	start = (end - start) / 1000;
	pr_info("ALL RECVD: %u MBytes/Sec\n", TOT_LEN / 1024 / 1024 / start);
	err = 0;
free:
	fput(priv.filp);
	return err;
}

static int quic_test_do_server(void)
{
	struct quic_test_priv priv = {};
	struct socket *sock, *newsock;
	struct sockaddr_in la = {};
	u64 len = 0, sid = 0;
	int err, flag = 0;

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

	pr_info("HANDSHAKE DONE\n");

	while (1) {
		err = quic_test_recvmsg(newsock, &rcv_msg, sizeof(rcv_msg), &sid, &flag);
		if (err < 0) {
			pr_info("recv error %d\n", err);
			goto free_flip;
		}
		len += err;
		usleep_range(20, 40);
		if (flag & QUIC_STREAM_FLAG_FIN)
			break;
		pr_info("  recv len: %lld, stream_id: %lld, flag: %d.\n", len, sid, flag);
	}

	pr_info("RECV DONE: tot_len %lld, stream_id: %lld, flag: %d.\n", len, sid, flag);

	flag = QUIC_STREAM_FLAG_FIN;
	strscpy(snd_msg, "recv done", sizeof(snd_msg));
	err = quic_test_sendmsg(newsock, snd_msg, strlen(snd_msg), sid, flag);
	if (err < 0) {
		pr_info("send %d\n", err);
		goto free_flip;
	}
	msleep(100);
	err = 0;
free_flip:
	fput(priv.filp);
free:
	sock_release(sock);
	return err;
}

static int quic_test_init(void)
{
	pr_info("[QUIC_TEST] Quic Test Start\n");
	if (!strcmp(role, "client"))
		return quic_test_do_client();
	if (!strcmp(role, "server"))
		return quic_test_do_server();
	return -EINVAL;
}

static void quic_test_exit(void)
{
	pr_info("[QUIC_TEST] Quic Test Exit\n");
}

module_init(quic_test_init);
module_exit(quic_test_exit);

module_param_string(role, role, ROLE_LEN, 0644);
module_param_string(alpn, alpn, ALPN_LEN, 0644);
module_param_string(ip, ip, IP_LEN, 0644);
module_param_named(port, port, int, 0644);

MODULE_PARM_DESC(role, "client or server");
MODULE_PARM_DESC(ip, "server address");
MODULE_PARM_DESC(port, "server port");
MODULE_PARM_DESC(alpn, "alpn name");

MODULE_AUTHOR("Xin Long <lucien.xin@gmail.com>");
MODULE_DESCRIPTION("Test For Support for the QUIC protocol (RFC9000)");
MODULE_LICENSE("GPL");
