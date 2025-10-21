// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Initialization/cleanup for QUIC protocol support.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include <net/inet_common.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <net/protocol.h>
#include <net/tls.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
#include <net/rps.h>
#endif

#include "socket.h"

static unsigned int quic_net_id __read_mostly;

struct quic_transport_param quic_default_param __read_mostly;
struct kmem_cache *quic_frame_cachep __read_mostly;
struct percpu_counter quic_sockets_allocated;

long sysctl_quic_mem[3];
int sysctl_quic_rmem[3];
int sysctl_quic_wmem[3];
int sysctl_quic_alpn_demux;

static int quic_inet_connect(struct socket *sock, struct sockaddr *addr, int addr_len, int flags)
{
	struct sock *sk = sock->sk;

	if (addr_len < (int)sizeof(addr->sa_family))
		return -EINVAL;

	return sk->sk_prot->connect(sk, addr, addr_len);
}

static int quic_inet_listen(struct socket *sock, int backlog)
{
	struct quic_conn_id_set *source, *dest;
	struct quic_path_group *paths;
	struct quic_conn_id conn_id;
	struct quic_crypto *crypto;
	struct quic_packet *packet;
	struct sock *sk = sock->sk;
	union quic_addr *a;
	int err = -EINVAL;

	lock_sock(sk);

	crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	packet = quic_packet(sk);
	source = quic_source(sk);
	dest = quic_dest(sk);
	paths = quic_paths(sk);

	if (!backlog) {
		if (quic_is_listen(sk)) { /* Exit listen state if backlog is zero. */
			err = 0;
			goto free;
		}
		goto out;
	}

	if (!sk_unhashed(sk)) /* Already hashed/listening. */
		goto out;

	a = quic_path_saddr(paths, 0);
	if (!a->v4.sin_port) { /* Auto-bind if not already bound. */
		err = quic_path_bind(sk, paths, 0);
		if (err)
			goto free;
		quic_set_sk_addr(sk, a, true);
	}
	/* Generate and add destination and source connection IDs for sending Initial-level
	 * CLOSE frames to refuse connection attempts in case of verification failure.
	 */
	quic_conn_id_generate(&conn_id);
	err = quic_conn_id_add(dest, &conn_id, 0, NULL);
	if (err)
		goto free;
	quic_conn_id_generate(&conn_id);
	err = quic_conn_id_add(source, &conn_id, 0, sk);
	if (err)
		goto free;
	/* Install initial keys to generate Retry/Stateless Reset tokens. */
	err = quic_crypto_set_cipher(crypto, TLS_CIPHER_AES_GCM_128, 0);
	if (err)
		goto free;

	/* Set socket state to LISTENING and add to sock hash table. */
	quic_set_state(sk, QUIC_SS_LISTENING);
	sk->sk_max_ack_backlog = backlog;
	paths->serv = 1; /* Mark this as a server. */
	err = sk->sk_prot->hash(sk);
	if (err)
		goto free;
out:
	release_sock(sk);
	return err;
free:
	quic_set_state(sk, QUIC_SS_CLOSED);
	sk->sk_max_ack_backlog = 0;
	paths->serv = 0;

	quic_conn_id_set_free(source);
	quic_conn_id_set_free(dest);
	quic_crypto_free(crypto);
	goto out;
}

static int quic_inet_getname(struct socket *sock, struct sockaddr *uaddr, int peer)
{
	return quic_get_sk_addr(sock, uaddr, peer);
}

static __poll_t quic_inet_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	struct sock *sk = sock->sk;
	struct list_head *head;
	__poll_t mask;

	poll_wait(file, sk_sleep(sk), wait);

	sock_rps_record_flow(sk); /* Record the flow's CPU association for RFS. */

	/* A listening socket becomes readable when the accept queue is not empty. */
	if (quic_is_listen(sk))
		return !list_empty(quic_reqs(sk)) ? (EPOLLIN | EPOLLRDNORM) : 0;

	mask = 0;
	if (sk->sk_err || !skb_queue_empty_lockless(&sk->sk_error_queue)) /* Error check. */
		mask |= EPOLLERR | (sock_flag(sk, SOCK_SELECT_ERR_QUEUE) ? EPOLLPRI : 0);

	head = &quic_inq(sk)->recv_list;
	if (!list_empty(head)) /* Readable check. */
		mask |= EPOLLIN | EPOLLRDNORM;

	if (quic_is_closed(sk)) {
		/* A broken connection should report almost everything in order to let
		 * applications to detect it reliable.
		 */
		mask |= EPOLLHUP;
		mask |= EPOLLERR;
		mask |= EPOLLIN | EPOLLRDNORM | EPOLLRDHUP;
		mask |= EPOLLOUT | EPOLLWRNORM;
		return mask;
	}

	if (sk_stream_wspace(sk) > 0 && quic_outq_wspace(sk, NULL) > 0) { /* Writable check. */
		mask |= EPOLLOUT | EPOLLWRNORM;
	} else {
		sk_set_bit(SOCKWQ_ASYNC_NOSPACE, sk);
		/* Do writeable check again after the bit is set to avoid a lost I/O signal,
		 * similar to sctp_poll().
		 */
		if (sk_stream_wspace(sk) > 0 && quic_outq_wspace(sk, NULL) > 0)
			mask |= EPOLLOUT | EPOLLWRNORM;
	}
	return mask;
}

static struct ctl_table quic_table[] = {
	{
		.procname	= "quic_mem",
		.data		= &sysctl_quic_mem,
		.maxlen		= sizeof(sysctl_quic_mem),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax
	},
	{
		.procname	= "quic_rmem",
		.data		= &sysctl_quic_rmem,
		.maxlen		= sizeof(sysctl_quic_rmem),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "quic_wmem",
		.data		= &sysctl_quic_wmem,
		.maxlen		= sizeof(sysctl_quic_wmem),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "alpn_demux",
		.data		= &sysctl_quic_alpn_demux,
		.maxlen		= sizeof(sysctl_quic_alpn_demux),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
#ifndef register_sysctl
	{ /* sentinel */ }
#endif
};

struct quic_net *quic_net(struct net *net)
{
	return net_generic(net, quic_net_id);
}

#ifdef CONFIG_PROC_FS
static int quic_conns_seq_show(struct seq_file *seq, void *v)
{
	struct net *net = seq_file_net(seq);
	u32 hash = (u32)(*(loff_t *)v);
	struct hlist_nulls_node *node;
	struct quic_path_group *paths;
	struct quic_shash_head *head;
	struct quic_outqueue *outq;
	struct sock *sk;
	uid_t uid;

	if (hash >= quic_sock_hash_size())
		return -ENOMEM;

	head = quic_sock_head(hash);
	rcu_read_lock();
	sk_nulls_for_each_rcu(sk, node, &head->head) {
		if (net != sock_net(sk))
			continue;

		seq_printf(seq, "%pK\t%d\t", sk, sk->sk_state);

		paths = quic_paths(sk);
		quic_seq_dump_addr(seq, quic_path_saddr(paths, 0));
		quic_seq_dump_addr(seq, quic_path_daddr(paths, 0));
		quic_seq_dump_addr(seq, quic_path_uaddr(paths, 0));

		outq = quic_outq(sk);
		seq_printf(seq, "%d\t%d\t%d\t%d\t%d\t%d\t%d\t", outq->window,
			   quic_packet_mss(quic_packet(sk)), outq->inflight,
			   READ_ONCE(sk->sk_wmem_queued), sk_rmem_alloc_get(sk),
			   sk->sk_sndbuf, sk->sk_rcvbuf);

		uid = from_kuid_munged(seq_user_ns(seq), sock_net_uid(net, sk));
		seq_printf(seq, "%u\t%lu\n", uid, sock_i_ino(sk));
	}
	rcu_read_unlock();
	return 0;
}

static void *quic_conns_seq_start(struct seq_file *seq, loff_t *pos)
{
	if (*pos >= quic_sock_hash_size())
		return NULL;

	if (*pos < 0)
		*pos = 0;

	if (*pos == 0)
		seq_printf(seq, "SOCK\tSTATE\tLOCAL_ADDRESS\tREMOTE_ADDRESS\tUDP_ADDRESS\t"
				"WINDOW\tMSS\tIN_FLIGHT\tTX_QUEUE\tRX_QUEUE\tSNDBUF\tRCVBUF\t"
				"UID\tINODE\n");

	return (void *)pos;
}

static void *quic_conns_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	if (++*pos >= quic_sock_hash_size())
		return NULL;

	return pos;
}

static void quic_conns_seq_stop(struct seq_file *seq, void *v)
{
}

static int quic_eps_seq_show(struct seq_file *seq, void *v)
{
	struct net *net = seq_file_net(seq);
	u32 hash = (u32)(*(loff_t *)v);
	struct hlist_nulls_node *node;
	struct quic_path_group *paths;
	struct quic_shash_head *head;
	struct sock *sk;
	uid_t uid;

	if (hash >= quic_listen_sock_hash_size())
		return -ENOMEM;

	head = quic_listen_sock_head(hash);
	rcu_read_lock();
	sk_nulls_for_each_rcu(sk, node, &head->head) {
		if (net != sock_net(sk))
			continue;

		seq_printf(seq, "%pK\t%d\t", sk, sk->sk_state);

		paths = quic_paths(sk);
		quic_seq_dump_addr(seq, quic_path_saddr(paths, 0));
		quic_seq_dump_addr(seq, quic_path_uaddr(paths, 0));

		uid = from_kuid_munged(seq_user_ns(seq), sock_net_uid(net, sk));
		seq_printf(seq, "%u\t%lu\n", uid, sock_i_ino(sk));
	}
	rcu_read_unlock();
	return 0;
}

static void *quic_eps_seq_start(struct seq_file *seq, loff_t *pos)
{
	if (*pos >= quic_listen_sock_hash_size())
		return NULL;

	if (*pos < 0)
		*pos = 0;

	if (*pos == 0)
		seq_printf(seq, "SOCK\tSTATE\tLOCAL_ADDRESS\tUDP_ADDRESS\t"
				"UID\tINODE\n");

	return (void *)pos;
}

static void *quic_eps_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	if (++*pos >= quic_listen_sock_hash_size())
		return NULL;

	return pos;
}

static void quic_eps_seq_stop(struct seq_file *seq, void *v)
{
}

static const struct snmp_mib quic_snmp_list[] = {
	SNMP_MIB_ITEM("QuicConnCurrentEstabs", QUIC_MIB_CONN_CURRENTESTABS),
	SNMP_MIB_ITEM("QuicConnPassiveEstabs", QUIC_MIB_CONN_PASSIVEESTABS),
	SNMP_MIB_ITEM("QuicConnActiveEstabs", QUIC_MIB_CONN_ACTIVEESTABS),
	SNMP_MIB_ITEM("QuicPktRcvFastpaths", QUIC_MIB_PKT_RCVFASTPATHS),
	SNMP_MIB_ITEM("QuicPktDecFastpaths", QUIC_MIB_PKT_DECFASTPATHS),
	SNMP_MIB_ITEM("QuicPktEncFastpaths", QUIC_MIB_PKT_ENCFASTPATHS),
	SNMP_MIB_ITEM("QuicPktRcvBacklogs", QUIC_MIB_PKT_RCVBACKLOGS),
	SNMP_MIB_ITEM("QuicPktDecBacklogs", QUIC_MIB_PKT_DECBACKLOGS),
	SNMP_MIB_ITEM("QuicPktEncBacklogs", QUIC_MIB_PKT_ENCBACKLOGS),
	SNMP_MIB_ITEM("QuicPktInvHdrDrop", QUIC_MIB_PKT_INVHDRDROP),
	SNMP_MIB_ITEM("QuicPktInvNumDrop", QUIC_MIB_PKT_INVNUMDROP),
	SNMP_MIB_ITEM("QuicPktInvFrmDrop", QUIC_MIB_PKT_INVFRMDROP),
	SNMP_MIB_ITEM("QuicPktRcvDrop", QUIC_MIB_PKT_RCVDROP),
	SNMP_MIB_ITEM("QuicPktDecDrop", QUIC_MIB_PKT_DECDROP),
	SNMP_MIB_ITEM("QuicPktEncDrop", QUIC_MIB_PKT_ENCDROP),
	SNMP_MIB_ITEM("QuicFrmRcvBufDrop", QUIC_MIB_FRM_RCVBUFDROP),
	SNMP_MIB_ITEM("QuicFrmRetrans", QUIC_MIB_FRM_RETRANS),
	SNMP_MIB_ITEM("QuicFrmOutCloses", QUIC_MIB_FRM_OUTCLOSES),
	SNMP_MIB_ITEM("QuicFrmInCloses", QUIC_MIB_FRM_INCLOSES),
#ifndef snmp_get_cpu_field_batch_cnt
	SNMP_MIB_SENTINEL
#endif
};

static int quic_snmp_seq_show(struct seq_file *seq, void *v)
{
#ifndef snmp_get_cpu_field_batch_cnt
	unsigned long buff[QUIC_MIB_MAX];
	struct net *net = seq->private;
	u32 idx;

	memset(buff, 0, sizeof(unsigned long) * QUIC_MIB_MAX);

	snmp_get_cpu_field_batch(buff, quic_snmp_list, quic_net(net)->stat);
	for (idx = 0; quic_snmp_list[idx].name; idx++)
#else
	unsigned long buff[ARRAY_SIZE(quic_snmp_list)];
	const int cnt = ARRAY_SIZE(quic_snmp_list);
	struct net *net = seq->private;
	u32 idx;

	memset(buff, 0, sizeof(buff));

	snmp_get_cpu_field_batch_cnt(buff, quic_snmp_list, cnt, quic_net(net)->stat);
	for (idx = 0; idx < cnt; idx++)
#endif
		seq_printf(seq, "%-32s\t%ld\n", quic_snmp_list[idx].name, buff[idx]);

	return 0;
}

static const struct seq_operations quic_conns_seq_ops = {
	.show		= quic_conns_seq_show,
	.start		= quic_conns_seq_start,
	.next		= quic_conns_seq_next,
	.stop		= quic_conns_seq_stop,
};

static const struct seq_operations quic_eps_seq_ops = {
	.show		= quic_eps_seq_show,
	.start		= quic_eps_seq_start,
	.next		= quic_eps_seq_next,
	.stop		= quic_eps_seq_stop,
};

static int quic_net_proc_init(struct net *net)
{
	quic_net(net)->proc_net = proc_net_mkdir(net, "quic", net->proc_net);
	if (!quic_net(net)->proc_net)
		return -ENOMEM;

	if (!proc_create_net_single("snmp", 0444, quic_net(net)->proc_net,
				    quic_snmp_seq_show, NULL))
		goto free;
	if (!proc_create_net("conns", 0444, quic_net(net)->proc_net,
			     &quic_conns_seq_ops, sizeof(struct seq_net_private)))
		goto free;
	if (!proc_create_net("eps", 0444, quic_net(net)->proc_net,
			     &quic_eps_seq_ops, sizeof(struct seq_net_private)))
		goto free;
	return 0;
free:
	remove_proc_subtree("quic", net->proc_net);
	quic_net(net)->proc_net = NULL;
	return -ENOMEM;
}

static void quic_net_proc_exit(struct net *net)
{
	remove_proc_subtree("quic", net->proc_net);
	quic_net(net)->proc_net = NULL;
}
#endif

static void quic_transport_param_init(void)
{
	struct quic_transport_param *p = &quic_default_param;

	p->max_udp_payload_size = QUIC_MAX_UDP_PAYLOAD;
	p->ack_delay_exponent = QUIC_DEF_ACK_DELAY_EXPONENT;
	p->max_ack_delay = QUIC_DEF_ACK_DELAY;
	p->active_connection_id_limit = QUIC_CONN_ID_DEF;
	p->max_idle_timeout = QUIC_DEF_IDLE_TIMEOUT;
	p->max_data = (u64)QUIC_PATH_MAX_PMTU * 32;
	p->max_stream_data_bidi_local = (u64)QUIC_PATH_MAX_PMTU * 16;
	p->max_stream_data_bidi_remote = (u64)QUIC_PATH_MAX_PMTU * 16;
	p->max_stream_data_uni = (u64)QUIC_PATH_MAX_PMTU * 16;
	p->max_streams_bidi = QUIC_DEF_STREAMS;
	p->max_streams_uni = QUIC_DEF_STREAMS;
}

static const struct proto_ops quic_proto_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = inet_release,
	.bind		   = inet_bind,
	.connect	   = quic_inet_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = inet_accept,
	.getname	   = quic_inet_getname,
	.poll		   = quic_inet_poll,
	.ioctl		   = inet_ioctl,
	.gettstamp	   = sock_gettstamp,
	.listen		   = quic_inet_listen,
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = inet_recvmsg,
	.mmap		   = sock_no_mmap,
};

static struct inet_protosw quic_stream_protosw = {
	.type       = SOCK_STREAM,
	.protocol   = IPPROTO_QUIC,
	.prot       = &quic_prot,
	.ops        = &quic_proto_ops,
};

static struct inet_protosw quic_dgram_protosw = {
	.type       = SOCK_DGRAM,
	.protocol   = IPPROTO_QUIC,
	.prot       = &quic_prot,
	.ops        = &quic_proto_ops,
};

static const struct proto_ops quicv6_proto_ops = {
	.family		   = PF_INET6,
	.owner		   = THIS_MODULE,
	.release	   = inet6_release,
	.bind		   = inet6_bind,
	.connect	   = quic_inet_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = inet_accept,
	.getname	   = quic_inet_getname,
	.poll		   = quic_inet_poll,
	.ioctl		   = inet6_ioctl,
	.gettstamp	   = sock_gettstamp,
	.listen		   = quic_inet_listen,
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = inet_recvmsg,
	.mmap		   = sock_no_mmap,
};

static struct inet_protosw quicv6_stream_protosw = {
	.type       = SOCK_STREAM,
	.protocol   = IPPROTO_QUIC,
	.prot       = &quicv6_prot,
	.ops        = &quicv6_proto_ops,
};

static struct inet_protosw quicv6_dgram_protosw = {
	.type       = SOCK_DGRAM,
	.protocol   = IPPROTO_QUIC,
	.prot       = &quicv6_prot,
	.ops        = &quicv6_proto_ops,
};

static int quic_protosw_init(void)
{
	int err;

	err = proto_register(&quic_prot, 1);
	if (err)
		return err;

	err = proto_register(&quicv6_prot, 1);
	if (err) {
		proto_unregister(&quic_prot);
		return err;
	}

	inet_register_protosw(&quic_stream_protosw);
	inet_register_protosw(&quic_dgram_protosw);
	inet6_register_protosw(&quicv6_stream_protosw);
	inet6_register_protosw(&quicv6_dgram_protosw);

	return 0;
}

static void quic_protosw_exit(void)
{
	inet_unregister_protosw(&quic_dgram_protosw);
	inet_unregister_protosw(&quic_stream_protosw);
	proto_unregister(&quic_prot);

	inet6_unregister_protosw(&quicv6_dgram_protosw);
	inet6_unregister_protosw(&quicv6_stream_protosw);
	proto_unregister(&quicv6_prot);
}

static int __net_init quic_net_init(struct net *net)
{
	struct quic_net *qn = quic_net(net);
	int err;

	qn->stat = alloc_percpu(struct quic_mib);
	if (!qn->stat)
		return -ENOMEM;

	err = quic_crypto_set_cipher(&qn->crypto, TLS_CIPHER_AES_GCM_128, CRYPTO_ALG_ASYNC);
	if (err) {
		free_percpu(qn->stat);
		qn->stat = NULL;
		return err;
	}

	INIT_WORK(&qn->work, quic_packet_backlog_work);
	skb_queue_head_init(&qn->backlog_list);

#ifdef CONFIG_PROC_FS
	err = quic_net_proc_init(net);
	if (err) {
		quic_crypto_free(&qn->crypto);
		free_percpu(qn->stat);
		qn->stat = NULL;
	}
#endif
	return err;
}

static void __net_exit quic_net_exit(struct net *net)
{
	struct quic_net *qn = quic_net(net);

#ifdef CONFIG_PROC_FS
	quic_net_proc_exit(net);
#endif
	skb_queue_purge(&qn->backlog_list);
	cancel_work_sync(&qn->work);
	quic_crypto_free(&qn->crypto);
	free_percpu(qn->stat);
	qn->stat = NULL;
}

static struct pernet_operations quic_net_ops = {
	.init = quic_net_init,
	.exit = quic_net_exit,
	.id   = &quic_net_id,
	.size = sizeof(struct quic_net),
};

#ifdef CONFIG_SYSCTL
static struct ctl_table_header *quic_sysctl_header;

static void quic_sysctl_register(void)
{
	quic_sysctl_header = register_net_sysctl(&init_net, "net/quic", quic_table);
}

static void quic_sysctl_unregister(void)
{
	unregister_net_sysctl_table(quic_sysctl_header);
}
#endif

static __init int quic_init(void)
{
	int max_share, err = -ENOMEM;
	unsigned long limit;

	/* Set QUIC memory limits based on available system memory, similar to sctp_init(). */
	limit = nr_free_buffer_pages() / 8;
	limit = max(limit, 128UL);
	sysctl_quic_mem[0] = (long)limit / 4 * 3;
	sysctl_quic_mem[1] = (long)limit;
	sysctl_quic_mem[2] = sysctl_quic_mem[0] * 2;

	limit = (sysctl_quic_mem[1]) << (PAGE_SHIFT - 7);
	max_share = min(4UL * 1024 * 1024, limit);

	sysctl_quic_rmem[0] = PAGE_SIZE;
	sysctl_quic_rmem[1] = 1024 * 1024;
	sysctl_quic_rmem[2] = max(sysctl_quic_rmem[1], max_share);

	sysctl_quic_wmem[0] = PAGE_SIZE;
	sysctl_quic_wmem[1] = 16 * 1024;
	sysctl_quic_wmem[2] = max(64 * 1024, max_share);

	quic_path_init(quic_packet_rcv);
	quic_transport_param_init();
	quic_crypto_init();

	quic_frame_cachep = kmem_cache_create("quic_frame", sizeof(struct quic_frame),
					      0, SLAB_HWCACHE_ALIGN, NULL);
	if (!quic_frame_cachep)
		goto err;

	err = percpu_counter_init(&quic_sockets_allocated, 0, GFP_KERNEL);
	if (err)
		goto err_percpu_counter;

	err = quic_hash_tables_init();
	if (err)
		goto err_hash;

	err = register_pernet_subsys(&quic_net_ops);
	if (err)
		goto err_def_ops;

	err = quic_protosw_init();
	if (err)
		goto err_protosw;

#ifdef CONFIG_SYSCTL
	quic_sysctl_register();
#endif
	pr_info("quic: init\n");
	return 0;

err_protosw:
	unregister_pernet_subsys(&quic_net_ops);
err_def_ops:
	quic_hash_tables_destroy();
err_hash:
	percpu_counter_destroy(&quic_sockets_allocated);
err_percpu_counter:
	kmem_cache_destroy(quic_frame_cachep);
err:
	return err;
}

static __exit void quic_exit(void)
{
#ifdef CONFIG_SYSCTL
	quic_sysctl_unregister();
#endif
	quic_protosw_exit();
	unregister_pernet_subsys(&quic_net_ops);
	quic_hash_tables_destroy();
	percpu_counter_destroy(&quic_sockets_allocated);
	kmem_cache_destroy(quic_frame_cachep);
	pr_info("quic: exit\n");
}

module_init(quic_init);
module_exit(quic_exit);

MODULE_ALIAS("net-pf-" __stringify(PF_INET) "-proto-261");
MODULE_ALIAS("net-pf-" __stringify(PF_INET6) "-proto-261");
MODULE_AUTHOR("Xin Long <lucien.xin@gmail.com>");
MODULE_DESCRIPTION("Support for the QUIC protocol (RFC9000)");
MODULE_LICENSE("GPL");
