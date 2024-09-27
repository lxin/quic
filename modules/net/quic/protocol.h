/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

extern struct kmem_cache *quic_frame_cachep __read_mostly;
extern struct workqueue_struct *quic_wq __read_mostly;
extern struct percpu_counter quic_sockets_allocated;
extern u8 quic_random_data[32] __read_mostly;

extern long sysctl_quic_mem[3];
extern int sysctl_quic_rmem[3];
extern int sysctl_quic_wmem[3];

struct quic_addr_family_ops {
	sa_family_t sa_family;
	int	addr_len;
	int	iph_len;

	void	(*udp_conf_init)(struct sock *sk, struct udp_port_cfg *conf, union quic_addr *addr);
	int	(*flow_route)(struct sock *sk, union quic_addr *da, union quic_addr *sa);
	void	(*lower_xmit)(struct sock *sk, struct sk_buff *skb, union quic_addr *da,
			      union quic_addr *sa);

	void	(*get_pref_addr)(union quic_addr *addr, u8 **pp, u32 *plen);
	void	(*set_pref_addr)(u8 *p, union quic_addr *addr);
	void	(*seq_dump_addr)(struct seq_file *seq, union quic_addr *addr);

	void	(*get_msg_addr)(union quic_addr *addr, struct sk_buff *skb, bool src);
	void	(*set_sk_addr)(struct sock *sk, union quic_addr *addr, bool src);
	int	(*get_sk_addr)(struct socket *sock, struct sockaddr *addr, int peer);
	bool	(*cmp_sk_addr)(struct sock *sk, union quic_addr *a, union quic_addr *addr);
	int	(*get_mtu_info)(struct sk_buff *skb, u32 *info);

	void	(*set_sk_ecn)(struct sock *sk, u8 ecn);
	int	(*get_msg_ecn)(struct sk_buff *skb);

	int	(*setsockopt)(struct sock *sk, int level, int optname, sockptr_t optval,
			      unsigned int optlen);
	int	(*getsockopt)(struct sock *sk, int level, int optname, char __user *optval,
			      int __user *optlen);
};

enum {
	QUIC_MIB_NUM = 0,
	QUIC_MIB_CONN_CURRENTESTABS,
	QUIC_MIB_CONN_PASSIVEESTABS,
	QUIC_MIB_CONN_ACTIVEESTABS,
	QUIC_MIB_PKT_RCVFASTPATHS,
	QUIC_MIB_PKT_DECFASTPATHS,
	QUIC_MIB_PKT_ENCFASTPATHS,
	QUIC_MIB_PKT_RCVBACKLOGS,
	QUIC_MIB_PKT_DECBACKLOGS,
	QUIC_MIB_PKT_ENCBACKLOGS,
	QUIC_MIB_PKT_INVHDRDROP,
	QUIC_MIB_PKT_INVNUMDROP,
	QUIC_MIB_PKT_INVFRMDROP,
	QUIC_MIB_PKT_RCVDROP,
	QUIC_MIB_PKT_DECDROP,
	QUIC_MIB_PKT_ENCDROP,
	QUIC_MIB_FRM_RCVBUFDROP,
	QUIC_MIB_FRM_RETRANS,
	QUIC_MIB_FRM_CLOSES,
	QUIC_MIB_MAX
};

struct quic_mib {
	unsigned long	mibs[QUIC_MIB_MAX];
};

struct quic_net {
	DEFINE_SNMP_STAT(struct quic_mib, stat);
#ifdef CONFIG_PROC_FS
	struct proc_dir_entry *proc_net;
#endif
};

#define QUIC_INC_STATS(net, field)	SNMP_INC_STATS(quic_net(net)->stat, field)
#define QUIC_DEC_STATS(net, field)	SNMP_DEC_STATS(quic_net(net)->stat, field)

void quic_get_msg_addr(struct sock *sk, union quic_addr *addr, struct sk_buff *skb, bool src);
void quic_seq_dump_addr(struct sock *sk, struct seq_file *seq, union quic_addr *addr);
void quic_get_pref_addr(struct sock *sk, union quic_addr *addr, u8 **pp, u32 *plen);
void quic_set_pref_addr(struct sock *sk, u8 *p, union quic_addr *addr);

bool quic_cmp_sk_addr(struct sock *sk, union quic_addr *a, union quic_addr *addr);
void quic_get_sk_addr(struct socket *sock, struct sockaddr *a, bool peer);
void quic_set_sk_addr(struct sock *sk, union quic_addr *a, bool src);

void quic_lower_xmit(struct sock *sk, struct sk_buff *skb, union quic_addr *da,
		     union quic_addr *sa);
int quic_flow_route(struct sock *sk, union quic_addr *da, union quic_addr *sa);
struct quic_net *quic_net(struct net *net);

void quic_udp_conf_init(struct sock *sk, struct udp_port_cfg *conf, union quic_addr *a);
int quic_get_mtu_info(struct sock *sk, struct sk_buff *skb, u32 *info);
int quic_get_msg_ecn(struct sock *sk, struct sk_buff *skb);
void quic_set_sk_ecn(struct sock *sk, u8 ecn);

struct quic_addr_family_ops *quic_af_ops_get_skb(struct sk_buff *skb);
struct quic_addr_family_ops *quic_af_ops_get(sa_family_t family);
int quic_addr_family(struct sock *sk);
int quic_encap_len(struct sock *sk);
int quic_addr_len(struct sock *sk);
