/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

extern struct quic_transport_param quic_default_param __read_mostly;
extern struct kmem_cache *quic_frame_cachep __read_mostly;
extern struct percpu_counter quic_sockets_allocated;

extern long sysctl_quic_mem[3];
extern int sysctl_quic_rmem[3];
extern int sysctl_quic_wmem[3];

enum {
	QUIC_MIB_NUM = 0,
	QUIC_MIB_CONN_CURRENTESTABS,	/* Currently established connections */
	QUIC_MIB_CONN_PASSIVEESTABS,	/* Connections established passively (server-side accept) */
	QUIC_MIB_CONN_ACTIVEESTABS,	/* Connections established actively (client-side connect) */
	QUIC_MIB_PKT_RCVFASTPATHS,	/* Packets received on the fast path */
	QUIC_MIB_PKT_DECFASTPATHS,	/* Packets successfully decrypted on the fast path */
	QUIC_MIB_PKT_ENCFASTPATHS,	/* Packets encrypted on the fast path (for transmission) */
	QUIC_MIB_PKT_RCVBACKLOGS,	/* Packets received via backlog processing */
	QUIC_MIB_PKT_DECBACKLOGS,	/* Packets decrypted in backlog handler */
	QUIC_MIB_PKT_ENCBACKLOGS,	/* Packets encrypted in backlog handler */
	QUIC_MIB_PKT_INVHDRDROP,	/* Packets dropped due to invalid headers */
	QUIC_MIB_PKT_INVNUMDROP,	/* Packets dropped due to invalid packet numbers */
	QUIC_MIB_PKT_INVFRMDROP,	/* Packets dropped due to invalid frames */
	QUIC_MIB_PKT_RCVDROP,		/* Packets dropped on receive (general errors) */
	QUIC_MIB_PKT_DECDROP,		/* Packets dropped due to decryption failure */
	QUIC_MIB_PKT_ENCDROP,		/* Packets dropped due to encryption failure */
	QUIC_MIB_FRM_RCVBUFDROP,	/* Frames dropped due to receive buffer limits */
	QUIC_MIB_FRM_RETRANS,		/* Frames retransmitted */
	QUIC_MIB_FRM_OUTCLOSES,		/* Frames of CONNECTION_CLOSE sent */
	QUIC_MIB_FRM_INCLOSES,		/* Frames of CONNECTION_CLOSE received */
	QUIC_MIB_MAX
};

struct quic_mib {
	unsigned long	mibs[QUIC_MIB_MAX];	/* Array of counters indexed by the enum above */
};

struct quic_net {
	DEFINE_SNMP_STAT(struct quic_mib, stat);	/* Per-network namespace MIB statistics */
#ifdef CONFIG_PROC_FS
	struct proc_dir_entry *proc_net;	/* procfs entry for dumping QUIC socket stats */
#endif
	struct quic_crypto crypto;	/* Context for decrypting Initial packets for ALPN */
	spinlock_t lock;	/* Lock protecting crypto context for Initial packet decryption */
};

struct quic_net *quic_net(struct net *net);

#define QUIC_INC_STATS(net, field)	SNMP_INC_STATS(quic_net(net)->stat, field)
#define QUIC_DEC_STATS(net, field)	SNMP_DEC_STATS(quic_net(net)->stat, field)
