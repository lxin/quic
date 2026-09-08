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

DECLARE_STATIC_KEY_FALSE(quic_alpn_demux_key);

extern long sysctl_quic_mem[3];
extern int sysctl_quic_rmem[3];
extern int sysctl_quic_wmem[3];

enum {
	QUIC_MIB_NUM = 0,
	QUIC_MIB_CONN_CURRENTESTABS, /* Current established connections */
	QUIC_MIB_CONN_PASSIVEESTABS, /* Passively established connections */
	QUIC_MIB_CONN_ACTIVEESTABS,  /* Actively established connections */
	QUIC_MIB_PKT_RCVFASTPATHS,   /* Packets received on fast path */
	QUIC_MIB_PKT_DECFASTPATHS,   /* Packets decrypted on fast path */
	QUIC_MIB_PKT_ENCFASTPATHS,   /* Packets encrypted on fast path */
	QUIC_MIB_PKT_RCVBACKLOGS,    /* Packets processed via backlog */
	QUIC_MIB_PKT_DECBACKLOGS,    /* Packets decrypted in backlog */
	QUIC_MIB_PKT_ENCBACKLOGS,    /* Packets encrypted in backlog */
	QUIC_MIB_PKT_INVHDRDROP,     /* Dropped: invalid packet header */
	QUIC_MIB_PKT_INVNUMDROP,     /* Dropped: invalid packet number */
	QUIC_MIB_PKT_INVFRMDROP,     /* Dropped: invalid frame */
	QUIC_MIB_PKT_RCVDROP,        /* Dropped on receive (general) */
	QUIC_MIB_PKT_DECDROP,        /* Dropped: decryption failure */
	QUIC_MIB_PKT_ENCDROP,        /* Dropped: encryption failure */
	QUIC_MIB_FRM_RCVBUFDROP,     /* Frames dropped: recv buf limit */
	QUIC_MIB_FRM_RETRANS,        /* Frames retransmitted */
	QUIC_MIB_FRM_OUTCLOSES,      /* CONNECTION_CLOSE frames sent */
	QUIC_MIB_FRM_INCLOSES,       /* CONNECTION_CLOSE frames rcvd */
	QUIC_MIB_MAX
};

struct quic_mib {
	unsigned long mibs[QUIC_MIB_MAX]; /* Counters indexed by QUIC_MIB_* */
};

struct quic_net {
	DEFINE_SNMP_STAT(struct quic_mib, stat); /* Per-net QUIC MIB stats */
#if IS_ENABLED(CONFIG_PROC_FS)
	struct proc_dir_entry *proc_net; /* procfs entry for QUIC stats */
#endif
};

struct quic_net *quic_net(struct net *net);

#define QUIC_INC_STATS(net, field) SNMP_INC_STATS(quic_net(net)->stat, field)
#define QUIC_DEC_STATS(net, field) SNMP_DEC_STATS(quic_net(net)->stat, field)
