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

extern long sysctl_quic_mem[3];
extern int sysctl_quic_rmem[3];
extern int sysctl_quic_wmem[3];

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

struct quic_net *quic_net(struct net *net);

#define QUIC_INC_STATS(net, field)	SNMP_INC_STATS(quic_net(net)->stat, field)
#define QUIC_DEC_STATS(net, field)	SNMP_DEC_STATS(quic_net(net)->stat, field)
