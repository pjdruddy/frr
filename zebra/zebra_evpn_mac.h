/*
 * Zebra EVPN MAC Data structures and definitions
 * These are "internal" to this function.
 * Copyright (C) 2016, 2017 Cumulus Networks, Inc.
 * Copyright (C) 2020 Volta Networks.
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _ZEBRA_EVPN_MAC_H
#define _ZEBRA_EVPN_MAC_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct zebra_mac_t_ zebra_mac_t;

struct host_rb_entry {
	RB_ENTRY(host_rb_entry) hl_entry;

	struct prefix p;
};

RB_HEAD(host_rb_tree_entry, host_rb_entry);
RB_PROTOTYPE(host_rb_tree_entry, host_rb_entry, hl_entry,
	     host_rb_entry_compare);
/*
 * MAC hash table.
 *
 * This table contains the MAC addresses pertaining to this VNI.
 * This includes local MACs learnt on an attached VLAN that maps
 * to this VNI as well as remote MACs learnt and installed by BGP.
 * Local MACs will be known either on a VLAN sub-interface or
 * on (port, VLAN); however, it is sufficient for zebra to maintain
 * against the VNI i.e., it does not need to retain the local "port"
 * information. The correct VNI will be obtained as zebra maintains
 * the mapping (of VLAN to VNI).
 */
struct zebra_mac_t_ {
	/* MAC address. */
	struct ethaddr macaddr;

	uint32_t flags;
#define ZEBRA_MAC_LOCAL 0x01
#define ZEBRA_MAC_REMOTE 0x02
#define ZEBRA_MAC_AUTO 0x04	/* Auto created for neighbor. */
#define ZEBRA_MAC_STICKY 0x08      /* Static MAC */
#define ZEBRA_MAC_REMOTE_RMAC 0x10 /* remote router mac */
#define ZEBRA_MAC_DEF_GW 0x20
/* remote VTEP advertised MAC as default GW */
#define ZEBRA_MAC_REMOTE_DEF_GW 0x40
#define ZEBRA_MAC_DUPLICATE 0x80
/* MAC is locally active on an ethernet segment peer */
#define ZEBRA_MAC_ES_PEER_ACTIVE 0x100
/* MAC has been proxy-advertised by peers. This means we need to
 * keep the entry for forwarding but cannot advertise it
 */
#define ZEBRA_MAC_ES_PEER_PROXY 0x200
/* We have not been able to independently establish that the host is
 * local connected but one or more ES peers claims it is.
 * We will maintain the entry for forwarding purposes and continue
 * to advertise it as locally attached but with a "proxy" flag
 */
#define ZEBRA_MAC_LOCAL_INACTIVE 0x400

#define ZEBRA_MAC_ALL_LOCAL_FLAGS (ZEBRA_MAC_LOCAL | ZEBRA_MAC_LOCAL_INACTIVE)
#define ZEBRA_MAC_ALL_PEER_FLAGS                                               \
	(ZEBRA_MAC_ES_PEER_PROXY | ZEBRA_MAC_ES_PEER_ACTIVE)

	/* back pointer to zevi */
	zebra_evi_t *zevi;

	/* Local or remote info. */
	union {
		struct {
			ifindex_t ifindex;
			vlanid_t vid;
		} local;

		struct in_addr r_vtep_ip;
	} fwd_info;

	/* Local or remote ES */
	struct zebra_evpn_es *es;
	/* memory used to link the mac to the es */
	struct listnode es_listnode;

	/* Mobility sequence numbers associated with this entry. */
	uint32_t rem_seq;
	uint32_t loc_seq;

	/* List of neigh associated with this mac */
	struct list *neigh_list;

	/* list of hosts pointing to this remote RMAC */
	struct host_rb_tree_entry host_rb;

	/* Duplicate mac detection */
	uint32_t dad_count;

	struct thread *dad_mac_auto_recovery_timer;

	struct timeval detect_start_time;

	time_t dad_dup_detect_time;

	/* used for ageing out the PEER_ACTIVE flag */
	struct thread *hold_timer;

	/* number of neigh entries (using this mac) that have
	 * ZEBRA_MAC_ES_PEER_ACTIVE or ZEBRA_NEIGH_ES_PEER_PROXY
	 */
	uint32_t sync_neigh_cnt;
};

/*
 * Context for MAC hash walk - used by callbacks.
 */
struct mac_walk_ctx {
	zebra_evi_t *zevi;      /* VNI hash */
	struct zebra_vrf *zvrf; /* VRF - for client notification. */
	int uninstall;		/* uninstall from kernel? */
	int upd_client;		/* uninstall from client? */

	uint32_t flags;
#define DEL_LOCAL_MAC 0x1
#define DEL_REMOTE_MAC 0x2
#define DEL_ALL_MAC (DEL_LOCAL_MAC | DEL_REMOTE_MAC)
#define DEL_REMOTE_MAC_FROM_VTEP 0x4
#define SHOW_REMOTE_MAC_FROM_VTEP 0x8

	struct in_addr r_vtep_ip; /* To walk MACs from specific VTEP */

	struct vty *vty;	  /* Used by VTY handlers */
	uint32_t count;		  /* Used by VTY handlers */
	struct json_object *json; /* Used for JSON Output */
	bool print_dup;		  /* Used to print dup addr list */
};

/* temporary datastruct to pass info between the mac-update and
 * neigh-update while handling mac-ip routes
 */
struct sync_mac_ip_ctx {
	bool ignore_macip;
	bool mac_created;
	bool mac_inactive;
	bool mac_dp_update_deferred;
	zebra_mac_t *mac;
};

#ifdef __cplusplus
}
#endif

#endif /*_ZEBRA_EVPN_MAC_H */
