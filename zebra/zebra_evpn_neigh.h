/*
 * Zebra EVPN Neighbor Data structures and definitions
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

#ifndef _ZEBRA_EVPN_NEIGH_H
#define _ZEBRA_EVPN_NEIGH_H

#ifdef __cplusplus
extern "C" {
#endif
typedef struct zebra_neigh_t_ zebra_neigh_t;

#define IS_ZEBRA_NEIGH_ACTIVE(n) (n->state == ZEBRA_NEIGH_ACTIVE)

#define IS_ZEBRA_NEIGH_INACTIVE(n) (n->state == ZEBRA_NEIGH_INACTIVE)

#define ZEBRA_NEIGH_SET_ACTIVE(n) n->state = ZEBRA_NEIGH_ACTIVE

#define ZEBRA_NEIGH_SET_INACTIVE(n) n->state = ZEBRA_NEIGH_INACTIVE

/*
 * Neighbor hash table.
 *
 * This table contains the neighbors (IP to MAC bindings) pertaining to
 * this VNI. This includes local neighbors learnt on the attached VLAN
 * device that maps to this VNI as well as remote neighbors learnt and
 * installed by BGP.
 * Local neighbors will be known against the VLAN device (SVI); however,
 * it is sufficient for zebra to maintain against the VNI. The correct
 * VNI will be obtained as zebra maintains the mapping (of VLAN to VNI).
 */
struct zebra_neigh_t_ {
	/* IP address. */
	struct ipaddr ip;

	/* MAC address. */
	struct ethaddr emac;

	/* Back pointer to MAC. Only applicable to hosts in a L2-VNI. */
	zebra_mac_t *mac;

	/* Underlying interface. */
	ifindex_t ifindex;

	zebra_evi_t *zevi;

	uint32_t flags;
#define ZEBRA_NEIGH_LOCAL 0x01
#define ZEBRA_NEIGH_REMOTE 0x02
#define ZEBRA_NEIGH_REMOTE_NH 0x04 /* neigh entry for remote vtep */
#define ZEBRA_NEIGH_DEF_GW 0x08
#define ZEBRA_NEIGH_ROUTER_FLAG 0x10
#define ZEBRA_NEIGH_DUPLICATE 0x20
#define ZEBRA_NEIGH_SVI_IP 0x40
/* rxed from an ES peer */
#define ZEBRA_NEIGH_ES_PEER_ACTIVE 0x80
/* rxed from an ES peer as a proxy advertisement */
#define ZEBRA_NEIGH_ES_PEER_PROXY 0x100
/* We have not been able to independently establish that the host
 * is local connected
 */
#define ZEBRA_NEIGH_LOCAL_INACTIVE 0x200
#define ZEBRA_NEIGH_ALL_LOCAL_FLAGS                                            \
	(ZEBRA_NEIGH_LOCAL | ZEBRA_NEIGH_LOCAL_INACTIVE)
#define ZEBRA_NEIGH_ALL_PEER_FLAGS                                             \
	(ZEBRA_NEIGH_ES_PEER_PROXY | ZEBRA_NEIGH_ES_PEER_ACTIVE)

	enum zebra_neigh_state state;

	/* Remote VTEP IP - applicable only for remote neighbors. */
	struct in_addr r_vtep_ip;

	/*
	 * Mobility sequence numbers associated with this entry. The rem_seq
	 * represents the sequence number from the client (BGP) for the most
	 * recent add or update of this entry while the loc_seq represents
	 * the sequence number informed (or to be informed) by zebra to BGP
	 * for this entry.
	 */
	uint32_t rem_seq;
	uint32_t loc_seq;

	/* list of hosts pointing to this remote NH entry */
	struct host_rb_tree_entry host_rb;

	/* Duplicate ip detection */
	uint32_t dad_count;

	struct thread *dad_ip_auto_recovery_timer;

	struct timeval detect_start_time;

	time_t dad_dup_detect_time;

	/* used for ageing out the PEER_ACTIVE flag */
	struct thread *hold_timer;
};

/*
 * Context for neighbor hash walk - used by callbacks.
 */
struct neigh_walk_ctx {
	zebra_evi_t *zevi;      /* VNI hash */
	struct zebra_vrf *zvrf; /* VRF - for client notification. */
	int uninstall;		/* uninstall from kernel? */
	int upd_client;		/* uninstall from client? */

	uint32_t flags;
#define DEL_LOCAL_NEIGH 0x1
#define DEL_REMOTE_NEIGH 0x2
#define DEL_ALL_NEIGH (DEL_LOCAL_NEIGH | DEL_REMOTE_NEIGH)
#define DEL_REMOTE_NEIGH_FROM_VTEP 0x4
#define SHOW_REMOTE_NEIGH_FROM_VTEP 0x8

	struct in_addr r_vtep_ip; /* To walk neighbors from specific VTEP */

	struct vty *vty;	  /* Used by VTY handlers */
	uint32_t count;		  /* Used by VTY handlers */
	uint8_t addr_width;       /* Used by VTY handlers */
	struct json_object *json; /* Used for JSON Output */
};

int neigh_list_cmp(void *p1, void *p2);
void zevi_process_neigh_on_local_mac_del(zebra_evi_t *zevi, zebra_mac_t *zmac);
int zevi_neigh_del(zebra_evi_t *zevi, zebra_neigh_t *n);
int zevi_neigh_send_add_to_client(zebra_evi_t *zevi, struct ipaddr *ip,
				  struct ethaddr *macaddr, zebra_mac_t *zmac,
				  uint32_t neigh_flags, uint32_t seq);
int zevi_neigh_send_del_to_client(zebra_evi_t *zevi, struct ipaddr *ip,
				  struct ethaddr *mac, uint32_t flags,
				  int state, bool force);
int zevi_local_neigh_update(zebra_evi_t *zevi, struct interface *ifp,
			    struct ipaddr *ip, struct ethaddr *macaddr,
			    bool is_router, bool local_inactive,
			    bool dp_static);
void zevi_process_neigh_on_remote_mac_del(zebra_evi_t *zevi, zebra_mac_t *zmac);
void zevi_neigh_del_all(zebra_evi_t *zevi, int uninstall, int upd_client,
			uint32_t flags);
zebra_neigh_t *zevi_neigh_lookup(zebra_evi_t *zevi, struct ipaddr *ip);
void zebra_vxlan_dup_addr_detect_for_neigh(struct zebra_vrf *zvrf,
					   zebra_neigh_t *nbr,
					   struct in_addr vtep_ip, bool do_dad,
					   bool *is_dup_detect, bool is_local);
zebra_neigh_t *
zebra_evpn_proc_sync_neigh_update(zebra_evi_t *zevi, zebra_neigh_t *n,
				  uint16_t ipa_len, struct ipaddr *ipaddr,
				  uint8_t flags, uint32_t seq, esi_t *esi,
				  struct sync_mac_ip_ctx *ctx);
void zebra_evpn_sync_neigh_del(zebra_neigh_t *n);
bool zebra_evpn_neigh_is_bgp_seq_ok(zebra_evi_t *zevi, zebra_neigh_t *n,
				    struct ethaddr *macaddr, uint32_t seq);
struct hash *zebra_neigh_db_create(const char *desc);
void zevi_process_neigh_on_remote_mac_add(zebra_evi_t *zevi, zebra_mac_t *zmac);
void zevi_process_neigh_on_local_mac_change(zebra_evi_t *zevi,
					    zebra_mac_t *zmac, bool seq_change,
					    bool es_change);

void zevi_install_neigh_hash(struct hash_bucket *bucket, void *ctxt);
uint32_t num_dup_detected_neighs(zebra_evi_t *zevi);
int zevi_remote_neigh_update(zebra_evi_t *zevi, struct interface *ifp,
			     struct ipaddr *ip, struct ethaddr *macaddr,
			     uint16_t state);

void zevi_send_neigh_to_client(zebra_evi_t *zevi);
int remote_neigh_count(zebra_mac_t *zmac);
int zevi_rem_neigh_install(zebra_evi_t *zevi, zebra_neigh_t *n,
			   bool was_static);
void zevi_clear_dup_neigh_hash(struct hash_bucket *bucket, void *ctxt);
void zevi_find_neigh_addr_width(struct hash_bucket *bucket, void *ctxt);
void zevi_print_dad_neigh_hash(struct hash_bucket *bucket, void *ctxt);
void zevi_print_neigh_hash(struct hash_bucket *bucket, void *ctxt);
void zevi_print_neigh_hash_all_evi_detail(struct hash_bucket *bucket,
					  void **args);
void zevi_print_neigh(zebra_neigh_t *n, void *ctxt, json_object *json);
void zevi_print_neigh_hdr(struct vty *vty, struct neigh_walk_ctx *wctx);
void zevi_print_neigh_hash_all_evi(struct hash_bucket *bucket, void **args);

void process_neigh_remote_macip_add(zebra_evi_t *zevi, struct zebra_vrf *zvrf,
				    struct ipaddr *ipaddr, zebra_mac_t *mac,
				    struct in_addr vtep_ip, uint8_t flags,
				    uint32_t seq);
int zebra_evpn_neigh_gw_macip_add(struct interface *ifp, zebra_evi_t *zevi,
				  struct ipaddr *ip, zebra_mac_t *mac);

void zevi_neigh_remote_uninstall(zebra_evi_t *zevi, struct zebra_vrf *zvrf,
				 zebra_neigh_t *n, zebra_mac_t *mac,
				 struct ipaddr *ipaddr);
int zevi_neigh_del_ip(zebra_evi_t *zevi, struct zebra_vrf *zvrf,
		      struct ipaddr *ip);

#ifdef __cplusplus
}
#endif

#endif /*_ZEBRA_EVPN_NEIGH_H */
