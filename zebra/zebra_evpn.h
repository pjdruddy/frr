/*
 * Zebra EVPN Data structures and definitions
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

#ifndef _ZEBRA_EVPN_H
#define _ZEBRA_EVPN_H

#include <zebra.h>

#include "if.h"
#include "linklist.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct zebra_evi_t_ zebra_evi_t;
typedef struct zebra_vtep_t_ zebra_vtep_t;

RB_HEAD(zebra_es_evi_rb_head, zebra_evpn_es_evi);
RB_PROTOTYPE(zebra_es_evi_rb_head, zebra_evpn_es_evi, rb_node,
	     zebra_es_evi_rb_cmp);

/*
 * VTEP info
 *
 * Right now, this just has each remote VTEP's IP address.
 */
struct zebra_vtep_t_ {
	/* Remote IP. */
	/* NOTE: Can only be IPv4 right now. */
	struct in_addr vtep_ip;
	/* Flood mode (one of enum vxlan_flood_control) based on the PMSI
	 * tunnel type advertised by the remote VTEP
	 */
	int flood_control;

	/* Links. */
	struct zebra_vtep_t_ *next;
	struct zebra_vtep_t_ *prev;
};

/*
 * VNI hash table
 *
 * Contains information pertaining to a VNI:
 * - the list of remote VTEPs (with this VNI)
 */
struct zebra_evi_t_ {
	/* VNI - key */
	vni_t vni;

	/* ES flags */
	uint32_t flags;
#define ZEVI_READY_FOR_BGP (1 << 0) /* ready to be sent to BGP */

	/* Flag for advertising gw macip */
	uint8_t advertise_gw_macip;

	/* Flag for advertising svi macip */
	uint8_t advertise_svi_macip;

	/* Flag for advertising gw macip */
	uint8_t advertise_subnet;

	/* Corresponding VxLAN interface. */
	struct interface *vxlan_if;

	/* List of remote VTEPs */
	zebra_vtep_t *vteps;

	/* Local IP */
	struct in_addr local_vtep_ip;

	/* PIM-SM MDT group for BUM flooding */
	struct in_addr mcast_grp;

	/* tenant VRF, if any */
	vrf_id_t vrf_id;

	/* List of local or remote MAC */
	struct hash *mac_table;

	/* List of local or remote neighbors (MAC+IP) */
	struct hash *neigh_table;

	/* RB tree of ES-EVIs */
	struct zebra_es_evi_rb_head es_evi_rb_tree;

	/* List of local ESs */
	struct list *local_es_evi_list;
};

void *zevi_alloc(void *p);
zebra_evi_t *zevi_lookup(vni_t vni);
zebra_evi_t *zevi_add(vni_t vni);
void process_remote_macip_add(vni_t vni, struct ethaddr *macaddr,
			      uint16_t ipa_len, struct ipaddr *ipaddr,
			      uint8_t flags, uint32_t seq,
			      struct in_addr vtep_ip, esi_t *esi);

void process_remote_macip_del(vni_t vni, struct ethaddr *macaddr,
			      uint16_t ipa_len, struct ipaddr *ipaddr,
			      struct in_addr vtep_ip);
struct interface *zevi_map_to_svi(zebra_evi_t *zevi);
int advertise_gw_macip_enabled(zebra_evi_t *zevi);
int advertise_svi_macip_enabled(zebra_evi_t *zevi);
void zevi_evpn_cfg_cleanup(struct hash_bucket *bucket, void *ctxt);
void zevi_cleanup_all(struct hash_bucket *bucket, void *arg);
void zevi_handle_flooding_remote_vteps(struct hash_bucket *bucket, void *zvrf);
int zevi_send_add_to_client(zebra_evi_t *zevi);
int zevi_send_del_to_client(zebra_evi_t *zevi);
bool vni_hash_cmp(const void *p1, const void *p2);
unsigned int vni_hash_keymake(const void *p);
void zevi_read_mac_neigh(zebra_evi_t *zevi, struct interface *ifp);
void zevi_install_mac_hash(struct hash_bucket *bucket, void *ctxt);
struct interface *zevi_map_to_macvlan(struct interface *br_if,
				      struct interface *svi_if);
zebra_evi_t *zevi_from_svi(struct interface *ifp, struct interface *br_if);
zebra_evi_t *zevi_map_vlan(struct interface *ifp, struct interface *br_if,
			   vlanid_t vid);
void zevi_svi_macip_del_for_vni_hash(struct hash_bucket *bucket, void *ctxt);
void zevi_gw_macip_add_for_vni_hash(struct hash_bucket *bucket, void *ctxt);
void zevi_gw_macip_del_for_vni_hash(struct hash_bucket *bucket, void *ctxt);
int zevi_advertise_subnet(zebra_evi_t *zevi, struct interface *ifp,
			  int advertise);
void zevi_print_hash_detail(struct hash_bucket *bucket, void *data);
void zevi_print_hash(struct hash_bucket *bucket, void *ctxt[]);
void zevi_print(zebra_evi_t *zevi, void **ctxt);
void zevi_install_mac_hash(struct hash_bucket *bucket, void *ctxt);

#ifdef __cplusplus
}
#endif

#endif /*_ZEBRA_EVPN_H */
