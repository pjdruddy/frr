/*
 * Zebra EVPN for VxLAN code
 * Copyright (C) 2016, 2017 Cumulus Networks, Inc.
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

#include <zebra.h>

#include "hash.h"
#include "if.h"
#include "jhash.h"
#include "linklist.h"
#include "log.h"
#include "memory.h"
#include "prefix.h"
#include "stream.h"
#include "table.h"
#include "vlan.h"
#include "vxlan.h"
#ifdef GNU_LINUX
#include <linux/neighbour.h>
#endif

#include "zebra/zebra_router.h"
#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/rt_netlink.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_l2.h"
#include "zebra/zebra_memory.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_evpn.h"
#include "zebra/zebra_evpn_mac.h"
#include "zebra/zebra_evpn_neigh.h"
#include "zebra/zebra_vxlan_private.h"
#include "zebra/zebra_evpn_mh.h"
#include "zebra/zebra_router.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZEVI, "VNI hash");
DEFINE_MTYPE_STATIC(ZEBRA, ZEVI_VTEP, "VNI remote VTEP");

/* PMSI strings. */
#define VXLAN_FLOOD_STR_NO_INFO "-"
#define VXLAN_FLOOD_STR_DEFAULT VXLAN_FLOOD_STR_NO_INFO
static const struct message zvtep_flood_str[] = {
	{VXLAN_FLOOD_DISABLED, VXLAN_FLOOD_STR_NO_INFO},
	{VXLAN_FLOOD_PIM_SM, "PIM-SM"},
	{VXLAN_FLOOD_HEAD_END_REPL, "HER"},
	{0}
};

/* PJDR: find a way to share this */
extern void zevi_l3vni_cleanup(struct zebra_vrf *zvrf, zebra_evi_t *zevi);

static int zevi_del(zebra_evi_t *zevi);
static int zevi_vtep_match(struct in_addr *vtep_ip, zebra_vtep_t *zvtep);
static zebra_vtep_t *zevi_vtep_find(zebra_evi_t *zevi, struct in_addr *vtep_ip);
static zebra_vtep_t *zevi_vtep_add(zebra_evi_t *zevi, struct in_addr *vtep_ip,
				   int flood_control);
static int zevi_vtep_del(zebra_evi_t *zevi, zebra_vtep_t *zvtep);
static int zevi_vtep_del_all(zebra_evi_t *zevi, int uninstall);
static int zevi_vtep_install(zebra_evi_t *zevi, zebra_vtep_t *zvtep);
static int zevi_vtep_uninstall(zebra_evi_t *zevi, struct in_addr *vtep_ip);
static int zevi_del_macip_for_intf(struct interface *ifp, zebra_evi_t *zevi);
static int zevi_add_macip_for_intf(struct interface *ifp, zebra_evi_t *zevi);
static int zevi_gw_macip_add(struct interface *ifp, zebra_evi_t *zevi,
			     struct ethaddr *macaddr, struct ipaddr *ip);
static int zevi_gw_macip_del(struct interface *ifp, zebra_evi_t *zevi,
			     struct ipaddr *ip);

int advertise_gw_macip_enabled(zebra_evi_t *zevi)
{
	struct zebra_vrf *zvrf;

	zvrf = zebra_vrf_get_evpn();
	if (zvrf && zvrf->advertise_gw_macip)
		return 1;

	if (zevi && zevi->advertise_gw_macip)
		return 1;

	return 0;
}

int advertise_svi_macip_enabled(zebra_evi_t *zevi)
{
	struct zebra_vrf *zvrf;

	zvrf = zebra_vrf_get_evpn();
	if (zvrf && zvrf->advertise_svi_macip)
		return 1;

	if (zevi && zevi->advertise_svi_macip)
		return 1;

	return 0;
}

/*
 * Print a specific VNI entry.
 */
void zevi_print(zebra_evi_t *zevi, void **ctxt)
{
	struct vty *vty;
	zebra_vtep_t *zvtep;
	uint32_t num_macs;
	uint32_t num_neigh;
	json_object *json = NULL;
	json_object *json_vtep_list = NULL;
	json_object *json_ip_str = NULL;

	vty = ctxt[0];
	json = ctxt[1];

	if (json == NULL) {
		vty_out(vty, "VNI: %u\n", zevi->vni);
		vty_out(vty, " Type: %s\n", "L2");
		vty_out(vty, " Tenant VRF: %s\n", vrf_id_to_name(zevi->vrf_id));
	} else {
		json_object_int_add(json, "vni", zevi->vni);
		json_object_string_add(json, "type", "L2");
		json_object_string_add(json, "vrf",
				       vrf_id_to_name(zevi->vrf_id));
	}

	if (!zevi->vxlan_if) { // unexpected
		if (json == NULL)
			vty_out(vty, " VxLAN interface: unknown\n");
		return;
	}
	num_macs = num_valid_macs(zevi);
	num_neigh = hashcount(zevi->neigh_table);
	if (json == NULL) {
		vty_out(vty, " VxLAN interface: %s\n", zevi->vxlan_if->name);
		vty_out(vty, " VxLAN ifIndex: %u\n", zevi->vxlan_if->ifindex);
		vty_out(vty, " Local VTEP IP: %s\n",
			inet_ntoa(zevi->local_vtep_ip));
		vty_out(vty, " Mcast group: %s\n", inet_ntoa(zevi->mcast_grp));
	} else {
		json_object_string_add(json, "vxlanInterface",
				       zevi->vxlan_if->name);
		json_object_int_add(json, "ifindex", zevi->vxlan_if->ifindex);
		json_object_string_add(json, "vtepIp",
				       inet_ntoa(zevi->local_vtep_ip));
		json_object_string_add(json, "mcastGroup",
				       inet_ntoa(zevi->mcast_grp));
		json_object_string_add(json, "advertiseGatewayMacip",
				       zevi->advertise_gw_macip ? "Yes" : "No");
		json_object_int_add(json, "numMacs", num_macs);
		json_object_int_add(json, "numArpNd", num_neigh);
	}
	if (!zevi->vteps) {
		if (json == NULL)
			vty_out(vty, " No remote VTEPs known for this VNI\n");
	} else {
		if (json == NULL)
			vty_out(vty, " Remote VTEPs for this VNI:\n");
		else
			json_vtep_list = json_object_new_array();
		for (zvtep = zevi->vteps; zvtep; zvtep = zvtep->next) {
			const char *flood_str = lookup_msg(
				zvtep_flood_str, zvtep->flood_control,
				VXLAN_FLOOD_STR_DEFAULT);

			if (json == NULL) {
				vty_out(vty, "  %s flood: %s\n",
					inet_ntoa(zvtep->vtep_ip), flood_str);
			} else {
				json_ip_str = json_object_new_string(
					inet_ntoa(zvtep->vtep_ip));
				json_object_array_add(json_vtep_list,
						      json_ip_str);
			}
		}
		if (json)
			json_object_object_add(json, "numRemoteVteps",
					       json_vtep_list);
	}
	if (json == NULL) {
		vty_out(vty,
			" Number of MACs (local and remote) known for this VNI: %u\n",
			num_macs);
		vty_out(vty,
			" Number of ARPs (IPv4 and IPv6, local and remote) "
			"known for this VNI: %u\n",
			num_neigh);
		vty_out(vty, " Advertise-gw-macip: %s\n",
			zevi->advertise_gw_macip ? "Yes" : "No");
	}
}

/* Private Structure to pass callback data for hash iterator */
struct zevi_evpn_show {
	struct vty *vty;
	json_object *json;
	struct zebra_vrf *zvrf;
	bool use_json;
};

/*
 * Print a VNI hash entry - called for display of all VNIs.
 */
void zevi_print_hash(struct hash_bucket *bucket, void *ctxt[])
{
	struct vty *vty;
	zebra_evi_t *zevi;
	zebra_vtep_t *zvtep;
	uint32_t num_vteps = 0;
	uint32_t num_macs = 0;
	uint32_t num_neigh = 0;
	json_object *json = NULL;
	json_object *json_vni = NULL;
	json_object *json_ip_str = NULL;
	json_object *json_vtep_list = NULL;

	vty = ctxt[0];
	json = ctxt[1];

	zevi = (zebra_evi_t *)bucket->data;

	zvtep = zevi->vteps;
	while (zvtep) {
		num_vteps++;
		zvtep = zvtep->next;
	}

	num_macs = num_valid_macs(zevi);
	num_neigh = hashcount(zevi->neigh_table);
	if (json == NULL)
		vty_out(vty, "%-10u %-4s %-21s %-8u %-8u %-15u %-37s\n",
			zevi->vni, "L2",
			zevi->vxlan_if ? zevi->vxlan_if->name : "unknown",
			num_macs, num_neigh, num_vteps,
			vrf_id_to_name(zevi->vrf_id));
	else {
		char vni_str[VNI_STR_LEN];
		snprintf(vni_str, VNI_STR_LEN, "%u", zevi->vni);
		json_vni = json_object_new_object();
		json_object_int_add(json_vni, "vni", zevi->vni);
		json_object_string_add(json_vni, "type", "L2");
		json_object_string_add(json_vni, "vxlanIf",
				       zevi->vxlan_if ? zevi->vxlan_if->name
						      : "unknown");
		json_object_int_add(json_vni, "numMacs", num_macs);
		json_object_int_add(json_vni, "numArpNd", num_neigh);
		json_object_int_add(json_vni, "numRemoteVteps", num_vteps);
		json_object_string_add(json_vni, "tenantVrf",
				       vrf_id_to_name(zevi->vrf_id));
		if (num_vteps) {
			json_vtep_list = json_object_new_array();
			for (zvtep = zevi->vteps; zvtep; zvtep = zvtep->next) {
				json_ip_str = json_object_new_string(
					inet_ntoa(zvtep->vtep_ip));
				json_object_array_add(json_vtep_list,
						      json_ip_str);
			}
			json_object_object_add(json_vni, "remoteVteps",
					       json_vtep_list);
		}
		json_object_object_add(json, vni_str, json_vni);
	}
}

/*
 * Print a VNI hash entry in detail - called for display of all VNIs.
 */
void zevi_print_hash_detail(struct hash_bucket *bucket, void *data)
{
	struct vty *vty;
	zebra_evi_t *zevi;
	json_object *json_array = NULL;
	bool use_json = false;
	struct zevi_evpn_show *zes = data;

	vty = zes->vty;
	json_array = zes->json;
	use_json = zes->use_json;

	zevi = (zebra_evi_t *)bucket->data;

	zebra_vxlan_print_vni(vty, zes->zvrf, zevi->vni, use_json, json_array);

	if (!use_json)
		vty_out(vty, "\n");
}

static int zevi_del_macip_for_intf(struct interface *ifp, zebra_evi_t *zevi)
{
	struct listnode *cnode = NULL, *cnnode = NULL;
	struct connected *c = NULL;
	struct ethaddr macaddr;

	memcpy(&macaddr.octet, ifp->hw_addr, ETH_ALEN);

	for (ALL_LIST_ELEMENTS(ifp->connected, cnode, cnnode, c)) {
		struct ipaddr ip;

		memset(&ip, 0, sizeof(struct ipaddr));
		if (!CHECK_FLAG(c->conf, ZEBRA_IFC_REAL))
			continue;

		if (c->address->family == AF_INET) {
			ip.ipa_type = IPADDR_V4;
			memcpy(&(ip.ipaddr_v4), &(c->address->u.prefix4),
			       sizeof(struct in_addr));
		} else if (c->address->family == AF_INET6) {
			ip.ipa_type = IPADDR_V6;
			memcpy(&(ip.ipaddr_v6), &(c->address->u.prefix6),
			       sizeof(struct in6_addr));
		} else {
			continue;
		}

		zevi_gw_macip_del(ifp, zevi, &ip);
	}

	return 0;
}

static int zevi_add_macip_for_intf(struct interface *ifp, zebra_evi_t *zevi)
{
	struct listnode *cnode = NULL, *cnnode = NULL;
	struct connected *c = NULL;
	struct ethaddr macaddr;

	memcpy(&macaddr.octet, ifp->hw_addr, ETH_ALEN);

	for (ALL_LIST_ELEMENTS(ifp->connected, cnode, cnnode, c)) {
		struct ipaddr ip;

		memset(&ip, 0, sizeof(struct ipaddr));
		if (!CHECK_FLAG(c->conf, ZEBRA_IFC_REAL))
			continue;

		if (c->address->family == AF_INET) {
			ip.ipa_type = IPADDR_V4;
			memcpy(&(ip.ipaddr_v4), &(c->address->u.prefix4),
			       sizeof(struct in_addr));
		} else if (c->address->family == AF_INET6) {
			ip.ipa_type = IPADDR_V6;
			memcpy(&(ip.ipaddr_v6), &(c->address->u.prefix6),
			       sizeof(struct in6_addr));
		} else {
			continue;
		}

		zevi_gw_macip_add(ifp, zevi, &macaddr, &ip);
	}
	return 0;
}


static int ip_prefix_send_to_client(vrf_id_t vrf_id, struct prefix *p,
				    uint16_t cmd)
{
	struct zserv *client = NULL;
	struct stream *s = NULL;
	char buf[PREFIX_STRLEN];

	client = zserv_find_client(ZEBRA_ROUTE_BGP, 0);
	/* BGP may not be running. */
	if (!client)
		return 0;

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, cmd, vrf_id);
	stream_put(s, p, sizeof(struct prefix));

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Send ip prefix %s %s on vrf %s",
			   prefix2str(p, buf, sizeof(buf)),
			   (cmd == ZEBRA_IP_PREFIX_ROUTE_ADD) ? "ADD" : "DEL",
			   vrf_id_to_name(vrf_id));

	if (cmd == ZEBRA_IP_PREFIX_ROUTE_ADD)
		client->prefixadd_cnt++;
	else
		client->prefixdel_cnt++;

	return zserv_send_message(client, s);
}

int zevi_advertise_subnet(zebra_evi_t *zevi, struct interface *ifp,
			  int advertise)
{
	struct listnode *cnode = NULL, *cnnode = NULL;
	struct connected *c = NULL;
	struct ethaddr macaddr;

	memcpy(&macaddr.octet, ifp->hw_addr, ETH_ALEN);

	for (ALL_LIST_ELEMENTS(ifp->connected, cnode, cnnode, c)) {
		struct prefix p;

		memcpy(&p, c->address, sizeof(struct prefix));

		/* skip link local address */
		if (IN6_IS_ADDR_LINKLOCAL(&p.u.prefix6))
			continue;

		apply_mask(&p);
		if (advertise)
			ip_prefix_send_to_client(ifp->vrf_id, &p,
						 ZEBRA_IP_PREFIX_ROUTE_ADD);
		else
			ip_prefix_send_to_client(ifp->vrf_id, &p,
						 ZEBRA_IP_PREFIX_ROUTE_DEL);
	}
	return 0;
}

/*
 * zevi_gw_macip_add_to_client
 */
static int zevi_gw_macip_add(struct interface *ifp, zebra_evi_t *zevi,
			     struct ethaddr *macaddr, struct ipaddr *ip)
{
	zebra_mac_t *mac = NULL;
	struct zebra_if *zif = NULL;
	struct zebra_l2info_vxlan *vxl = NULL;

	zif = zevi->vxlan_if->info;
	if (!zif)
		return -1;

	vxl = &zif->l2info.vxl;

	mac = zebra_evpn_mac_lookup(zevi, macaddr);

	if (zebra_evpn_mac_gw_macip_add(ifp, zevi, ip, mac, macaddr,
					vxl->access_vlan)
	    != 0)
		return -1;

	return zebra_evpn_neigh_gw_macip_add(ifp, zevi, ip, mac);
}

/*
 * zevi_gw_macip_del_from_client
 */
static int zevi_gw_macip_del(struct interface *ifp, zebra_evi_t *zevi,
			     struct ipaddr *ip)
{
	char buf1[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];
	zebra_neigh_t *n = NULL;
	zebra_mac_t *mac = NULL;

	/* If the neigh entry is not present nothing to do*/
	n = zevi_neigh_lookup(zevi, ip);
	if (!n)
		return 0;

	/* mac entry should be present */
	mac = zebra_evpn_mac_lookup(zevi, &n->emac);
	if (!mac) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"MAC %s doesn't exist for neigh %s on VNI %u",
				prefix_mac2str(&n->emac, buf1, sizeof(buf1)),
				ipaddr2str(ip, buf2, sizeof(buf2)), zevi->vni);
		return -1;
	}

	/* If the entry is not local nothing to do*/
	if (!CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL))
		return -1;

	/* only need to delete the entry from bgp if we sent it before */
	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"%u:SVI %s(%u) VNI %u, sending GW MAC %s IP %s del to BGP",
			ifp->vrf_id, ifp->name, ifp->ifindex, zevi->vni,
			prefix_mac2str(&(n->emac), buf1, sizeof(buf1)),
			ipaddr2str(ip, buf2, sizeof(buf2)));

	/* Remove neighbor from BGP. */
	zevi_neigh_send_del_to_client(zevi, &n->ip, &n->emac, n->flags,
				      ZEBRA_NEIGH_ACTIVE, false /*force*/);

	/* Delete this neighbor entry. */
	zevi_neigh_del(zevi, n);

	/* see if the mac needs to be deleted as well*/
	if (mac)
		zevi_deref_ip2mac(zevi, mac);

	return 0;
}

void zevi_gw_macip_del_for_vni_hash(struct hash_bucket *bucket, void *ctxt)
{
	zebra_evi_t *zevi = NULL;
	struct zebra_if *zif = NULL;
	struct zebra_l2info_vxlan zl2_info;
	struct interface *vlan_if = NULL;
	struct interface *vrr_if = NULL;
	struct interface *ifp;

	/* Add primary SVI MAC*/
	zevi = (zebra_evi_t *)bucket->data;

	/* Global (Zvrf) advertise-default-gw is disabled,
	 * but zevi advertise-default-gw is enabled
	 */
	if (zevi->advertise_gw_macip) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("VNI: %u GW-MACIP enabled, retain gw-macip",
				   zevi->vni);
		return;
	}

	ifp = zevi->vxlan_if;
	if (!ifp)
		return;
	zif = ifp->info;

	/* If down or not mapped to a bridge, we're done. */
	if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
		return;

	zl2_info = zif->l2info.vxl;

	vlan_if =
		zvni_map_to_svi(zl2_info.access_vlan, zif->brslave_info.br_if);
	if (!vlan_if)
		return;

	/* Del primary MAC-IP */
	zevi_del_macip_for_intf(vlan_if, zevi);

	/* Del VRR MAC-IP - if any*/
	vrr_if = zebra_get_vrr_intf_for_svi(vlan_if);
	if (vrr_if)
		zevi_del_macip_for_intf(vrr_if, zevi);

	return;
}

void zevi_gw_macip_add_for_vni_hash(struct hash_bucket *bucket, void *ctxt)
{
	zebra_evi_t *zevi = NULL;
	struct zebra_if *zif = NULL;
	struct zebra_l2info_vxlan zl2_info;
	struct interface *vlan_if = NULL;
	struct interface *vrr_if = NULL;
	struct interface *ifp = NULL;

	zevi = (zebra_evi_t *)bucket->data;

	ifp = zevi->vxlan_if;
	if (!ifp)
		return;
	zif = ifp->info;

	/* If down or not mapped to a bridge, we're done. */
	if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
		return;
	zl2_info = zif->l2info.vxl;

	vlan_if =
		zvni_map_to_svi(zl2_info.access_vlan, zif->brslave_info.br_if);
	if (!vlan_if)
		return;

	/* Add primary SVI MAC-IP */
	zevi_add_macip_for_intf(vlan_if, zevi);

	if (advertise_gw_macip_enabled(zevi)) {
		/* Add VRR MAC-IP - if any*/
		vrr_if = zebra_get_vrr_intf_for_svi(vlan_if);
		if (vrr_if)
			zevi_add_macip_for_intf(vrr_if, zevi);
	}

	return;
}

void zevi_svi_macip_del_for_vni_hash(struct hash_bucket *bucket, void *ctxt)
{
	zebra_evi_t *zevi = NULL;
	struct zebra_if *zif = NULL;
	struct zebra_l2info_vxlan zl2_info;
	struct interface *vlan_if = NULL;
	struct interface *ifp;

	/* Add primary SVI MAC*/
	zevi = (zebra_evi_t *)bucket->data;
	if (!zevi)
		return;

	/* Global(vrf) advertise-svi-ip disabled, but zevi advertise-svi-ip
	 * enabled
	 */
	if (zevi->advertise_svi_macip) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"VNI: %u SVI-MACIP enabled, retain svi-macip",
				zevi->vni);
		return;
	}

	ifp = zevi->vxlan_if;
	if (!ifp)
		return;
	zif = ifp->info;

	/* If down or not mapped to a bridge, we're done. */
	if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
		return;

	zl2_info = zif->l2info.vxl;

	vlan_if =
		zvni_map_to_svi(zl2_info.access_vlan, zif->brslave_info.br_if);
	if (!vlan_if)
		return;

	/* Del primary MAC-IP */
	zevi_del_macip_for_intf(vlan_if, zevi);

	return;
}

/*
 * Map port or (port, VLAN) to a VNI. This is invoked upon getting MAC
 * notifications, to see if they are of interest.
 */
zebra_evi_t *zevi_map_vlan(struct interface *ifp, struct interface *br_if,
			   vlanid_t vid)
{
	struct zebra_ns *zns;
	struct route_node *rn;
	struct interface *tmp_if = NULL;
	struct zebra_if *zif;
	struct zebra_l2info_bridge *br;
	struct zebra_l2info_vxlan *vxl = NULL;
	uint8_t bridge_vlan_aware;
	zebra_evi_t *zevi;
	int found = 0;

	/* Determine if bridge is VLAN-aware or not */
	zif = br_if->info;
	assert(zif);
	br = &zif->l2info.br;
	bridge_vlan_aware = br->vlan_aware;

	/* See if this interface (or interface plus VLAN Id) maps to a VxLAN */
	/* TODO: Optimize with a hash. */
	zns = zebra_ns_lookup(NS_DEFAULT);
	for (rn = route_top(zns->if_table); rn; rn = route_next(rn)) {
		tmp_if = (struct interface *)rn->info;
		if (!tmp_if)
			continue;
		zif = tmp_if->info;
		if (!zif || zif->zif_type != ZEBRA_IF_VXLAN)
			continue;
		if (!if_is_operative(tmp_if))
			continue;
		vxl = &zif->l2info.vxl;

		if (zif->brslave_info.br_if != br_if)
			continue;

		if (!bridge_vlan_aware || vxl->access_vlan == vid) {
			found = 1;
			break;
		}
	}

	if (!found)
		return NULL;

	zevi = zevi_lookup(vxl->vni);
	return zevi;
}

/*
 * Map SVI and associated bridge to a VNI. This is invoked upon getting
 * neighbor notifications, to see if they are of interest.
 */
zebra_evi_t *zevi_from_svi(struct interface *ifp, struct interface *br_if)
{
	struct zebra_ns *zns;
	struct route_node *rn;
	struct interface *tmp_if = NULL;
	struct zebra_if *zif;
	struct zebra_l2info_bridge *br;
	struct zebra_l2info_vxlan *vxl = NULL;
	uint8_t bridge_vlan_aware;
	vlanid_t vid = 0;
	zebra_evi_t *zevi;
	int found = 0;

	if (!br_if)
		return NULL;

	/* Make sure the linked interface is a bridge. */
	if (!IS_ZEBRA_IF_BRIDGE(br_if))
		return NULL;

	/* Determine if bridge is VLAN-aware or not */
	zif = br_if->info;
	assert(zif);
	br = &zif->l2info.br;
	bridge_vlan_aware = br->vlan_aware;
	if (bridge_vlan_aware) {
		struct zebra_l2info_vlan *vl;

		if (!IS_ZEBRA_IF_VLAN(ifp))
			return NULL;

		zif = ifp->info;
		assert(zif);
		vl = &zif->l2info.vl;
		vid = vl->vid;
	}

	/* See if this interface (or interface plus VLAN Id) maps to a VxLAN */
	/* TODO: Optimize with a hash. */
	zns = zebra_ns_lookup(NS_DEFAULT);
	for (rn = route_top(zns->if_table); rn; rn = route_next(rn)) {
		tmp_if = (struct interface *)rn->info;
		if (!tmp_if)
			continue;
		zif = tmp_if->info;
		if (!zif || zif->zif_type != ZEBRA_IF_VXLAN)
			continue;
		if (!if_is_operative(tmp_if))
			continue;
		vxl = &zif->l2info.vxl;

		if (zif->brslave_info.br_if != br_if)
			continue;

		if (!bridge_vlan_aware || vxl->access_vlan == vid) {
			found = 1;
			break;
		}
	}

	if (!found)
		return NULL;

	zevi = zevi_lookup(vxl->vni);
	return zevi;
}


struct interface *zevi_map_to_svi(zebra_evi_t *zevi)
{
	struct interface *ifp;
	struct zebra_if *zif = NULL;
	struct zebra_l2info_vxlan zl2_info;

	ifp = zevi->vxlan_if;
	if (!ifp)
		return NULL;
	zif = ifp->info;
	if (!zif)
		return NULL;

	/* If down or not mapped to a bridge, we're done. */
	if (!if_is_operative(ifp) || !zif->brslave_info.br_if)
		return NULL;
	zl2_info = zif->l2info.vxl;
	return zvni_map_to_svi(zl2_info.access_vlan, zif->brslave_info.br_if);
}

/* Map to MAC-VLAN interface corresponding to specified SVI interface.
 */
struct interface *zevi_map_to_macvlan(struct interface *br_if,
				      struct interface *svi_if)
{
	struct zebra_ns *zns;
	struct route_node *rn;
	struct interface *tmp_if = NULL;
	struct zebra_if *zif;
	int found = 0;

	/* Defensive check, caller expected to invoke only with valid bridge. */
	if (!br_if)
		return NULL;

	if (!svi_if) {
		zlog_debug("svi_if is not passed.");
		return NULL;
	}

	/* Determine if bridge is VLAN-aware or not */
	zif = br_if->info;
	assert(zif);

	/* Identify corresponding VLAN interface. */
	zns = zebra_ns_lookup(NS_DEFAULT);
	for (rn = route_top(zns->if_table); rn; rn = route_next(rn)) {
		tmp_if = (struct interface *)rn->info;
		/* Check oper status of the SVI. */
		if (!tmp_if || !if_is_operative(tmp_if))
			continue;
		zif = tmp_if->info;

		if (!zif || zif->zif_type != ZEBRA_IF_MACVLAN)
			continue;

		if (zif->link == svi_if) {
			found = 1;
			break;
		}
	}

	return found ? tmp_if : NULL;
}

/*
 * Install MAC hash entry - called upon access VLAN change.
 */
void zevi_install_mac_hash(struct hash_bucket *bucket, void *ctxt)
{
	zebra_mac_t *mac;
	struct mac_walk_ctx *wctx = ctxt;

	mac = (zebra_mac_t *)bucket->data;

	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE))
		zevi_rem_mac_install(wctx->zevi, mac, false);
}

/*
 * Read and populate local MACs and neighbors corresponding to this VNI.
 */
void zevi_read_mac_neigh(zebra_evi_t *zevi, struct interface *ifp)
{
	struct zebra_ns *zns;
	struct zebra_if *zif;
	struct interface *vlan_if;
	struct zebra_l2info_vxlan *vxl;
	struct interface *vrr_if;

	zif = ifp->info;
	vxl = &zif->l2info.vxl;
	zns = zebra_ns_lookup(NS_DEFAULT);

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug(
			"Reading MAC FDB and Neighbors for intf %s(%u) VNI %u master %u",
			ifp->name, ifp->ifindex, zevi->vni,
			zif->brslave_info.bridge_ifindex);

	macfdb_read_for_bridge(zns, ifp, zif->brslave_info.br_if);
	vlan_if = zvni_map_to_svi(vxl->access_vlan, zif->brslave_info.br_if);
	if (vlan_if) {

		/* Add SVI MAC-IP */
		zevi_add_macip_for_intf(vlan_if, zevi);

		/* Add VRR MAC-IP - if any*/
		vrr_if = zebra_get_vrr_intf_for_svi(vlan_if);
		if (vrr_if)
			zevi_add_macip_for_intf(vrr_if, zevi);

		neigh_read_for_vlan(zns, vlan_if);
	}
}

/*
 * Hash function for VNI.
 */
unsigned int vni_hash_keymake(const void *p)
{
	const zebra_evi_t *zevi = p;

	return (jhash_1word(zevi->vni, 0));
}

/*
 * Compare 2 VNI hash entries.
 */
bool vni_hash_cmp(const void *p1, const void *p2)
{
	const zebra_evi_t *zevi1 = p1;
	const zebra_evi_t *zevi2 = p2;

	return (zevi1->vni == zevi2->vni);
}

int vni_list_cmp(void *p1, void *p2)
{
	const zebra_evi_t *zevi1 = p1;
	const zebra_evi_t *zevi2 = p2;

	if (zevi1->vni == zevi2->vni)
		return 0;
	return (zevi1->vni < zevi2->vni) ? -1 : 1;
}

/*
 * Callback to allocate VNI hash entry.
 */
void *zevi_alloc(void *p)
{
	const zebra_evi_t *tmp_vni = p;
	zebra_evi_t *zevi;

	zevi = XCALLOC(MTYPE_ZEVI, sizeof(zebra_evi_t));
	zevi->vni = tmp_vni->vni;
	return ((void *)zevi);
}

/*
 * Look up VNI hash entry.
 */
zebra_evi_t *zevi_lookup(vni_t vni)
{
	struct zebra_vrf *zvrf;
	zebra_evi_t tmp_vni;
	zebra_evi_t *zevi = NULL;

	zvrf = zebra_vrf_get_evpn();
	assert(zvrf);
	memset(&tmp_vni, 0, sizeof(zebra_evi_t));
	tmp_vni.vni = vni;
	zevi = hash_lookup(zvrf->vni_table, &tmp_vni);

	return zevi;
}

/*
 * Add VNI hash entry.
 */
zebra_evi_t *zevi_add(vni_t vni)
{
	struct zebra_vrf *zvrf;
	zebra_evi_t tmp_zevi;
	zebra_evi_t *zevi = NULL;

	zvrf = zebra_vrf_get_evpn();
	assert(zvrf);
	memset(&tmp_zevi, 0, sizeof(zebra_evi_t));
	tmp_zevi.vni = vni;
	zevi = hash_get(zvrf->vni_table, &tmp_zevi, zevi_alloc);
	assert(zevi);

	zebra_evpn_vni_es_init(zevi);

	/* Create hash table for MAC */
	zevi->mac_table = zebra_mac_db_create("Zebra VNI MAC Table");

	/* Create hash table for neighbors */
	zevi->neigh_table = zebra_neigh_db_create("Zebra VNI Neighbor Table");

	return zevi;
}

/* vni<=>vxlan_zif association */
static void zevi_vxlan_if_set(zebra_evi_t *zevi, struct interface *ifp,
			      bool set)
{
	struct zebra_if *zif;

	if (set) {
		if (zevi->vxlan_if == ifp)
			return;
		zevi->vxlan_if = ifp;
	} else {
		if (!zevi->vxlan_if)
			return;
		zevi->vxlan_if = NULL;
	}

	if (ifp)
		zif = ifp->info;
	else
		zif = NULL;

	zebra_evpn_vxl_vni_set(zif, zevi, set);
}

/*
 * Delete VNI hash entry.
 */
static int zevi_del(zebra_evi_t *zevi)
{
	struct zebra_vrf *zvrf;
	zebra_evi_t *tmp_zevi;

	zvrf = zebra_vrf_get_evpn();
	assert(zvrf);

	zevi_vxlan_if_set(zevi, zevi->vxlan_if, false /* set */);

	/* Remove references to the BUM mcast grp */
	zebra_vxlan_sg_deref(zevi->local_vtep_ip, zevi->mcast_grp);

	/* Free the neighbor hash table. */
	hash_free(zevi->neigh_table);
	zevi->neigh_table = NULL;

	/* Free the MAC hash table. */
	hash_free(zevi->mac_table);
	zevi->mac_table = NULL;

	zebra_evpn_vni_es_cleanup(zevi);

	/* Free the VNI hash entry and allocated memory. */
	tmp_zevi = hash_release(zvrf->vni_table, zevi);
	XFREE(MTYPE_ZEVI, tmp_zevi);

	return 0;
}

/*
 * Inform BGP about local VNI addition.
 */
int zevi_send_add_to_client(zebra_evi_t *zevi)
{
	struct zserv *client;
	struct stream *s;
	int rc;

	client = zserv_find_client(ZEBRA_ROUTE_BGP, 0);
	/* BGP may not be running. */
	if (!client)
		return 0;

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);

	zclient_create_header(s, ZEBRA_VNI_ADD, zebra_vrf_get_evpn_id());
	stream_putl(s, zevi->vni);
	stream_put_in_addr(s, &zevi->local_vtep_ip);
	stream_put(s, &zevi->vrf_id, sizeof(vrf_id_t)); /* tenant vrf */
	stream_put_in_addr(s, &zevi->mcast_grp);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Send VNI_ADD %u %s tenant vrf %s to %s", zevi->vni,
			   inet_ntoa(zevi->local_vtep_ip),
			   vrf_id_to_name(zevi->vrf_id),
			   zebra_route_string(client->proto));

	client->vniadd_cnt++;
	rc = zserv_send_message(client, s);

	if (!(zevi->flags & ZEVI_READY_FOR_BGP)) {
		zevi->flags |= ZEVI_READY_FOR_BGP;
		/* once the VNI is sent the ES-EVIs can also be replayed
		 * to BGP
		 */
		zebra_evpn_vni_update_all_es(zevi);
	}
	return rc;
}

/*
 * Inform BGP about local VNI deletion.
 */
int zevi_send_del_to_client(zebra_evi_t *zevi)
{
	struct zserv *client;
	struct stream *s;

	client = zserv_find_client(ZEBRA_ROUTE_BGP, 0);
	/* BGP may not be running. */
	if (!client)
		return 0;

	if (zevi->flags & ZEVI_READY_FOR_BGP) {
		zevi->flags &= ~ZEVI_READY_FOR_BGP;
		/* the ES-EVIs must be removed from BGP before the VNI is */
		zebra_evpn_vni_update_all_es(zevi);
	}

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);
	stream_reset(s);

	zclient_create_header(s, ZEBRA_VNI_DEL, zebra_vrf_get_evpn_id());
	stream_putl(s, zevi->vni);

	/* Write packet size. */
	stream_putw_at(s, 0, stream_get_endp(s));

	if (IS_ZEBRA_DEBUG_VXLAN)
		zlog_debug("Send VNI_DEL %u to %s", zevi->vni,
			   zebra_route_string(client->proto));

	client->vnidel_cnt++;
	return zserv_send_message(client, s);
}

/*
 * See if remote VTEP matches with prefix.
 */
static int zevi_vtep_match(struct in_addr *vtep_ip, zebra_vtep_t *zvtep)
{
	return (IPV4_ADDR_SAME(vtep_ip, &zvtep->vtep_ip));
}

/*
 * Locate remote VTEP in VNI hash table.
 */
static zebra_vtep_t *zevi_vtep_find(zebra_evi_t *zevi, struct in_addr *vtep_ip)
{
	zebra_vtep_t *zvtep;

	if (!zevi)
		return NULL;

	for (zvtep = zevi->vteps; zvtep; zvtep = zvtep->next) {
		if (zevi_vtep_match(vtep_ip, zvtep))
			break;
	}

	return zvtep;
}

/*
 * Add remote VTEP to VNI hash table.
 */
static zebra_vtep_t *zevi_vtep_add(zebra_evi_t *zevi, struct in_addr *vtep_ip,
				   int flood_control)

{
	zebra_vtep_t *zvtep;

	zvtep = XCALLOC(MTYPE_ZEVI_VTEP, sizeof(zebra_vtep_t));

	zvtep->vtep_ip = *vtep_ip;
	zvtep->flood_control = flood_control;

	if (zevi->vteps)
		zevi->vteps->prev = zvtep;
	zvtep->next = zevi->vteps;
	zevi->vteps = zvtep;

	return zvtep;
}

/*
 * Remove remote VTEP from VNI hash table.
 */
static int zevi_vtep_del(zebra_evi_t *zevi, zebra_vtep_t *zvtep)
{
	if (zvtep->next)
		zvtep->next->prev = zvtep->prev;
	if (zvtep->prev)
		zvtep->prev->next = zvtep->next;
	else
		zevi->vteps = zvtep->next;

	zvtep->prev = zvtep->next = NULL;
	XFREE(MTYPE_ZEVI_VTEP, zvtep);

	return 0;
}

/*
 * Delete all remote VTEPs for this VNI (upon VNI delete). Also
 * uninstall from kernel if asked to.
 */
static int zevi_vtep_del_all(zebra_evi_t *zevi, int uninstall)
{
	zebra_vtep_t *zvtep, *zvtep_next;

	if (!zevi)
		return -1;

	for (zvtep = zevi->vteps; zvtep; zvtep = zvtep_next) {
		zvtep_next = zvtep->next;
		if (uninstall)
			zevi_vtep_uninstall(zevi, &zvtep->vtep_ip);
		zevi_vtep_del(zevi, zvtep);
	}

	return 0;
}

/*
 * Install remote VTEP into the kernel if the remote VTEP has asked
 * for head-end-replication.
 */
static int zevi_vtep_install(zebra_evi_t *zevi, zebra_vtep_t *zvtep)
{
	if (is_vxlan_flooding_head_end() &&
	    (zvtep->flood_control == VXLAN_FLOOD_HEAD_END_REPL)) {
		if (ZEBRA_DPLANE_REQUEST_FAILURE
		    == dplane_vtep_add(zevi->vxlan_if, &zvtep->vtep_ip,
				       zevi->vni))
			return -1;
	}

	return 0;
}

/*
 * Uninstall remote VTEP from the kernel.
 */
static int zevi_vtep_uninstall(zebra_evi_t *zevi, struct in_addr *vtep_ip)
{
	if (!zevi->vxlan_if) {
		zlog_debug("VNI %u hash %p couldn't be uninstalled - no intf",
			   zevi->vni, zevi);
		return -1;
	}

	if (ZEBRA_DPLANE_REQUEST_FAILURE
	    == dplane_vtep_delete(zevi->vxlan_if, vtep_ip, zevi->vni))
		return -1;

	return 0;
}

/*
 * Install or uninstall flood entries in the kernel corresponding to
 * remote VTEPs. This is invoked upon change to BUM handling.
 */
void zevi_handle_flooding_remote_vteps(struct hash_bucket *bucket, void *zvrf)
{
	zebra_evi_t *zevi;
	zebra_vtep_t *zvtep;

	zevi = (zebra_evi_t *)bucket->data;
	if (!zevi)
		return;

	for (zvtep = zevi->vteps; zvtep; zvtep = zvtep->next) {
		if (is_vxlan_flooding_head_end())
			zevi_vtep_install(zevi, zvtep);
		else
			zevi_vtep_uninstall(zevi, &zvtep->vtep_ip);
	}
}

/*
 * Cleanup VNI/VTEP and update kernel
 */
void zevi_cleanup_all(struct hash_bucket *bucket, void *arg)
{
	zebra_evi_t *zevi = NULL;
	struct zebra_vrf *zvrf = (struct zebra_vrf *)arg;

	zevi = (zebra_evi_t *)bucket->data;

	/* remove from l3-vni list */
	zevi_l3vni_cleanup(zvrf, zevi);

	/* Free up all neighbors and MACs, if any. */
	zevi_neigh_del_all(zevi, 1, 0, DEL_ALL_NEIGH);
	zevi_mac_del_all(zevi, 1, 0, DEL_ALL_MAC);

	/* Free up all remote VTEPs, if any. */
	zevi_vtep_del_all(zevi, 1);

	/* Delete the hash entry. */
	zevi_del(zevi);
}

static void
zebra_vxlan_process_sync_macip_add(zebra_evi_t *zevi, struct ethaddr *macaddr,
				   uint16_t ipa_len, struct ipaddr *ipaddr,
				   uint8_t flags, uint32_t seq, esi_t *esi)
{
	struct sync_mac_ip_ctx ctx;
	char macbuf[ETHER_ADDR_STRLEN];
	char ipbuf[INET6_ADDRSTRLEN];
	bool sticky;
	bool remote_gw;
	zebra_neigh_t *n = NULL;

	sticky = !!CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_STICKY);
	remote_gw = !!CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_GW);
	/* if sticky or remote-gw ignore updates from the peer */
	if (sticky || remote_gw) {
		if (IS_ZEBRA_DEBUG_VXLAN || IS_ZEBRA_DEBUG_EVPN_MH_NEIGH
		    || IS_ZEBRA_DEBUG_EVPN_MH_MAC)
			zlog_debug(
				"Ignore sync-macip vni %u mac %s%s%s%s%s",
				zevi->vni,
				prefix_mac2str(macaddr, macbuf, sizeof(macbuf)),
				ipa_len ? " IP " : "",
				ipa_len ? ipaddr2str(ipaddr, ipbuf,
						     sizeof(ipbuf))
					: "",
				sticky ? " sticky" : "",
				remote_gw ? " remote_gw" : "");
		return;
	}

	if (ipa_len) {
		n = zevi_neigh_lookup(zevi, ipaddr);
		if (n && !zebra_evpn_neigh_is_bgp_seq_ok(zevi, n, macaddr, seq))
			return;
	}

	memset(&ctx, 0, sizeof(ctx));
	ctx.mac = zebra_evpn_proc_sync_mac_update(
		zevi, macaddr, ipa_len, ipaddr, flags, seq, esi, &ctx);
	if (ctx.ignore_macip || !ctx.mac || !ipa_len)
		return;

	zebra_evpn_proc_sync_neigh_update(zevi, n, ipa_len, ipaddr, flags, seq,
					  esi, &ctx);
}

/************************** remote mac-ip handling **************************/
/* Process a remote MACIP add from BGP. */

void process_remote_macip_add(vni_t vni, struct ethaddr *macaddr,
			      uint16_t ipa_len, struct ipaddr *ipaddr,
			      uint8_t flags, uint32_t seq,
			      struct in_addr vtep_ip, esi_t *esi)
{
	zebra_evi_t *zevi;
	zebra_vtep_t *zvtep;
	zebra_mac_t *mac = NULL;
	struct interface *ifp = NULL;
	struct zebra_if *zif = NULL;
	struct zebra_vrf *zvrf;

	/* Locate VNI hash entry - expected to exist. */
	zevi = zevi_lookup(vni);
	if (!zevi) {
		zlog_warn("Unknown VNI %u upon remote MACIP ADD", vni);
		return;
	}

	ifp = zevi->vxlan_if;
	if (ifp)
		zif = ifp->info;
	if (!ifp || !if_is_operative(ifp) || !zif || !zif->brslave_info.br_if) {
		zlog_warn(
			"Ignoring remote MACIP ADD VNI %u, invalid interface state or info",
			vni);
		return;
	}

	/* Type-2 routes from another PE can be interpreted as remote or
	 * SYNC based on the destination ES -
	 * SYNC - if ES is local
	 * REMOTE - if ES is not local
	 */
	if (flags & ZEBRA_MACIP_TYPE_SYNC_PATH) {
		zebra_vxlan_process_sync_macip_add(zevi, macaddr, ipa_len,
						   ipaddr, flags, seq, esi);
		return;
	}

	/* The remote VTEP specified should normally exist, but it is
	 * possible that when peering comes up, peer may advertise MACIP
	 * routes before advertising type-3 routes.
	 */
	if (vtep_ip.s_addr) {
		zvtep = zevi_vtep_find(zevi, &vtep_ip);
		if (!zvtep) {
			zvtep = zevi_vtep_add(zevi, &vtep_ip,
					      VXLAN_FLOOD_DISABLED);
			if (!zvtep) {
				flog_err(
					EC_ZEBRA_VTEP_ADD_FAILED,
					"Failed to add remote VTEP, VNI %u zevi %p upon remote MACIP ADD",
					vni, zevi);
				return;
			}

			zevi_vtep_install(zevi, zvtep);
		}
	}


	zvrf = vrf_info_lookup(zevi->vxlan_if->vrf_id);
	if (!zvrf)
		return;

	mac = zebra_evpn_mac_lookup(zevi, macaddr);

	if (process_mac_remote_macip_add(zevi, zvrf, ipa_len, ipaddr, mac,
					 vtep_ip, flags, seq, esi)
	    != 0)
		return;

	process_neigh_remote_macip_add(zevi, zvrf, ipaddr, mac, vtep_ip, flags,
				       seq);
}

/* Process a remote MACIP delete from BGP. */
void process_remote_macip_del(vni_t vni, struct ethaddr *macaddr,
			      uint16_t ipa_len, struct ipaddr *ipaddr,
			      struct in_addr vtep_ip)
{
	zebra_evi_t *zevi;
	zebra_mac_t *mac = NULL;
	zebra_neigh_t *n = NULL;
	struct interface *ifp = NULL;
	struct zebra_if *zif = NULL;
	struct zebra_ns *zns;
	struct zebra_l2info_vxlan *vxl;
	struct zebra_vrf *zvrf;
	char buf[ETHER_ADDR_STRLEN];
	char buf1[INET6_ADDRSTRLEN];

	/* Locate VNI hash entry - expected to exist. */
	zevi = zevi_lookup(vni);
	if (!zevi) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug("Unknown VNI %u upon remote MACIP DEL", vni);
		return;
	}

	ifp = zevi->vxlan_if;
	if (ifp)
		zif = ifp->info;
	if (!ifp || !if_is_operative(ifp) || !zif || !zif->brslave_info.br_if) {
		if (IS_ZEBRA_DEBUG_VXLAN)
			zlog_debug(
				"Ignoring remote MACIP DEL VNI %u, invalid interface state or info",
				vni);
		return;
	}
	zns = zebra_ns_lookup(NS_DEFAULT);
	vxl = &zif->l2info.vxl;

	mac = zebra_evpn_mac_lookup(zevi, macaddr);
	if (ipa_len)
		n = zevi_neigh_lookup(zevi, ipaddr);

	if (n && !mac) {
		zlog_warn(
			"Failed to locate MAC %s for neigh %s VNI %u upon remote MACIP DEL",
			prefix_mac2str(macaddr, buf, sizeof(buf)),
			ipaddr2str(ipaddr, buf1, sizeof(buf1)), vni);
		return;
	}

	/* If the remote mac or neighbor doesn't exist there is nothing
	 * more to do. Otherwise, uninstall the entry and then remove it.
	 */
	if (!mac && !n)
		return;

	zvrf = vrf_info_lookup(zevi->vxlan_if->vrf_id);

	/* Ignore the delete if this mac is a gateway mac-ip */
	if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL)
	    && CHECK_FLAG(mac->flags, ZEBRA_MAC_DEF_GW)) {
		zlog_warn(
			"Ignore remote MACIP DEL VNI %u MAC %s%s%s as MAC is already configured as gateway MAC",
			vni, prefix_mac2str(macaddr, buf, sizeof(buf)),
			ipa_len ? " IP " : "",
			ipa_len ? ipaddr2str(ipaddr, buf1, sizeof(buf1)) : "");
		return;
	}

	/* Uninstall remote neighbor or MAC. */
	if (n)
		zevi_neigh_remote_uninstall(zevi, zvrf, n, mac, ipaddr);
	else {
		/* DAD: when MAC is freeze state as remote learn event,
		 * remote mac-ip delete event is received will result in freeze
		 * entry removal, first fetch kernel for the same entry present
		 * as LOCAL and reachable, avoid deleting this entry instead
		 * use kerenel local entry to update during unfreeze time.
		 */
		if (zvrf->dad_freeze
		    && CHECK_FLAG(mac->flags, ZEBRA_MAC_DUPLICATE)
		    && CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE)) {
			if (IS_ZEBRA_DEBUG_VXLAN)
				zlog_debug(
					"%s: MAC %s (flags 0x%x) is remote and duplicate, read kernel for local entry",
					__func__,
					prefix_mac2str(macaddr, buf,
						       sizeof(buf)),
					mac->flags);
			macfdb_read_specific_mac(zns, zif->brslave_info.br_if,
						 macaddr, vxl->access_vlan);
		}

		if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL)) {
			if (!ipa_len)
				zebra_evpn_sync_mac_del(mac);
		} else if (CHECK_FLAG(mac->flags, ZEBRA_NEIGH_REMOTE)) {
			zebra_evpn_rem_mac_del(zevi, mac);
		}
	}
}

/************************** EVPN BGP config management ************************/


void zevi_evpn_cfg_cleanup(struct hash_bucket *bucket, void *ctxt)
{
	zebra_evi_t *zevi = NULL;

	zevi = (zebra_evi_t *)bucket->data;
	zevi->advertise_gw_macip = 0;
	zevi->advertise_svi_macip = 0;
	zevi->advertise_subnet = 0;

	zevi_neigh_del_all(zevi, 1, 0,
			   DEL_REMOTE_NEIGH | DEL_REMOTE_NEIGH_FROM_VTEP);
	zevi_mac_del_all(zevi, 1, 0, DEL_REMOTE_MAC | DEL_REMOTE_MAC_FROM_VTEP);
	zevi_vtep_del_all(zevi, 1);
}
