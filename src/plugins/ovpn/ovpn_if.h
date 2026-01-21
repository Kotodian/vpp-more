/*
 * ovpn_if.h - OpenVPN interface header file
 *
 * Copyright (c) 2025 <blackfaceuncle@gmail.com>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __included_ovpn_if_h__
#define __included_ovpn_if_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

/* OpenVPN interface instance */
typedef struct ovpn_if_t_
{
  u32 dev_instance;
  u32 user_instance;
  u32 sw_if_index;
  u32 hw_if_index;

  /* Interface name */
  u8 *name; /* Custom interface name (e.g., "tun0") */

  /* Interface configuration */
  ip_address_t local_addr;
  ip_address_t remote_addr;
  u16 local_port;
  u16 remote_port;

  /* Interface flags */
  u8 is_tun;  /* TUN (IP) or TAP (Ethernet) mode */
  u8 is_ipv6; /* IPv4 or IPv6 */

  /* L2 bridge domain for TAP mode */
  u32 bd_index; /* Bridge domain index (~0 if not in BD) */
  u32 bd_id;	/* Bridge domain ID */
} ovpn_if_t;

/* OpenVPN interface main */
typedef struct ovpn_if_main_t_
{
  /* Pool of OpenVPN interfaces */
  ovpn_if_t *ovpn_ifs;

  /* Hash table: dev_instance -> ovpn_if index */
  uword *ovpn_if_index_by_sw_if_index;

  /* Next bridge domain ID for TAP mode (starts from 10000 to avoid conflicts) */
  u32 next_bd_id;

  /* Convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} ovpn_if_main_t;

extern ovpn_if_main_t ovpn_if_main;
extern vnet_device_class_t ovpn_device_class;
extern vnet_hw_interface_class_t ovpn_hw_interface_class;
extern vnet_hw_interface_class_t ovpn_tap_hw_interface_class;

/* API functions */
int ovpn_if_create (vlib_main_t *vm, u8 *name, u8 is_tun, u16 mtu,
		    u32 *sw_if_indexp);
int ovpn_if_delete (vlib_main_t *vm, u32 sw_if_index);
int ovpn_if_set_local_addr (u32 sw_if_index, ip_address_t *addr);
int ovpn_if_set_remote_addr (u32 sw_if_index, ip_address_t *addr);

/* Lookup functions */
ovpn_if_t *ovpn_if_get_from_sw_if_index (u32 sw_if_index);

/* Update adjacencies when peer state changes */
void ovpn_if_update_adj_for_peer (u32 sw_if_index);

/* Format functions */
format_function_t format_ovpn_if_name;
format_function_t format_ovpn_if;

/* Unformat functions */
unformat_function_t unformat_ovpn_if;

#endif /* __included_ovpn_if_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
