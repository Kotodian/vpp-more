/*
 * ovpn_if.c - OpenVPN interface implementation
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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/adj/adj_nbr.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/l2/l2_fib.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <ovpn/ovpn_if.h>
#include <ovpn/ovpn.h>

/* Extern output node registrations */
extern vlib_node_registration_t ovpn4_output_node;
extern vlib_node_registration_t ovpn6_output_node;
extern vlib_node_registration_t ovpn4_output_handoff_node;
extern vlib_node_registration_t ovpn6_output_handoff_node;

ovpn_if_main_t ovpn_if_main;

/* Device class instance counter */
static u32 ovpn_instance_counter = 0;

/* Get OpenVPN interface from sw_if_index */
ovpn_if_t *
ovpn_if_get_from_sw_if_index (u32 sw_if_index)
{
  ovpn_if_main_t *oim = &ovpn_if_main;
  uword *p;

  p = hash_get (oim->ovpn_if_index_by_sw_if_index, sw_if_index);
  if (p == 0)
    return NULL;

  return pool_elt_at_index (oim->ovpn_ifs, p[0]);
}

/* Format OpenVPN interface name */
u8 *
format_ovpn_if_name (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  ovpn_if_main_t *oim = &ovpn_if_main;
  ovpn_if_t *oif = pool_elt_at_index (oim->ovpn_ifs, dev_instance);

  if (oif->name && vec_len (oif->name) > 0)
    return format (s, "%s", oif->name);
  else
    return format (s, "ovpn%u", dev_instance);
}

/* Format OpenVPN interface details */
u8 *
format_ovpn_if (u8 *s, va_list *args)
{
  u32 dev_instance = va_arg (*args, u32);
  ovpn_if_main_t *oim = &ovpn_if_main;
  ovpn_if_t *oif = pool_elt_at_index (oim->ovpn_ifs, dev_instance);

  if (oif->name && vec_len (oif->name) > 0)
    s = format (s, "%s", oif->name);
  else
    s = format (s, "ovpn%u", dev_instance);

  s = format (s, "\n  Mode: %s", oif->is_tun ? "TUN (L3)" : "TAP (L2)");

  if (ip_address_is_zero (&oif->local_addr) == 0)
    s = format (s, "\n  Local:  %U:%u", format_ip_address, &oif->local_addr,
		oif->local_port);

  if (ip_address_is_zero (&oif->remote_addr) == 0)
    s = format (s, "\n  Remote: %U:%u", format_ip_address, &oif->remote_addr,
		oif->remote_port);

  return s;
}

/* Unformat OpenVPN interface name */
uword
unformat_ovpn_if (unformat_input_t *input, va_list *args)
{
  u32 *result = va_arg (*args, u32 *);
  u32 instance;

  if (unformat (input, "ovpn%u", &instance))
    {
      *result = instance;
      return 1;
    }
  return 0;
}

/* Device class admin up/down function */
static clib_error_t *
ovpn_if_admin_up_down (vnet_main_t *vnm, u32 hw_if_index, u32 flags)
{
  u32 hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
		   VNET_HW_INTERFACE_FLAG_LINK_UP :
		   0;
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);
  return 0;
}

/*
 * Adjacency midchain fixup callback for OpenVPN.
 * Called by adj-midchain-tx AFTER the rewrite (outer IP+UDP header) is
 * applied. Updates the IP length, IP checksum, and UDP length fields to match
 * the actual encrypted payload size.
 */
static void
ovpn_adj_midchain_fixup (vlib_main_t *vm, const struct ip_adjacency_t_ *adj,
			 vlib_buffer_t *b, const void *data)
{
  /* Buffer now starts at outer IP header (rewrite has been applied) */
  u8 *ip_start = vlib_buffer_get_current (b);
  u8 ip_version = (ip_start[0] >> 4) & 0xf;
  u16 total_len = vlib_buffer_length_in_chain (vm, b);

  if (ip_version == 4)
    {
      ip4_header_t *ip4 = (ip4_header_t *) ip_start;
      udp_header_t *udp = (udp_header_t *) (ip4 + 1);

      /* Update IP total length */
      u16 old_len = ip4->length;
      u16 new_len = clib_host_to_net_u16 (total_len);
      ip4->length = new_len;

      /* Incrementally update IP checksum */
      ip_csum_t sum = ip4->checksum;
      sum = ip_csum_update (sum, old_len, new_len, ip4_header_t, length);
      ip4->checksum = ip_csum_fold (sum);

      /* Update UDP length (checksum = 0 is valid for UDP over IPv4) */
      udp->length = clib_host_to_net_u16 (total_len - sizeof (ip4_header_t));
      udp->checksum = 0;
    }
  else if (ip_version == 6)
    {
      ip6_header_t *ip6 = (ip6_header_t *) ip_start;
      udp_header_t *udp = (udp_header_t *) (ip6 + 1);
      int bogus = 0;

      /* Update IPv6 payload length */
      ip6->payload_length =
	clib_host_to_net_u16 (total_len - sizeof (ip6_header_t));
      udp->length = ip6->payload_length;

      /* IPv6 UDP checksum is mandatory */
      udp->checksum = 0;
      udp->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b, ip6, &bogus);
    }
}

/*
 * Update adjacency callback for OpenVPN interface
 * Converts neighbor adjacencies into midchain adjacencies that
 * will be processed by the OpenVPN output nodes
 */
static void
ovpn_if_update_adj (vnet_main_t *vnm, u32 sw_if_index, adj_index_t ai)
{
  ovpn_instance_t *inst;
  ovpn_peer_t *peer;
  ip_adjacency_t *adj;

  adj = adj_get (ai);

  /* Get instance by sw_if_index */
  inst = ovpn_instance_get_by_sw_if_index (sw_if_index);
  if (!inst)
    {
      /*
       * No instance found - convert to midchain with NULL fixup to avoid
       * sending ARP/ND to resolve the next-hop via the ovpn interface.
       */
      adj_nbr_midchain_update_rewrite (ai, NULL, NULL, ADJ_FLAG_NONE, NULL);
      return;
    }

  /*
   * Find a peer that matches the adjacency's next-hop
   * For OpenVPN, we look for an established peer on this interface
   */
  int peer_found = 0;
  pool_foreach (peer, inst->multi_context.peer_db.peers)
    {
      if (peer->sw_if_index != sw_if_index)
	continue;
      if (peer->state != OVPN_PEER_STATE_ESTABLISHED)
	continue;

      /*
       * Check if this peer's virtual IP matches the adjacency next-hop
       * or if we're in P2P mode (any packet goes to the single peer)
       */
      int match = 0;

      if (peer->virtual_ip_set)
	{
	  /* Check if next-hop matches virtual IP */
	  if (adj->ia_nh_proto == FIB_PROTOCOL_IP4 &&
	      peer->virtual_ip.version == AF_IP4)
	    {
	      if (ip4_address_compare (&adj->sub_type.nbr.next_hop.ip4,
				       &peer->virtual_ip.ip.ip4) == 0)
		match = 1;
	    }
	  else if (adj->ia_nh_proto == FIB_PROTOCOL_IP6 &&
		   peer->virtual_ip.version == AF_IP6)
	    {
	      if (ip6_address_compare (&adj->sub_type.nbr.next_hop.ip6,
				       &peer->virtual_ip.ip.ip6) == 0)
		match = 1;
	    }
	}
      else
	{
	  /* P2P mode - accept any destination */
	  match = 1;
	}

      if (match)
	{
	  /* Associate this adjacency with the peer */
	  ovpn_peer_adj_index_add (peer->peer_id, ai);

	  /*
	   * Convert to midchain with proper fixup and rewrite.
	   * IMPORTANT: This must be called ONCE with all parameters - the
	   * fixup function is only installed on the first call that converts
	   * the adjacency to a midchain type.
	   */
	  adj_nbr_midchain_update_rewrite (ai, ovpn_adj_midchain_fixup, NULL,
					   ADJ_FLAG_MIDCHAIN_IP_STACK,
					   vec_dup (peer->rewrite));

	  /*
	   * Direct the adjacency to the OpenVPN output handoff node.
	   * This ensures all output for a peer goes through the same thread,
	   * which is required for thread-safe access to fragment seq_id and
	   * other per-peer state without using atomics or locks.
	   */
	  u32 output_node_index = (adj->ia_nh_proto == FIB_PROTOCOL_IP4) ?
				    ovpn4_output_handoff_node.index :
				    ovpn6_output_handoff_node.index;
	  adj_nbr_midchain_update_next_node (ai, output_node_index);

	  /* Stack the adjacency on the path to reach the peer's endpoint */
	  ovpn_peer_adj_stack (peer, ai);

	  peer_found = 1;
	  break;
	}
    }

  if (!peer_found)
    {
      /*
       * No matching peer found - convert to midchain with NULL fixup to avoid
       * sending ARP/ND to resolve the next-hop via the ovpn interface.
       */
      adj_nbr_midchain_update_rewrite (ai, NULL, NULL, ADJ_FLAG_NONE, NULL);
    }
}

/*
 * Callback for adjacency walk - updates each adjacency
 */
static adj_walk_rc_t
ovpn_if_adj_walk_cb (adj_index_t ai, void *ctx)
{
  u32 sw_if_index = *(u32 *) ctx;
  vnet_main_t *vnm = vnet_get_main ();
  ovpn_if_update_adj (vnm, sw_if_index, ai);
  return ADJ_WALK_RC_CONTINUE;
}

/*
 * Update all adjacencies on interface when peer state changes
 * Called when a new peer is established to associate adjacencies
 */
void
ovpn_if_update_adj_for_peer (u32 sw_if_index)
{
  fib_protocol_t proto;

  FOR_EACH_FIB_IP_PROTOCOL (proto)
  {
    adj_nbr_walk (sw_if_index, proto, ovpn_if_adj_walk_cb, &sw_if_index);
  }
}

/*
 * TAP mode L2 output callback
 * Called when packets are sent out via the TAP interface in L2 mode
 * This is the tx_function for the device class when in TAP mode
 *
 * In TAP mode:
 * - Incoming buffer contains an Ethernet frame (from bridge domain)
 * - We need to prepend the outer IP+UDP headers (rewrite) before encryption
 * - Then route to the OpenVPN output node for encryption
 */
VNET_DEVICE_CLASS_TX_FN (ovpn_device_class)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > 0)
    {
      vlib_buffer_t *b0 = b[0];
      u32 sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];

      /*
       * Get the instance for this interface.
       * For TAP mode L2 output, we need to encrypt the Ethernet frame
       * and send it via UDP to the peer.
       */
      ovpn_instance_t *inst = ovpn_instance_get_by_sw_if_index (sw_if_index);

      if (PREDICT_FALSE (!inst))
	{
	  /* No instance - drop */
	  next[0] = 0; /* error-drop */
	  goto next;
	}

      /*
       * For TAP mode, we need to find the peer for this frame.
       * Look up the destination MAC address in the Ethernet header
       * to find the peer that owns this MAC (learned during RX).
       *
       * If MAC lookup fails (unknown destination or broadcast),
       * fall back to the first established peer for P2P mode.
       */
      ovpn_peer_t *peer = NULL;
      u8 *eth_hdr = vlib_buffer_get_current (b0);

      if (PREDICT_TRUE (b0->current_length >= 14))
	{
	  u8 *dst_mac = eth_hdr; /* Destination MAC at offset 0 */

	  /* Skip broadcast/multicast - use first peer for flooding */
	  if (!(dst_mac[0] & 0x01))
	    {
	      /* Unicast - lookup peer by destination MAC */
	      u32 peer_id =
		ovpn_peer_mac_lookup (&inst->multi_context.peer_db, dst_mac);
	      if (peer_id != ~0)
		{
		  peer = ovpn_peer_get (&inst->multi_context.peer_db, peer_id);
		  if (peer && !ovpn_peer_is_established (peer))
		    peer = NULL; /* Peer exists but not ready */
		}
	    }
	}

      /* Fallback: use first established peer (P2P mode or broadcast) */
      if (!peer)
	{
	  pool_foreach (peer, inst->multi_context.peer_db.peers)
	    {
	      if (peer->state == OVPN_PEER_STATE_ESTABLISHED)
		break;
	    }
	}

      if (PREDICT_FALSE (!peer || peer->state != OVPN_PEER_STATE_ESTABLISHED))
	{
	  /* No established peer - drop */
	  next[0] = 0; /* error-drop */
	  goto next;
	}

      /*
       * Prepend the outer IP+UDP headers (rewrite) to the buffer.
       * The peer's rewrite contains the pre-built IP+UDP header template.
       * The output node expects the buffer to start with the outer headers.
       */
      if (PREDICT_TRUE (vec_len (peer->rewrite) > 0))
	{
	  u32 rewrite_len = vec_len (peer->rewrite);

	  /* Make room for the rewrite at the front of the buffer */
	  vlib_buffer_advance (b0, -(i32) rewrite_len);

	  /* Copy the rewrite template to the buffer */
	  clib_memcpy_fast (vlib_buffer_get_current (b0), peer->rewrite,
			    rewrite_len);
	}
      else
	{
	  /* No rewrite available - drop */
	  next[0] = 0; /* error-drop */
	  goto next;
	}

      /*
       * Store the peer_id in vnet_buffer for the output node.
       * The output node will look up the peer and encrypt the frame.
       */
      vnet_buffer (b0)->ip.adj_index[VLIB_TX] = peer->adj_index;

      /*
       * Route to the OpenVPN output node for encryption.
       * Use ovpn4-output or ovpn6-output based on transport.
       */
      next[0] = inst->is_ipv6 ? 2 : 1; /* ovpn6-output : ovpn4-output */

    next:
      b++;
      next++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

/* Register OpenVPN device class */
VNET_DEVICE_CLASS (ovpn_device_class) = {
  .name = "OpenVPN",
  .format_device_name = format_ovpn_if_name,
  .format_device = format_ovpn_if,
  .admin_up_down_function = ovpn_if_admin_up_down,
  .tx_function_n_errors = 1,
  .tx_function_error_strings = (char *[]){ "No peer found" },
};

/* Register OpenVPN hardware interface class (TUN mode - L3) */
VNET_HW_INTERFACE_CLASS (ovpn_hw_interface_class) = {
  .name = "OpenVPN",
  .update_adjacency = ovpn_if_update_adj,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_NBMA,
};

/*
 * TAP mode hardware interface class.
 * Uses Ethernet characteristics for L2 bridging support.
 */
VNET_HW_INTERFACE_CLASS (ovpn_tap_hw_interface_class) = {
  .name = "OpenVPN-TAP",
  .format_header = format_ethernet_header_with_length,
  .build_rewrite = ethernet_build_rewrite,
  .update_adjacency = ethernet_update_adjacency,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};

/* Create OpenVPN interface */
int
ovpn_if_create (vlib_main_t *vm __attribute__ ((unused)), u8 *name, u8 is_tun,
		u16 mtu, u32 *sw_if_indexp)
{
  ovpn_if_main_t *oim = &ovpn_if_main;
  vnet_main_t *vnm = oim->vnet_main;
  ovpn_if_t *oif;
  vnet_eth_interface_registration_t eir = {};
  u32 dev_instance;
  u32 hw_if_index;
  u8 address[6] = {
    [0] = 0x02, /* locally administered */
    [1] = 0xfe,
  };

  /* Allocate interface instance */
  pool_get_zero (oim->ovpn_ifs, oif);
  dev_instance = oif - oim->ovpn_ifs;
  oif->dev_instance = dev_instance;
  oif->user_instance = ovpn_instance_counter++;
  oif->is_tun = is_tun;

  /* Store custom interface name */
  if (name && name[0] != 0)
    {
      /* Use format to copy the name as a vec (name may be a plain string) */
      oif->name = format (0, "%s", name);
    }
  else
    {
      /* Generate default name if not provided */
      oif->name = format (0, "ovpn%u", dev_instance);
    }

  /* Generate MAC address */
  address[5] = dev_instance & 0xff;
  address[4] = (dev_instance >> 8) & 0xff;
  address[3] = (dev_instance >> 16) & 0xff;
  address[2] = (dev_instance >> 24) & 0xff;

  if (is_tun)
    {
      /* TUN mode - create as hardware interface with ovpn_hw_interface_class
       */
      vnet_hw_interface_t *hi;

      hw_if_index =
	vnet_register_interface (vnm, ovpn_device_class.index, dev_instance,
				 ovpn_hw_interface_class.index, dev_instance);

      hi = vnet_get_hw_interface (vnm, hw_if_index);
      oif->hw_if_index = hw_if_index;
      oif->sw_if_index = hi->sw_if_index;
    }
  else
    {
      /*
       * TAP mode - create as ethernet interface with L2 support.
       * Uses vnet_eth_register_interface which creates a proper Ethernet
       * interface that can participate in bridging and L2 switching.
       */
      vnet_hw_interface_t *hi;

      eir.dev_class_index = ovpn_device_class.index;
      eir.dev_instance = dev_instance;
      eir.address = address;
      hw_if_index = vnet_eth_register_interface (vnm, &eir);

      hi = vnet_get_hw_interface (vnm, hw_if_index);
      oif->hw_if_index = hw_if_index;
      oif->sw_if_index = hi->sw_if_index;

      /*
       * Set up the tx_function next nodes for L2 output path.
       * The tx_function routes packets to OpenVPN output nodes.
       * Use hi->tx_node_index which is the actual TX node for this interface.
       */
      vlib_node_add_named_next_with_slot (vnm->vlib_main, hi->tx_node_index,
					  "error-drop", 0);
      vlib_node_add_named_next_with_slot (vnm->vlib_main, hi->tx_node_index,
					  "ovpn4-output", 1);
      vlib_node_add_named_next_with_slot (vnm->vlib_main, hi->tx_node_index,
					  "ovpn6-output", 2);
    }

  /* Rename hardware interface to use custom name */
  if (oif->name && vec_len (oif->name) > 0)
    {
      /* Add null terminator for vnet_rename_interface */
      vec_add1 (oif->name, 0);
      vnet_rename_interface (vnm, hw_if_index, (char *) oif->name);
      vec_dec_len (oif->name, 1);
    }

  /* Set MTU on interface */
  vnet_sw_interface_set_mtu (vnm, oif->sw_if_index, mtu);

  /* Enable interface */
  vnet_sw_interface_set_flags (vnm, oif->sw_if_index,
			       VNET_SW_INTERFACE_FLAG_ADMIN_UP);

  /* Add to hash table */
  hash_set (oim->ovpn_if_index_by_sw_if_index, oif->sw_if_index, dev_instance);

  if (sw_if_indexp)
    *sw_if_indexp = oif->sw_if_index;

  return 0;
}

/* Delete OpenVPN interface */
int
ovpn_if_delete (vlib_main_t *vm __attribute__ ((unused)), u32 sw_if_index)
{
  ovpn_if_main_t *oim = &ovpn_if_main;
  vnet_main_t *vnm = oim->vnet_main;
  ovpn_if_t *oif;

  oif = ovpn_if_get_from_sw_if_index (sw_if_index);
  if (!oif)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Disable interface */
  vnet_sw_interface_set_flags (vnm, sw_if_index, 0);

  /* Delete hardware interface */
  vnet_delete_hw_interface (vnm, oif->hw_if_index);

  /* Remove from hash table */
  hash_unset (oim->ovpn_if_index_by_sw_if_index, sw_if_index);

  /* Free interface name */
  if (oif->name)
    vec_free (oif->name);

  /* Free pool element */
  pool_put (oim->ovpn_ifs, oif);

  return 0;
}

/* Set local address */
int
ovpn_if_set_local_addr (u32 sw_if_index, ip_address_t *addr)
{
  ovpn_if_t *oif = ovpn_if_get_from_sw_if_index (sw_if_index);

  if (!oif)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  ip_address_copy (&oif->local_addr, addr);
  oif->is_ipv6 = (addr->version == AF_IP6);

  return 0;
}

/* Set remote address */
int
ovpn_if_set_remote_addr (u32 sw_if_index, ip_address_t *addr)
{
  ovpn_if_t *oif = ovpn_if_get_from_sw_if_index (sw_if_index);

  if (!oif)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  ip_address_copy (&oif->remote_addr, addr);

  return 0;
}

/* CLI command to create OpenVPN interface */
static clib_error_t *
ovpn_if_create_command_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd __attribute__ ((unused)))
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *name = 0;
  u8 is_tun = 1;
  u16 mtu = 1420; /* Default MTU */
  u32 sw_if_index = ~0;
  clib_error_t *error = NULL;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected interface name");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "name %s", &name))
	;
      else if (unformat (line_input, "tun"))
	is_tun = 1;
      else if (unformat (line_input, "tap"))
	is_tun = 0;
      else if (unformat (line_input, "mtu %u", &mtu))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  rv = ovpn_if_create (vm, name, is_tun, mtu, &sw_if_index);

  if (rv < 0)
    {
      error = clib_error_return (0, "failed to create OpenVPN interface");
      goto done;
    }

  vlib_cli_output (vm, "Created OpenVPN interface: %U (sw_if_index %u)",
		   format_vnet_sw_if_index_name, vnet_get_main (), sw_if_index,
		   sw_if_index);

done:
  vec_free (name);
  unformat_free (line_input);
  return error;
}

/* CLI command to delete OpenVPN interface */
static clib_error_t *
ovpn_if_delete_command_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd __attribute__ ((unused)))
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  clib_error_t *error = NULL;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected interface");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm,
		    &sw_if_index))
	;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (sw_if_index == ~0)
    {
      error = clib_error_return (0, "interface not specified");
      goto done;
    }

  rv = ovpn_if_delete (vm, sw_if_index);

  if (rv < 0)
    {
      error = clib_error_return (0, "failed to delete OpenVPN interface");
      goto done;
    }

  vlib_cli_output (vm, "Deleted OpenVPN interface");

done:
  unformat_free (line_input);
  return error;
}

/* CLI command: create ovpn interface */
VLIB_CLI_COMMAND (ovpn_if_create_command, static) = {
  .path = "create ovpn interface",
  .short_help = "create ovpn interface name <name> [tun|tap] [mtu <size>]",
  .function = ovpn_if_create_command_fn,
};

/* CLI command: delete ovpn interface */
VLIB_CLI_COMMAND (ovpn_if_delete_command, static) = {
  .path = "delete ovpn interface",
  .short_help = "delete ovpn interface <interface>",
  .function = ovpn_if_delete_command_fn,
};

/* Initialize OpenVPN interface subsystem */
static clib_error_t *
ovpn_if_init (vlib_main_t *vm)
{
  ovpn_if_main_t *oim = &ovpn_if_main;

  oim->vlib_main = vm;
  oim->vnet_main = vnet_get_main ();
  oim->ovpn_if_index_by_sw_if_index = hash_create (0, sizeof (uword));

  return 0;
}

VLIB_INIT_FUNCTION (ovpn_if_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
