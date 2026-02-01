/*
 * ovpn_input.c - OpenVPN input node
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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/udp/udp_local.h>
#include <ovpn/ovpn.h>
#include <ovpn/ovpn_packet.h>
#include <ovpn/ovpn_peer.h>
#include <ovpn/ovpn_crypto.h>
#include <ovpn/ovpn_handshake.h>
#include <ovpn/ovpn_options.h>
#include <ovpn/ovpn_if.h>
#include <ovpn/ovpn_mssfix.h>
#include <ovpn/ovpn_fragment.h>
#include <vnet/ip-neighbor/ip_neighbor.h>
#include <vnet/adj/adj_nbr.h>
#include <vnet/fib/fib_table.h>
#include <vlib/threads.h>
#include <vnet/l2/l2_input.h>

/* Input node next indices */
typedef enum
{
  OVPN_INPUT_NEXT_HANDOFF_HANDSHAKE,
  OVPN_INPUT_NEXT_HANDOFF_DATA,
  OVPN_INPUT_NEXT_IP4_INPUT,
  OVPN_INPUT_NEXT_IP6_INPUT,
  OVPN_INPUT_NEXT_L2_INPUT,
  OVPN_INPUT_NEXT_HANDSHAKE,
  OVPN_INPUT_NEXT_REASS4,
  OVPN_INPUT_NEXT_REASS6,
  OVPN_INPUT_NEXT_REASS_L2,
  OVPN_INPUT_NEXT_SLOW_PATH,
  OVPN_INPUT_NEXT_DROP,
  OVPN_INPUT_N_NEXT,
} ovpn_input_next_t;

/* Error codes */
typedef enum
{
  OVPN_INPUT_ERROR_NONE,
  OVPN_INPUT_ERROR_TOO_SHORT,
  OVPN_INPUT_ERROR_INVALID_OPCODE,
  OVPN_INPUT_ERROR_INSTANCE_NOT_FOUND,
  OVPN_INPUT_ERROR_PEER_NOT_FOUND,
  OVPN_INPUT_ERROR_DECRYPT_FAILED,
  OVPN_INPUT_ERROR_HMAC_MISMATCH,
  OVPN_INPUT_ERROR_HMAC_OP_FAILED,
  OVPN_INPUT_ERROR_DECRYPT_OP_FAILED,
  OVPN_INPUT_ERROR_REPLAY,
  OVPN_INPUT_ERROR_NO_CRYPTO,
  OVPN_INPUT_ERROR_BAD_IP_VERSION,
  OVPN_INPUT_ERROR_FRAG_INCOMPLETE,
  OVPN_INPUT_ERROR_BAD_SRC,
  OVPN_INPUT_ERROR_CLIENT_TO_CLIENT,
  OVPN_INPUT_N_ERROR,
} ovpn_input_error_t;

static char *ovpn_input_error_strings[] = {
  [OVPN_INPUT_ERROR_NONE] = "No error",
  [OVPN_INPUT_ERROR_TOO_SHORT] = "Packet too short",
  [OVPN_INPUT_ERROR_INVALID_OPCODE] = "Invalid opcode",
  [OVPN_INPUT_ERROR_INSTANCE_NOT_FOUND] = "Instance not found for port",
  [OVPN_INPUT_ERROR_PEER_NOT_FOUND] = "Peer not found",
  [OVPN_INPUT_ERROR_DECRYPT_FAILED] = "Decryption failed",
  [OVPN_INPUT_ERROR_HMAC_MISMATCH] = "HMAC mismatch",
  [OVPN_INPUT_ERROR_HMAC_OP_FAILED] = "HMAC operation failed",
  [OVPN_INPUT_ERROR_DECRYPT_OP_FAILED] = "Decrypt operation failed",
  [OVPN_INPUT_ERROR_REPLAY] = "Replay detected",
  [OVPN_INPUT_ERROR_NO_CRYPTO] = "No crypto context",
  [OVPN_INPUT_ERROR_BAD_IP_VERSION] = "Bad IP version in decrypted payload",
  [OVPN_INPUT_ERROR_FRAG_INCOMPLETE] = "Fragment waiting for reassembly",
  [OVPN_INPUT_ERROR_BAD_SRC] = "Source address mismatch (float disabled)",
  [OVPN_INPUT_ERROR_CLIENT_TO_CLIENT] = "Client-to-client traffic blocked",
};

/* Trace data */
typedef struct
{
  u8 opcode;
  u8 key_id;
  u32 peer_id;
  u32 packet_id;
  u32 sw_if_index;
  u16 packet_len;
  u8 next_index;
  u8 error;
} ovpn_input_trace_t;

static u8 *
format_ovpn_input_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ovpn_input_trace_t *t = va_arg (*args, ovpn_input_trace_t *);

  s = format (s, "ovpn-input: opcode %U key_id %u peer_id %u",
	      format_ovpn_opcode, t->opcode, t->key_id, t->peer_id);
  s = format (s, "\n  packet_id %u len %u sw_if_index %u", t->packet_id,
	      t->packet_len, t->sw_if_index);
  s = format (s, "\n  next %u error %u", t->next_index, t->error);

  return s;
}

/*
 * Arguments for deferred peer setup on main thread.
 */
typedef struct
{
  u32 sw_if_index;
  ip4_address_t client_ip;
  u32 peer_id;
} ovpn_peer_setup_args_t;

/*
 * Complete peer setup on main thread (adjacency creation).
 */
static void
ovpn_peer_setup_main_thread_fn (ovpn_peer_setup_args_t *args)
{
  ip46_address_t nh_addr = { 0 };
  ip46_address_set_ip4 (&nh_addr, &args->client_ip);

  adj_nbr_add_or_lock (FIB_PROTOCOL_IP4, VNET_LINK_IP4, &nh_addr,
		       args->sw_if_index);

  fib_prefix_t pfx = {
    .fp_len = 32,
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_addr.ip4 = args->client_ip,
  };

  u32 fib_index =
    fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, args->sw_if_index);

  ovpn_main_t *omp = &ovpn_main;
  fib_table_entry_path_add (
    fib_index, &pfx, omp->fib_src_hi, FIB_ENTRY_FLAG_NONE, DPO_PROTO_IP4,
    &nh_addr, args->sw_if_index, ~0, 1, NULL, FIB_ROUTE_PATH_FLAG_NONE);
}

/*
 * Extract remote address and port from outer IP/UDP headers.
 */
always_inline void
ovpn_extract_remote_endpoint (vlib_buffer_t *b, u8 is_ip6,
			      ip_address_t *remote_addr, u16 *remote_port)
{
  u8 *current = vlib_buffer_get_current (b);

  if (is_ip6)
    {
      ip6_header_t *ip6 =
	(ip6_header_t *) (current - sizeof (ip6_header_t) - sizeof (udp_header_t));
      udp_header_t *udp = (udp_header_t *) (ip6 + 1);
      ip_address_set (remote_addr, &ip6->src_address, AF_IP6);
      *remote_port = clib_net_to_host_u16 (udp->src_port);
    }
  else
    {
      ip4_header_t *ip4 =
	(ip4_header_t *) (current - sizeof (ip4_header_t) - sizeof (udp_header_t));
      udp_header_t *udp = (udp_header_t *) (ip4 + 1);
      ip_address_set (remote_addr, &ip4->src_address, AF_IP4);
      *remote_port = clib_net_to_host_u16 (udp->src_port);
    }
}

/*
 * Map CBC decrypt return code to error type.
 */
always_inline ovpn_input_error_t
ovpn_map_cbc_error (int rv)
{
  switch (rv)
    {
    case -1:
      return OVPN_INPUT_ERROR_NO_CRYPTO;
    case -2:
      return OVPN_INPUT_ERROR_TOO_SHORT;
    case -3:
      return OVPN_INPUT_ERROR_DECRYPT_FAILED;
    case -4:
      return OVPN_INPUT_ERROR_HMAC_OP_FAILED;
    case -5:
      return OVPN_INPUT_ERROR_HMAC_MISMATCH;
    case -6:
      return OVPN_INPUT_ERROR_DECRYPT_OP_FAILED;
    case -7:
      return OVPN_INPUT_ERROR_REPLAY;
    default:
      return OVPN_INPUT_ERROR_DECRYPT_FAILED;
    }
}

/*
 * Handle special control packets (ping, exit-notify).
 * Returns next node index if handled, or -1 to continue normal processing.
 */
always_inline int
ovpn_handle_control_payload (vlib_main_t *vm, vlib_buffer_t *b,
			     ovpn_peer_t *peer, ovpn_instance_t *inst)
{
  u8 *payload = vlib_buffer_get_current (b);
  u32 len = b->current_length;

  if (ovpn_is_ping_packet (payload, len))
    {
      ovpn_peer_send_ping (vm, peer);
      return OVPN_INPUT_NEXT_DROP;
    }

  if (ovpn_is_exit_notify (payload, len))
    {
      vlib_process_signal_event_mt (
	vm, ovpn_periodic_node.index, OVPN_PROCESS_EVENT_EXIT_NOTIFY,
	OVPN_EXIT_NOTIFY_DATA (inst->instance_id, peer->peer_id));
      return OVPN_INPUT_NEXT_DROP;
    }

  return -1;
}

/*
 * Determine next node based on TUN/TAP mode and inner protocol.
 */
always_inline ovpn_input_next_t
ovpn_route_decrypted_packet (vlib_main_t *vm, vlib_buffer_t *b,
			     ovpn_instance_t *inst, ovpn_peer_t *peer)
{
  if (!inst->options.is_tun)
    {
      /* TAP mode - Ethernet frame */
      vnet_update_l2_len (b);

      if (b->current_length >= 14)
	{
	  u8 *src_mac = vlib_buffer_get_current (b) + 6;
	  ovpn_peer_mac_learn (&inst->multi_context.peer_db, src_mac,
			       peer->peer_id);
	}
      return OVPN_INPUT_NEXT_L2_INPUT;
    }

  /* TUN mode - IP packet */
  if (inst->options.pool_start.version == AF_IP6)
    return OVPN_INPUT_NEXT_IP6_INPUT;

  return OVPN_INPUT_NEXT_IP4_INPUT;
}

/*
 * Process fragment header and reassembly.
 * Returns: 1 = continue processing, 0 = drop (waiting for fragments), -1 = error
 */
always_inline int
ovpn_process_fragment (vlib_main_t *vm, vlib_buffer_t *b,
		       ovpn_frag_state_t *frag_state, f64 now)
{
  if (b->current_length < OVPN_FRAG_HDR_SIZE)
    return 1;

  u8 *frag_data = vlib_buffer_get_current (b);
  u8 frag_type, seq_id, frag_id;
  u16 frag_size;
  u32 frag_hdr;

  clib_memcpy (&frag_hdr, frag_data, OVPN_FRAG_HDR_SIZE);
  ovpn_frag_parse_header (frag_hdr, &frag_type, &seq_id, &frag_id, &frag_size);

  if (frag_type == OVPN_FRAG_WHOLE)
    {
      vlib_buffer_advance (b, OVPN_FRAG_HDR_SIZE);
      return 1;
    }

  if (frag_type == OVPN_FRAG_YES_NOTLAST || frag_type == OVPN_FRAG_YES_LAST)
    {
      u8 *reassembled = NULL;
      u32 reassembled_len = 0;

      int rv = ovpn_frag_process_fragment (frag_data, b->current_length,
					   frag_state, now, &reassembled,
					   &reassembled_len);

      if (rv == 1 && reassembled)
	{
	  if (reassembled_len <= vlib_buffer_get_default_data_size (vm))
	    {
	      b->current_data = 0;
	      b->current_length = reassembled_len;
	      clib_memcpy (vlib_buffer_get_current (b), reassembled,
			   reassembled_len);
	    }
	  clib_mem_free (reassembled);
	  return 1;
	}

      if (rv == 0)
	return 0; /* Waiting for more fragments */

      return -1; /* Reassembly error */
    }

  return 1;
}

/*
 * Check if packet is client-to-client (TUN mode only).
 * Returns true if the destination is another client and should be dropped.
 */
always_inline int
ovpn_check_client_to_client (vlib_buffer_t *b, ovpn_instance_t *inst,
			     ovpn_peer_t *src_peer)
{
  if (!inst || inst->options.client_to_client || !inst->options.is_tun)
    return 0;

  u8 *data = vlib_buffer_get_current (b);
  ip_address_t dst_ip = { 0 };

  if (inst->options.pool_start.version == AF_IP6)
    {
      if (b->current_length >= sizeof (ip6_header_t))
	{
	  ip6_header_t *ip6 = (ip6_header_t *) data;
	  ip_address_set (&dst_ip, &ip6->dst_address, AF_IP6);
	}
    }
  else
    {
      if (b->current_length >= sizeof (ip4_header_t))
	{
	  ip4_header_t *ip4 = (ip4_header_t *) data;
	  ip_address_set (&dst_ip, &ip4->dst_address, AF_IP4);
	}
    }

  if (dst_ip.version == 0)
    return 0;

  ovpn_peer_t *dst_peer =
    ovpn_peer_lookup_by_virtual_ip (&inst->multi_context.peer_db, &dst_ip);

  return (dst_peer && dst_peer->peer_id != src_peer->peer_id);
}

/*
 * Create peer for static key mode.
 */
static ovpn_peer_t *
ovpn_static_key_create_peer (vlib_main_t *vm, ovpn_instance_t *inst,
			     const ip_address_t *remote_addr, u16 remote_port)
{
  ovpn_peer_db_t *db = &inst->multi_context.peer_db;
  f64 now = vlib_time_now (vm);

  u32 peer_id = ovpn_peer_create (db, remote_addr, remote_port);
  if (peer_id == ~0)
    return NULL;

  ovpn_peer_t *peer = ovpn_peer_get (db, peer_id);
  if (!peer)
    return NULL;

  peer->sw_if_index = inst->sw_if_index;
  peer->is_ipv6 = (remote_addr->version == AF_IP6) ? 1 : 0;

  /* Build rewrite for sending packets */
  ip_address_t local_addr;
  if (peer->is_ipv6)
    ip_address_set (&local_addr, &inst->options.server_addr.fp_addr.ip6,
		    AF_IP6);
  else
    ip_address_set (&local_addr, &inst->options.server_addr.fp_addr.ip4,
		    AF_IP4);

  ovpn_peer_build_rewrite (peer, &local_addr, inst->local_port);

  /* Set up crypto context */
  ovpn_peer_key_t *key = &peer->keys[OVPN_KEY_SLOT_PRIMARY];
  key->key_id = 0;
  key->is_active = 1;
  key->created_at = now;
  key->expires_at = 0;

  int rv = ovpn_setup_static_key_crypto (
    &key->crypto, inst->cipher_alg, inst->options.static_key,
    inst->options.static_key_direction, inst->options.replay_window);

  if (rv < 0)
    {
      ovpn_peer_delete (db, peer_id);
      return NULL;
    }

  peer->current_key_slot = OVPN_KEY_SLOT_PRIMARY;

  /* Add key to bihash */
  clib_bihash_kv_8_8_t kv;
  kv.key = ovpn_peer_key_hash_key (peer_id, key->key_id);
  kv.value = (u64) (uword) &key->crypto;
  clib_bihash_add_del_8_8 (&db->key_hash, &kv, 1);

  /* Check max-clients limit */
  if (inst->options.max_clients > 0 &&
      db->n_established >= inst->options.max_clients)
    {
      ovpn_peer_delete (db, peer_id);
      return NULL;
    }

  /* Transition to ESTABLISHED */
  ovpn_peer_set_state (peer, OVPN_PEER_STATE_ESTABLISHED);
  db->n_established++;

  peer->last_rx_time = now;
  peer->last_tx_time = now;
  peer->established_time = now;
  peer->input_thread_index = ~0;

  /* Set up virtual IP for P2P mode */
  if (!peer->is_ipv6)
    {
      ip4_address_t client_ip, server_ip;
      ip_interface_address_t *ia;
      int found_addr = 0;

      foreach_ip_interface_address (
	&ip4_main.lookup_main, ia, peer->sw_if_index, 1, ({
	  ip4_address_t *a =
	    ip_interface_address_get_address (&ip4_main.lookup_main, ia);
	  clib_memcpy (&server_ip, a, sizeof (ip4_address_t));
	  found_addr = 1;
	}));

      if (found_addr)
	{
	  client_ip.as_u32 =
	    clib_host_to_net_u32 (clib_net_to_host_u32 (server_ip.as_u32) + 1);

	  ip_address_set (&peer->virtual_ip, &client_ip, AF_IP4);
	  peer->virtual_ip_set = 1;

	  ovpn_peer_setup_args_t args = {
	    .sw_if_index = peer->sw_if_index,
	    .client_ip = client_ip,
	    .peer_id = peer_id,
	  };
	  vlib_rpc_call_main_thread (ovpn_peer_setup_main_thread_fn,
				     (u8 *) &args, sizeof (args));
	}
    }

  return peer;
}

always_inline uword
ovpn_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		   vlib_frame_t *frame, u8 is_ip6)
{
  u32 n_left_from, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 thread_index = vm->thread_index;
  f64 now = vlib_time_now (vm);
  ovpn_per_thread_crypto_t *ptd = ovpn_crypto_get_ptd (thread_index);
  ovpn_instance_t *instances[VLIB_FRAME_SIZE];
  u32 n_vectors = frame->n_vectors;

  /* Packet IDs for replay tracking (indexed by buffer position) */
  u32 packet_ids[VLIB_FRAME_SIZE];
  ovpn_crypto_context_t *crypto_contexts[VLIB_FRAME_SIZE];
  ovpn_peer_t *peers[VLIB_FRAME_SIZE];
  /* NAT/float: track remote addresses for address change detection */
  ip_address_t remote_addrs[VLIB_FRAME_SIZE];
  u16 remote_ports[VLIB_FRAME_SIZE];
  /* Track rx bytes per buffer for batched counter updates */
  u32 rx_bytes[VLIB_FRAME_SIZE];
  /* Track error counts per error type for batched counter updates */
  u32 error_counts[OVPN_INPUT_N_ERROR];
  u32 decrypt_count = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  /* Initialize tracking arrays (only the active frame range). */
  if (n_vectors > 0)
    {
      clib_memset (peers, 0, n_vectors * sizeof (peers[0]));
      clib_memset (crypto_contexts, 0, n_vectors * sizeof (crypto_contexts[0]));
      clib_memset (rx_bytes, 0, n_vectors * sizeof (rx_bytes[0]));
      clib_memset (instances, 0, n_vectors * sizeof (instances[0]));
    }
  clib_memset (error_counts, 0, sizeof (error_counts));

  /* Reset per-thread crypto state for batch processing */
  ovpn_crypto_reset_ptd (ptd);

  while (n_left_from > 0)
    {
      /* Prefetch next buffer header and data for reduced cache misses */
      if (n_left_from > 2)
	{
	  vlib_prefetch_buffer_header (b[2], LOAD);
	  clib_prefetch_load (vlib_buffer_get_current (b[1]));
	}

      vlib_buffer_t *b0 = b[0];
      ovpn_input_error_t error = OVPN_INPUT_ERROR_NONE;
      ovpn_input_next_t next0 = OVPN_INPUT_NEXT_DROP;
      u8 *data;
      u32 len;
      u8 op_byte, opcode, key_id;
      u32 peer_id = 0;
      u32 packet_id = 0;
      ovpn_peer_t *peer = NULL;
      ovpn_crypto_context_t *crypto = NULL;
      int rv;
      u32 buf_idx = b - bufs;
      ip_address_t remote_addr = { 0 };
      u16 remote_port = 0;

      /* Get packet data - buffer should point to OpenVPN payload (after UDP)
       */
      data = vlib_buffer_get_current (b0);
      len = b0->current_length;

      /* Check minimum length */
      if (PREDICT_FALSE (len < OVPN_OP_SIZE))
	{
	  error = OVPN_INPUT_ERROR_TOO_SHORT;
	  goto trace;
	}

      /* Parse opcode and key_id */
      op_byte = data[0];
      opcode = ovpn_op_get_opcode (op_byte);
      key_id = ovpn_op_get_key_id (op_byte);

      /*
       * Look up instance by destination port from UDP header.
       * Each instance has a unique port number.
       */
      ovpn_instance_t *inst = NULL;
      {
	u8 *udp_start = data - sizeof (udp_header_t);
	udp_header_t *udp = (udp_header_t *) udp_start;
	u16 dst_port = clib_net_to_host_u16 (udp->dst_port);
	inst = ovpn_instance_get_by_port (dst_port);
      }
      if (PREDICT_FALSE (!inst))
	{
	  error = OVPN_INPUT_ERROR_INSTANCE_NOT_FOUND;
	  goto trace;
	}

      /*
       * Legacy static key mode without opcode (P2P mode).
       *
       * IMPORTANT: Modern OpenVPN (2.x+) uses P_DATA_V1 opcode even in
       * static key mode. Only very old configurations use the no-opcode
       * format: [HMAC:32][IV:16][encrypted(packet_id:4 + timestamp:4 +
       * payload)]
       *
       * We only use this path if:
       * 1. Static key mode is enabled
       * 2. Using CBC cipher (not AEAD)
       * 3. First byte does NOT look like a valid data opcode
       * 4. Packet is large enough for HMAC + IV + minimum encrypted data
       *
       * If the first byte is a valid P_DATA_V1 or P_DATA_V2 opcode,
       * let the normal opcode processing handle it.
       */
      int looks_like_data_opcode = (opcode == OVPN_OP_DATA_V1 ||
				    opcode == OVPN_OP_DATA_V2);

      if (PREDICT_FALSE (inst->options.static_key_mode &&
			 !OVPN_CIPHER_IS_AEAD (inst->cipher_alg) &&
			 !looks_like_data_opcode &&
			 len >= (OVPN_CBC_HMAC_SIZE + OVPN_IV_SIZE + 16)))
	{
	  /* This is a static key mode data packet without opcode */
	  /* Extract remote endpoint using helper */
	  ovpn_extract_remote_endpoint (b0, is_ip6, &remote_addr, &remote_port);

	  /* Lookup peer by remote endpoint */
	  peer = ovpn_peer_lookup_by_remote (&inst->multi_context.peer_db,
					     &remote_addr, remote_port);

	  /* Auto-create peer if not found */
	  if (PREDICT_FALSE (!peer))
	    {
	      peer = ovpn_static_key_create_peer (vm, inst, &remote_addr,
						  remote_port);
	    }

	  if (PREDICT_FALSE (!peer || !ovpn_peer_is_established (peer)))
	    {
	      error = OVPN_INPUT_ERROR_PEER_NOT_FOUND;
	      goto trace;
	    }

	  /* Get crypto context */
	  crypto = ovpn_peer_get_crypto (peer);
	  if (PREDICT_FALSE (!crypto || !crypto->is_valid))
	    {
	      error = OVPN_INPUT_ERROR_NO_CRYPTO;
	      goto trace;
	    }

	  /* Decrypt using CBC mode without opcode
	   * The buffer starts at HMAC, format:
	   * [HMAC:32][IV:16][encrypted_data]
	   */
	  rv = ovpn_crypto_cbc_decrypt_no_opcode (vm, crypto, b0, &packet_id);
	  if (rv < 0)
	    {
	      error = ovpn_map_cbc_error (rv);
	      goto trace;
	    }

	  /* Successfully decrypted - set up for IP stack */
	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = peer->sw_if_index;

	  /* Apply MSS clamping if configured */
	  if (PREDICT_FALSE (inst->options.mssfix > 0))
	    ovpn_mssfix_packet (vm, b0, inst->options.mssfix,
			       inst->options.is_tun);

	  if (b0->current_length >= 1)
	    {
	      /* Handle ping/exit-notify control packets */
	      int ctrl_next = ovpn_handle_control_payload (vm, b0, peer, inst);
	      if (ctrl_next >= 0)
		{
		  next0 = ctrl_next;
		  goto done;
		}

	      /* Route to appropriate next node */
	      next0 = ovpn_route_decrypted_packet (vm, b0, inst, peer);
	    }

	  /* Store peer and rx bytes for batched counter update */
	  u32 pkt_bytes =
	    (b0->flags & VLIB_BUFFER_NEXT_PRESENT) ?
	    vlib_buffer_length_in_chain (vm, b0) : b0->current_length;
	  peers[buf_idx] = peer;
	  rx_bytes[buf_idx] = pkt_bytes;

	  /* Update peer statistics */
	  ovpn_peer_update_rx (peer, now, pkt_bytes);

	  goto done;
	}

      /*
       * Not a static key no-opcode packet.
       * Validate the opcode for normal OpenVPN packet processing.
       */
      if (PREDICT_FALSE (!ovpn_opcode_is_valid (opcode)))
	{
	  error = OVPN_INPUT_ERROR_INVALID_OPCODE;
	  goto trace;
	}

      /* Handle based on packet type */
      if (ovpn_opcode_is_data (opcode))
	{
	  /*
	   * Data channel packet
	   */

	  if (opcode == OVPN_OP_DATA_V2)
	    {
	      /* DATA_V2 has peer_id in header */
	      if (PREDICT_FALSE (len < OVPN_DATA_V2_MIN_SIZE + OVPN_TAG_SIZE))
		{
		  error = OVPN_INPUT_ERROR_TOO_SHORT;
		  goto trace;
		}

	  ovpn_data_v2_header_t *hdr = (ovpn_data_v2_header_t *) data;
	  peer_id = ovpn_data_v2_get_peer_id (hdr);

	  /* Extract remote endpoint (float/static-key handling) */
	  ovpn_extract_remote_endpoint (b0, is_ip6, &remote_addr,
					&remote_port);
	  if (inst->options.float_enabled)
	    {
	      ip_address_copy (&remote_addrs[buf_idx], &remote_addr);
	      remote_ports[buf_idx] = remote_port;
	    }
	    }
	  else
	    {
	      /*
	       * DATA_V1 - lookup peer by remote endpoint (outer IP:port)
	       */
	      u32 min_size = inst->options.static_key_mode &&
				 !OVPN_CIPHER_IS_AEAD (inst->cipher_alg) ?
			       OVPN_DATA_V1_CBC_MIN_SIZE :
			       (OVPN_DATA_V1_MIN_SIZE + OVPN_TAG_SIZE);
	      if (PREDICT_FALSE (len < min_size))
		{
		  error = OVPN_INPUT_ERROR_TOO_SHORT;
		  goto trace;
		}

	      /* Extract remote address from outer IP header */
	      ovpn_extract_remote_endpoint (b0, is_ip6, &remote_addr,
					    &remote_port);

	      /* Store remote address for NAT/float detection only if enabled */
	      if (inst->options.float_enabled)
		{
		  ip_address_copy (&remote_addrs[buf_idx], &remote_addr);
		  remote_ports[buf_idx] = remote_port;
		}

	      /* Lookup peer by remote endpoint */
	      peer = ovpn_peer_lookup_by_remote (&inst->multi_context.peer_db,
						 &remote_addr, remote_port);
	      if (peer)
		{
		  peer_id = peer->peer_id;
		}
	      else

		/*
		 * Static key mode: auto-create peer on first packet
		 * This allows clients to connect without handshake
		 */
		if (PREDICT_FALSE (!peer && inst->options.static_key_mode))
		  {
		    peer = ovpn_static_key_create_peer (vm, inst, &remote_addr,
							remote_port);
		    if (peer)
		      peer_id = peer->peer_id;
		  }

	      if (PREDICT_FALSE (!peer))
		{
		  error = OVPN_INPUT_ERROR_PEER_NOT_FOUND;
		  goto trace;
		}
	    }

	  /* Lookup peer by peer_id (for DATA_V2 path) */
	  if (!peer)
	    peer = ovpn_peer_get (&inst->multi_context.peer_db, peer_id);

	  /*
	   * Float check: If peer was found by peer_id but source address
	   * doesn't match, verify that float is enabled before accepting.
	   * This happens when client's NAT rebinds to a different port/IP.
	   * Address mismatch is rare, so use PREDICT_FALSE for optimization.
	   */
	  if (PREDICT_FALSE (!inst->options.float_enabled) && peer &&
	      PREDICT_FALSE (peer->remote_port != remote_port ||
			     ip_address_cmp (&peer->remote_addr, &remote_addr) != 0))
	    {
	      /* Address mismatch - reject if float is disabled */
	      error = OVPN_INPUT_ERROR_BAD_SRC;
	      peer = NULL; /* Force PEER_NOT_FOUND error path */
	      goto trace;
	    }

	  /*
	   * DATA_V2 with unknown peer_id in static key mode:
	   * Try to create peer using remote address from buffer
	   */
	  if (PREDICT_FALSE (!peer && inst->options.static_key_mode))
	    {
	      peer = ovpn_static_key_create_peer (vm, inst, &remote_addr,
						  remote_port);
	      if (peer)
		peer_id = peer->peer_id;
	    }

	  if (PREDICT_FALSE (!peer))
	    {
	      error = OVPN_INPUT_ERROR_PEER_NOT_FOUND;
	      goto trace;
	    }

	  /*
	   * Check peer state - only process data for established peers.
	   * Peer might be deleted or in handshake state.
	   */
	  if (PREDICT_FALSE (!ovpn_peer_is_established (peer)))
	    {
	      error = OVPN_INPUT_ERROR_PEER_NOT_FOUND;
	      goto trace;
	    }

	  /*
	   * Check if we need to handoff to peer's assigned thread
	   * Assign current thread if peer has no assigned thread yet
	   */
	  if (PREDICT_FALSE (peer->input_thread_index == ~0))
	    {
	      /* First packet for this peer - assign current thread */
	      ovpn_peer_assign_thread (peer, thread_index);
	    }

	  if (PREDICT_FALSE (thread_index != peer->input_thread_index))
	    {
	      /* Handoff to the peer's assigned thread */
	      next0 = OVPN_INPUT_NEXT_HANDOFF_DATA;
	      goto trace;
	    }

	  /*
	   * Get crypto context for this key_id using bihash (lock-free).
	   */
	  crypto = ovpn_peer_get_crypto_by_key_id (
	    &inst->multi_context.peer_db, peer_id, key_id);
	  if (PREDICT_FALSE (!crypto || !crypto->is_valid))
	    {
	      error = OVPN_INPUT_ERROR_NO_CRYPTO;
	      goto trace;
	    }

	  /*
	   * Handle decryption based on cipher mode
	   */
	  if (PREDICT_FALSE (!crypto->is_aead))
	    {
	      /* CBC+HMAC mode - process immediately (not batched) */
	      rv = ovpn_crypto_cbc_decrypt (vm, crypto, b0, &packet_id);
	      if (PREDICT_FALSE (rv < 0))
		{
		  error = ovpn_map_cbc_error (rv);
		  goto trace;
		}

	      /* Handle fragment reassembly if enabled */
	      if (PREDICT_FALSE (inst->options.fragment_size > 0))
		{
		  int frag_rv =
		    ovpn_process_fragment (vm, b0, &peer->frag_state, now);
		  if (frag_rv == 0)
		    {
		      next0 = OVPN_INPUT_NEXT_DROP;
		      b0->error = node->errors[OVPN_INPUT_ERROR_FRAG_INCOMPLETE];
		      goto done;
		    }
		  else if (frag_rv < 0)
		    {
		      next0 = OVPN_INPUT_NEXT_DROP;
		      goto done;
		    }
		}

	      /* Update peer statistics */
	      u32 pkt_bytes =
		(b0->flags & VLIB_BUFFER_NEXT_PRESENT) ?
		vlib_buffer_length_in_chain (vm, b0) : b0->current_length;
	      ovpn_peer_update_rx (peer, now, pkt_bytes);
	      rx_bytes[buf_idx] = pkt_bytes;

	      vnet_buffer (b0)->sw_if_index[VLIB_RX] = peer->sw_if_index;

	      /* Apply MSS clamping if configured */
	      if (PREDICT_FALSE (inst->options.mssfix > 0))
		ovpn_mssfix_packet (vm, b0, inst->options.mssfix,
				    inst->options.is_tun);

	      /* Handle control packets and determine routing */
	      if (b0->current_length >= 1)
		{
		  int ctrl_next =
		    ovpn_handle_control_payload (vm, b0, peer, inst);
		  if (ctrl_next >= 0)
		    {
		      next0 = ctrl_next;
		      goto done;
		    }
		  next0 = ovpn_route_decrypted_packet (vm, b0, inst, peer);
		}
	      else
		{
		  error = OVPN_INPUT_ERROR_DECRYPT_FAILED;
		  goto trace;
		}

	      /* Store peer for NAT/float tracking */
	      packet_ids[buf_idx] = packet_id;
	      peers[buf_idx] = peer;
	    }
	  else
	    {
	      /*
	       * AEAD mode - prepare for batch processing
	       */
	      rv = ovpn_crypto_decrypt_prepare (vm, ptd, crypto, b0, buf_idx,
						&packet_id);
	      if (PREDICT_FALSE (rv < 0))
		{
		  if (rv == -4)
		    error = OVPN_INPUT_ERROR_REPLAY;
		  else
		    error = OVPN_INPUT_ERROR_DECRYPT_FAILED;
		  goto trace;
		}

	      /* Store context for post-processing after batch crypto */
	      packet_ids[buf_idx] = packet_id;
	      instances[buf_idx] = inst;
	      crypto_contexts[buf_idx] = crypto;
	      peers[buf_idx] = peer;
	      decrypt_count++;

	      /* Mark for pending decryption - will be updated after batch */
	      next0 =
		OVPN_INPUT_NEXT_IP4_INPUT; /* Placeholder, will be fixed up */
	    }
	}
      else if (ovpn_opcode_is_control (opcode))
	{
	  /*
	   * Control channel packet (handshake)
	   * Must be processed on main thread (thread 0)
	   */
	  if (thread_index != 0)
	    {
	      /* Handoff to main thread */
	      next0 = OVPN_INPUT_NEXT_HANDOFF_HANDSHAKE;
	      goto trace;
	    }

	  /* We're on main thread - process handshake */
	  next0 = OVPN_INPUT_NEXT_HANDSHAKE;
	}

    done:
      /* Successfully processed packet - continue to trace */

    trace:
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ovpn_input_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->opcode = opcode;
	  t->key_id = key_id;
	  t->peer_id = peer_id;
	  t->packet_id = packet_id;
	  t->sw_if_index = peer ? peer->sw_if_index : ~0;
	  t->packet_len = len;
	  t->next_index = next0;
	  t->error = error;
	}

      if (error != OVPN_INPUT_ERROR_NONE)
	{
	  b0->error = node->errors[error];
	  next0 = OVPN_INPUT_NEXT_DROP;
	  error_counts[error]++;
	}

      next[0] = next0;

      /* Next iteration */
      from += 1;
      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  /*
   * Batch process all decrypt operations
   * This handles both single-buffer and chained-buffer crypto
   */
  if (decrypt_count > 0)
    {
      ovpn_crypto_decrypt_process (vm, node, ptd, bufs, nexts,
				   OVPN_INPUT_NEXT_DROP);

      /*
       * Post-process decrypted packets (AEAD mode only):
       * - Update replay windows
       * - Advance buffers past headers
       * - Determine inner packet type
       * - Update statistics
       *
       * Note: CBC packets are fully processed inline and skip this loop
       */
      for (u32 i = 0; i < frame->n_vectors; i++)
	{
	  /* Skip packets that weren't queued for AEAD decryption */
	  if (!crypto_contexts[i])
	    {
	      continue;
	    }

	  /* Skip packets that failed decryption */
	  if (nexts[i] == OVPN_INPUT_NEXT_DROP)
	    {
	      continue;
	    }
	  vlib_buffer_t *b0 = bufs[i];
	  ovpn_peer_t *peer = peers[i];
	  ovpn_crypto_context_t *crypto = crypto_contexts[i];
	  u32 packet_id = packet_ids[i];
	  ovpn_instance_t *pkt_inst = instances[i];

	  /* Update replay window */
	  ovpn_crypto_update_replay (crypto, packet_id);

	  /*
	   * NAT/float: Check if remote address changed.
	   * Only queue update after successful decrypt (authentication).
	   * Address changes are rare, so use PREDICT_FALSE for optimization.
	   */
	  if (pkt_inst && pkt_inst->options.float_enabled &&
	      PREDICT_FALSE (peer->remote_port != remote_ports[i] ||
			     ip_address_cmp (&peer->remote_addr, &remote_addrs[i]) != 0))
	    {
	      /* Store pending address and signal main thread */
	      ip_address_copy (&peer->pending_remote_addr, &remote_addrs[i]);
	      peer->pending_remote_port = remote_ports[i];
	      vlib_process_signal_event_mt (
		vm, ovpn_periodic_node.index, OVPN_PROCESS_EVENT_ADDR_UPDATE,
		OVPN_ADDR_UPDATE_DATA (pkt_inst->instance_id, peer->peer_id));
	    }

	  /*
	   * Advance buffer past header and tag to plaintext.
	   * DATA_V1: [opcode:1][packet_id:4][tag:16][plaintext:N]
	   * DATA_V2: [opcode:1][peer_id:3][packet_id:4][tag:16][plaintext:N]
	   */
	  u8 *pkt_data = vlib_buffer_get_current (b0);
	  u8 opcode = pkt_data[0] >> 3;
	  if (opcode == OVPN_OP_DATA_V1)
	    vlib_buffer_advance (b0,
				 sizeof (ovpn_data_v1_header_t) + OVPN_TAG_SIZE);
	  else
	    vlib_buffer_advance (b0,
				 sizeof (ovpn_data_v2_header_t) + OVPN_TAG_SIZE);

	  /* Handle fragment reassembly if enabled */
	  if (PREDICT_FALSE (pkt_inst && pkt_inst->options.fragment_size > 0))
	    {
	      int frag_rv =
		ovpn_process_fragment (vm, b0, &peer->frag_state, now);
	      if (frag_rv == 0)
		{
		  nexts[i] = OVPN_INPUT_NEXT_DROP;
		  b0->error = node->errors[OVPN_INPUT_ERROR_FRAG_INCOMPLETE];
		  continue;
		}
	      else if (frag_rv < 0)
		{
		  nexts[i] = OVPN_INPUT_NEXT_DROP;
		  continue;
		}
	    }

	  /* Update peer statistics */
	  u32 pkt_bytes =
	    (b0->flags & VLIB_BUFFER_NEXT_PRESENT) ?
	    vlib_buffer_length_in_chain (vm, b0) : b0->current_length;
	  ovpn_peer_update_rx (peer, now, pkt_bytes);
	  rx_bytes[i] = pkt_bytes;

	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = peer->sw_if_index;

	  /* Apply MSS clamping if configured */
	  if (PREDICT_FALSE (pkt_inst && pkt_inst->options.mssfix > 0))
	    ovpn_mssfix_packet (vm, b0, pkt_inst->options.mssfix,
			       pkt_inst->options.is_tun);

	  /* Handle control packets and routing */
	  if (PREDICT_TRUE (b0->current_length >= 1))
	    {
	      /* Handle ping/exit-notify */
	      int ctrl_next =
		ovpn_handle_control_payload (vm, b0, peer, pkt_inst);
	      if (ctrl_next >= 0)
		{
		  nexts[i] = ctrl_next;
		  continue;
		}

	      /* Client-to-client check */
	      if (ovpn_check_client_to_client (b0, pkt_inst, peer))
		{
		  nexts[i] = OVPN_INPUT_NEXT_DROP;
		  b0->error = node->errors[OVPN_INPUT_ERROR_CLIENT_TO_CLIENT];
		  continue;
		}

	      /* Route to appropriate next node */
	      if (pkt_inst)
		nexts[i] = ovpn_route_decrypted_packet (vm, b0, pkt_inst, peer);
	      else
		nexts[i] = OVPN_INPUT_NEXT_IP4_INPUT;
	    }
	}
    }

  /*
   * Batch update interface rx counters
   * Iterate through all buffers and increment counters per sw_if_index
   */
  {
    vnet_main_t *vnm = vnet_get_main ();
    for (u32 i = 0; i < frame->n_vectors; i++)
      {
	if (peers[i] && rx_bytes[i] > 0)
	  {
	    vlib_increment_combined_counter (
	      vnm->interface_main.combined_sw_if_counters +
		VNET_INTERFACE_COUNTER_RX,
	      thread_index, peers[i]->sw_if_index, 1, rx_bytes[i]);
	  }
      }
  }

  /*
   * Batch update error counters
   */
  for (u32 i = 1; i < OVPN_INPUT_N_ERROR; i++)
    {
      if (error_counts[i] > 0)
	vlib_node_increment_counter (vm, node->node_index, i, error_counts[i]);
    }

  vlib_buffer_enqueue_to_next (vm, node, vlib_frame_vector_args (frame), nexts,
			       frame->n_vectors);

  return frame->n_vectors;
}

/*
 * Handshake node next indices
 */
typedef enum
{
  OVPN_HANDSHAKE_NEXT_DROP,
  OVPN_HANDSHAKE_NEXT_IP4_LOOKUP,
  OVPN_HANDSHAKE_NEXT_IP6_LOOKUP,
  OVPN_HANDSHAKE_N_NEXT,
} ovpn_handshake_next_t;

/*
 * Handshake node error codes
 */
typedef enum
{
  OVPN_HANDSHAKE_ERROR_NONE,
  OVPN_HANDSHAKE_ERROR_PROCESSED,
  OVPN_HANDSHAKE_ERROR_INVALID,
  OVPN_HANDSHAKE_ERROR_HMAC_FAILED,
  OVPN_HANDSHAKE_ERROR_NO_PENDING,
  OVPN_HANDSHAKE_N_ERROR,
} ovpn_handshake_error_t;

static char *ovpn_handshake_error_strings[] = {
  [OVPN_HANDSHAKE_ERROR_NONE] = "No error",
  [OVPN_HANDSHAKE_ERROR_PROCESSED] = "Processed",
  [OVPN_HANDSHAKE_ERROR_INVALID] = "Invalid packet",
  [OVPN_HANDSHAKE_ERROR_HMAC_FAILED] = "HMAC verification failed",
  [OVPN_HANDSHAKE_ERROR_NO_PENDING] = "No pending connection",
};

/*
 * Handshake trace data
 */
typedef struct
{
  u8 opcode;
  u8 key_id;
  ip46_address_t src_addr;
  ip46_address_t dst_addr;
  u16 src_port;
  u16 dst_port;
  u8 is_ip6;
  int result;
} ovpn_handshake_trace_t;

static u8 *
format_ovpn_handshake_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ovpn_handshake_trace_t *t = va_arg (*args, ovpn_handshake_trace_t *);

  s = format (s, "ovpn-handshake: opcode %U key_id %u result %d",
	      format_ovpn_opcode, t->opcode, t->key_id, t->result);
  if (t->is_ip6)
    s = format (s, "\n  src %U:%u dst %U:%u", format_ip6_address,
		&t->src_addr.ip6, t->src_port, format_ip6_address,
		&t->dst_addr.ip6, t->dst_port);
  else
    s = format (s, "\n  src %U:%u dst %U:%u", format_ip4_address,
		&t->src_addr.ip4, t->src_port, format_ip4_address,
		&t->dst_addr.ip4, t->dst_port);

  return s;
}

/*
 * Handshake node - handles control channel processing
 * This node runs on main thread (thread 0) only
 */
static uword
ovpn_handshake_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			vlib_frame_t *frame, u8 is_ip4)
{
  u32 n_left_from, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 n_processed = 0;

  /* Assert we're on main thread */
  ASSERT (vm->thread_index == 0);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from > 0)
    {
      vlib_buffer_t *b0 = b[0];
      u16 next0 = OVPN_HANDSHAKE_NEXT_DROP;
      ip_address_t src_addr, dst_addr;
      u16 src_port, dst_port;
      u8 is_ip6 = 0;
      int rv;
      u8 opcode = 0, key_id = 0;
      u8 *data;

      /* Get opcode from first byte */
      data = vlib_buffer_get_current (b0);
      if (b0->current_length >= 1)
	{
	  opcode = ovpn_op_get_opcode (data[0]);
	  key_id = ovpn_op_get_key_id (data[0]);
	}

      /*
       * Extract IP addresses and ports from the original packet.
       * Use instance configuration for IP version.
       */
      {
	u8 *current = vlib_buffer_get_current (b0);
	u8 *udp_start = current - sizeof (udp_header_t);
	udp_header_t *udp = (udp_header_t *) udp_start;

	/* Get ports from UDP header */
	dst_port = clib_net_to_host_u16 (udp->dst_port);
	src_port = clib_net_to_host_u16 (udp->src_port);

	/* Use node type to determine IP version (is_ip4 parameter) */
	if (!is_ip4)
	  {
	    u8 *ip6_start = udp_start - sizeof (ip6_header_t);
	    ip6_header_t *ip6 = (ip6_header_t *) ip6_start;

	    ip_address_set (&src_addr, &ip6->src_address, AF_IP6);
	    ip_address_set (&dst_addr, &ip6->dst_address, AF_IP6);
	    is_ip6 = 1;
	  }
	else
	  {
	    u8 *ip4_start = udp_start - sizeof (ip4_header_t);
	    ip4_header_t *ip4 = (ip4_header_t *) ip4_start;

	    ip_address_set (&src_addr, &ip4->src_address, AF_IP4);
	    ip_address_set (&dst_addr, &ip4->dst_address, AF_IP4);
	    is_ip6 = 0;
	  }
      }

      /* Process the handshake packet */
      rv = ovpn_handshake_process_packet (vm, b0, &src_addr, src_port,
					  &dst_addr, dst_port, is_ip6);

      if (rv >= 0)
	{
	  n_processed++;
	}

      /* Always drop the incoming control packet after processing */
      next0 = OVPN_HANDSHAKE_NEXT_DROP;

      /* Trace */
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ovpn_handshake_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->opcode = opcode;
	  t->key_id = key_id;
	  t->is_ip6 = is_ip6;
	  t->result = rv;
	  if (is_ip6)
	    {
	      clib_memcpy (&t->src_addr.ip6, &src_addr.ip.ip6,
			   sizeof (ip6_address_t));
	      clib_memcpy (&t->dst_addr.ip6, &dst_addr.ip.ip6,
			   sizeof (ip6_address_t));
	    }
	  else
	    {
	      t->src_addr.ip4.as_u32 = src_addr.ip.ip4.as_u32;
	      t->dst_addr.ip4.as_u32 = dst_addr.ip.ip4.as_u32;
	    }
	  t->src_port = src_port;
	  t->dst_port = dst_port;
	}

      next[0] = next0;
      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  vlib_node_increment_counter (vm, node->node_index,
			       OVPN_HANDSHAKE_ERROR_PROCESSED, n_processed);

  return frame->n_vectors;
}

VLIB_NODE_FN (ovpn4_handshake_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ovpn_handshake_node_fn (vm, node, frame, 1);
}

VLIB_NODE_FN (ovpn6_handshake_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ovpn_handshake_node_fn (vm, node, frame, 0);
}

VLIB_NODE_FN (ovpn4_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ovpn_input_inline (vm, node, frame, 0 /* is_ip6 */);
}

VLIB_NODE_FN (ovpn6_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ovpn_input_inline (vm, node, frame, 1 /* is_ip6 */);
}

VLIB_REGISTER_NODE (ovpn4_handshake_node) = {
  .name = "ovpn4-handshake",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_handshake_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = OVPN_HANDSHAKE_N_ERROR,
  .error_strings = ovpn_handshake_error_strings,
  .n_next_nodes = OVPN_HANDSHAKE_N_NEXT,
  .next_nodes = {
    [OVPN_HANDSHAKE_NEXT_DROP] = "error-drop",
    [OVPN_HANDSHAKE_NEXT_IP4_LOOKUP] = "ip4-lookup",
    [OVPN_HANDSHAKE_NEXT_IP6_LOOKUP] = "ip6-lookup",
  },
};

VLIB_REGISTER_NODE (ovpn6_handshake_node) = {
  .name = "ovpn6-handshake",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_handshake_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = OVPN_HANDSHAKE_N_ERROR,
  .error_strings = ovpn_handshake_error_strings,
  .n_next_nodes = OVPN_HANDSHAKE_N_NEXT,
  .next_nodes = {
    [OVPN_HANDSHAKE_NEXT_DROP] = "error-drop",
    [OVPN_HANDSHAKE_NEXT_IP4_LOOKUP] = "ip4-lookup",
    [OVPN_HANDSHAKE_NEXT_IP6_LOOKUP] = "ip6-lookup",
  },
};

VLIB_REGISTER_NODE (ovpn4_input_node) = {
  .name = "ovpn4-input",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = OVPN_INPUT_N_ERROR,
  .error_strings = ovpn_input_error_strings,
  .n_next_nodes = OVPN_INPUT_N_NEXT,
  .next_nodes = {
    [OVPN_INPUT_NEXT_HANDOFF_HANDSHAKE] = "ovpn4-handshake-handoff",
    [OVPN_INPUT_NEXT_HANDOFF_DATA] = "ovpn4-input-data-handoff",
    [OVPN_INPUT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
    [OVPN_INPUT_NEXT_IP6_INPUT] = "ip6-input",
    [OVPN_INPUT_NEXT_L2_INPUT] = "l2-input",
    [OVPN_INPUT_NEXT_HANDSHAKE] = "ovpn4-handshake",
    [OVPN_INPUT_NEXT_REASS4] = "ovpn4-reass",
    [OVPN_INPUT_NEXT_REASS6] = "ovpn6-reass",
    [OVPN_INPUT_NEXT_REASS_L2] = "ovpn-l2-reass",
    [OVPN_INPUT_NEXT_SLOW_PATH] = "ovpn-slow-path",
    [OVPN_INPUT_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (ovpn6_input_node) = {
  .name = "ovpn6-input",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = OVPN_INPUT_N_ERROR,
  .error_strings = ovpn_input_error_strings,
  .n_next_nodes = OVPN_INPUT_N_NEXT,
  .next_nodes = {
    [OVPN_INPUT_NEXT_HANDOFF_HANDSHAKE] = "ovpn6-handshake-handoff",
    [OVPN_INPUT_NEXT_HANDOFF_DATA] = "ovpn6-input-data-handoff",
    [OVPN_INPUT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
    [OVPN_INPUT_NEXT_IP6_INPUT] = "ip6-input",
    [OVPN_INPUT_NEXT_L2_INPUT] = "l2-input",
    [OVPN_INPUT_NEXT_HANDSHAKE] = "ovpn6-handshake",
    [OVPN_INPUT_NEXT_REASS4] = "ovpn4-reass",
    [OVPN_INPUT_NEXT_REASS6] = "ovpn6-reass",
    [OVPN_INPUT_NEXT_REASS_L2] = "ovpn-l2-reass",
    [OVPN_INPUT_NEXT_SLOW_PATH] = "ovpn-slow-path",
    [OVPN_INPUT_NEXT_DROP] = "error-drop",
  },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
