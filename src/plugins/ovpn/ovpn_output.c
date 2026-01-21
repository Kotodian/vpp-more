/*
 * ovpn_output.c - OpenVPN output node
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
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/adj/adj.h>
#include <ovpn/ovpn.h>
#include <ovpn/ovpn_packet.h>
#include <ovpn/ovpn_peer.h>
#include <ovpn/ovpn_crypto.h>
#include <ovpn/ovpn_mssfix.h>
#include <ovpn/ovpn_fragment.h>

/* Output node next indices */
typedef enum
{
  OVPN_OUTPUT_NEXT_HANDOFF,
  OVPN_OUTPUT_NEXT_INTERFACE_OUTPUT,
  OVPN_OUTPUT_NEXT_FRAG,
  OVPN_OUTPUT_NEXT_ERROR,
  OVPN_OUTPUT_N_NEXT,
} ovpn_output_next_t;

/* Error codes */
typedef enum
{
  OVPN_OUTPUT_ERROR_NONE,
  OVPN_OUTPUT_ERROR_PEER_NOT_FOUND,
  OVPN_OUTPUT_ERROR_NO_CRYPTO,
  OVPN_OUTPUT_ERROR_ENCRYPT_FAILED,
  OVPN_OUTPUT_ERROR_NO_BUFFER_SPACE,
  OVPN_OUTPUT_ERROR_FRAG_TOO_BIG,
  OVPN_OUTPUT_N_ERROR,
} ovpn_output_error_t;

static char *ovpn_output_error_strings[] = {
  [OVPN_OUTPUT_ERROR_NONE] = "No error",
  [OVPN_OUTPUT_ERROR_PEER_NOT_FOUND] = "Peer not found",
  [OVPN_OUTPUT_ERROR_NO_CRYPTO] = "No crypto context",
  [OVPN_OUTPUT_ERROR_ENCRYPT_FAILED] = "Encryption failed",
  [OVPN_OUTPUT_ERROR_NO_BUFFER_SPACE] = "No buffer space",
  [OVPN_OUTPUT_ERROR_FRAG_TOO_BIG] = "Packet too big for fragment",
};

/* Trace data */
typedef struct
{
  u32 peer_id;
  u32 adj_index;
  u32 packet_id;
  u16 inner_len;
  u16 outer_len;
  u8 next_index;
  u8 error;
} ovpn_output_trace_t;

static u8 *
format_ovpn4_output_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ovpn_output_trace_t *t = va_arg (*args, ovpn_output_trace_t *);

  s = format (s, "ovpn4-output: peer_id %u adj_index %u packet_id %u",
	      t->peer_id, t->adj_index, t->packet_id);
  s = format (s, "\n  inner_len %u outer_len %u", t->inner_len, t->outer_len);
  s = format (s, "\n  next %u error %u", t->next_index, t->error);

  return s;
}

static u8 *
format_ovpn6_output_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ovpn_output_trace_t *t = va_arg (*args, ovpn_output_trace_t *);

  s = format (s, "ovpn6-output: peer_id %u adj_index %u packet_id %u",
	      t->peer_id, t->adj_index, t->packet_id);
  s = format (s, "\n  inner_len %u outer_len %u", t->inner_len, t->outer_len);
  s = format (s, "\n  next %u error %u", t->next_index, t->error);

  return s;
}

/*
 * Common output inline function
 * Encrypts packets and prepares them for adj-midchain-tx
 */
always_inline uword
ovpn_output_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vlib_frame_t *frame, u8 is_ip4)
{
  u32 n_left_from, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  f64 now = vlib_time_now (vm);
  u32 last_adj_index = ~0;
  u32 last_peer_id = ~0;
  u32 last_sw_if_index = ~0;
  ovpn_peer_t *peer = NULL;
  ovpn_instance_t *inst = NULL;
  u32 thread_index = vm->thread_index;
  ovpn_per_thread_crypto_t *ptd = ovpn_crypto_get_ptd (thread_index);

  /* Track peers for post-processing */
  ovpn_peer_t *peers[VLIB_FRAME_SIZE];
  u16 inner_lens[VLIB_FRAME_SIZE];
  /* Track tx bytes per buffer for batched counter updates */
  u32 tx_bytes[VLIB_FRAME_SIZE];
  /* Track error counts per error type for batched counter updates */
  u32 error_counts[OVPN_OUTPUT_N_ERROR];
  u32 encrypt_count = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  /* Initialize tracking arrays */
  clib_memset (peers, 0, sizeof (peers));
  clib_memset (tx_bytes, 0, sizeof (tx_bytes));
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
      ovpn_output_error_t error = OVPN_OUTPUT_ERROR_NONE;
      ovpn_output_next_t next0 = OVPN_OUTPUT_NEXT_ERROR;
      ovpn_crypto_context_t *crypto = NULL;
      u32 adj_index;
      u32 peer_id = 0;
      u32 packet_id = 0;
      u16 inner_len, outer_len = 0;
      int rv;

      inner_len = b0->current_length;

      /* Get adjacency index from buffer */
      adj_index = vnet_buffer (b0)->ip.adj_index[VLIB_TX];

      /*
       * Lookup peer and instance by adjacency index (cached).
       * The peer contains sw_if_index which maps to an instance.
       */
      if (PREDICT_FALSE (adj_index != last_adj_index))
	{
	  peer_id = ovpn_peer_get_by_adj_index (adj_index);
	  if (peer_id != ~0 && peer_id != last_peer_id)
	    {
	      /* Get instance from sw_if_index of the interface this adj uses
	       */
	      u32 sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	      if (sw_if_index != last_sw_if_index)
		{
		  inst = ovpn_instance_get_by_sw_if_index (sw_if_index);
		  last_sw_if_index = sw_if_index;
		}
	      if (inst)
		{
		  peer = ovpn_peer_get (&inst->multi_context.peer_db, peer_id);
		  last_peer_id = peer_id;
		}
	      else
		{
		  peer = NULL;
		}
	    }
	  else if (peer_id == ~0)
	    {
	      peer = NULL;
	    }
	  last_adj_index = adj_index;
	}
      else
	{
	  peer_id = last_peer_id;
	}

      /*
       * Check peer state atomically - allow ESTABLISHED and REKEYING.
       * Peer might be deleted or in wrong state.
       */
      if (PREDICT_FALSE (!peer || !ovpn_peer_is_established (peer)))
	{
	  error = OVPN_OUTPUT_ERROR_PEER_NOT_FOUND;
	  goto trace;
	}

      /*
       * Get current crypto context (lock-free).
       * During rekey, peer has two valid keys - output always uses current.
       * The current_key_slot is updated atomically after new key is installed.
       */
      u8 key_slot = peer->current_key_slot;
      crypto = &peer->keys[key_slot].crypto;
      if (PREDICT_FALSE (!crypto || !crypto->is_valid))
	{
	  error = OVPN_OUTPUT_ERROR_NO_CRYPTO;
	  goto trace;
	}

      /* Get key_id for the current key slot */
      u8 key_id = peer->keys[key_slot].key_id;

      /*
       * When we reach this node from adj-midchain, the buffer contains:
       * [outer IP:20/40][outer UDP:8][inner packet]
       * We need to save the outer headers, encrypt only the inner packet,
       * then prepend the outer headers back after encryption.
       */
      u32 outer_hdr_len =
	(is_ip4 ? sizeof (ip4_header_t) : sizeof (ip6_header_t)) +
	sizeof (udp_header_t);

      /* Save outer headers before processing */
      u8 saved_outer_hdr[48]; /* Max size for IPv6 + UDP */
      clib_memcpy_fast (saved_outer_hdr, vlib_buffer_get_current (b0),
			outer_hdr_len);

      /* Advance past outer headers to inner packet */
      vlib_buffer_advance (b0, outer_hdr_len);
      inner_len = b0->current_length;

      /*
       * Apply MSS clamping if configured.
       * This must be done before encryption while we have access to the
       * plaintext inner packet.
       */
      if (PREDICT_FALSE (inst->options.mssfix > 0))
	{
	  ovpn_mssfix_packet (vm, b0, inst->options.mssfix,
			      inst->options.is_tun);
	}

      /*
       * Handle fragmentation if configured.
       * OpenVPN fragmentation adds a 4-byte header before encryption.
       * fragment_size is the max OUTER UDP payload size.
       *
       * Encryption overhead for AEAD: 8 (opcode+peer_id+packet_id) + 16 (tag)
       * Encryption overhead for CBC+HMAC: ~32+ bytes (HMAC + IV + padding)
       */
      if (PREDICT_FALSE (inst->options.fragment_size > 0))
	{
	  u16 frag_size = inst->options.fragment_size;
	  u16 crypto_overhead =
	    crypto->is_aead ? 24 : 48; /* Conservative estimate */
	  u16 max_frag_payload =
	    (frag_size > crypto_overhead + OVPN_FRAG_HDR_SIZE)
	      ? (frag_size - crypto_overhead - OVPN_FRAG_HDR_SIZE)
	      : 0;

	  inner_len = b0->current_length;

	  if (PREDICT_FALSE (inner_len > max_frag_payload))
	    {
	      /*
	       * Packet too big for single fragment - route to frag node.
	       * Buffer already points to inner packet (outer headers stripped).
	       * Frag node will add outer headers after encryption.
	       */
	      next0 = OVPN_OUTPUT_NEXT_FRAG;
	      goto trace;
	    }
	  else
	    {
	      /*
	       * Packet fits in single fragment.
	       * Prepend FRAG_WHOLE header.
	       */
	      u32 frag_hdr = ovpn_frag_make_header (OVPN_FRAG_WHOLE, 0, 0, 0);
	      vlib_buffer_advance (b0, -OVPN_FRAG_HDR_SIZE);
	      u8 *frag_hdr_ptr = vlib_buffer_get_current (b0);
	      clib_memcpy_fast (frag_hdr_ptr, &frag_hdr, OVPN_FRAG_HDR_SIZE);

	      /* Update inner_len to include fragment header */
	      inner_len = b0->current_length;
	    }
	}

      /*
       * Encrypt the packet based on cipher mode
       */
      if (PREDICT_TRUE (crypto->is_aead))
	{
	  /*
	   * AEAD mode: Prepare encrypt operation (supports chained buffers)
	   * ovpn_crypto_encrypt_prepare will:
	   * 1. Linearize buffer chain if needed
	   * 2. Prepend OpenVPN header (opcode + peer_id + packet_id)
	   * 3. Reserve space for authentication tag
	   * 4. Queue crypto operation for batch processing
	   */
	  u32 buf_idx = b - bufs;
	  rv = ovpn_crypto_encrypt_prepare (vm, ptd, crypto, b0, buf_idx,
					    peer->peer_id, key_id);
	  if (PREDICT_FALSE (rv < 0))
	    {
	      if (rv == -3)
		error = OVPN_OUTPUT_ERROR_NO_BUFFER_SPACE;
	      else
		error = OVPN_OUTPUT_ERROR_ENCRYPT_FAILED;
	      /* Restore buffer position on error */
	      vlib_buffer_advance (b0, -(i32) outer_hdr_len);
	      goto trace;
	    }

	  /*
	   * Prepend outer headers back to the buffer.
	   * After encrypt_prepare, buffer contains:
	   * [OpenVPN hdr][encrypted inner packet][tag]
	   * We need:
	   * [outer IP][outer UDP][OpenVPN hdr][encrypted inner][tag]
	   */
	  vlib_buffer_advance (b0, -(i32) outer_hdr_len);
	  clib_memcpy_fast (vlib_buffer_get_current (b0), saved_outer_hdr,
			    outer_hdr_len);

	  /* Store context for post-processing after batch crypto */
	  peers[buf_idx] = peer;
	  inner_lens[buf_idx] = inner_len;
	  encrypt_count++;

	  packet_id = crypto->packet_id_send - 1; /* Was just incremented */
	}
      else
	{
	  /*
	   * CBC+HMAC mode: Process immediately (not batched)
	   *
	   * Buffer state at this point:
	   * - Outer headers (IP+UDP) were already saved to saved_outer_hdr above
	   * - Buffer has been advanced past outer headers
	   * - Current position points to inner packet
	   *
	   * We need to:
	   * 1. Encrypt the inner packet (prepends hmac+iv)
	   * 2. Retreat to make room for outer headers
	   * 3. Restore outer headers at the beginning
	   */

	  /* Encrypt the inner packet (this prepends hmac+iv) */
	  rv = ovpn_crypto_cbc_encrypt (vm, crypto, b0);
	  if (PREDICT_FALSE (rv < 0))
	    {
	      /* Revert buffer position before dropping */
	      vlib_buffer_advance (b0, -(i32) outer_hdr_len);
	      error = OVPN_OUTPUT_ERROR_ENCRYPT_FAILED;
	      goto trace;
	    }

	  /*
	   * After encryption, buffer structure is:
	   *   current_data points to encrypted packet (HMAC)
	   *   current_length = encrypted packet size
	   *
	   * We need to:
	   * 1. Make room for outer headers by moving encrypted data forward
	   * 2. Copy outer headers to the beginning
	   *
	   * Note: The memmove from encrypted_start to final_start + outer_hdr_len
	   * may be a no-op since they end up at the same address, but the
	   * memcpy of the outer header is essential.
	   */
	  u32 encrypted_len = b0->current_length;

	  /* Retreat to make room for outer headers */
	  vlib_buffer_advance (b0, -(i32) outer_hdr_len);

	  /* Get final position and copy outer headers */
	  u8 *final_start = vlib_buffer_get_current (b0);

	  /* Copy saved outer headers to the beginning */
	  clib_memcpy_fast (final_start, saved_outer_hdr, outer_hdr_len);

	  /* Update buffer length to include outer headers */
	  b0->current_length = outer_hdr_len + encrypted_len;

	  /*
	   * Update outer IP/UDP length fields to reflect new packet size.
	   * The original headers had lengths based on the inner packet,
	   * but now we have the encrypted payload which is larger.
	   */
	  u16 total_len = b0->current_length;
	  if (is_ip4)
	    {
	      ip4_header_t *ip4 = (ip4_header_t *) final_start;
	      udp_header_t *udp = (udp_header_t *) (ip4 + 1);
	      ip4->length = clib_host_to_net_u16 (total_len);

	      /* Compute full IP checksum (template had checksum=0) */
	      ip4->checksum = 0;
	      ip4->checksum = ip4_header_checksum (ip4);

	      /* Update UDP length - skip checksum for IPv4 (optional per RFC 768) */
	      udp->length =
		clib_host_to_net_u16 (total_len - sizeof (ip4_header_t));
	      udp->checksum = 0;
	    }
	  else
	    {
	      ip6_header_t *ip6 = (ip6_header_t *) final_start;
	      udp_header_t *udp = (udp_header_t *) (ip6 + 1);
	      ip6->payload_length =
		clib_host_to_net_u16 (total_len - sizeof (ip6_header_t));
	      udp->length =
		clib_host_to_net_u16 (total_len - sizeof (ip6_header_t));
	      udp->checksum = 0;
	    }

	  packet_id = crypto->packet_id_send - 1;
	  outer_len = vlib_buffer_length_in_chain (vm, b0);

	  /* Update peer stats and store for batched counter update */
	  ovpn_peer_update_tx (peer, vlib_time_now (vm), outer_len);
	  {
	    u32 buf_idx = b - bufs;
	    peers[buf_idx] = peer;
	    tx_bytes[buf_idx] = outer_len;
	  }
	}

      /* Mark for pending encryption - will be updated after batch */
      next0 = OVPN_OUTPUT_NEXT_INTERFACE_OUTPUT;

    trace:
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ovpn_output_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->peer_id = peer_id;
	  t->adj_index = adj_index;
	  t->packet_id = packet_id;
	  t->inner_len = inner_len;
	  t->outer_len = outer_len;
	  t->next_index = next0;
	  t->error = error;
	}

      if (error != OVPN_OUTPUT_ERROR_NONE)
	{
	  b0->error = node->errors[error];
	  next0 = OVPN_OUTPUT_NEXT_ERROR;
	  error_counts[error]++;
	}

      next[0] = next0;

      /* Next iteration */
      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  /*
   * Batch process all encrypt operations
   * This handles both single-buffer and chained-buffer crypto
   */
  if (encrypt_count > 0)
    {
      ovpn_crypto_encrypt_process (vm, node, ptd, bufs, nexts,
				   OVPN_OUTPUT_NEXT_ERROR);

      /*
       * Post-process encrypted packets:
       * - Update IP/UDP length fields
       * - Update statistics
       */
      for (u32 i = 0; i < frame->n_vectors; i++)
	{
	  /* Skip packets that weren't queued for encryption */
	  if (!peers[i])
	    continue;

	  /* Skip packets that failed encryption */
	  if (nexts[i] == OVPN_OUTPUT_NEXT_ERROR)
	    continue;

	  vlib_buffer_t *b0 = bufs[i];
	  ovpn_peer_t *peer0 = peers[i];
	  u16 outer_len = vlib_buffer_length_in_chain (vm, b0);

	  /*
	   * The rewrite (IP + UDP headers) is already applied by adj-midchain
	   * We just need to fix up the length fields
	   */
	  if (is_ip4)
	    {
	      ip4_header_t *ip4 = vlib_buffer_get_current (b0);
	      udp_header_t *udp = (udp_header_t *) (ip4 + 1);
	      u16 new_len = clib_host_to_net_u16 (outer_len);

	      /* Update IP length and recompute checksum from scratch
	       * (rewrite template may have checksum=0) */
	      ip4->length = new_len;
	      ip4->checksum = 0;
	      ip4->checksum = ip4_header_checksum (ip4);

	      /* Update UDP length - skip checksum for IPv4 (optional per RFC 768) */
	      udp->length =
		clib_host_to_net_u16 (outer_len - sizeof (ip4_header_t));
	      udp->checksum = 0;
	    }
	  else
	    {
	      ip6_header_t *ip6 = vlib_buffer_get_current (b0);
	      udp_header_t *udp = (udp_header_t *) (ip6 + 1);
	      int bogus = 0;

	      ip6->payload_length =
		clib_host_to_net_u16 (outer_len - sizeof (ip6_header_t));
	      udp->length = ip6->payload_length;

	      /* IPv6 UDP checksum is mandatory */
	      udp->checksum = 0;
	      udp->checksum =
		ip6_tcp_udp_icmp_compute_checksum (vm, b0, ip6, &bogus);
	    }

	  /* Update peer statistics and store tx bytes for batched counter */
	  ovpn_peer_update_tx (peer0, now, outer_len);
	  tx_bytes[i] = outer_len;
	}
    }

  /*
   * Batch update interface tx counters
   * Iterate through all buffers and increment counters per sw_if_index
   */
  {
    vnet_main_t *vnm = vnet_get_main ();
    for (u32 i = 0; i < frame->n_vectors; i++)
      {
	if (peers[i] && tx_bytes[i] > 0)
	  {
	    vlib_increment_combined_counter (
	      vnm->interface_main.combined_sw_if_counters +
		VNET_INTERFACE_COUNTER_TX,
	      thread_index, peers[i]->sw_if_index, 1, tx_bytes[i]);
	  }
      }
  }

  /*
   * Batch update error counters
   */
  for (u32 i = 1; i < OVPN_OUTPUT_N_ERROR; i++)
    {
      if (error_counts[i] > 0)
	vlib_node_increment_counter (vm, node->node_index, i, error_counts[i]);
    }

  vlib_buffer_enqueue_to_next (vm, node, vlib_frame_vector_args (frame), nexts,
			       frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (ovpn4_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ovpn_output_inline (vm, node, frame, /* is_ip4 */ 1);
}

VLIB_NODE_FN (ovpn6_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ovpn_output_inline (vm, node, frame, /* is_ip4 */ 0);
}

VLIB_REGISTER_NODE (ovpn4_output_node) = {
  .name = "ovpn4-output",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn4_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = OVPN_OUTPUT_N_ERROR,
  .error_strings = ovpn_output_error_strings,
  .n_next_nodes = OVPN_OUTPUT_N_NEXT,
  .next_nodes = {
    [OVPN_OUTPUT_NEXT_HANDOFF] = "ovpn4-output-handoff",
    [OVPN_OUTPUT_NEXT_INTERFACE_OUTPUT] = "adj-midchain-tx",
    [OVPN_OUTPUT_NEXT_FRAG] = "ovpn4-frag-output",
    [OVPN_OUTPUT_NEXT_ERROR] = "error-drop",
  },
};

VLIB_REGISTER_NODE (ovpn6_output_node) = {
  .name = "ovpn6-output",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn6_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = OVPN_OUTPUT_N_ERROR,
  .error_strings = ovpn_output_error_strings,
  .n_next_nodes = OVPN_OUTPUT_N_NEXT,
  .next_nodes = {
    [OVPN_OUTPUT_NEXT_HANDOFF] = "ovpn6-output-handoff",
    [OVPN_OUTPUT_NEXT_INTERFACE_OUTPUT] = "adj-midchain-tx",
    [OVPN_OUTPUT_NEXT_FRAG] = "ovpn6-frag-output",
    [OVPN_OUTPUT_NEXT_ERROR] = "error-drop",
  },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
