/*
 * ovpn_frag_output.c - OpenVPN fragment output node
 *
 * Copyright (c) 2025 <blackfaceuncle@gmail.com>
 * Licensed under the Apache License, Version 2.0
 *
 * This node handles packets that require fragmentation.
 * It creates multiple fragment buffers, encrypts each, and sends them out.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/adj/adj.h>
#include <ovpn/ovpn.h>
#include <ovpn/ovpn_packet.h>
#include <ovpn/ovpn_peer.h>
#include <ovpn/ovpn_crypto.h>
#include <ovpn/ovpn_fragment.h>

/* Fragment output node next indices */
typedef enum
{
  OVPN_FRAG_OUTPUT_NEXT_INTERFACE_OUTPUT,
  OVPN_FRAG_OUTPUT_NEXT_DROP,
  OVPN_FRAG_OUTPUT_N_NEXT,
} ovpn_frag_output_next_t;

/* Error codes */
typedef enum
{
  OVPN_FRAG_OUTPUT_ERROR_NONE,
  OVPN_FRAG_OUTPUT_ERROR_ENCRYPT_FAILED,
  OVPN_FRAG_OUTPUT_ERROR_NO_BUFFER,
  OVPN_FRAG_OUTPUT_ERROR_TOO_BIG,
  OVPN_FRAG_OUTPUT_N_ERROR,
} ovpn_frag_output_error_t;

static char *ovpn_frag_output_error_strings[] = {
  [OVPN_FRAG_OUTPUT_ERROR_NONE] = "No error",
  [OVPN_FRAG_OUTPUT_ERROR_ENCRYPT_FAILED] = "Encryption failed",
  [OVPN_FRAG_OUTPUT_ERROR_NO_BUFFER] = "No buffer available",
  [OVPN_FRAG_OUTPUT_ERROR_TOO_BIG] = "Packet too big for fragmentation",
};

/* Trace data */
typedef struct
{
  u32 peer_id;
  u32 n_fragments;
  u16 original_len;
  u16 max_frag_payload;
} ovpn_frag_output_trace_t;

static u8 *
format_ovpn_frag_output_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ovpn_frag_output_trace_t *t = va_arg (*args, ovpn_frag_output_trace_t *);

  s = format (s, "ovpn-frag-output: peer_id %u original_len %u "
		 "max_frag_payload %u n_fragments %u",
	      t->peer_id, t->original_len, t->max_frag_payload, t->n_fragments);

  return s;
}

/*
 * Fragment output node inline function
 *
 * This node receives packets that need fragmentation from ovpn-output.
 * Buffer metadata contains:
 *   - vnet_buffer(b)->ip.adj_index[VLIB_TX]: adjacency index
 *   - vnet_buffer(b)->sw_if_index[VLIB_TX]: output interface
 *
 * The packet data starts at the inner payload (after outer headers were saved).
 *
 * Uses the standard VPP frame-based enqueueing pattern (like ip4-frag node).
 */

always_inline uword
ovpn_frag_output_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *frame, u8 is_ip4)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  u32 frags_sent = 0;
  u32 error_too_big = 0;
  u32 error_encrypt_failed = 0;
  u32 error_no_peer = 0;
  f64 now = vlib_time_now (vm);
  u32 *buffer = 0; /* Reusable vector for fragments */

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 adj_index;
	  ovpn_peer_t *peer;
	  ovpn_instance_t *inst;
	  ovpn_crypto_context_t *crypto;
	  u32 next0 = OVPN_FRAG_OUTPUT_NEXT_DROP;
	  ovpn_frag_output_error_t error0 = OVPN_FRAG_OUTPUT_ERROR_NONE;

	  /* Prefetch next buffer for reduced cache misses */
	  if (n_left_from > 1)
	    {
	      vlib_buffer_t *p1 = vlib_get_buffer (vm, from[1]);
	      vlib_prefetch_buffer_header (p1, LOAD);
	      clib_prefetch_load (vlib_buffer_get_current (p1));
	    }

	  bi0 = from[0];
	  from++;
	  n_left_from--;

	  b0 = vlib_get_buffer (vm, bi0);

	  /* Get adjacency and peer */
	  adj_index = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
	  u32 sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	  u32 peer_id = ovpn_peer_get_by_adj_index (adj_index);

	  if (PREDICT_FALSE (peer_id == ~0))
	    {
	      error0 = OVPN_FRAG_OUTPUT_ERROR_NO_BUFFER;
	      error_no_peer++;
	      goto enqueue_original;
	    }

	  /* Get instance from sw_if_index */
	  inst = ovpn_instance_get_by_sw_if_index (sw_if_index);
	  if (PREDICT_FALSE (!inst))
	    {
	      error0 = OVPN_FRAG_OUTPUT_ERROR_NO_BUFFER;
	      error_no_peer++;
	      goto enqueue_original;
	    }

	  /* Get peer from instance's peer database */
	  peer = ovpn_peer_get (&inst->multi_context.peer_db, peer_id);
	  if (PREDICT_FALSE (!peer ||
			     peer->state != OVPN_PEER_STATE_ESTABLISHED))
	    {
	      error0 = OVPN_FRAG_OUTPUT_ERROR_NO_BUFFER;
	      error_no_peer++;
	      goto enqueue_original;
	    }

	  crypto = ovpn_peer_get_crypto (peer);
	  if (PREDICT_FALSE (!crypto || !crypto->is_valid))
	    {
	      error0 = OVPN_FRAG_OUTPUT_ERROR_NO_BUFFER;
	      error_no_peer++;
	      goto enqueue_original;
	    }

	  /* Calculate fragmentation parameters */
	  u16 frag_size = inst->options.fragment_size;
	  u16 crypto_overhead = crypto->is_aead ? 24 : 48;
	  u16 max_frag_payload =
	    (frag_size > crypto_overhead + OVPN_FRAG_HDR_SIZE)
	      ? (frag_size - crypto_overhead - OVPN_FRAG_HDR_SIZE)
	      : 0;

	  if (PREDICT_FALSE (max_frag_payload == 0))
	    {
	      error0 = OVPN_FRAG_OUTPUT_ERROR_TOO_BIG;
	      error_too_big++;
	      goto enqueue_original;
	    }

	  /* Create fragments - modifies b0 to be first fragment */
	  u32 *extra_bis = NULL;
	  u32 n_extra = 0;
	  int frag_rv = ovpn_frag_create_fragments (
	    vm, b0, max_frag_payload, &peer->frag_state, &extra_bis, &n_extra);

	  if (PREDICT_FALSE (frag_rv < 0))
	    {
	      error0 = OVPN_FRAG_OUTPUT_ERROR_TOO_BIG;
	      error_too_big++;
	      goto enqueue_original;
	    }

	  /* Build list of all fragment buffer indices in reusable vector */
	  vec_add1 (buffer, bi0); /* First fragment */
	  if (extra_bis)
	    {
	      for (u32 i = 0; i < n_extra; i++)
		vec_add1 (buffer, extra_bis[i]);
	      vec_free (extra_bis);
	    }

	  /* Get adjacency rewrite for outer headers */
	  ip_adjacency_t *adj = adj_get (adj_index);
	  u8 *rewrite = adj->rewrite_header.data;
	  u16 rewrite_len = adj->rewrite_header.data_bytes;
	  u8 key_id = peer->keys[peer->current_key_slot].key_id;

	  /* Process each fragment: encrypt and add outer headers */
	  u32 n_frags = vec_len (buffer);
	  for (u32 fi = 0; fi < n_frags; fi++)
	    {
	      vlib_buffer_t *fb = vlib_get_buffer (vm, buffer[fi]);
	      int enc_rv;

	      /* Encrypt fragment */
	      if (crypto->is_aead)
		enc_rv =
		  ovpn_crypto_encrypt (vm, crypto, fb, peer->peer_id, key_id);
	      else
		enc_rv = ovpn_crypto_cbc_encrypt (vm, crypto, fb);

	      if (PREDICT_FALSE (enc_rv < 0))
		{
		  error_encrypt_failed++;
		  /* Mark this fragment for drop, continue with others */
		  continue;
		}

	      /* Prepend outer headers (IP + UDP) */
	      vlib_buffer_advance (fb, -(i32) rewrite_len);
	      clib_memcpy_fast (vlib_buffer_get_current (fb), rewrite,
				rewrite_len);

	      /* Fix up IP/UDP lengths */
	      u16 outer_len = vlib_buffer_length_in_chain (vm, fb);
	      if (is_ip4)
		{
		  ip4_header_t *ip4 = vlib_buffer_get_current (fb);
		  udp_header_t *udp = (udp_header_t *) (ip4 + 1);
		  ip4->length = clib_host_to_net_u16 (outer_len);
		  ip4->checksum = 0;
		  ip4->checksum = ip4_header_checksum (ip4);
		  udp->length =
		    clib_host_to_net_u16 (outer_len - sizeof (ip4_header_t));
		  udp->checksum = 0;
		}
	      else
		{
		  ip6_header_t *ip6 = vlib_buffer_get_current (fb);
		  udp_header_t *udp = (udp_header_t *) (ip6 + 1);
		  ip6->payload_length =
		    clib_host_to_net_u16 (outer_len - sizeof (ip6_header_t));
		  udp->length =
		    clib_host_to_net_u16 (outer_len - sizeof (ip6_header_t));
		  udp->checksum = 0;
		}

	      /* Set buffer metadata */
	      vnet_buffer (fb)->sw_if_index[VLIB_TX] = sw_if_index;
	      vnet_buffer (fb)->ip.adj_index[VLIB_TX] = adj_index;

	      /* Update peer stats */
	      ovpn_peer_update_tx (peer, now, outer_len);
	      frags_sent++;
	    }

	  /* Trace if needed (on first fragment) */
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ovpn_frag_output_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->peer_id = peer->peer_id;
	      t->n_fragments = n_frags;
	      t->original_len = b0->current_length;
	      t->max_frag_payload = max_frag_payload;
	    }

	  /* Enqueue all fragments */
	  next0 = OVPN_FRAG_OUTPUT_NEXT_INTERFACE_OUTPUT;

	enqueue_original:
	  /* If we had an error before fragmentation, buffer is empty,
	   * add original packet to be dropped */
	  if (vec_len (buffer) == 0)
	    vec_add1 (buffer, bi0);

	  /* Enqueue all buffers in the vector */
	  {
	    u32 *frag_from = buffer;
	    u32 frag_left = vec_len (buffer);

	    while (frag_left > 0)
	      {
		while (frag_left > 0 && n_left_to_next > 0)
		  {
		    u32 fi0 = frag_from[0];
		    frag_from++;
		    frag_left--;

		    to_next[0] = fi0;
		    to_next++;
		    n_left_to_next--;

		    vlib_get_buffer (vm, fi0)->error = node->errors[error0];
		    vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
						     to_next, n_left_to_next,
						     fi0, next0);
		  }
		vlib_put_next_frame (vm, node, next_index, n_left_to_next);
		vlib_get_next_frame (vm, node, next_index, to_next,
				     n_left_to_next);
	      }
	  }
	  vec_reset_length (buffer);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vec_free (buffer);

  /* Update error counters */
  if (frags_sent > 0)
    vlib_node_increment_counter (vm, node->node_index,
				 OVPN_FRAG_OUTPUT_ERROR_NONE, frags_sent);
  if (error_too_big > 0)
    vlib_node_increment_counter (vm, node->node_index,
				 OVPN_FRAG_OUTPUT_ERROR_TOO_BIG, error_too_big);
  if (error_encrypt_failed > 0)
    vlib_node_increment_counter (vm, node->node_index,
				 OVPN_FRAG_OUTPUT_ERROR_ENCRYPT_FAILED,
				 error_encrypt_failed);
  if (error_no_peer > 0)
    vlib_node_increment_counter (vm, node->node_index,
				 OVPN_FRAG_OUTPUT_ERROR_NO_BUFFER,
				 error_no_peer);

  return frame->n_vectors;
}

VLIB_NODE_FN (ovpn4_frag_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ovpn_frag_output_inline (vm, node, frame, /* is_ip4 */ 1);
}

VLIB_NODE_FN (ovpn6_frag_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ovpn_frag_output_inline (vm, node, frame, /* is_ip4 */ 0);
}

VLIB_REGISTER_NODE (ovpn4_frag_output_node) = {
  .name = "ovpn4-frag-output",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_frag_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = OVPN_FRAG_OUTPUT_N_ERROR,
  .error_strings = ovpn_frag_output_error_strings,
  .n_next_nodes = OVPN_FRAG_OUTPUT_N_NEXT,
  .next_nodes = {
    [OVPN_FRAG_OUTPUT_NEXT_INTERFACE_OUTPUT] = "adj-midchain-tx",
    [OVPN_FRAG_OUTPUT_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (ovpn6_frag_output_node) = {
  .name = "ovpn6-frag-output",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_frag_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = OVPN_FRAG_OUTPUT_N_ERROR,
  .error_strings = ovpn_frag_output_error_strings,
  .n_next_nodes = OVPN_FRAG_OUTPUT_N_NEXT,
  .next_nodes = {
    [OVPN_FRAG_OUTPUT_NEXT_INTERFACE_OUTPUT] = "adj-midchain-tx",
    [OVPN_FRAG_OUTPUT_NEXT_DROP] = "error-drop",
  },
};
