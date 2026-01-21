/*
 * ovpn_reass.c - OpenVPN fragment reassembly node
 *
 * Copyright (c) 2025 <blackfaceuncle@gmail.com>
 * Licensed under the Apache License, Version 2.0
 *
 * This node handles fragment reassembly for incoming fragmented packets.
 * It receives decrypted fragments and reassembles them into complete packets.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <ovpn/ovpn.h>
#include <ovpn/ovpn_packet.h>
#include <ovpn/ovpn_peer.h>
#include <ovpn/ovpn_fragment.h>

/* Reassembly node next indices */
typedef enum
{
  OVPN_REASS_NEXT_IP4_INPUT,
  OVPN_REASS_NEXT_IP6_INPUT,
  OVPN_REASS_NEXT_L2_INPUT,
  OVPN_REASS_NEXT_SLOW_PATH,
  OVPN_REASS_NEXT_DROP,
  OVPN_REASS_N_NEXT,
} ovpn_reass_next_t;

/* Error codes */
typedef enum
{
  OVPN_REASS_ERROR_NONE,
  OVPN_REASS_ERROR_REASSEMBLED,
  OVPN_REASS_ERROR_WAITING,
  OVPN_REASS_ERROR_FAILED,
  OVPN_REASS_ERROR_WHOLE,
  OVPN_REASS_N_ERROR,
} ovpn_reass_error_t;

static char *ovpn_reass_error_strings[] = {
  [OVPN_REASS_ERROR_NONE] = "No error",
  [OVPN_REASS_ERROR_REASSEMBLED] = "Reassembly complete",
  [OVPN_REASS_ERROR_WAITING] = "Waiting for fragments",
  [OVPN_REASS_ERROR_FAILED] = "Reassembly failed",
  [OVPN_REASS_ERROR_WHOLE] = "Whole packet (no fragmentation)",
};

/* Trace data */
typedef struct
{
  u32 peer_id;
  u8 frag_type;
  u8 seq_id;
  u8 frag_id;
  u16 frag_size;
  u8 reassembled;
} ovpn_reass_trace_t;

static u8 *
format_ovpn_reass_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ovpn_reass_trace_t *t = va_arg (*args, ovpn_reass_trace_t *);

  char *frag_types[] = { "whole", "first", "middle", "last" };
  s = format (s,
	      "ovpn-reass: peer %u type %s seq_id %u frag_id %u "
	      "size %u reassembled %u",
	      t->peer_id,
	      t->frag_type < 4 ? frag_types[t->frag_type] : "unknown",
	      t->seq_id, t->frag_id, t->frag_size, t->reassembled);

  return s;
}

/*
 * Reassembly node inline function
 *
 * Buffer metadata expected:
 *   vnet_buffer(b)->sw_if_index[VLIB_RX]: tunnel sw_if_index
 *   vnet_buffer(b)->ip.adj_index[VLIB_RX]: peer_id (repurposed)
 *
 * The buffer data starts at the fragment header (4 bytes).
 */
always_inline uword
ovpn_reass_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		   vlib_frame_t *frame, u8 is_ip6, u8 is_tun)
{
  u32 n_left_from, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  f64 now = vlib_time_now (vm);
  u32 n_reassembled = 0, n_waiting = 0, n_failed = 0, n_whole = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from > 0)
    {
      vlib_buffer_t *b0 = b[0];
      u16 next0 = OVPN_REASS_NEXT_DROP;
      u8 frag_type = 0, seq_id = 0, frag_id = 0;
      u16 frag_size = 0;
      u8 reassembled = 0;

      /* Get peer from buffer metadata */
      u32 sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      u32 peer_id = vnet_buffer (b0)->ip.adj_index[VLIB_RX];

      ovpn_instance_t *inst = ovpn_instance_get_by_sw_if_index (sw_if_index);
      ovpn_peer_t *peer = NULL;

      if (inst)
	peer = ovpn_peer_get (&inst->multi_context.peer_db, peer_id);

      if (PREDICT_FALSE (!peer))
	{
	  next0 = OVPN_REASS_NEXT_DROP;
	  goto trace;
	}

      /* Parse fragment header */
      if (b0->current_length >= OVPN_FRAG_HDR_SIZE)
	{
	  u8 *frag_data = vlib_buffer_get_current (b0);
	  u32 frag_hdr;

	  clib_memcpy (&frag_hdr, frag_data, OVPN_FRAG_HDR_SIZE);
	  ovpn_frag_parse_header (frag_hdr, &frag_type, &seq_id, &frag_id,
				  &frag_size);

	  if (frag_type == OVPN_FRAG_WHOLE)
	    {
	      /* Unfragmented packet - just strip header and forward */
	      vlib_buffer_advance (b0, OVPN_FRAG_HDR_SIZE);
	      n_whole++;

	      /* Check for control messages */
	      u8 *payload = vlib_buffer_get_current (b0);
	      if (ovpn_is_ping_packet (payload, b0->current_length) ||
		  ovpn_is_exit_notify (payload, b0->current_length))
		{
		  next0 = OVPN_REASS_NEXT_SLOW_PATH;
		}
	      else if (!is_tun)
		{
		  next0 = OVPN_REASS_NEXT_L2_INPUT;
		}
	      else if (is_ip6)
		{
		  next0 = OVPN_REASS_NEXT_IP6_INPUT;
		}
	      else
		{
		  next0 = OVPN_REASS_NEXT_IP4_INPUT;
		}
	    }
	  else if (frag_type == OVPN_FRAG_YES_NOTLAST ||
		   frag_type == OVPN_FRAG_YES_LAST)
	    {
	      /* Fragment - process reassembly */
	      u8 *reassembled_data = NULL;
	      u32 reassembled_len = 0;
	      int frag_rv;

	      frag_rv =
		ovpn_frag_process_fragment (frag_data, b0->current_length,
					    &peer->frag_state, now,
					    &reassembled_data, &reassembled_len);

	      if (frag_rv == 1 && reassembled_data)
		{
		  /* Reassembly complete - replace buffer contents */
		  reassembled = 1;
		  n_reassembled++;

		  if (reassembled_len <= vlib_buffer_get_default_data_size (vm))
		    {
		      b0->current_data = 0;
		      b0->current_length = reassembled_len;
		      clib_memcpy (vlib_buffer_get_current (b0),
				   reassembled_data, reassembled_len);
		      clib_mem_free (reassembled_data);
		    }
		  else
		    {
		      clib_mem_free (reassembled_data);
		      n_failed++;
		      next0 = OVPN_REASS_NEXT_DROP;
		      goto trace;
		    }

		  /* Check for control messages */
		  u8 *payload = vlib_buffer_get_current (b0);
		  if (ovpn_is_ping_packet (payload, b0->current_length) ||
		      ovpn_is_exit_notify (payload, b0->current_length))
		    {
		      next0 = OVPN_REASS_NEXT_SLOW_PATH;
		    }
		  else if (!is_tun)
		    {
		      next0 = OVPN_REASS_NEXT_L2_INPUT;
		    }
		  else if (is_ip6)
		    {
		      next0 = OVPN_REASS_NEXT_IP6_INPUT;
		    }
		  else
		    {
		      next0 = OVPN_REASS_NEXT_IP4_INPUT;
		    }
		}
	      else if (frag_rv == 0)
		{
		  /* Waiting for more fragments - drop this buffer */
		  n_waiting++;
		  next0 = OVPN_REASS_NEXT_DROP;
		}
	      else
		{
		  /* Reassembly error */
		  n_failed++;
		  next0 = OVPN_REASS_NEXT_DROP;
		}
	    }
	  else
	    {
	      /* Unknown fragment type (e.g., FRAG_TEST) - drop */
	      next0 = OVPN_REASS_NEXT_DROP;
	    }
	}
      else
	{
	  /* Packet too short for fragment header */
	  n_failed++;
	  next0 = OVPN_REASS_NEXT_DROP;
	}

    trace:
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ovpn_reass_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->peer_id = peer ? peer->peer_id : ~0;
	  t->frag_type = frag_type;
	  t->seq_id = seq_id;
	  t->frag_id = frag_id;
	  t->frag_size = frag_size;
	  t->reassembled = reassembled;
	}

      next[0] = next0;
      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  /* Update counters */
  if (n_reassembled > 0)
    vlib_node_increment_counter (vm, node->node_index,
				 OVPN_REASS_ERROR_REASSEMBLED, n_reassembled);
  if (n_waiting > 0)
    vlib_node_increment_counter (vm, node->node_index,
				 OVPN_REASS_ERROR_WAITING, n_waiting);
  if (n_failed > 0)
    vlib_node_increment_counter (vm, node->node_index,
				 OVPN_REASS_ERROR_FAILED, n_failed);
  if (n_whole > 0)
    vlib_node_increment_counter (vm, node->node_index, OVPN_REASS_ERROR_WHOLE,
				 n_whole);

  return frame->n_vectors;
}

/* IPv4 TUN mode reassembly */
VLIB_NODE_FN (ovpn4_reass_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ovpn_reass_inline (vm, node, frame, /* is_ip6 */ 0, /* is_tun */ 1);
}

/* IPv6 TUN mode reassembly */
VLIB_NODE_FN (ovpn6_reass_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ovpn_reass_inline (vm, node, frame, /* is_ip6 */ 1, /* is_tun */ 1);
}

/* TAP mode reassembly (L2) */
VLIB_NODE_FN (ovpn_l2_reass_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ovpn_reass_inline (vm, node, frame, /* is_ip6 */ 0, /* is_tun */ 0);
}

VLIB_REGISTER_NODE (ovpn4_reass_node) = {
  .name = "ovpn4-reass",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_reass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = OVPN_REASS_N_ERROR,
  .error_strings = ovpn_reass_error_strings,
  .n_next_nodes = OVPN_REASS_N_NEXT,
  .next_nodes = {
    [OVPN_REASS_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
    [OVPN_REASS_NEXT_IP6_INPUT] = "ip6-input",
    [OVPN_REASS_NEXT_L2_INPUT] = "l2-input",
    [OVPN_REASS_NEXT_SLOW_PATH] = "ovpn-slow-path",
    [OVPN_REASS_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (ovpn6_reass_node) = {
  .name = "ovpn6-reass",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_reass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = OVPN_REASS_N_ERROR,
  .error_strings = ovpn_reass_error_strings,
  .n_next_nodes = OVPN_REASS_N_NEXT,
  .next_nodes = {
    [OVPN_REASS_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
    [OVPN_REASS_NEXT_IP6_INPUT] = "ip6-input",
    [OVPN_REASS_NEXT_L2_INPUT] = "l2-input",
    [OVPN_REASS_NEXT_SLOW_PATH] = "ovpn-slow-path",
    [OVPN_REASS_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (ovpn_l2_reass_node) = {
  .name = "ovpn-l2-reass",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_reass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = OVPN_REASS_N_ERROR,
  .error_strings = ovpn_reass_error_strings,
  .n_next_nodes = OVPN_REASS_N_NEXT,
  .next_nodes = {
    [OVPN_REASS_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
    [OVPN_REASS_NEXT_IP6_INPUT] = "ip6-input",
    [OVPN_REASS_NEXT_L2_INPUT] = "l2-input",
    [OVPN_REASS_NEXT_SLOW_PATH] = "ovpn-slow-path",
    [OVPN_REASS_NEXT_DROP] = "error-drop",
  },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
