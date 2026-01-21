/*
 * ovpn_slow_path.c - OpenVPN slow path node for control messages
 *
 * Copyright (c) 2025 <blackfaceuncle@gmail.com>
 * Licensed under the Apache License, Version 2.0
 *
 * This node handles:
 * - Ping/keepalive packets
 * - Explicit-exit-notify packets
 * - Other control messages in the data channel
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <ovpn/ovpn.h>
#include <ovpn/ovpn_packet.h>
#include <ovpn/ovpn_peer.h>

/* Slow path node next indices */
typedef enum
{
  OVPN_SLOW_PATH_NEXT_DROP,
  OVPN_SLOW_PATH_N_NEXT,
} ovpn_slow_path_next_t;

/* Error codes */
typedef enum
{
  OVPN_SLOW_PATH_ERROR_NONE,
  OVPN_SLOW_PATH_ERROR_PING,
  OVPN_SLOW_PATH_ERROR_EXIT_NOTIFY,
  OVPN_SLOW_PATH_ERROR_UNKNOWN,
  OVPN_SLOW_PATH_N_ERROR,
} ovpn_slow_path_error_t;

static char *ovpn_slow_path_error_strings[] = {
  [OVPN_SLOW_PATH_ERROR_NONE] = "No error",
  [OVPN_SLOW_PATH_ERROR_PING] = "Ping processed",
  [OVPN_SLOW_PATH_ERROR_EXIT_NOTIFY] = "Exit notify processed",
  [OVPN_SLOW_PATH_ERROR_UNKNOWN] = "Unknown control message",
};

/* Trace data */
typedef struct
{
  u32 peer_id;
  u32 instance_id;
  u8 msg_type; /* 0=unknown, 1=ping, 2=exit */
} ovpn_slow_path_trace_t;

static u8 *
format_ovpn_slow_path_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ovpn_slow_path_trace_t *t = va_arg (*args, ovpn_slow_path_trace_t *);

  char *msg_types[] = { "unknown", "ping", "exit-notify" };
  s = format (s, "ovpn-slow-path: instance %u peer %u msg_type %s",
	      t->instance_id, t->peer_id,
	      t->msg_type < 3 ? msg_types[t->msg_type] : "invalid");

  return s;
}

/*
 * Slow path node - handles ping and exit-notify
 *
 * Buffer metadata expected:
 *   vnet_buffer(b)->sw_if_index[VLIB_RX]: tunnel sw_if_index
 *   Buffer opaque: peer_id and instance_id stored by input node
 */
always_inline uword
ovpn_slow_path_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vlib_frame_t *frame)
{
  u32 n_left_from, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u32 n_ping = 0, n_exit = 0, n_unknown = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from > 0)
    {
      vlib_buffer_t *b0 = b[0];
      u16 next0 = OVPN_SLOW_PATH_NEXT_DROP;
      u8 msg_type = 0;

      u8 *data = vlib_buffer_get_current (b0);
      u32 len = b0->current_length;

      /* Get peer and instance from buffer opaque */
      u32 sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      ovpn_instance_t *inst = ovpn_instance_get_by_sw_if_index (sw_if_index);

      u32 peer_id = vnet_buffer (b0)->ip.adj_index[VLIB_RX]; /* Repurposed */
      ovpn_peer_t *peer = NULL;

      if (inst)
	peer = ovpn_peer_get (&inst->multi_context.peer_db, peer_id);

      if (len >= 1)
	{
	  /* Check for ping packet */
	  if (ovpn_is_ping_packet (data, len))
	    {
	      msg_type = 1;
	      n_ping++;

	      /* Respond to keepalive ping */
	      if (peer)
		ovpn_peer_send_ping (vm, peer);
	    }
	  /* Check for explicit-exit-notify */
	  else if (ovpn_is_exit_notify (data, len))
	    {
	      msg_type = 2;
	      n_exit++;

	      /* Signal periodic process to cleanup peer on main thread */
	      if (inst && peer)
		{
		  vlib_process_signal_event_mt (
		    vm, ovpn_periodic_node.index, OVPN_PROCESS_EVENT_EXIT_NOTIFY,
		    OVPN_EXIT_NOTIFY_DATA (inst->instance_id, peer->peer_id));
		}
	    }
	  else
	    {
	      n_unknown++;
	    }
	}

      /* Always drop - these are control messages, not forwarded */
      next0 = OVPN_SLOW_PATH_NEXT_DROP;

      /* Trace */
      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ovpn_slow_path_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->peer_id = peer ? peer->peer_id : ~0;
	  t->instance_id = inst ? inst->instance_id : ~0;
	  t->msg_type = msg_type;
	}

      next[0] = next0;
      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  /* Update counters */
  if (n_ping > 0)
    vlib_node_increment_counter (vm, node->node_index,
				 OVPN_SLOW_PATH_ERROR_PING, n_ping);
  if (n_exit > 0)
    vlib_node_increment_counter (vm, node->node_index,
				 OVPN_SLOW_PATH_ERROR_EXIT_NOTIFY, n_exit);
  if (n_unknown > 0)
    vlib_node_increment_counter (vm, node->node_index,
				 OVPN_SLOW_PATH_ERROR_UNKNOWN, n_unknown);

  return frame->n_vectors;
}

VLIB_NODE_FN (ovpn_slow_path_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return ovpn_slow_path_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (ovpn_slow_path_node) = {
  .name = "ovpn-slow-path",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_slow_path_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = OVPN_SLOW_PATH_N_ERROR,
  .error_strings = ovpn_slow_path_error_strings,
  .n_next_nodes = OVPN_SLOW_PATH_N_NEXT,
  .next_nodes = {
    [OVPN_SLOW_PATH_NEXT_DROP] = "error-drop",
  },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
