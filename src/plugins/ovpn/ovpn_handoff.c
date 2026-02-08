/*
 * ovpn_handoff.c - OpenVPN handoff nodes
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

#include <ovpn/ovpn.h>
#include <ovpn/ovpn_peer.h>
#include <ovpn/ovpn_packet.h>

#define foreach_ovpn_handoff_error \
  _ (CONGESTION_DROP, "congestion drop")

typedef enum
{
#define _(sym, str) OVPN_HANDOFF_ERROR_##sym,
  foreach_ovpn_handoff_error
#undef _
    OVPN_HANDOFF_N_ERROR,
} ovpn_handoff_error_t;

static char *ovpn_handoff_error_strings[] = {
#define _(sym, string) string,
  foreach_ovpn_handoff_error
#undef _
};

typedef enum
{
  OVPN_HANDOFF_HANDSHAKE,
  OVPN_HANDOFF_INP_DATA,
  OVPN_HANDOFF_OUT_TUN,
} ovpn_handoff_mode_t;

typedef struct ovpn_handoff_trace_t_
{
  u32 next_worker_index;
  u32 peer_id;
} ovpn_handoff_trace_t;

static u8 *
format_ovpn_handoff_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ovpn_handoff_trace_t *t = va_arg (*args, ovpn_handoff_trace_t *);

  s = format (s, "ovpn-handoff: next-worker %d peer %d", t->next_worker_index,
	      t->peer_id);

  return s;
}

static_always_inline uword
ovpn_handoff (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame,
	      u32 fq_index, ovpn_handoff_mode_t mode)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 thread_indices[VLIB_FRAME_SIZE], *ti;
  u32 n_enq, n_left_from, *from;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);

  b = bufs;
  ti = thread_indices;

  while (n_left_from > 0)
    {
      u32 peer_id = ~0;
      ovpn_instance_t *inst = NULL;

      if (PREDICT_FALSE (mode == OVPN_HANDOFF_HANDSHAKE))
	{
	  /* Handshake packets always go to main thread (thread 0) */
	  ti[0] = 0;
	}
      else if (mode == OVPN_HANDOFF_INP_DATA)
	{
	  /* Data packets go to the peer's assigned input thread */
	  u8 *data = vlib_buffer_get_current (b[0]);
	  u8 opcode = ovpn_op_get_opcode (data[0]);

	  if (opcode == OVPN_OP_DATA_V2)
	    {
	      ovpn_data_v2_header_t *hdr = (ovpn_data_v2_header_t *) data;
	      peer_id = ovpn_data_v2_get_peer_id (hdr);
	    }

	  /* Look up instance by destination port */
	  u8 *udp_start = data - sizeof (udp_header_t);
	  udp_header_t *udp = (udp_header_t *) udp_start;
	  u16 dst_port = clib_net_to_host_u16 (udp->dst_port);
	  inst = ovpn_instance_get_by_port (dst_port);

	  ovpn_peer_t *peer = NULL;
	  if (inst)
	    peer = ovpn_peer_get (&inst->multi_context.peer_db, peer_id);
	  if (peer)
	    {
	      ti[0] = peer->input_thread_index;
	    }
	  else
	    {
	      /* Unknown peer, drop on main thread */
	      ti[0] = 0;
	    }
	}
      else /* OVPN_HANDOFF_OUT_TUN */
	{
	  /* Output packets - translate adj_index to peer_id first */
	  u32 adj_index = vnet_buffer (b[0])->ip.adj_index[VLIB_TX];
	  peer_id = ovpn_peer_get_by_adj_index (adj_index);
	  u32 sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
	  inst = ovpn_instance_get_by_sw_if_index (sw_if_index);
	  ovpn_peer_t *peer = NULL;
	  if (inst && peer_id != ~0)
	    peer = ovpn_peer_get (&inst->multi_context.peer_db, peer_id);
	  if (peer)
	    {
	      ti[0] = peer->input_thread_index;
	    }
	  else
	    {
	      ti[0] = 0;
	    }
	}

      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  ovpn_handoff_trace_t *t =
	    vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->next_worker_index = ti[0];
	  t->peer_id = peer_id;
	}

      n_left_from -= 1;
      ti += 1;
      b += 1;
    }

  n_enq = vlib_buffer_enqueue_to_thread (vm, node, fq_index, from,
					 thread_indices, frame->n_vectors, 1);

  if (n_enq < frame->n_vectors)
    vlib_node_increment_counter (vm, node->node_index,
				 OVPN_HANDOFF_ERROR_CONGESTION_DROP,
				 frame->n_vectors - n_enq);

  return n_enq;
}

/*
 * IPv4 handshake handoff - goes to main thread
 */
VLIB_NODE_FN (ovpn4_handshake_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  ovpn_main_t *omp = &ovpn_main;
  return ovpn_handoff (vm, node, from_frame, omp->in4_fq_index,
		       OVPN_HANDOFF_HANDSHAKE);
}

/*
 * IPv6 handshake handoff - goes to main thread
 */
VLIB_NODE_FN (ovpn6_handshake_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  ovpn_main_t *omp = &ovpn_main;
  return ovpn_handoff (vm, node, from_frame, omp->in6_fq_index,
		       OVPN_HANDOFF_HANDSHAKE);
}

/*
 * IPv4 data handoff - goes to peer's assigned thread
 */
VLIB_NODE_FN (ovpn4_input_data_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  ovpn_main_t *omp = &ovpn_main;
  return ovpn_handoff (vm, node, from_frame, omp->in4_fq_index,
		       OVPN_HANDOFF_INP_DATA);
}

/*
 * IPv6 data handoff - goes to peer's assigned thread
 */
VLIB_NODE_FN (ovpn6_input_data_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  ovpn_main_t *omp = &ovpn_main;
  return ovpn_handoff (vm, node, from_frame, omp->in6_fq_index,
		       OVPN_HANDOFF_INP_DATA);
}

/*
 * IPv4 output handoff
 */
VLIB_NODE_FN (ovpn4_output_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  ovpn_main_t *omp = &ovpn_main;
  return ovpn_handoff (vm, node, from_frame, omp->out4_fq_index,
		       OVPN_HANDOFF_OUT_TUN);
}

/*
 * IPv6 output handoff
 */
VLIB_NODE_FN (ovpn6_output_handoff_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *from_frame)
{
  ovpn_main_t *omp = &ovpn_main;
  return ovpn_handoff (vm, node, from_frame, omp->out6_fq_index,
		       OVPN_HANDOFF_OUT_TUN);
}

/* Node registrations */
VLIB_REGISTER_NODE (ovpn4_handshake_handoff_node) = {
  .name = "ovpn4-handshake-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (ovpn_handoff_error_strings),
  .error_strings = ovpn_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_REGISTER_NODE (ovpn6_handshake_handoff_node) = {
  .name = "ovpn6-handshake-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (ovpn_handoff_error_strings),
  .error_strings = ovpn_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_REGISTER_NODE (ovpn4_input_data_handoff_node) = {
  .name = "ovpn4-input-data-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (ovpn_handoff_error_strings),
  .error_strings = ovpn_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_REGISTER_NODE (ovpn6_input_data_handoff_node) = {
  .name = "ovpn6-input-data-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (ovpn_handoff_error_strings),
  .error_strings = ovpn_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_REGISTER_NODE (ovpn4_output_handoff_node) = {
  .name = "ovpn4-output-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (ovpn_handoff_error_strings),
  .error_strings = ovpn_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_REGISTER_NODE (ovpn6_output_handoff_node) = {
  .name = "ovpn6-output-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_ovpn_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (ovpn_handoff_error_strings),
  .error_strings = ovpn_handoff_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
