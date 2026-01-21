/*
 * ovpn_fragment.c - OpenVPN fragmentation implementation
 *
 * Copyright (c) 2025 <blackfaceuncle@gmail.com>
 * Licensed under the Apache License, Version 2.0
 */

#include <ovpn/ovpn_fragment.h>
#include <vppinfra/pool.h>
#include <vppinfra/hash.h>
#include <vlib/vlib.h>

/*
 * Initialize fragment state for a peer
 */
void
ovpn_frag_state_init (ovpn_frag_state_t *state)
{
  clib_memset (state, 0, sizeof (*state));
}

/*
 * Free a single reassembly context
 */
static void
ovpn_frag_reassembly_free (ovpn_frag_reassembly_t *reasm)
{
  for (int i = 0; i < OVPN_FRAG_MAX_FRAGS; i++)
    {
      if (reasm->fragments[i])
	{
	  clib_mem_free (reasm->fragments[i]);
	  reasm->fragments[i] = NULL;
	}
    }
  reasm->received_mask = 0;
  reasm->total_len = 0;
}

/*
 * Free fragment state
 */
void
ovpn_frag_state_free (ovpn_frag_state_t *state)
{
  /* Free all fragment data in each reassembly context */
  for (int i = 0; i < 256; i++)
    {
      ovpn_frag_reassembly_free (&state->reassembly[i]);
    }

  clib_memset (state, 0, sizeof (*state));
}

/*
 * Fragment a packet for transmission
 */
int
ovpn_frag_fragment_packet (const u8 *data, u32 len, u16 max_frag_size,
			   ovpn_frag_state_t *state, u8 ***fragments_out,
			   u16 **frag_lengths_out, u32 *n_fragments_out)
{
  u8 **fragments = NULL;
  u16 *frag_lengths = NULL;
  u32 n_fragments;
  u32 payload_per_frag;
  u8 seq_id;

  if (!data || len == 0 || max_frag_size < OVPN_FRAG_HDR_SIZE + 1)
    return -1;

  /* Calculate payload size per fragment (excluding header) */
  payload_per_frag = max_frag_size - OVPN_FRAG_HDR_SIZE;

  /* Check if fragmentation is needed */
  if (len <= payload_per_frag)
    {
      /* No fragmentation needed - send as FRAG_WHOLE */
      u8 *frag = clib_mem_alloc (OVPN_FRAG_HDR_SIZE + len);
      u32 hdr = ovpn_frag_make_header (OVPN_FRAG_WHOLE, 0, 0, 0);

      clib_memcpy (frag, &hdr, OVPN_FRAG_HDR_SIZE);
      clib_memcpy (frag + OVPN_FRAG_HDR_SIZE, data, len);

      vec_add1 (fragments, frag);
      vec_add1 (frag_lengths, OVPN_FRAG_HDR_SIZE + len);

      *fragments_out = fragments;
      *frag_lengths_out = frag_lengths;
      *n_fragments_out = 1;
      return 0;
    }

  /* Calculate number of fragments needed */
  n_fragments = (len + payload_per_frag - 1) / payload_per_frag;
  if (n_fragments > OVPN_FRAG_MAX_FRAGS)
    {
      return -2;
    }

  /* Get sequence ID */
  seq_id = state->tx_seq_id++;

  /* Create fragments */
  u32 offset = 0;
  for (u32 i = 0; i < n_fragments; i++)
    {
      u32 frag_payload_len =
	(i == n_fragments - 1) ? (len - offset) : payload_per_frag;
      u8 frag_type =
	(i == n_fragments - 1) ? OVPN_FRAG_YES_LAST : OVPN_FRAG_YES_NOTLAST;

      u8 *frag = clib_mem_alloc (OVPN_FRAG_HDR_SIZE + frag_payload_len);

      /* Build header - include max_frag_size only in LAST fragment */
      u16 hdr_size = (frag_type == OVPN_FRAG_YES_LAST) ? max_frag_size : 0;
      u32 hdr = ovpn_frag_make_header (frag_type, seq_id, i, hdr_size);

      clib_memcpy (frag, &hdr, OVPN_FRAG_HDR_SIZE);
      clib_memcpy (frag + OVPN_FRAG_HDR_SIZE, data + offset, frag_payload_len);

      vec_add1 (fragments, frag);
      vec_add1 (frag_lengths, OVPN_FRAG_HDR_SIZE + frag_payload_len);

      offset += frag_payload_len;
    }

  *fragments_out = fragments;
  *frag_lengths_out = frag_lengths;
  *n_fragments_out = n_fragments;

  return 0;
}

/*
 * Get reassembly context for a sequence ID (direct array access)
 */
static ovpn_frag_reassembly_t *
ovpn_frag_get_reassembly (ovpn_frag_state_t *state, u8 seq_id, f64 now)
{
  ovpn_frag_reassembly_t *reasm = &state->reassembly[seq_id];

  /* Initialize first_frag_time if this is a new reassembly */
  if (reasm->received_mask == 0 && reasm->first_frag_time == 0)
    {
      reasm->seq_id = seq_id;
      reasm->first_frag_time = now;
    }

  return reasm;
}

/*
 * Reset reassembly context for a sequence ID
 */
static void
ovpn_frag_delete_reassembly (ovpn_frag_state_t *state, u8 seq_id)
{
  ovpn_frag_reassembly_free (&state->reassembly[seq_id]);
  /* Also reset first_frag_time so it can be reused */
  state->reassembly[seq_id].first_frag_time = 0;
}

/*
 * Check if reassembly is complete
 */
static int
ovpn_frag_is_complete (ovpn_frag_reassembly_t *reasm)
{
  if (!reasm->have_last)
    return 0;

  /* Check all fragments from 0 to max_frag_id are present */
  u32 expected_mask = (1u << (reasm->max_frag_id + 1)) - 1;
  return (reasm->received_mask == expected_mask);
}

/*
 * Reassemble complete packet
 */
static u8 *
ovpn_frag_reassemble (ovpn_frag_reassembly_t *reasm, u32 *len_out)
{
  u8 *result = clib_mem_alloc (reasm->total_len);
  u32 offset = 0;

  for (u8 i = 0; i <= reasm->max_frag_id; i++)
    {
      if (reasm->fragments[i])
	{
	  clib_memcpy (result + offset, reasm->fragments[i],
		       reasm->frag_lengths[i]);
	  offset += reasm->frag_lengths[i];
	}
    }

  *len_out = reasm->total_len;
  return result;
}

/*
 * Process an incoming fragment
 */
int
ovpn_frag_process_fragment (const u8 *data, u32 len, ovpn_frag_state_t *state,
			    f64 now, u8 **reassembled, u32 *reassembled_len)
{
  u8 frag_type, seq_id, frag_id;
  u16 frag_size;
  ovpn_frag_reassembly_t *reasm;

  *reassembled = NULL;
  *reassembled_len = 0;

  if (len < OVPN_FRAG_HDR_SIZE)
    return -1;

  /* Periodically expire old incomplete reassemblies (every 1 second) */
  if (now - state->last_expire_time > 1.0)
    {
      ovpn_frag_expire_old (state, now, OVPN_FRAG_TIMEOUT);
      state->last_expire_time = now;
    }

  /* Parse fragment header */
  u32 net_hdr;
  clib_memcpy (&net_hdr, data, OVPN_FRAG_HDR_SIZE);
  ovpn_frag_parse_header (net_hdr, &frag_type, &seq_id, &frag_id, &frag_size);

  /* Debug logging removed */
  /* Handle unfragmented packet */
  if (frag_type == OVPN_FRAG_WHOLE)
    {
      u32 payload_len = len - OVPN_FRAG_HDR_SIZE;
      *reassembled = clib_mem_alloc (payload_len);
      clib_memcpy (*reassembled, data + OVPN_FRAG_HDR_SIZE, payload_len);
      *reassembled_len = payload_len;
      return 1;
    }

  /* Validate fragment ID */
  if (frag_id >= OVPN_FRAG_MAX_FRAGS)
    return -2;

  /* If sequence ID wraps before timeout, drop stale reassembly */
  if (frag_id == 0 && state->reassembly[seq_id].received_mask != 0 &&
      state->reassembly[seq_id].first_frag_time != 0 &&
      (now - state->reassembly[seq_id].first_frag_time) < OVPN_FRAG_TIMEOUT)
    {
      ovpn_frag_delete_reassembly (state, seq_id);
    }

  /* Get or create reassembly context */
  reasm = ovpn_frag_get_reassembly (state, seq_id, now);

  /* Check for duplicate */
  if (reasm->received_mask & (1u << frag_id))
    {
      /* Duplicate fragment - ignore */
      return 0;
    }

  /* Store fragment payload (without header) */
  u32 payload_len = len - OVPN_FRAG_HDR_SIZE;
  reasm->fragments[frag_id] = clib_mem_alloc (payload_len);
  clib_memcpy (reasm->fragments[frag_id], data + OVPN_FRAG_HDR_SIZE,
	       payload_len);
  reasm->frag_lengths[frag_id] = payload_len;
  reasm->received_mask |= (1u << frag_id);
  reasm->total_len += payload_len;

  /* Handle LAST fragment */
  if (frag_type == OVPN_FRAG_YES_LAST)
    {
      reasm->have_last = 1;
      reasm->max_frag_id = frag_id;
      reasm->max_frag_size = frag_size;
    }

  /* Check if complete */
  if (ovpn_frag_is_complete (reasm))
    {
      *reassembled = ovpn_frag_reassemble (reasm, reassembled_len);
      ovpn_frag_delete_reassembly (state, seq_id);
      return 1;
    }

  /* Debug logging removed */
  return 0;
}

/*
 * Expire old reassembly contexts
 */
void
ovpn_frag_expire_old (ovpn_frag_state_t *state, f64 now, f64 timeout)
{
  /* Iterate through all 256 possible seq_ids and expire old entries */
  for (int i = 0; i < 256; i++)
    {
      ovpn_frag_reassembly_t *reasm = &state->reassembly[i];

      /* Only check entries that have fragments (received_mask != 0)
       * and have been active (first_frag_time != 0) */
      if (reasm->received_mask != 0 && reasm->first_frag_time != 0)
	{
	  if (now - reasm->first_frag_time > timeout)
	    {
	      ovpn_frag_delete_reassembly (state, i);
	    }
	}
    }
}

/*
 * Fragment a VPP buffer for multi-fragment transmission
 */
int
ovpn_frag_create_fragments (vlib_main_t *vm, vlib_buffer_t *b0,
			    u16 max_frag_payload, ovpn_frag_state_t *state,
			    u32 **extra_bis, u32 *n_extra)
{
  u8 *data;
  u32 data_len;
  u32 n_fragments;
  u8 seq_id;
  u32 *new_bis = NULL;
  u32 offset;

  *extra_bis = NULL;
  *n_extra = 0;

  data = vlib_buffer_get_current (b0);
  data_len = b0->current_length;

  if (max_frag_payload < 1)
    return -1;

  /* Calculate number of fragments needed */
  n_fragments = (data_len + max_frag_payload - 1) / max_frag_payload;

  if (n_fragments > OVPN_FRAG_MAX_FRAGS)
    {
      return -2;
    }

  /* Ensure headroom for fragment header */
  if (PREDICT_FALSE (b0->current_data < OVPN_FRAG_HDR_SIZE))
    return -4;

  /* Single fragment - just add FRAG_WHOLE header */
  if (n_fragments == 1)
    {
      u32 hdr = ovpn_frag_make_header (OVPN_FRAG_WHOLE, 0, 0, 0);
      vlib_buffer_advance (b0, -OVPN_FRAG_HDR_SIZE);
      clib_memcpy_fast (vlib_buffer_get_current (b0), &hdr, OVPN_FRAG_HDR_SIZE);
      return 0;
    }

  /* Multi-fragment: need to allocate extra buffers */
  seq_id = state->tx_seq_id++;

  /* Allocate buffers for fragments 2..N */
  u32 n_alloc = n_fragments - 1;
  vec_validate (new_bis, n_alloc - 1);

  if (vlib_buffer_alloc (vm, new_bis, n_alloc) != n_alloc)
    {
      vec_free (new_bis);
      return -3;
    }

  /*
   * Create fragments:
   * - Fragment 0: modify original buffer b0
   * - Fragments 1..N-1: use newly allocated buffers
   */
  offset = 0;

  for (u32 i = 0; i < n_fragments; i++)
    {
      u32 frag_payload_len;
      u8 frag_type;
      u32 hdr;
      vlib_buffer_t *fb;

      /* Calculate this fragment's payload length */
      if (i == n_fragments - 1)
	frag_payload_len = data_len - offset;
      else
	frag_payload_len = max_frag_payload;

      /* Determine fragment type */
      if (i == n_fragments - 1)
	frag_type = OVPN_FRAG_YES_LAST;
      else
	frag_type = OVPN_FRAG_YES_NOTLAST;

      /* Build header - only LAST fragment includes max payload size */
      u16 hdr_size =
	(frag_type == OVPN_FRAG_YES_LAST) ? max_frag_payload : 0;
      hdr = ovpn_frag_make_header (frag_type, seq_id, i, hdr_size);

      if (i == 0)
	{
	  /*
	   * First fragment: modify original buffer.
	   * We need to truncate to frag_payload_len and prepend header.
	   */
	  fb = b0;

	  /* Move data to make room for header, then truncate */
	  vlib_buffer_advance (fb, -OVPN_FRAG_HDR_SIZE);
	  u8 *dst = vlib_buffer_get_current (fb);

	  /* Write header */
	  clib_memcpy_fast (dst, &hdr, OVPN_FRAG_HDR_SIZE);

	  /* Data is already in place, just set correct length */
	  fb->current_length = OVPN_FRAG_HDR_SIZE + frag_payload_len;
	}
      else
	{
	  /*
	   * Additional fragments: use newly allocated buffer.
	   * Copy fragment header + payload from original data.
	   */
	  fb = vlib_get_buffer (vm, new_bis[i - 1]);

	  /* Reset buffer - must clear all length-related fields */
	  fb->current_data = 0;
	  fb->current_length = OVPN_FRAG_HDR_SIZE + frag_payload_len;
	  fb->total_length_not_including_first_buffer = 0;
	  fb->flags = 0;

	  u8 *dst = vlib_buffer_get_current (fb);

	  /* Write header */
	  clib_memcpy_fast (dst, &hdr, OVPN_FRAG_HDR_SIZE);

	  /* Copy payload from original data */
	  clib_memcpy_fast (dst + OVPN_FRAG_HDR_SIZE, data + offset,
			    frag_payload_len);
	}

      offset += frag_payload_len;
    }

  *extra_bis = new_bis;
  *n_extra = n_alloc;

  return 0;
}
