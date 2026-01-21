/*
 * ovpn_fragment.h - OpenVPN fragmentation support
 *
 * Copyright (c) 2025 <blackfaceuncle@gmail.com>
 * Licensed under the Apache License, Version 2.0
 */

#ifndef __included_ovpn_fragment_h__
#define __included_ovpn_fragment_h__

#include <vppinfra/types.h>
#include <vppinfra/vec.h>
#include <vppinfra/time.h>
#include <vlib/vlib.h>

/*
 * OpenVPN Fragment Header Format (32 bits, network byte order)
 *
 * The fragment header is prepended to the payload BEFORE encryption.
 *
 * Bit layout:
 *   [31:29] - unused (3 bits)
 *   [28:15] - fragment_size (14 bits) - max size, only valid in LAST fragment
 *   [14:10] - fragment_id (5 bits) - fragment order (0-31)
 *   [9:2]   - sequence_id (8 bits) - groups fragments of same packet
 *   [1:0]   - fragment_type (2 bits) - WHOLE, NOT_LAST, LAST, TEST
 */

/* Fragment type constants */
#define OVPN_FRAG_WHOLE	    0 /* Unfragmented packet */
#define OVPN_FRAG_YES_NOTLAST 1 /* Intermediate fragment */
#define OVPN_FRAG_YES_LAST    2 /* Final fragment */
#define OVPN_FRAG_TEST	    3 /* Reserved for MTU testing */

/* Header field masks and shifts */
#define OVPN_FRAG_TYPE_MASK  0x00000003
#define OVPN_FRAG_TYPE_SHIFT 0

#define OVPN_FRAG_SEQ_ID_MASK  0x000000ff
#define OVPN_FRAG_SEQ_ID_SHIFT 2

#define OVPN_FRAG_ID_MASK  0x0000001f
#define OVPN_FRAG_ID_SHIFT 10

#define OVPN_FRAG_SIZE_MASK  0x00003fff
#define OVPN_FRAG_SIZE_SHIFT 15

/* Fragment size rounding (4-byte alignment) */
#define OVPN_FRAG_SIZE_ROUND_SHIFT 2
#define OVPN_FRAG_SIZE_ROUND_MASK  0x3

/* Maximum fragments per packet (5 bits = 32) */
#define OVPN_FRAG_MAX_FRAGS 32

/* Fragment header size */
#define OVPN_FRAG_HDR_SIZE 4

/* Default fragment timeout (seconds) */
#define OVPN_FRAG_TIMEOUT 10.0

/*
 * Fragment reassembly state for a single packet being reassembled
 */
typedef struct ovpn_frag_reassembly_t_
{
  /* Sequence ID we're reassembling */
  u8 seq_id;

  /* Bitmap of received fragments (up to 32) */
  u32 received_mask;

  /* Expected max fragment ID (set when LAST fragment received) */
  u8 max_frag_id;
  u8 have_last;

  /* Fragment data storage */
  u8 *fragments[OVPN_FRAG_MAX_FRAGS];
  u16 frag_lengths[OVPN_FRAG_MAX_FRAGS];

  /* Total reassembled length */
  u32 total_len;

  /* Timestamp for timeout */
  f64 first_frag_time;

  /* Max fragment size (from LAST fragment) */
  u16 max_frag_size;

} ovpn_frag_reassembly_t;

/*
 * Per-peer fragment state
 *
 * Uses a direct array indexed by seq_id (256 entries) instead of hash
 * for simpler and more predictable behavior. Most entries will be unused,
 * but this avoids hash lookup overhead and potential hash bugs.
 */
typedef struct ovpn_frag_state_t_
{
  /* Outgoing fragment sequence ID (increments per fragmented packet) */
  u8 tx_seq_id;

  /* Direct array of reassembly contexts indexed by seq_id */
  ovpn_frag_reassembly_t reassembly[256];

  /* Last time we ran expiration check */
  f64 last_expire_time;

} ovpn_frag_state_t;

/*
 * Build fragment header value
 *
 * OpenVPN fragment header is a 32-bit value stored in network byte order.
 * The bit layout in host byte order (before conversion):
 *   bits 0-1:   fragment_type
 *   bits 2-9:   sequence_id
 *   bits 10-14: fragment_id
 *   bits 15-28: fragment_size (rounded)
 *
 * OpenVPN uses hton_fragment_header_type() when writing headers,
 * so we must convert to network byte order here.
 */
static inline u32
ovpn_frag_make_header (u8 frag_type, u8 seq_id, u8 frag_id, u16 frag_size)
{
  u32 hdr = 0;
  hdr |= (frag_type & OVPN_FRAG_TYPE_MASK) << OVPN_FRAG_TYPE_SHIFT;
  hdr |= (seq_id & OVPN_FRAG_SEQ_ID_MASK) << OVPN_FRAG_SEQ_ID_SHIFT;
  hdr |= (frag_id & OVPN_FRAG_ID_MASK) << OVPN_FRAG_ID_SHIFT;
  hdr |= ((frag_size >> OVPN_FRAG_SIZE_ROUND_SHIFT) & OVPN_FRAG_SIZE_MASK)
	 << OVPN_FRAG_SIZE_SHIFT;
  return clib_host_to_net_u32 (hdr);
}

/*
 * Parse fragment header
 *
 * The header is read via memcpy from buffer as a u32.
 * Convert from network byte order to host byte order for parsing.
 */
static inline void
ovpn_frag_parse_header (u32 hdr, u8 *frag_type, u8 *seq_id, u8 *frag_id,
			u16 *frag_size)
{
  hdr = clib_net_to_host_u32 (hdr);
  *frag_type = (hdr >> OVPN_FRAG_TYPE_SHIFT) & OVPN_FRAG_TYPE_MASK;
  *seq_id = (hdr >> OVPN_FRAG_SEQ_ID_SHIFT) & OVPN_FRAG_SEQ_ID_MASK;
  *frag_id = (hdr >> OVPN_FRAG_ID_SHIFT) & OVPN_FRAG_ID_MASK;
  *frag_size = ((hdr >> OVPN_FRAG_SIZE_SHIFT) & OVPN_FRAG_SIZE_MASK)
	       << OVPN_FRAG_SIZE_ROUND_SHIFT;
}

/*
 * Initialize fragment state for a peer
 */
void ovpn_frag_state_init (ovpn_frag_state_t *state);

/*
 * Free fragment state
 */
void ovpn_frag_state_free (ovpn_frag_state_t *state);

/*
 * Fragment a packet for transmission
 *
 * @param data Input packet data
 * @param len Input packet length
 * @param max_frag_size Maximum fragment payload size
 * @param state Fragment state (for sequence ID)
 * @param fragments Output: vector of fragment buffers (caller frees each)
 * @param n_fragments Output: number of fragments created
 * @return 0 on success, <0 on error
 *
 * If the packet fits in max_frag_size, a single FRAG_WHOLE packet is returned.
 * Otherwise, multiple fragments are created with proper headers.
 */
int ovpn_frag_fragment_packet (const u8 *data, u32 len, u16 max_frag_size,
			       ovpn_frag_state_t *state, u8 ***fragments,
			       u16 **frag_lengths, u32 *n_fragments);

/*
 * Process an incoming fragment
 *
 * @param data Fragment data (including fragment header)
 * @param len Fragment length
 * @param state Fragment state for this peer
 * @param now Current time
 * @param reassembled Output: reassembled packet if complete (caller frees)
 * @param reassembled_len Output: length of reassembled packet
 * @return 1 if packet complete, 0 if more fragments needed, <0 on error
 */
int ovpn_frag_process_fragment (const u8 *data, u32 len,
				ovpn_frag_state_t *state, f64 now,
				u8 **reassembled, u32 *reassembled_len);

/*
 * Expire old reassembly contexts
 *
 * @param state Fragment state
 * @param now Current time
 * @param timeout Timeout in seconds
 */
void ovpn_frag_expire_old (ovpn_frag_state_t *state, f64 now, f64 timeout);

/*
 * Fragment a VPP buffer for multi-fragment transmission
 *
 * This function splits an oversized packet into multiple VPP buffers,
 * each containing a properly formatted fragment with header.
 *
 * @param vm VPP main pointer
 * @param b0 Original buffer (will be modified to contain first fragment)
 * @param max_frag_payload Max payload per fragment (excluding header)
 * @param state Fragment state (for sequence ID)
 * @param extra_bis Output: vector of buffer indices for fragments 2..N
 * @param n_extra Output: number of extra buffers created
 * @return 0 on success, <0 on error
 *
 * On success:
 * - b0 is modified to contain the first fragment (with header)
 * - extra_bis contains buffer indices for fragments 2..N
 * - Caller must process all buffers and free extra_bis vector
 *
 * On error:
 * - b0 is unchanged
 * - extra_bis is NULL
 */
int ovpn_frag_create_fragments (vlib_main_t *vm, vlib_buffer_t *b0,
				u16 max_frag_payload,
				ovpn_frag_state_t *state, u32 **extra_bis,
				u32 *n_extra);

#endif /* __included_ovpn_fragment_h__ */
