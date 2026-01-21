/*
 * ovpn_packet.h - OpenVPN packet format definitions
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

#ifndef __included_ovpn_packet_h__
#define __included_ovpn_packet_h__

#include <vnet/ip/ip_types.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>

/*
 * OpenVPN Packet Format
 *
 * Control Channel (P_CONTROL_*, P_ACK_V1):
 * +--------+----------+----------+---------+----------+---------+
 * | opcode | session  |   ack    | packet  |  payload |
 * | +keyid |    id    |  array   |   id    |  (TLS)   |
 * +--------+----------+----------+---------+----------+---------+
 *  1 byte    8 bytes   variable   4 bytes   variable
 *
 * Data Channel V1 (P_DATA_V1):
 * +--------+---------+----------------+-----+
 * | opcode | packet  |   encrypted    | tag |
 * | +keyid |   id    |    payload     |     |
 * +--------+---------+----------------+-----+
 *  1 byte   4 bytes     variable      16 bytes (for GCM)
 *
 * Data Channel V2 (P_DATA_V2):
 * +--------+---------+---------+----------------+-----+
 * | opcode | peer_id | packet  |   encrypted    | tag |
 * | +keyid | (24bit) |   id    |    payload     |     |
 * +--------+---------+---------+----------------+-----+
 *  1 byte   3 bytes   4 bytes     variable      16 bytes
 */

/* Opcode and key_id are packed in the first byte */
#define OVPN_OP_KEY_ID_MASK  0x07
#define OVPN_OP_OPCODE_SHIFT 3
#define OVPN_OP_OPCODE_MASK  0xF8

/* Extract opcode and key_id from first byte */
#define ovpn_op_get_opcode(op) (((op) >> OVPN_OP_OPCODE_SHIFT) & 0x1F)
#define ovpn_op_get_key_id(op) ((op) & OVPN_OP_KEY_ID_MASK)

/* Build opcode byte from opcode and key_id */
#define ovpn_op_compose(opcode, key_id)                                       \
  ((((opcode) & 0x1F) << OVPN_OP_OPCODE_SHIFT) |                              \
   ((key_id) & OVPN_OP_KEY_ID_MASK))

/* Opcodes */
typedef enum
{
  OVPN_OP_NONE = 0,
  OVPN_OP_CONTROL_HARD_RESET_CLIENT_V1 = 1, /* Deprecated */
  OVPN_OP_CONTROL_HARD_RESET_SERVER_V1 = 2, /* Deprecated */
  OVPN_OP_CONTROL_SOFT_RESET_V1 = 3,
  OVPN_OP_CONTROL_V1 = 4,
  OVPN_OP_ACK_V1 = 5,
  OVPN_OP_DATA_V1 = 6,
  OVPN_OP_CONTROL_HARD_RESET_CLIENT_V2 = 7,
  OVPN_OP_CONTROL_HARD_RESET_SERVER_V2 = 8,
  OVPN_OP_DATA_V2 = 9,
  OVPN_OP_CONTROL_HARD_RESET_CLIENT_V3 = 10,
  OVPN_OP_CONTROL_WKC_V1 = 11,
} ovpn_opcode_t;

/* Check if opcode is valid */
always_inline u8
ovpn_opcode_is_valid (u8 opcode)
{
  /* Include deprecated opcodes 1-2 for compatibility */
  return opcode >= OVPN_OP_CONTROL_HARD_RESET_CLIENT_V1 &&
	 opcode <= OVPN_OP_CONTROL_WKC_V1;
}

/* Check if this is a control channel packet */
always_inline u8
ovpn_opcode_is_control (u8 opcode)
{
  return opcode == OVPN_OP_CONTROL_HARD_RESET_CLIENT_V1 ||
	 opcode == OVPN_OP_CONTROL_HARD_RESET_SERVER_V1 ||
	 opcode == OVPN_OP_CONTROL_SOFT_RESET_V1 ||
	 opcode == OVPN_OP_CONTROL_V1 || opcode == OVPN_OP_ACK_V1 ||
	 opcode == OVPN_OP_CONTROL_HARD_RESET_CLIENT_V2 ||
	 opcode == OVPN_OP_CONTROL_HARD_RESET_SERVER_V2 ||
	 opcode == OVPN_OP_CONTROL_HARD_RESET_CLIENT_V3 ||
	 opcode == OVPN_OP_CONTROL_WKC_V1;
}

/* Check if this is a data channel packet */
always_inline u8
ovpn_opcode_is_data (u8 opcode)
{
  return opcode == OVPN_OP_DATA_V1 || opcode == OVPN_OP_DATA_V2;
}

/* Check if this is a hard reset */
always_inline u8
ovpn_opcode_is_hard_reset (u8 opcode)
{
  return opcode == OVPN_OP_CONTROL_HARD_RESET_CLIENT_V1 ||
	 opcode == OVPN_OP_CONTROL_HARD_RESET_SERVER_V1 ||
	 opcode == OVPN_OP_CONTROL_HARD_RESET_CLIENT_V2 ||
	 opcode == OVPN_OP_CONTROL_HARD_RESET_SERVER_V2 ||
	 opcode == OVPN_OP_CONTROL_HARD_RESET_CLIENT_V3;
}

/* Check if this is a soft reset (rekey) */
always_inline u8
ovpn_opcode_is_soft_reset (u8 opcode)
{
  return opcode == OVPN_OP_CONTROL_SOFT_RESET_V1;
}

/* Packet header sizes */
#define OVPN_OP_SIZE	     1	/* opcode + key_id */
#define OVPN_SESSION_ID_SIZE 8	/* session ID */
#define OVPN_PACKET_ID_SIZE  4	/* packet ID */
#define OVPN_PEER_ID_SIZE    3	/* peer ID for DATA_V2 */
#define OVPN_AEAD_TAG_SIZE   16 /* GCM/Poly1305 tag */

/* Minimum packet sizes */
#define OVPN_DATA_V1_MIN_SIZE (OVPN_OP_SIZE + OVPN_PACKET_ID_SIZE)
#define OVPN_DATA_V2_MIN_SIZE                                                 \
  (OVPN_OP_SIZE + OVPN_PEER_ID_SIZE + OVPN_PACKET_ID_SIZE)
#define OVPN_CONTROL_MIN_SIZE                                                 \
  (OVPN_OP_SIZE + OVPN_SESSION_ID_SIZE + 1 /* ack count */)

/* Maximum values */
#define OVPN_MAX_PEER_ID 0xFFFFFF /* 24-bit peer ID */

/*
 * Data packet header for V1 format
 */
typedef CLIB_PACKED (struct {
  u8 opcode_keyid;
  u32 packet_id;
  /* followed by encrypted payload and tag */
}) ovpn_data_v1_header_t;

/*
 * Data packet header for V2 format (with peer_id)
 * Note: peer_id is encoded in the high 24 bits of the first 4 bytes
 */
typedef CLIB_PACKED (struct {
  u8 opcode_keyid;
  u8 peer_id[3]; /* 24-bit peer ID, big-endian */
  u32 packet_id;
  /* followed by encrypted payload and tag */
}) ovpn_data_v2_header_t;

/* Extract peer_id from V2 header */
always_inline u32
ovpn_data_v2_get_peer_id (const ovpn_data_v2_header_t *hdr)
{
  return ((u32) hdr->peer_id[0] << 16) | ((u32) hdr->peer_id[1] << 8) |
	 ((u32) hdr->peer_id[2]);
}

/* Set peer_id in V2 header */
always_inline void
ovpn_data_v2_set_peer_id (ovpn_data_v2_header_t *hdr, u32 peer_id)
{
  hdr->peer_id[0] = (peer_id >> 16) & 0xFF;
  hdr->peer_id[1] = (peer_id >> 8) & 0xFF;
  hdr->peer_id[2] = peer_id & 0xFF;
}

/*
 * AEAD nonce format for OpenVPN
 * 12 bytes total: [packet_id:4][implicit_iv:8]
 * The implicit_iv is derived during key exchange
 */
typedef CLIB_PACKED (struct {
  u32 packet_id;
  u8 implicit_iv[8];
}) ovpn_aead_nonce_t;

STATIC_ASSERT_SIZEOF (ovpn_aead_nonce_t, 12);

/*
 * Build AEAD nonce from packet_id and implicit IV
 */
always_inline void
ovpn_aead_nonce_build (ovpn_aead_nonce_t *nonce, u32 packet_id,
		       const u8 *implicit_iv)
{
  nonce->packet_id = clib_host_to_net_u32 (packet_id);
  clib_memcpy_fast (nonce->implicit_iv, implicit_iv, 8);
}

/*
 * Control packet header
 */
typedef CLIB_PACKED (struct {
  u8 opcode_keyid;
  u8 session_id[OVPN_SESSION_ID_SIZE];
  /* followed by: ack array, packet_id, payload */
}) ovpn_control_header_t;

/*
 * Packet trace data for debugging
 */
typedef struct
{
  u8 opcode;
  u8 key_id;
  u32 peer_id;
  u32 packet_id;
  u32 sw_if_index;
  ip46_address_t src;
  ip46_address_t dst;
  u16 src_port;
  u16 dst_port;
} ovpn_packet_trace_t;

/* Format function for trace */
always_inline u8 *
format_ovpn_opcode (u8 *s, va_list *args)
{
  u8 opcode = va_arg (*args, u32);

  switch (opcode)
    {
    case OVPN_OP_CONTROL_HARD_RESET_CLIENT_V1:
      return format (s, "HARD_RESET_CLIENT_V1");
    case OVPN_OP_CONTROL_HARD_RESET_SERVER_V1:
      return format (s, "HARD_RESET_SERVER_V1");
    case OVPN_OP_CONTROL_SOFT_RESET_V1:
      return format (s, "SOFT_RESET_V1");
    case OVPN_OP_CONTROL_V1:
      return format (s, "CONTROL_V1");
    case OVPN_OP_ACK_V1:
      return format (s, "ACK_V1");
    case OVPN_OP_DATA_V1:
      return format (s, "DATA_V1");
    case OVPN_OP_CONTROL_HARD_RESET_CLIENT_V2:
      return format (s, "HARD_RESET_CLIENT_V2");
    case OVPN_OP_CONTROL_HARD_RESET_SERVER_V2:
      return format (s, "HARD_RESET_SERVER_V2");
    case OVPN_OP_DATA_V2:
      return format (s, "DATA_V2");
    case OVPN_OP_CONTROL_HARD_RESET_CLIENT_V3:
      return format (s, "HARD_RESET_CLIENT_V3");
    case OVPN_OP_CONTROL_WKC_V1:
      return format (s, "CONTROL_WKC_V1");
    default:
      return format (s, "UNKNOWN(%u)", opcode);
    }
}

#endif /* __included_ovpn_packet_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
