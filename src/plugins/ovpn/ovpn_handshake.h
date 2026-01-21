/*
 * ovpn_handshake.h - OpenVPN control channel handshake
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

#ifndef __included_ovpn_handshake_h__
#define __included_ovpn_handshake_h__

#include <vlib/vlib.h>
#include <vnet/ip/ip_types.h>
#include <ovpn/ovpn_session_id.h>
#include <ovpn/ovpn_reliable.h>
#include <ovpn/ovpn_packet.h>

/*
 * Pending connection state
 *
 * When we receive P_CONTROL_HARD_RESET_CLIENT_V2, we create a pending
 * connection and send P_CONTROL_HARD_RESET_SERVER_V2 with ACK.
 * The connection becomes established when we receive P_ACK_V1.
 */
typedef enum
{
  OVPN_PENDING_STATE_INITIAL = 0,
  OVPN_PENDING_STATE_SENT_RESET, /* Sent server reset, waiting for ACK */
  OVPN_PENDING_STATE_ESTABLISHED, /* Received ACK, ready for TLS */
} ovpn_pending_state_t;

/* Forward declaration for TLS-Crypt context (defined below) */
typedef struct ovpn_tls_crypt_t_ ovpn_tls_crypt_t;

typedef struct ovpn_pending_connection_t_
{
  /* State */
  ovpn_pending_state_t state;

  /* Remote address and port */
  ip_address_t remote_addr;
  u16 remote_port;

  /* Session IDs */
  ovpn_session_id_t local_session_id;  /* Our session ID */
  ovpn_session_id_t remote_session_id; /* Client's session ID */

  /* Key ID from initial packet */
  u8 key_id;

  /* Packet ID tracking */
  u32 packet_id_send; /* Next packet ID to send */
  u32 packet_id_recv; /* Expected packet ID to receive */

  /* ACK tracking */
  ovpn_reliable_ack_t recv_ack; /* Packet IDs we need to ACK */
  ovpn_reliable_ack_t sent_ack; /* Packet IDs we sent, waiting for ACK */

  /* Timestamps */
  f64 created_time;
  f64 last_activity;
  f64 timeout; /* When this pending connection expires */

  /* Buffer index for storing response packet */
  u32 response_buf_index;

  /* Reliable send structure for retransmission */
  ovpn_reliable_t *send_reliable;

  /*
   * Per-client TLS-Crypt context for TLS-Crypt-V2
   * When client uses tls-crypt-v2, we unwrap their key and store it here
   * This overrides the global tls_crypt context for this connection
   */
  ovpn_tls_crypt_t *client_tls_crypt;

  /* Flag indicating this is a tls-crypt-v2 connection */
  u8 is_tls_crypt_v2;

} ovpn_pending_connection_t;

/* Forward declaration - actual definition in ovpn.h */
struct ovpn_pending_db_t_;
typedef struct ovpn_pending_db_t_ ovpn_pending_db_t;

/*
 * Control channel replay window size (must be power of 2, max 64)
 * Used by both TLS-Auth and TLS-Crypt for replay protection
 */
#define OVPN_CONTROL_REPLAY_WINDOW_SIZE 64

/*
 * HMAC context for tls-auth
 * Uses SHA256 by default
 *
 * TLS-Auth packet format (incoming):
 * [opcode+keyid (1)] [HMAC (32)] [packet_id (4)] [net_time (4)] [session_id (8)] ...
 *
 * The packet_id/net_time after HMAC is for REPLAY PROTECTION (wrapper layer)
 * The packet_id inside the control packet (after ack_array) is for RELIABLE ORDERING
 */
#define OVPN_HMAC_KEY_SIZE	  64
#define OVPN_HMAC_SIZE		  32 /* SHA256 output */
#define OVPN_TLS_AUTH_PACKET_ID_SIZE 4
#define OVPN_TLS_AUTH_NET_TIME_SIZE  4

/* TLS-Auth overhead: HMAC + packet_id + net_time */
#define OVPN_TLS_AUTH_OVERHEAD                                                \
  (OVPN_HMAC_SIZE + OVPN_TLS_AUTH_PACKET_ID_SIZE + OVPN_TLS_AUTH_NET_TIME_SIZE)

typedef struct ovpn_tls_auth_t_
{
  u8 enabled;

  /*
   * Separate keys for encrypt (sending) and decrypt (receiving)
   * OpenVPN static key files have 4 x 64-byte keys, but we only use
   * the first 32 bytes of each HMAC key for SHA256:
   *   - Key 0 (bytes 0-31): Direction 0 HMAC key
   *   - Key 1 (bytes 64-95): Direction 1 HMAC key
   *
   * For server mode (key_direction=0):
   *   - encrypt_key = direction 0 (for server->client)
   *   - decrypt_key = direction 1 (for client->server)
   *
   * For client mode (key_direction=1):
   *   - encrypt_key = direction 1 (for client->server)
   *   - decrypt_key = direction 0 (for server->client)
   */
  u8 encrypt_key[OVPN_HMAC_SIZE]; /* HMAC key for outgoing packets */
  u8 decrypt_key[OVPN_HMAC_SIZE]; /* HMAC key for incoming packets */

  /* Replay protection for incoming packets (wrapper packet_id) */
  u64 replay_bitmap;
  u32 replay_packet_id_floor;

  /* Time-based replay protection (control channel uses long-form packet_id) */
  u32 replay_time_floor; /* Oldest acceptable timestamp (unix seconds) */
  u32 time_backtrack;	 /* Max seconds a packet can be older than latest */

  /* Packet ID for outgoing packets */
  u32 packet_id_send;
} ovpn_tls_auth_t;

/*
 * TLS-Auth wrapped packet header (placed after opcode byte)
 */
typedef CLIB_PACKED (struct {
  u8 hmac[OVPN_HMAC_SIZE];
  u32 packet_id;  /* For replay protection (network byte order) */
  u32 net_time;	  /* Timestamp (network byte order) */
  /* followed by: session_id, ack_array, msg_packet_id, payload */
}) ovpn_tls_auth_header_t;

/*
 * Check replay for TLS-Auth wrapper packet_id with time validation
 *
 * Control channel uses long-form packet_id (packet_id + net_time).
 * Both sequence number and timestamp are validated for replay protection.
 *
 * @param ctx       TLS-Auth context
 * @param packet_id Packet sequence number from wrapper
 * @param net_time  Timestamp from wrapper (unix seconds, network byte order converted)
 * @param now       Current time (unix seconds)
 * @return 1 if packet is valid, 0 if replay/invalid
 */
always_inline int
ovpn_tls_auth_check_replay (const ovpn_tls_auth_t *ctx, u32 packet_id,
			    u32 net_time, u32 now)
{
  u32 diff;

  /*
   * Note: packet_id 0 is valid for the first control packet
   * (HARD_RESET_CLIENT_V2). We use the sliding window mechanism
   * below to detect replays rather than rejecting packet_id 0.
   */

  /* Check timestamp if time_backtrack is enabled (non-zero) */
  if (ctx->time_backtrack > 0)
    {
      /* Reject if timestamp is too old */
      if (net_time < ctx->replay_time_floor)
	return 0;

      /* Reject if timestamp is too far in the past relative to now */
      if (now > net_time && (now - net_time) > ctx->time_backtrack)
	return 0;

      /* Reject if timestamp is too far in the future (clock skew protection) */
      if (net_time > now && (net_time - now) > ctx->time_backtrack)
	return 0;
    }

  /* Check packet_id against sliding window */
  if (packet_id < ctx->replay_packet_id_floor)
    return 0;

  diff = packet_id - ctx->replay_packet_id_floor;

  /* Ahead of window - OK */
  if (diff >= OVPN_CONTROL_REPLAY_WINDOW_SIZE)
    return 1;

  /* Check if already seen in bitmap */
  if (ctx->replay_bitmap & (1ULL << diff))
    return 0;

  return 1;
}

/*
 * Update replay window for TLS-Auth
 *
 * @param ctx       TLS-Auth context
 * @param packet_id Packet sequence number
 * @param net_time  Timestamp from packet (unix seconds)
 */
always_inline void
ovpn_tls_auth_update_replay (ovpn_tls_auth_t *ctx, u32 packet_id, u32 net_time)
{
  u32 diff;

  if (packet_id < ctx->replay_packet_id_floor)
    return;

  diff = packet_id - ctx->replay_packet_id_floor;

  if (diff >= OVPN_CONTROL_REPLAY_WINDOW_SIZE)
    {
      u32 shift = diff - OVPN_CONTROL_REPLAY_WINDOW_SIZE + 1;
      if (shift >= 64)
	ctx->replay_bitmap = 0;
      else
	ctx->replay_bitmap >>= shift;
      ctx->replay_packet_id_floor += shift;
      diff = packet_id - ctx->replay_packet_id_floor;
    }

  ctx->replay_bitmap |= (1ULL << diff);

  /* Update time floor if this timestamp is newer */
  if (ctx->time_backtrack > 0 && net_time > ctx->replay_time_floor)
    ctx->replay_time_floor = net_time - ctx->time_backtrack;
}

/*
 * TLS-Crypt context
 *
 * TLS-Crypt provides both authentication and encryption of control channel
 * packets. OpenVPN static key files are 2048 bits (256 bytes) total, but
 * TLS-Crypt only uses the first 1024 bits (128 bytes) organized as:
 *   - 256 bits (32 bytes): HMAC key for client->server direction
 *   - 256 bits (32 bytes): AES-256-CTR key for client->server direction
 *   - 256 bits (32 bytes): HMAC key for server->client direction
 *   - 256 bits (32 bytes): AES-256-CTR key for server->client direction
 *
 * The remaining 128 bytes of the static key file are unused by TLS-Crypt.
 *
 * TLS-Crypt packet format (wrapped):
 * +--------+----------+---------+----------+------------------+
 * | opcode | session  | HMAC    | packet_id|  encrypted       |
 * | +keyid |    id    | (256b)  | +net_time|  payload         |
 * +--------+----------+---------+----------+------------------+
 *  1 byte    8 bytes   32 bytes   8 bytes     variable
 *
 * The HMAC is computed over: packet_id || net_time || opcode+keyid ||
 *                            session_id || encrypted_payload
 * The encryption covers the original control packet content after session_id
 *
 * For tls-crypt, the wrapped packet structure is:
 *   [opcode+keyid][session_id][HMAC-256][packet_id][net_time][encrypted payload]
 *
 * Where encrypted payload = AES-256-CTR encrypted original control packet
 */
#define OVPN_TLS_CRYPT_KEY_FILE_SIZE  256 /* OpenVPN static key file (2048 bits) */
#define OVPN_TLS_CRYPT_KEY_SIZE	      128 /* Used portion for TLS-Crypt (1024 bits) */
#define OVPN_TLS_CRYPT_CIPHER_SIZE    32  /* AES-256 key size */
#define OVPN_TLS_CRYPT_HMAC_SIZE      32  /* SHA-256 HMAC output size */
#define OVPN_TLS_CRYPT_HMAC_KEY_SIZE  32  /* OpenVPN HMAC key size (256 bits) */
#define OVPN_TLS_CRYPT_IV_SIZE	    16	/* AES-256-CTR IV size */
#define OVPN_TLS_CRYPT_TAG_SIZE	    OVPN_TLS_CRYPT_HMAC_SIZE
#define OVPN_TLS_CRYPT_PACKET_ID_SIZE 4
#define OVPN_TLS_CRYPT_NET_TIME_SIZE  4
#define OVPN_TLS_CRYPT_BLOCK_SIZE     16

/* TLS-Crypt key structure (from OpenVPN static key file) */
typedef struct ovpn_tls_crypt_key_t_
{
  /* Server encrypt/client decrypt key (HMAC + cipher) */
  u8 server_hmac_key[OVPN_TLS_CRYPT_HMAC_SIZE];
  u8 server_cipher_key[OVPN_TLS_CRYPT_CIPHER_SIZE];
  /* Client encrypt/server decrypt key (HMAC + cipher) */
  u8 client_hmac_key[OVPN_TLS_CRYPT_HMAC_SIZE];
  u8 client_cipher_key[OVPN_TLS_CRYPT_CIPHER_SIZE];
} ovpn_tls_crypt_key_t;

/* TLS-Crypt context for encryption/decryption */
typedef struct ovpn_tls_crypt_t_
{
  u8 enabled;
  /* Keys used for server mode:
   * - encrypt with Key 0 (outgoing to client)
   * - decrypt with Key 1 (incoming from client)
   */
  u8 encrypt_hmac_key[OVPN_TLS_CRYPT_HMAC_KEY_SIZE];
  u8 encrypt_cipher_key[OVPN_TLS_CRYPT_CIPHER_SIZE];
  u8 decrypt_hmac_key[OVPN_TLS_CRYPT_HMAC_KEY_SIZE];
  u8 decrypt_cipher_key[OVPN_TLS_CRYPT_CIPHER_SIZE];

  /* Packet ID for sending */
  u32 packet_id_send;

  /* Replay protection for receiving (sliding window) */
  u64 replay_bitmap;
  u32 replay_packet_id_floor;

  /* Time-based replay protection (control channel uses long-form packet_id) */
  u32 replay_time_floor; /* Oldest acceptable timestamp (unix seconds) */
  u32 time_backtrack;	 /* Max seconds a packet can be older than latest */
} ovpn_tls_crypt_t;

/*
 * TLS-Crypt wrapped packet header
 * OpenVPN TLS-Crypt packet format (after opcode + session_id):
 *   [packet_id (4)] [net_time (4)] [HMAC (32)] [ciphertext]
 *
 * Full wire format:
 *   opcode || session_id || packet_id || net_time || HMAC || ciphertext
 *
 * HMAC is computed over:
 *   (opcode || session_id || packet_id || net_time || plaintext)
 *
 * IV for encryption: first 16 bytes of HMAC
 */
typedef CLIB_PACKED (struct {
  u32 packet_id;
  u32 net_time;
  u8 hmac[OVPN_TLS_CRYPT_HMAC_SIZE];
  /* followed by encrypted control packet */
}) ovpn_tls_crypt_header_t;

/* Overhead = packet_id + net_time + HMAC */
#define OVPN_TLS_CRYPT_OVERHEAD                                               \
  (OVPN_TLS_CRYPT_HMAC_SIZE + OVPN_TLS_CRYPT_PACKET_ID_SIZE +                 \
   OVPN_TLS_CRYPT_NET_TIME_SIZE)

/*
 * TLS-Crypt-V2 support
 *
 * TLS-Crypt-V2 adds client-specific keys. Each client has a unique key (Kc)
 * that is wrapped with the server's key and sent in P_CONTROL_HARD_RESET_CLIENT_V3.
 *
 * Server Key Format (from OpenVPN static key file, 256 bytes total):
 *   - Ke = first 256 bits of key 1 (AES-256-CTR encryption key)
 *   - Ka = first 256 bits of key 2 (HMAC-SHA256 authentication key)
 *
 * Wrapped Client Key (WKc) Format:
 *   [Tag (32 bytes)] [Encrypted(Kc || metadata)] [Length (2 bytes)]
 *
 * Where:
 *   - Tag = HMAC-SHA256(Ka, Kc || metadata)
 *   - IV = first 128 bits (16 bytes) of Tag
 *   - Encrypted data = AES-256-CTR(Ke, IV, Kc || metadata)
 *   - Kc = 2048 bits (256 bytes) client key
 *   - metadata = optional client metadata
 *   - Length = total length of Tag + Encrypted data (big-endian)
 *
 * P_CONTROL_HARD_RESET_CLIENT_V3 packet:
 *   [tls-crypt wrapped HARD_RESET using Kc] [WKc (cleartext)]
 *
 * P_CONTROL_WKC_V1:
 *   Used to resend WKc in stateless server mode (HMAC cookies)
 */

/* TLS-Crypt-V2 constants */
#define OVPN_TLS_CRYPT_V2_CLIENT_KEY_LEN  256 /* 2048 bits */
#define OVPN_TLS_CRYPT_V2_SERVER_KEY_LEN  256 /* 4 x 512-bit keys */
#define OVPN_TLS_CRYPT_V2_TAG_SIZE	  32  /* HMAC-SHA256 output */
#define OVPN_TLS_CRYPT_V2_MAX_WKC_LEN	  1024
#define OVPN_TLS_CRYPT_V2_MAX_METADATA_LEN                                    \
  (OVPN_TLS_CRYPT_V2_MAX_WKC_LEN - OVPN_TLS_CRYPT_V2_CLIENT_KEY_LEN -         \
   OVPN_TLS_CRYPT_V2_TAG_SIZE - 2)
#define OVPN_TLS_CRYPT_V2_MIN_WKC_LEN                                         \
  (OVPN_TLS_CRYPT_V2_TAG_SIZE + OVPN_TLS_CRYPT_V2_CLIENT_KEY_LEN + 2)

/*
 * TLS-Crypt-V2 server key structure
 * Extracted from OpenVPN static key file (first 64 bytes used)
 */
typedef struct ovpn_tls_crypt_v2_server_key_t_
{
  u8 encrypt_key[32]; /* Ke: AES-256-CTR key (first 256 bits of key 1) */
  u8 auth_key[32];    /* Ka: HMAC-SHA256 key (first 256 bits of key 2) */
} ovpn_tls_crypt_v2_server_key_t;

/*
 * TLS-Crypt-V2 context for server
 */
typedef struct ovpn_tls_crypt_v2_t_
{
  u8 enabled;
  ovpn_tls_crypt_v2_server_key_t server_key;
} ovpn_tls_crypt_v2_t;

/*
 * Unwrapped client key result
 */
typedef struct ovpn_tls_crypt_v2_client_key_t_
{
  u8 key[OVPN_TLS_CRYPT_V2_CLIENT_KEY_LEN]; /* 256-byte client key (Kc) */
  u8 *metadata;				    /* Optional metadata (allocated) */
  u32 metadata_len;
} ovpn_tls_crypt_v2_client_key_t;

/*
 * Parse TLS-Crypt-V2 server key from raw key data
 * The key data should be the binary content of an OpenVPN static key file
 * Returns 0 on success, <0 on error
 */
int ovpn_tls_crypt_v2_parse_server_key (const u8 *key_data, u32 key_len,
					ovpn_tls_crypt_v2_t *ctx);

/*
 * Unwrap a client key (WKc) using the server key
 *
 * @param ctx       TLS-Crypt-V2 context with server key
 * @param wkc       Wrapped client key blob
 * @param wkc_len   Length of WKc blob
 * @param client_key Output: unwrapped client key
 *
 * Returns 0 on success, <0 on error:
 *   -1: Invalid parameters
 *   -2: WKc too short
 *   -3: WKc too long
 *   -4: Authentication failed (HMAC mismatch)
 *   -5: Decryption failed
 */
int ovpn_tls_crypt_v2_unwrap_client_key (const ovpn_tls_crypt_v2_t *ctx,
					 const u8 *wkc, u32 wkc_len,
					 ovpn_tls_crypt_v2_client_key_t *client_key);

/*
 * Free resources in client key structure
 */
void ovpn_tls_crypt_v2_client_key_free (ovpn_tls_crypt_v2_client_key_t *client_key);

/*
 * Convert unwrapped client key to TLS-Crypt context
 * This creates a per-client TLS-Crypt context from the unwrapped Kc
 */
int ovpn_tls_crypt_v2_client_key_to_tls_crypt (
  const ovpn_tls_crypt_v2_client_key_t *client_key, ovpn_tls_crypt_t *tls_crypt,
  u8 is_server);

/*
 * Extract WKc from P_CONTROL_HARD_RESET_CLIENT_V3 packet
 *
 * The WKc is appended after the tls-crypt wrapped packet.
 * Format: [tls-crypt wrapped packet] [WKc]
 *
 * @param packet      Full packet data (after opcode byte)
 * @param packet_len  Total packet length
 * @param wkc_out     Output: pointer to WKc within packet
 * @param wkc_len_out Output: length of WKc
 * @param wrapped_len_out Output: length of tls-crypt wrapped portion
 *
 * Returns 0 on success, <0 on error
 */
int ovpn_tls_crypt_v2_extract_wkc (const u8 *packet, u32 packet_len,
				   const u8 **wkc_out, u32 *wkc_len_out,
				   u32 *wrapped_len_out);

/*
 * Initialize pending connection database
 */
void ovpn_pending_db_init (ovpn_pending_db_t *db);

/*
 * Free pending connection database
 */
void ovpn_pending_db_free (ovpn_pending_db_t *db);

/*
 * Create a new pending connection
 * Returns pointer to pending connection, or NULL on error
 */
ovpn_pending_connection_t *
ovpn_pending_connection_create (ovpn_pending_db_t *db,
				const ip_address_t *remote_addr,
				u16 remote_port,
				const ovpn_session_id_t *remote_session_id,
				u8 key_id);

/*
 * Find pending connection by remote address
 */
ovpn_pending_connection_t *
ovpn_pending_connection_lookup (ovpn_pending_db_t *db,
				const ip_address_t *remote_addr,
				u16 remote_port);

/*
 * Delete pending connection
 */
void ovpn_pending_connection_delete (ovpn_pending_db_t *db,
				     ovpn_pending_connection_t *pending);

/*
 * Delete expired pending connections
 */
void ovpn_pending_db_expire (ovpn_pending_db_t *db, f64 now);

/*
 * Hash key generation for remote address lookup
 */
always_inline u64
ovpn_pending_remote_hash_key (const ip_address_t *addr, u16 port)
{
  u64 key = 0;
  if (addr->version == AF_IP4)
    {
      key = ((u64) addr->ip.ip4.as_u32 << 16) | port;
    }
  else
    {
      /* For IPv6, use a simpler hash */
      key = addr->ip.ip6.as_u64[0] ^ addr->ip.ip6.as_u64[1];
      key = (key << 16) | port;
    }
  return key;
}

/*
 * Build and send P_CONTROL_HARD_RESET_SERVER_V2 response
 * Returns 0 on success, <0 on error
 */
int ovpn_handshake_send_server_reset (vlib_main_t *vm,
				      ovpn_pending_connection_t *pending,
				      vlib_buffer_t *response_buf);

/*
 * Process incoming control packet
 * Called from handshake node
 */
int ovpn_handshake_process_packet (vlib_main_t *vm, vlib_buffer_t *b,
				   const ip_address_t *src_addr, u16 src_port,
				   const ip_address_t *dst_addr, u16 dst_port,
				   u8 is_ip6);

/*
 * TLS-Auth unwrap: verify HMAC and check replay protection
 *
 * Input packet format (after opcode byte):
 *   [HMAC (32)] [packet_id (4)] [net_time (4)] [session_id...payload]
 *
 * Output: plaintext starting from session_id (HMAC + packet_id + net_time stripped)
 *
 * Note: The opcode must be passed separately because OpenVPN includes the opcode
 * in HMAC calculation even though it appears before the HMAC on the wire.
 * HMAC covers: [packet_id] [net_time] [opcode] [session_id...payload]
 *
 * Returns: length of plaintext, or <0 on error:
 *   -1: invalid parameters
 *   -2: packet too short
 *   -3: HMAC verification failed
 *   -4: replay detected
 */
int ovpn_tls_auth_unwrap (ovpn_tls_auth_t *ctx, const u8 *wrapped, u32 wrapped_len,
			  u8 *plaintext, u32 plaintext_buf_len);

/*
 * TLS-Auth wrap: add HMAC and packet_id/net_time for outgoing packets
 *
 * The opcode must be passed separately because OpenVPN includes the opcode
 * in HMAC calculation in a specific order.
 * HMAC covers: [packet_id] [net_time] [opcode] [session_id...payload]
 *
 * Returns: length of wrapped packet, or <0 on error
 */
int ovpn_tls_auth_wrap (ovpn_tls_auth_t *ctx, const u8 *plaintext, u32 plain_len,
			u8 *wrapped, u32 wrapped_buf_len);

/*
 * Legacy HMAC verification (simple, no replay protection)
 * Returns 1 if HMAC is valid, 0 if invalid
 * @deprecated Use ovpn_tls_auth_unwrap instead
 */
int ovpn_handshake_verify_hmac (const u8 *data, u32 len,
				const ovpn_tls_auth_t *auth);

/*
 * Generate HMAC for outgoing control packet
 * @deprecated Use ovpn_tls_auth_wrap instead
 */
void ovpn_handshake_generate_hmac (u8 *data, u32 len, u8 *hmac_out,
				   const ovpn_tls_auth_t *auth);

/*
 * Parse TLS-Auth key from raw key data
 * The key data should be the binary content of an OpenVPN static key file
 *
 * @param key_data  Raw key file contents (PEM or binary format)
 * @param key_len   Length of key data
 * @param ctx       TLS-Auth context to initialize
 * @param is_server 1 for server mode, 0 for client mode
 *
 * Returns 0 on success, <0 on error:
 *   -1: Invalid parameters
 *   -2: Invalid key format
 *   -3: Key too short
 */
int ovpn_tls_auth_parse_key (const u8 *key_data, u32 key_len,
			     ovpn_tls_auth_t *ctx, u8 is_server);

/*
 * Compute HMAC-SHA256 for TLS-Crypt
 *
 * @param key   HMAC key (32 bytes)
 * @param data  Input data
 * @param len   Length of input data
 * @param out   Output buffer for HMAC (32 bytes)
 *
 * Returns 0 on success, <0 on error
 */
int ovpn_tls_crypt_hmac (const u8 *key, const u8 *data, u32 len, u8 *out);

/*
 * Parse TLS-Crypt key from raw key data
 * The key data should be the binary content of an OpenVPN static key file
 * Returns 0 on success, <0 on error
 */
int ovpn_tls_crypt_parse_key (const u8 *key_data, u32 key_len,
			      ovpn_tls_crypt_t *ctx, u8 is_server);

/*
 * Wrap (encrypt + authenticate) a control channel packet using TLS-Crypt
 *
 * Input: opcode_session (9 bytes: opcode + session_id), plaintext to encrypt
 * Output: wrapped packet written to out_buf
 *
 * HMAC is computed over: opcode || session_id || packet_id || net_time || ciphertext
 *
 * Returns: length of wrapped packet, or <0 on error
 */
int ovpn_tls_crypt_wrap (const ovpn_tls_crypt_t *ctx, const u8 *opcode_session,
			 const u8 *plaintext, u32 plain_len, u8 *wrapped,
			 u32 wrapped_buf_len);

/*
 * Unwrap (verify + decrypt) a control channel packet using TLS-Crypt
 *
 * Input: opcode_session (9 bytes: opcode + session_id), wrapped packet
 * Output: plaintext control packet written to plaintext buffer
 *
 * HMAC is computed over: opcode || session_id || packet_id || net_time || ciphertext
 *
 * Returns: length of plaintext, or <0 on error
 *
 * Note: This function performs replay protection check and updates the
 * replay window on success.
 */
int ovpn_tls_crypt_unwrap (ovpn_tls_crypt_t *ctx, const u8 *opcode_session,
			   const u8 *wrapped, u32 wrapped_len, u8 *plaintext,
			   u32 plaintext_buf_len);

/*
 * Check if a packet_id has been seen (replay detection) with time validation
 *
 * Control channel uses long-form packet_id (packet_id + net_time).
 * Both sequence number and timestamp are validated for replay protection.
 *
 * @param ctx       TLS-Crypt context
 * @param packet_id Packet sequence number from wrapper
 * @param net_time  Timestamp from wrapper (unix seconds, network byte order converted)
 * @param now       Current time (unix seconds)
 * @return 1 if packet is valid, 0 if replay detected
 */
always_inline int
ovpn_tls_crypt_check_replay (const ovpn_tls_crypt_t *ctx, u32 packet_id,
			     u32 net_time, u32 now)
{
  u32 diff;

  /* packet_id 0 is never valid */
  if (packet_id == 0)
    return 0;

  /* Check timestamp if time_backtrack is enabled (non-zero) */
  if (ctx->time_backtrack > 0)
    {
      /* Reject if timestamp is too old */
      if (net_time < ctx->replay_time_floor)
	return 0;

      /* Reject if timestamp is too far in the past relative to now */
      if (now > net_time && (now - net_time) > ctx->time_backtrack)
	return 0;

      /* Reject if timestamp is too far in the future (clock skew protection) */
      if (net_time > now && (net_time - now) > ctx->time_backtrack)
	return 0;
    }

  /* Too old - before our window */
  if (packet_id < ctx->replay_packet_id_floor)
    return 0;

  diff = packet_id - ctx->replay_packet_id_floor;

  /* Ahead of window - OK */
  if (diff >= OVPN_CONTROL_REPLAY_WINDOW_SIZE)
    return 1;

  /* Check bitmap for this position */
  if (ctx->replay_bitmap & (1ULL << diff))
    return 0; /* Already seen */

  return 1;
}

/*
 * Update replay window after successful packet verification
 *
 * @param ctx       TLS-Crypt context
 * @param packet_id Packet sequence number
 * @param net_time  Timestamp from packet (unix seconds)
 */
always_inline void
ovpn_tls_crypt_update_replay (ovpn_tls_crypt_t *ctx, u32 packet_id,
			      u32 net_time)
{
  u32 diff;

  if (packet_id < ctx->replay_packet_id_floor)
    return;

  diff = packet_id - ctx->replay_packet_id_floor;

  if (diff >= OVPN_CONTROL_REPLAY_WINDOW_SIZE)
    {
      /* Advance window */
      u32 shift = diff - OVPN_CONTROL_REPLAY_WINDOW_SIZE + 1;
      if (shift >= 64)
	ctx->replay_bitmap = 0;
      else
	ctx->replay_bitmap >>= shift;
      ctx->replay_packet_id_floor += shift;
      diff = packet_id - ctx->replay_packet_id_floor;
    }

  /* Mark as seen */
  ctx->replay_bitmap |= (1ULL << diff);

  /* Update time floor if this timestamp is newer */
  if (ctx->time_backtrack > 0 && net_time > ctx->replay_time_floor)
    ctx->replay_time_floor = net_time - ctx->time_backtrack;
}

/*
 * OpenVPN Control Channel Message Types
 *
 * These messages are sent over the TLS-encrypted control channel
 * after the TLS handshake completes. They are plaintext strings
 * inside P_CONTROL_V1 packets.
 */

/* Control message prefixes */
#define OVPN_MSG_PUSH_REQUEST "PUSH_REQUEST"
#define OVPN_MSG_PUSH_REPLY	  "PUSH_REPLY"
#define OVPN_MSG_AUTH_FAILED  "AUTH_FAILED"
#define OVPN_MSG_RESTART	  "RESTART"
#define OVPN_MSG_HALT		  "HALT"
#define OVPN_MSG_INFO		  "INFO"

/*
 * OpenVPN explicit-exit-notify and ping messages
 * These have special single-byte formats in the data channel
 */
#define OVPN_MSG_EXPLICIT_EXIT_NOTIFY 0x06 /* Single byte in data channel */

/*
 * OCC (Options Compatibility Check) string prefix
 * Used for protocol compatibility negotiation
 */
#define OVPN_OCC_STRING "occ"

/*
 * Ping message format
 * OpenVPN uses a specific 16-byte pattern for ping in the data channel:
 * 0x2a 0x18 0x7b 0xf3 0x64 0x1e 0xb4 0xcb 0x07 0xed 0x2d 0x0a 0x98 0x1f 0xc7 0x48
 */
#define OVPN_PING_STRING_SIZE 16
extern const u8 ovpn_ping_string[OVPN_PING_STRING_SIZE];

/*
 * Process control channel message (after TLS decryption)
 * Handles PUSH_REQUEST, AUTH_FAILED, etc.
 *
 * Returns: >0 if response should be sent, 0 if no response needed, <0 on error
 */
int ovpn_control_message_process (vlib_main_t *vm, struct ovpn_peer_t_ *peer,
				  const u8 *data, u32 len, u8 *response,
				  u32 *response_len);

/*
 * Build PUSH_REPLY message for a peer
 * Includes virtual IP, routes, DNS, and other pushed options
 */
int ovpn_build_push_reply (struct ovpn_peer_t_ *peer, char *buf, u32 buf_len);

/*
 * Check if data is a ping packet
 */
always_inline int
ovpn_is_ping_packet (const u8 *data, u32 len)
{
  extern const u8 ovpn_ping_string[OVPN_PING_STRING_SIZE];
  if (len < OVPN_PING_STRING_SIZE)
    return 0;
  return clib_memcmp (data, ovpn_ping_string, OVPN_PING_STRING_SIZE) == 0;
}

/*
 * Check if data is an explicit-exit-notify packet
 *
 * OpenVPN sends explicit-exit-notify as a single byte 0x06 in the
 * data channel (after decryption). When received, the server should
 * immediately clean up the peer connection.
 */
always_inline int
ovpn_is_exit_notify (const u8 *data, u32 len)
{
  if (len == 1 && data[0] == OVPN_MSG_EXPLICIT_EXIT_NOTIFY)
    return 1;
  return 0;
}

/*
 * Process control channel retransmission for an instance.
 * Checks all pending connections and established peers for control
 * packets that need retransmitting (timeout expired).
 *
 * Should be called periodically from the timer process.
 * Returns total number of packets retransmitted.
 */
struct ovpn_instance_t_;
int ovpn_control_channel_retransmit (vlib_main_t *vm,
				     struct ovpn_instance_t_ *inst);

#endif /* __included_ovpn_handshake_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
