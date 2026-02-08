/*
 * ovpn_crypto.h - OpenVPN data channel crypto
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

#ifndef __included_ovpn_crypto_h__
#define __included_ovpn_crypto_h__

#include <vlib/vlib.h>
#include <vnet/crypto/crypto.h>
#include <ovpn/ovpn_packet.h>

/* Supported cipher algorithms */
typedef enum
{
  OVPN_CIPHER_ALG_NONE = 0,
  OVPN_CIPHER_ALG_AES_128_GCM,
  OVPN_CIPHER_ALG_AES_256_GCM,
  OVPN_CIPHER_ALG_CHACHA20_POLY1305,
  /* CBC ciphers (for static key mode) */
  OVPN_CIPHER_ALG_AES_256_CBC,
} ovpn_cipher_alg_t;

/* Check if cipher is AEAD */
#define OVPN_CIPHER_IS_AEAD(alg)                                              \
  ((alg) == OVPN_CIPHER_ALG_AES_128_GCM ||                                    \
   (alg) == OVPN_CIPHER_ALG_AES_256_GCM ||                                    \
   (alg) == OVPN_CIPHER_ALG_CHACHA20_POLY1305)

/* Key sizes in bytes */
#define OVPN_KEY_SIZE_128	  16
#define OVPN_KEY_SIZE_256	  32
#define OVPN_KEY_SIZE_MAX	  32
#define OVPN_DATA_HMAC_KEY_SIZE 32 /* SHA-256 key size for data channel */

/* IV/Nonce sizes */
#define OVPN_IV_SIZE	     16
#define OVPN_NONCE_SIZE	     12
#define OVPN_IMPLICIT_IV_LEN 8

/* Tag/HMAC sizes */
#define OVPN_TAG_SIZE	   16	/* AEAD tag */
#define OVPN_HMAC_SIZE	   32	/* SHA-256 output */
#define OVPN_HMAC_SIZE_MIN 16	/* Minimum HMAC size for compatibility */
#define OVPN_CBC_HMAC_SIZE 32	/* SHA256 full output for CBC+HMAC mode */

/* CBC mode minimum packet size: opcode(1) + HMAC(32) + IV(16) + packet_id(4) + timestamp(4) */
#define OVPN_DATA_V1_CBC_MIN_SIZE                                             \
  (OVPN_OP_SIZE + OVPN_CBC_HMAC_SIZE + OVPN_IV_SIZE + 8)

/* Replay protection window constants */
#define OVPN_REPLAY_WINDOW_SIZE_DEFAULT 64
#define OVPN_REPLAY_WINDOW_SIZE_MIN	64
#define OVPN_REPLAY_WINDOW_SIZE_MAX	65536

/*
 * Crypto key material derived from TLS handshake
 * OpenVPN derives 4 keys: encrypt/decrypt for each direction
 */
typedef struct ovpn_key_material_t_
{
  u8 encrypt_key[OVPN_KEY_SIZE_MAX];
  u8 decrypt_key[OVPN_KEY_SIZE_MAX];
  u8 encrypt_implicit_iv[OVPN_IMPLICIT_IV_LEN];
  u8 decrypt_implicit_iv[OVPN_IMPLICIT_IV_LEN];
  /* HMAC keys for CBC cipher mode */
  u8 encrypt_hmac_key[OVPN_DATA_HMAC_KEY_SIZE];
  u8 decrypt_hmac_key[OVPN_DATA_HMAC_KEY_SIZE];
  u8 key_len;
  u8 hmac_key_len;
} ovpn_key_material_t;

/*
 * Per-key crypto context
 * Each key_state has its own crypto context
 */
typedef struct ovpn_crypto_context_t_
{
  /* VPP crypto key indices */
  vnet_crypto_key_index_t encrypt_key_index;
  vnet_crypto_key_index_t decrypt_key_index;

  /* HMAC key indices (for CBC cipher mode) */
  vnet_crypto_key_index_t encrypt_hmac_key_index;
  vnet_crypto_key_index_t decrypt_hmac_key_index;

  /* Crypto algorithm info */
  ovpn_cipher_alg_t cipher_alg;
  vnet_crypto_op_id_t encrypt_op_id;
  vnet_crypto_op_id_t decrypt_op_id;

  /* HMAC operation ID (for CBC cipher mode) */
  vnet_crypto_op_id_t hmac_op_id;

  /* Implicit IV for nonce construction (AEAD only) */
  u8 encrypt_implicit_iv[OVPN_IMPLICIT_IV_LEN];
  u8 decrypt_implicit_iv[OVPN_IMPLICIT_IV_LEN];

  /* Packet ID for replay protection */
  u32 packet_id_send;

  /* Replay window for received packets
   * For window_size <= 64: use replay_bitmap directly
   * For window_size > 64: use replay_bitmap_ext (dynamically allocated)
   */
  u64 replay_bitmap;
  u64 *replay_bitmap_ext; /* Extended bitmap for larger windows */
  u32 replay_packet_id_floor;
  u32 replay_window_size; /* Configured window size (64-65536) */

  /* Key is valid and ready for use */
  u8 is_valid;
  u8 is_aead;	 /* 1 for AEAD ciphers, 0 for CBC+HMAC */
  u8 use_data_v2; /* 1 for DATA_V2 format with peer_id, 0 for DATA_V1 */
} ovpn_crypto_context_t;

/*
 * Per-thread crypto data for batch operations
 */
typedef struct ovpn_per_thread_crypto_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* Crypto operation arrays - separate for single buffer vs chained */
  vnet_crypto_op_t *crypto_ops;
  vnet_crypto_op_t *chained_crypto_ops;

  /* Chunks for chained buffer crypto operations */
  vnet_crypto_op_chunk_t *chunks;

  /* Async crypto frames */
  vnet_crypto_async_frame_t **async_frames;

  /* IV storage for batch operations (12 bytes per op) */
  u8 *ivs;

  /* Temporary buffer for crypto operations */
  u8 scratch[2048];
} ovpn_per_thread_crypto_t;

/*
 * Initialize crypto subsystem
 */
clib_error_t *ovpn_crypto_init (vlib_main_t *vm);

/*
 * Create crypto context from key material
 * @param ctx           Crypto context to initialize
 * @param cipher_alg    Cipher algorithm to use
 * @param keys          Key material from TLS handshake
 * @param replay_window Replay protection window size (64-65536, 0 for default)
 */
int ovpn_crypto_context_init (ovpn_crypto_context_t *ctx,
			      ovpn_cipher_alg_t cipher_alg,
			      const ovpn_key_material_t *keys,
			      u32 replay_window);

/*
 * Destroy crypto context
 */
void ovpn_crypto_context_free (ovpn_crypto_context_t *ctx);

/*
 * Encrypt a data packet (in place)
 * Returns: 0 on success, <0 on error
 *
 * Input buffer should have:
 *   - Space reserved at start for header (OVPN_DATA_V2_MIN_SIZE)
 *   - Plaintext payload
 *   - Space at end for tag (OVPN_TAG_SIZE)
 *
 * Output buffer will contain:
 *   - opcode + peer_id (4 bytes for V2)
 *   - packet_id (4 bytes)
 *   - encrypted payload
 *   - authentication tag (16 bytes)
 */
int ovpn_crypto_encrypt (vlib_main_t *vm, ovpn_crypto_context_t *ctx,
			 vlib_buffer_t *b, u32 peer_id, u8 key_id);

/*
 * Decrypt a data packet (in place)
 * Returns: 0 on success, <0 on error
 *
 * Input buffer should contain:
 *   - opcode + peer_id (already parsed, buffer starts at packet_id)
 *   - packet_id (4 bytes)
 *   - encrypted payload
 *   - authentication tag (16 bytes)
 *
 * Output buffer will contain:
 *   - decrypted plaintext payload
 */
int ovpn_crypto_decrypt (vlib_main_t *vm, ovpn_crypto_context_t *ctx,
			 vlib_buffer_t *b, u32 *packet_id_out);

/*
 * Check packet ID for replay
 * Returns: 1 if packet is OK, 0 if replay detected
 */
int ovpn_crypto_check_replay (ovpn_crypto_context_t *ctx, u32 packet_id);

/*
 * Update replay window after successful decryption
 */
void ovpn_crypto_update_replay (ovpn_crypto_context_t *ctx, u32 packet_id);

/*
 * Get next packet ID for sending
 */
always_inline u32
ovpn_crypto_get_next_packet_id (ovpn_crypto_context_t *ctx)
{
  return __atomic_fetch_add (&ctx->packet_id_send, 1, __ATOMIC_RELAXED);
}

/*
 * Map cipher name string to algorithm enum
 */
ovpn_cipher_alg_t ovpn_crypto_cipher_alg_from_name (const char *name);

/*
 * Get key size for algorithm
 */
always_inline u8
ovpn_crypto_key_size (ovpn_cipher_alg_t alg)
{
  switch (alg)
    {
    case OVPN_CIPHER_ALG_AES_128_GCM:
      return OVPN_KEY_SIZE_128;
    case OVPN_CIPHER_ALG_AES_256_GCM:
    case OVPN_CIPHER_ALG_CHACHA20_POLY1305:
    case OVPN_CIPHER_ALG_AES_256_CBC:
      return OVPN_KEY_SIZE_256;
    default:
      return 0;
    }
}

/*
 * Static key support for testing
 * In production, keys are derived from TLS handshake
 */
int ovpn_crypto_set_static_key (ovpn_crypto_context_t *ctx,
				ovpn_cipher_alg_t cipher_alg, const u8 *key,
				u8 key_len, const u8 *implicit_iv);

/*
 * Set up static key crypto context for a peer from OpenVPN static.key file.
 *
 * @param ctx Crypto context to initialize
 * @param cipher_alg Cipher algorithm (must be AEAD)
 * @param static_key 256-byte static key from parsed file
 * @param direction 0=normal (server), 1=inverse (client)
 * @param replay_window Replay protection window size
 * @return 0 on success, <0 on error
 */
int ovpn_setup_static_key_crypto (ovpn_crypto_context_t *ctx,
				  ovpn_cipher_alg_t cipher_alg,
				  const u8 *static_key, u8 direction,
				  u32 replay_window);

/*
 * Get per-thread crypto data
 */
ovpn_per_thread_crypto_t *ovpn_crypto_get_ptd (u32 thread_index);

/*
 * Prepare encryption operation for a buffer (supports chained buffers)
 * This function linearizes the buffer chain and prepares the crypto op
 * Returns: 0 on success, <0 on error
 */
int ovpn_crypto_encrypt_prepare (vlib_main_t *vm,
				 ovpn_per_thread_crypto_t *ptd,
				 ovpn_crypto_context_t *ctx, vlib_buffer_t *b,
				 u32 bi, u32 peer_id, u8 key_id);

/*
 * Prepare decryption operation for a buffer (supports chained buffers)
 * This function linearizes the buffer chain and prepares the crypto op
 * Returns: 0 on success, <0 on error
 */
int ovpn_crypto_decrypt_prepare (vlib_main_t *vm,
				 ovpn_per_thread_crypto_t *ptd,
				 ovpn_crypto_context_t *ctx, vlib_buffer_t *b,
				 u32 bi, u32 *packet_id_out);

/*
 * Process all pending encryption operations (batch)
 * Handles both single-buffer and chained-buffer operations
 */
void ovpn_crypto_encrypt_process (vlib_main_t *vm, vlib_node_runtime_t *node,
				  ovpn_per_thread_crypto_t *ptd,
				  vlib_buffer_t *bufs[], u16 *nexts,
				  u16 drop_next);

/*
 * Process all pending decryption operations (batch)
 * Handles both single-buffer and chained-buffer operations
 */
void ovpn_crypto_decrypt_process (vlib_main_t *vm, vlib_node_runtime_t *node,
				  ovpn_per_thread_crypto_t *ptd,
				  vlib_buffer_t *bufs[], u16 *nexts,
				  u16 drop_next);

/*
 * Reset per-thread crypto state for new frame processing
 */
always_inline void
ovpn_crypto_reset_ptd (ovpn_per_thread_crypto_t *ptd)
{
  vec_reset_length (ptd->crypto_ops);
  vec_reset_length (ptd->chained_crypto_ops);
  vec_reset_length (ptd->chunks);
  vec_reset_length (ptd->ivs);
}

/*
 * CBC+HMAC mode decrypt for single packet (static key mode).
 * Packet format: [opcode:1][HMAC:32][IV:16][encrypted(packet_id:4 + timestamp:4 + payload)]
 * Note: Uses "long form" packet IDs with timestamp (default with replay-window).
 *
 * @param vm vlib_main_t
 * @param ctx crypto context (must be CBC mode)
 * @param b buffer containing packet (starting at opcode)
 * @param packet_id_out output: extracted packet_id
 * @return 0 on success, <0 on error
 */
int ovpn_crypto_cbc_decrypt (vlib_main_t *vm, ovpn_crypto_context_t *ctx,
			     vlib_buffer_t *b, u32 *packet_id_out);

/*
 * CBC+HMAC mode decrypt for static key mode packets WITHOUT opcode byte.
 * Packet format: [HMAC:32][IV:16][encrypted(packet_id:4 + timestamp:4 + payload)]
 * Note: Uses "long form" packet IDs with timestamp (default with replay-window).
 *
 * @param vm vlib_main_t
 * @param ctx crypto context (must be CBC mode)
 * @param b buffer containing packet (starting at HMAC, no opcode)
 * @param packet_id_out output: extracted packet_id
 * @return 0 on success, <0 on error
 */
int ovpn_crypto_cbc_decrypt_no_opcode (vlib_main_t *vm,
				       ovpn_crypto_context_t *ctx,
				       vlib_buffer_t *b, u32 *packet_id_out);

/*
 * CBC+HMAC mode encrypt for single packet (static key mode).
 * Packet format: [HMAC:32][IV:16][encrypted(packet_id:4 + timestamp:4 + payload)]
 * Note: Uses "long form" packet IDs with timestamp (default with replay-window).
 *
 * @param vm vlib_main_t
 * @param ctx crypto context (must be CBC mode)
 * @param b buffer containing plaintext payload
 * @return 0 on success, <0 on error
 */
int ovpn_crypto_cbc_encrypt (vlib_main_t *vm, ovpn_crypto_context_t *ctx,
			     vlib_buffer_t *b);

#endif /* __included_ovpn_crypto_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
