/*
 * ovpn_ssl.h - ovpn ssl header file
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

#ifndef __included_ovpn_ssl_h__
#define __included_ovpn_ssl_h__

#include <vlib/vlib.h>
#include <ovpn/ovpn_buffer.h>
#include <ovpn/ovpn_crypto.h>
#include <picotls.h>

/**
 * Secure memory zeroing that won't be optimized away by the compiler.
 * Used for clearing sensitive cryptographic material.
 */
always_inline void
ovpn_secure_zero_memory (void *ptr, size_t size)
{
  static void *(*const volatile memset_v) (void *, int, size_t) = &memset;
  memset_v (ptr, 0, size);
}

/**
 * Key Method 2 constants
 */
#define OVPN_KEY_METHOD_2	   2
#define OVPN_PRE_MASTER_SIZE	   48
#define OVPN_RANDOM_SIZE	   32
#define OVPN_MASTER_SECRET_SIZE	   48
#define OVPN_KEY_EXPANSION_SIZE	   256
#define OVPN_KEY_EXPANSION_ID	   "OpenVPN"
#define OVPN_MASTER_SECRET_LABEL   OVPN_KEY_EXPANSION_ID " master secret"
#define OVPN_KEY_EXPANSION_LABEL   OVPN_KEY_EXPANSION_ID " key expansion"

/**
 * Container for one half of random material to be used in %key method 2
 * data channel key generation.
 */
typedef struct ovpn_key_source_t_
{
  u8 pre_master[OVPN_PRE_MASTER_SIZE]; /**< Random used for master secret
					*   generation, provided only by client
					*   OpenVPN peer. */
  u8 random1[OVPN_RANDOM_SIZE];	       /**< Seed used for master secret
					*   generation, provided by both client
					*   and server. */
  u8 random2[OVPN_RANDOM_SIZE];	       /**< Seed used for key expansion,
					*   provided by both client and server.
					*/
} ovpn_key_source_t;

/**
 * Container for both halves of random material to be used in %key method
 * 2 \ref key_generation "data channel key generation".
 * @ingroup control_processor
 */
typedef struct ovpn_key_source2_t_
{
  u32 index;
  ovpn_key_source_t client; /**< Random provided by client. */
  ovpn_key_source_t server; /**< Random provided by server. */
} ovpn_key_source2_t;

/**
 * Key direction constants for bidirectional key derivation
 */
#define OVPN_KEY_DIRECTION_BIDIRECTIONAL 0
#define OVPN_KEY_DIRECTION_NORMAL	 1
#define OVPN_KEY_DIRECTION_INVERSE	 2

/**
 * Structure for a single key (cipher + hmac)
 * Matches OpenVPN's struct key layout
 */
typedef struct ovpn_key_t_
{
  u8 cipher[64]; /**< Cipher key material */
  u8 hmac[64];	 /**< HMAC key material */
} ovpn_key_t;

/**
 * Structure for bidirectional keys
 * keys[0] = client-to-server direction
 * keys[1] = server-to-client direction
 */
typedef struct ovpn_key2_t_
{
  int n;	      /**< Number of keys (1 or 2) */
  ovpn_key_t keys[2]; /**< The key pairs */
} ovpn_key2_t;

/**
 * Allocate a new key source structure
 * @return The pointer to the new key source structure
 * @note The returned pointer may become invalid if another allocation
 *       causes pool reallocation. Use ovpn_key_source2_get() with the
 *       stored index to get a fresh pointer when needed.
 */
ovpn_key_source2_t *ovpn_key_source2_alloc (void);

/**
 * Get a key source structure by index
 * @param index The pool index of the key source
 * @return The pointer to the key source structure
 */
ovpn_key_source2_t *ovpn_key_source2_get (u32 index);

/**
 * Free a key source structure by index
 * @param index The pool index of the key source to free
 */
void ovpn_key_source2_free_index (u32 index);

/**
 * Free a key source structure
 * @param key_src2 The pointer to the key source structure to free
 * @note Prefer ovpn_key_source2_free_index() when the pointer may be stale
 */
void ovpn_key_source2_free (ovpn_key_source2_t *key_src2);

/**
 * Generate random material for key_source
 * @param ks Key source to randomize
 * @param include_pre_master If true, also generate pre_master (client only)
 * @return 0 on success, <0 on error
 */
int ovpn_key_source_randomize (ovpn_key_source_t *ks, int include_pre_master);

/**
 * OpenVPN PRF (Pseudo-Random Function) based on TLS 1.0 PRF
 *
 * This implements the OpenVPN key derivation PRF which uses:
 * PRF(secret, label, seed1 || seed2 || seed3 || seed4) -> output
 *
 * @param secret The secret key for PRF
 * @param secret_len Length of secret
 * @param label Label string (e.g., "OpenVPN master secret")
 * @param seed1 First seed component (required)
 * @param seed1_len Length of seed1
 * @param seed2 Second seed component (optional, NULL if not used)
 * @param seed2_len Length of seed2
 * @param seed3 Third seed component (optional, NULL if not used)
 * @param seed3_len Length of seed3
 * @param seed4 Fourth seed component (optional, NULL if not used)
 * @param seed4_len Length of seed4
 * @param output Output buffer
 * @param output_len Desired output length
 * @return 0 on success, <0 on error
 */
int ovpn_prf (const u8 *secret, u32 secret_len, const char *label,
	      const u8 *seed1, u32 seed1_len, const u8 *seed2, u32 seed2_len,
	      const u8 *seed3, u32 seed3_len, const u8 *seed4, u32 seed4_len,
	      u8 *output, u32 output_len);

/**
 * Generate key expansion using OpenVPN PRF method
 *
 * This implements OpenVPN's Key Method 2 key expansion:
 * 1. Master secret = PRF(pre_master, "OpenVPN master secret",
 *                        client.random1 || server.random1)
 * 2. Key expansion = PRF(master, "OpenVPN key expansion",
 *                        client.random2 || server.random2 ||
 *                        client_sid || server_sid)
 *
 * @param key_src2 The key source containing both client and server random
 * @param client_sid Client session ID (8 bytes, can be NULL)
 * @param server_sid Server session ID (8 bytes, can be NULL)
 * @param is_server 1 if we are server, 0 if client
 * @param key2 Output structure for derived keys
 * @return 0 on success, <0 on error
 */
int ovpn_generate_key_expansion_prf (const ovpn_key_source2_t *key_src2,
				     const u8 *client_sid, const u8 *server_sid,
				     int is_server, ovpn_key2_t *key2);

/**
 * Write Key Method 2 data to buffer
 *
 * Writes the local key source random material to be sent to the peer.
 * Format: [key_method:1][pre_master:48 (client only)][random1:32][random2:32]
 *         [options_string][username][password][peer_info]
 *
 * @param buf Output buffer
 * @param ks2 Key source structure
 * @param local_sid Local session ID
 * @param is_server 1 if we are server, 0 if client
 * @param options Options string to send (can be NULL)
 * @return Number of bytes written, or <0 on error
 */
int ovpn_key_method_2_write (u8 *buf, u32 buf_len, ovpn_key_source2_t *ks2,
			     const u8 *local_sid, int is_server,
			     const char *options);

/**
 * Read Key Method 2 data from buffer
 *
 * Reads the peer's key source random material and options string.
 *
 * @param buf Input buffer
 * @param buf_len Buffer length
 * @param ks2 Key source structure to populate
 * @param is_server 1 if we are server (reading client data), 0 if client
 * @param options_out Output pointer for parsed options string (caller frees)
 * @return Number of bytes consumed, or <0 on error
 */
int ovpn_key_method_2_read (const u8 *buf, u32 buf_len, ovpn_key_source2_t *ks2,
			    int is_server, char **options_out);

/**
 * Read Key Method 2 data including username/password
 *
 * Extended version that also extracts username and password fields
 * for authentication. The username/password are only present when
 * the client is configured with --auth-user-pass.
 *
 * @param buf Input buffer
 * @param buf_len Buffer length
 * @param ks2 Key source structure to populate
 * @param is_server 1 if we are server (reading client data), 0 if client
 * @param options_out Output pointer for parsed options string (caller frees)
 * @param username_out Output pointer for username (caller frees, may be NULL)
 * @param password_out Output pointer for password (caller frees, may be NULL)
 * @return Number of bytes consumed, or <0 on error
 */
int ovpn_key_method_2_read_with_auth (const u8 *buf, u32 buf_len,
				      ovpn_key_source2_t *ks2, int is_server,
				      char **options_out, char **username_out,
				      char **password_out);

/**
 * Verify username/password against password file
 *
 * Password file format: one "username:password" per line
 *
 * @param password_file Path to password file
 * @param username Username to verify
 * @param password Password to verify
 * @return 0 if credentials valid, <0 on error or invalid credentials
 */
int ovpn_verify_user_pass (const char *password_file, const char *username,
			   const char *password);

/**
 * Derive data channel keys from TLS session using Key Method 2
 *
 * This is the main entry point for key derivation. It supports two methods:
 * 1. OpenVPN PRF-based derivation (traditional)
 * 2. TLS 1.3 Exporter (when use_tls_ekm is true)
 *
 * For PRF method, the key_src2 must be populated with random material
 * from both client and server via key_method_2_write/read.
 *
 * @param tls The picotls context (used for TLS-EKM method)
 * @param key_src2 Key source with random material (used for PRF method)
 * @param client_sid Client session ID
 * @param server_sid Server session ID
 * @param keys Output key material structure
 * @param cipher_alg The cipher algorithm to determine key length
 * @param is_server 1 if we are the server, 0 if client
 * @param use_tls_ekm If true, use TLS 1.3 Exporter instead of PRF
 * @return 0 on success, <0 on error
 */
int ovpn_derive_data_channel_keys_v2 (ptls_t *tls,
				      const ovpn_key_source2_t *key_src2,
				      const u8 *client_sid,
				      const u8 *server_sid,
				      ovpn_key_material_t *keys,
				      ovpn_cipher_alg_t cipher_alg,
				      int is_server, int use_tls_ekm,
				      int client_keydir);

/**
 * Derive data channel keys from TLS session (legacy interface)
 *
 * @deprecated Use ovpn_derive_data_channel_keys_v2 instead
 * @param tls The picotls context
 * @param keys Output key material structure
 * @param cipher_alg The cipher algorithm to determine key length
 * @param is_server 1 if we are the server, 0 if client
 * @return 0 on success, <0 on error
 */
int ovpn_derive_data_channel_keys (ptls_t *tls, ovpn_key_material_t *keys,
				   ovpn_cipher_alg_t cipher_alg, int is_server);

#endif /* __included_ovpn_ssl_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */