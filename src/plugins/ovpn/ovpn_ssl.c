/*
 * ovpn_ssl.c - ovpn ssl source file
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

#include <ovpn/ovpn_ssl.h>
#include <ovpn/ovpn_session_id.h>
#include <ovpn/ovpn_crypto.h>
#include <picotls/openssl.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* Global pool for reliable buffers */
ovpn_reli_buffer_t *ovpn_buf_pool;

/* Zero session ID for comparison */
const ovpn_session_id_t x_session_id_zero = { .id = { 0 } };

static ovpn_key_source2_t *ovpn_key_source2s;

ovpn_key_source2_t *
ovpn_key_source2_alloc (void)
{
  ovpn_key_source2_t *key_src2;
  pool_get (ovpn_key_source2s, key_src2);
  clib_memset (key_src2, 0, sizeof (ovpn_key_source2_t));
  key_src2->index = key_src2 - ovpn_key_source2s;
  return key_src2;
}

ovpn_key_source2_t *
ovpn_key_source2_get (u32 index)
{
  return pool_elt_at_index (ovpn_key_source2s, index);
}

void
ovpn_key_source2_free_index (u32 index)
{
  if (index == ~0 || pool_is_free_index (ovpn_key_source2s, index))
    return;
  ovpn_key_source2_t *key_src2 = pool_elt_at_index (ovpn_key_source2s, index);
  ovpn_secure_zero_memory (key_src2, sizeof (ovpn_key_source2_t));
  pool_put_index (ovpn_key_source2s, index);
}

void
ovpn_key_source2_free (ovpn_key_source2_t *key_src2)
{
  if (!key_src2)
    return;
  u32 index = key_src2->index;
  if (index == ~0 || pool_is_free_index (ovpn_key_source2s, index))
    return;
  ovpn_secure_zero_memory (key_src2, sizeof (ovpn_key_source2_t));
  pool_put_index (ovpn_key_source2s, index);
}

/*
 * Generate random material for key_source
 */
int
ovpn_key_source_randomize (ovpn_key_source_t *ks, int include_pre_master)
{
  if (!ks)
    return -1;

  /* Generate pre_master if requested (client only) */
  if (include_pre_master)
    {
      if (RAND_bytes (ks->pre_master, OVPN_PRE_MASTER_SIZE) != 1)
	return -2;
    }

  /* Generate random1 (used for master secret derivation) */
  if (RAND_bytes (ks->random1, OVPN_RANDOM_SIZE) != 1)
    return -3;

  /* Generate random2 (used for key expansion) */
  if (RAND_bytes (ks->random2, OVPN_RANDOM_SIZE) != 1)
    return -4;

  return 0;
}

/*
 * OpenVPN PRF implementation using TLS 1.0 PRF (P_MD5 XOR P_SHA1)
 *
 * This uses OpenSSL's TLS1-PRF implementation which handles the
 * MD5/SHA1 split internally.
 */
int
ovpn_prf (const u8 *secret, u32 secret_len, const char *label,
	  const u8 *seed1, u32 seed1_len, const u8 *seed2, u32 seed2_len,
	  const u8 *seed3, u32 seed3_len, const u8 *seed4, u32 seed4_len,
	  u8 *output, u32 output_len)
{
  EVP_KDF *kdf = NULL;
  EVP_KDF_CTX *kctx = NULL;
  u8 seed[512];
  u32 seed_len = 0;
  int ret = -1;
  OSSL_PARAM params[4];
  int param_idx = 0;

  if (!secret || !label || !seed1 || !output)
    return -1;

  /* Build combined seed: label || seed1 || seed2 || seed3 || seed4 */
  u32 label_len = strlen (label);

  if (label_len + seed1_len + seed2_len + seed3_len + seed4_len >
      sizeof (seed))
    return -2; /* Seed too large */

  /* Copy label first */
  clib_memcpy_fast (seed + seed_len, label, label_len);
  seed_len += label_len;

  /* Copy seed components */
  clib_memcpy_fast (seed + seed_len, seed1, seed1_len);
  seed_len += seed1_len;

  if (seed2 && seed2_len > 0)
    {
      clib_memcpy_fast (seed + seed_len, seed2, seed2_len);
      seed_len += seed2_len;
    }

  if (seed3 && seed3_len > 0)
    {
      clib_memcpy_fast (seed + seed_len, seed3, seed3_len);
      seed_len += seed3_len;
    }

  if (seed4 && seed4_len > 0)
    {
      clib_memcpy_fast (seed + seed_len, seed4, seed4_len);
      seed_len += seed4_len;
    }

  /* Use OpenSSL's TLS1-PRF */
  kdf = EVP_KDF_fetch (NULL, "TLS1-PRF", NULL);
  if (!kdf)
    goto done;

  kctx = EVP_KDF_CTX_new (kdf);
  if (!kctx)
    goto done;

  /* Set up parameters for TLS 1.0 PRF (uses MD5+SHA1) */
  params[param_idx++] = OSSL_PARAM_construct_utf8_string (
    OSSL_KDF_PARAM_DIGEST, (char *) "MD5-SHA1", 0);
  params[param_idx++] =
    OSSL_PARAM_construct_octet_string (OSSL_KDF_PARAM_SECRET, (void *) secret,
				       secret_len);
  params[param_idx++] = OSSL_PARAM_construct_octet_string (
    OSSL_KDF_PARAM_SEED, (void *) seed, seed_len);
  params[param_idx++] = OSSL_PARAM_construct_end ();

  if (EVP_KDF_derive (kctx, output, output_len, params) != 1)
    goto done;

  ret = 0;

done:
  if (kctx)
    EVP_KDF_CTX_free (kctx);
  if (kdf)
    EVP_KDF_free (kdf);

  /* Securely clear seed */
  ovpn_secure_zero_memory (seed, sizeof (seed));

  return ret;
}

/*
 * Generate key expansion using OpenVPN PRF method
 *
 * Implements OpenVPN's Key Method 2:
 * 1. master = PRF(pre_master, "OpenVPN master secret",
 *                 client.random1 || server.random1)
 * 2. keys = PRF(master, "OpenVPN key expansion",
 *               client.random2 || server.random2 || client_sid || server_sid)
 */
int
ovpn_generate_key_expansion_prf (const ovpn_key_source2_t *key_src2,
				 const u8 *client_sid, const u8 *server_sid,
				 int is_server, ovpn_key2_t *key2)
{
  u8 master[OVPN_MASTER_SECRET_SIZE];
  int ret;

  if (!key_src2 || !key2)
    return -1;

  clib_memset (key2, 0, sizeof (*key2));

  /*
   * Step 1: Derive master secret
   * PRF(client.pre_master, "OpenVPN master secret",
   *     client.random1 || server.random1)
   */
  ret = ovpn_prf (key_src2->client.pre_master, OVPN_PRE_MASTER_SIZE,
		  OVPN_MASTER_SECRET_LABEL, key_src2->client.random1,
		  OVPN_RANDOM_SIZE, key_src2->server.random1, OVPN_RANDOM_SIZE,
		  NULL, 0, NULL, 0, master, OVPN_MASTER_SECRET_SIZE);

  if (ret < 0)
    {
      ovpn_secure_zero_memory (master, sizeof (master));
      return -2;
    }

  /*
   * Step 2: Key expansion
   * PRF(master, "OpenVPN key expansion",
   *     client.random2 || server.random2 || client_sid || server_sid)
   *
   * Session IDs are optional but recommended for additional entropy
   */
  ret = ovpn_prf (master, OVPN_MASTER_SECRET_SIZE, OVPN_KEY_EXPANSION_LABEL,
		  key_src2->client.random2, OVPN_RANDOM_SIZE,
		  key_src2->server.random2, OVPN_RANDOM_SIZE, client_sid,
		  client_sid ? OVPN_SID_SIZE : 0, server_sid,
		  server_sid ? OVPN_SID_SIZE : 0, (u8 *) key2->keys,
		  OVPN_KEY_EXPANSION_SIZE);

  /* Securely clear master secret */
  ovpn_secure_zero_memory (master, sizeof (master));

  if (ret < 0)
    return -3;

  key2->n = 2;

  return 0;
}

/*
 * Write Key Method 2 data to buffer
 *
 * Format sent by client:
 *   [0]:     literal 0 (4 bytes for future use)
 *   [4]:     key_method (1 byte, value = 2)
 *   [5-52]:  pre_master (48 bytes) - client only
 *   [53-84]: random1 (32 bytes)
 *   [85-116]: random2 (32 bytes)
 *   [...]:   options string (null-terminated)
 *   [...]:   username (null-terminated or length-prefixed)
 *   [...]:   password (null-terminated or length-prefixed)
 *   [...]:   peer_info (optional)
 *
 * Format sent by server:
 *   [0]:     literal 0 (4 bytes)
 *   [4]:     key_method (1 byte, value = 2)
 *   [5-36]:  random1 (32 bytes)
 *   [37-68]: random2 (32 bytes)
 *   [...]:   options string (null-terminated)
 */
int
ovpn_key_method_2_write (u8 *buf, u32 buf_len, ovpn_key_source2_t *ks2,
			 const u8 *local_sid, int is_server, const char *options)
{
  u32 offset = 0;
  ovpn_key_source_t *local_ks;
  int rv;

  if (!buf || !ks2)
    return -1;

  /* Select local key source based on role */
  local_ks = is_server ? &ks2->server : &ks2->client;

  /* Generate our random material */
  rv = ovpn_key_source_randomize (local_ks, !is_server /* client sends pre_master */);
  if (rv < 0)
    return -2;

  /* Check minimum buffer size */
  u32 min_size = 4 + 1 + OVPN_RANDOM_SIZE * 2;
  if (!is_server)
    min_size += OVPN_PRE_MASTER_SIZE;
  if (buf_len < min_size)
    return -3;

  /* Write 4-byte zero (reserved for future use) */
  clib_memset (buf + offset, 0, 4);
  offset += 4;

  /* Write key method */
  buf[offset++] = OVPN_KEY_METHOD_2;

  /* Client sends pre_master, server does not */
  if (!is_server)
    {
      clib_memcpy_fast (buf + offset, local_ks->pre_master,
			OVPN_PRE_MASTER_SIZE);
      offset += OVPN_PRE_MASTER_SIZE;
    }

  /* Write random1 */
  clib_memcpy_fast (buf + offset, local_ks->random1, OVPN_RANDOM_SIZE);
  offset += OVPN_RANDOM_SIZE;

  /* Write random2 */
  clib_memcpy_fast (buf + offset, local_ks->random2, OVPN_RANDOM_SIZE);
  offset += OVPN_RANDOM_SIZE;

  /*
   * Write options string
   * Format: 2-byte length (network order) followed by string (null-terminated)
   * The length includes the null terminator
   */
  if (options && buf_len > offset + 2)
    {
      u32 opt_len = strlen (options) + 1; /* Include null terminator */
      if (offset + 2 + opt_len <= buf_len)
	{
	  /* Write 2-byte length in network order */
	  *(u16 *) (buf + offset) = clib_host_to_net_u16 ((u16) opt_len);
	  offset += 2;
	  /* Write string including null terminator */
	  clib_memcpy_fast (buf + offset, options, opt_len);
	  offset += opt_len;
	}
    }
  else if (buf_len > offset + 2)
    {
      /* Empty options string - length = 0 */
      *(u16 *) (buf + offset) = 0;
      offset += 2;
    }

  /*
   * Write empty username field (server doesn't send username)
   * Format: 2-byte length (0)
   */
  if (buf_len > offset + 2)
    {
      *(u16 *) (buf + offset) = 0;
      offset += 2;
    }

  /*
   * Write empty password field (server doesn't send password)
   * Format: 2-byte length (0)
   */
  if (buf_len > offset + 2)
    {
      *(u16 *) (buf + offset) = 0;
      offset += 2;
    }

  return offset;
}

/*
 * Read Key Method 2 data from buffer
 *
 * Format from client:
 *   [0-3]:   literal 0 (reserved)
 *   [4]:     key_method (1 byte, value = 2)
 *   [5-52]:  pre_master (48 bytes) - client only
 *   [53-84]: random1 (32 bytes)
 *   [85-116]: random2 (32 bytes)
 *   [117-118]: options_string_len (2 bytes, network order)
 *   [...]:   options_string (null-terminated)
 *   [...]:   username_len (2 bytes) + username
 *   [...]:   password_len (2 bytes) + password
 *   [...]:   peer_info (optional)
 */
int
ovpn_key_method_2_read (const u8 *buf, u32 buf_len, ovpn_key_source2_t *ks2,
			int is_server, char **options_out)
{
  u32 offset = 0;
  ovpn_key_source_t *remote_ks;

  if (!buf || !ks2)
    return -1;

  if (options_out)
    *options_out = NULL;

  /* Select remote key source based on role */
  /* If we are server, we read client data; if client, we read server data */
  remote_ks = is_server ? &ks2->client : &ks2->server;

  /* Check minimum size */
  u32 min_size = 4 + 1 + OVPN_RANDOM_SIZE * 2;
  if (is_server)
    min_size += OVPN_PRE_MASTER_SIZE; /* Client sends pre_master */
  if (buf_len < min_size)
    return -2;

  /* Skip 4-byte zero */
  offset += 4;

  /* Read and verify key method */
  if (buf[offset++] != OVPN_KEY_METHOD_2)
    return -3; /* Unsupported key method */

  /* Client sends pre_master, server does not */
  if (is_server)
    {
      /* We are server, reading client data - client sends pre_master */
      clib_memcpy_fast (remote_ks->pre_master, buf + offset,
			OVPN_PRE_MASTER_SIZE);
      offset += OVPN_PRE_MASTER_SIZE;
    }

  /* Read random1 */
  clib_memcpy_fast (remote_ks->random1, buf + offset, OVPN_RANDOM_SIZE);
  offset += OVPN_RANDOM_SIZE;

  /* Read random2 */
  clib_memcpy_fast (remote_ks->random2, buf + offset, OVPN_RANDOM_SIZE);
  offset += OVPN_RANDOM_SIZE;

  /*
   * Parse options string
   * Format: 2-byte length (network order) followed by null-terminated string
   */
  if (options_out && offset + 2 <= buf_len)
    {
      u16 opt_len = clib_net_to_host_u16 (*(u16 *) (buf + offset));
      offset += 2;

      if (opt_len > 0 && offset + opt_len <= buf_len)
	{
	  /* Allocate and copy options string */
	  char *opts = clib_mem_alloc (opt_len + 1);
	  if (opts)
	    {
	      clib_memcpy_fast (opts, buf + offset, opt_len);
	      opts[opt_len] = '\0';
	      *options_out = opts;
	    }
	  offset += opt_len;
	}
    }

  return offset;
}

/*
 * Read Key Method 2 data with username/password
 */
int
ovpn_key_method_2_read_with_auth (const u8 *buf, u32 buf_len,
				  ovpn_key_source2_t *ks2, int is_server,
				  char **options_out, char **username_out,
				  char **password_out)
{
  u32 offset = 0;
  ovpn_key_source_t *remote_ks;

  if (username_out)
    *username_out = NULL;
  if (password_out)
    *password_out = NULL;

  if (!buf || !ks2)
    return -1;

  if (options_out)
    *options_out = NULL;

  /* Select remote key source based on role */
  remote_ks = is_server ? &ks2->client : &ks2->server;

  /* Check minimum size */
  u32 min_size = 4 + 1 + OVPN_RANDOM_SIZE * 2;
  if (is_server)
    min_size += OVPN_PRE_MASTER_SIZE;
  if (buf_len < min_size)
    return -2;

  /* Skip 4-byte zero */
  offset += 4;

  /* Read and verify key method */
  if (buf[offset++] != OVPN_KEY_METHOD_2)
    return -3;

  /* Client sends pre_master, server does not */
  if (is_server)
    {
      clib_memcpy_fast (remote_ks->pre_master, buf + offset,
			OVPN_PRE_MASTER_SIZE);
      offset += OVPN_PRE_MASTER_SIZE;
    }

  /* Read random1 */
  clib_memcpy_fast (remote_ks->random1, buf + offset, OVPN_RANDOM_SIZE);
  offset += OVPN_RANDOM_SIZE;

  /* Read random2 */
  clib_memcpy_fast (remote_ks->random2, buf + offset, OVPN_RANDOM_SIZE);
  offset += OVPN_RANDOM_SIZE;

  /* Parse options string */
  if (offset + 2 <= buf_len)
    {
      u16 opt_len = clib_net_to_host_u16 (*(u16 *) (buf + offset));
      offset += 2;

      if (opt_len > 0 && offset + opt_len <= buf_len)
	{
	  if (options_out)
	    {
	      char *opts = clib_mem_alloc (opt_len + 1);
	      if (opts)
		{
		  clib_memcpy_fast (opts, buf + offset, opt_len);
		  opts[opt_len] = '\0';
		  *options_out = opts;
		}
	    }
	  offset += opt_len;
	}
    }

  /* Parse username (only if client sends it via auth-user-pass) */
  if (offset + 2 <= buf_len)
    {
      u16 user_len = clib_net_to_host_u16 (*(u16 *) (buf + offset));
      offset += 2;

      if (user_len > 0 && offset + user_len <= buf_len)
	{
	  if (username_out)
	    {
	      char *user = clib_mem_alloc (user_len + 1);
	      if (user)
		{
		  clib_memcpy_fast (user, buf + offset, user_len);
		  user[user_len] = '\0';
		  *username_out = user;
		}
	    }
	  offset += user_len;
	}
    }

  /* Parse password */
  if (offset + 2 <= buf_len)
    {
      u16 pass_len = clib_net_to_host_u16 (*(u16 *) (buf + offset));
      offset += 2;

      if (pass_len > 0 && offset + pass_len <= buf_len)
	{
	  if (password_out)
	    {
	      char *pass = clib_mem_alloc (pass_len + 1);
	      if (pass)
		{
		  clib_memcpy_fast (pass, buf + offset, pass_len);
		  pass[pass_len] = '\0';
		  *password_out = pass;
		}
	    }
	  offset += pass_len;
	}
    }

  return offset;
}

/*
 * Verify username/password against password file
 * File format: username:password (one per line)
 */
int
ovpn_verify_user_pass (const char *password_file, const char *username,
		       const char *password)
{
  FILE *f;
  char line[512];
  int found = 0;

  if (!password_file || !username || !password)
    return -1;

  f = fopen (password_file, "r");
  if (!f)
    return -2;

  while (fgets (line, sizeof (line), f))
    {
      char *p = line;
      char *file_user, *file_pass;

      /* Skip leading whitespace */
      while (*p == ' ' || *p == '\t')
	p++;

      /* Skip comments and empty lines */
      if (*p == '#' || *p == '\0' || *p == '\n')
	continue;

      /* Parse username:password */
      file_user = p;
      file_pass = strchr (p, ':');
      if (!file_pass)
	continue;

      *file_pass++ = '\0';

      /* Remove trailing newline from password */
      char *end = file_pass;
      while (*end && *end != '\n' && *end != '\r')
	end++;
      *end = '\0';

      /* Compare */
      if (strcmp (file_user, username) == 0 &&
	  strcmp (file_pass, password) == 0)
	{
	  found = 1;
	  break;
	}
    }

  fclose (f);

  return found ? 0 : -3;
}

/*
 * Derive data channel keys using Key Method 2 (v2 interface)
 *
 * Supports both:
 * 1. OpenVPN PRF-based derivation (traditional)
 * 2. TLS 1.3 Exporter with RFC 5705 (when use_tls_ekm is true)
 */
int
ovpn_derive_data_channel_keys_v2 (ptls_t *tls,
				  const ovpn_key_source2_t *key_src2,
				  const u8 *client_sid, const u8 *server_sid,
				  ovpn_key_material_t *keys,
				  ovpn_cipher_alg_t cipher_alg, int is_server,
				  int use_tls_ekm, int client_keydir)
{
  u8 key_len;
  int ret;

  /* Determine key length based on cipher */
  key_len = ovpn_crypto_key_size (cipher_alg);
  if (key_len == 0)
    return -1;

  clib_memset (keys, 0, sizeof (*keys));
  keys->key_len = key_len;

  if (use_tls_ekm)
    {
      /*
       * TLS 1.3 Exporter Method (RFC 5705)
       * Uses label "EXPORTER-OpenVPN-datakeys" for all key material
       */
      static const char *label = "EXPORTER-OpenVPN-datakeys";
      u8 exported_keys[256];

      if (!tls)
	return -2;

      /*
       * Export key material with empty context
       * OpenVPN 2.6 TLS-EKM uses empty context for key derivation
       * The last parameter is_early=0 for post-handshake exporter secret
       */
      ret = ptls_export_secret (tls, exported_keys, sizeof (exported_keys),
				label, ptls_iovec_init (NULL, 0), 0);
      if (ret != 0)
	return -3;

      /*
       * Key material layout (same as PRF method):
       * [0-63]:   keys[0].cipher - client-to-server cipher key
       * [64-127]: keys[0].hmac   - client-to-server hmac key
       * [128-191]: keys[1].cipher - server-to-client cipher key
       * [192-255]: keys[1].hmac   - server-to-client hmac key
       */
      if (is_server)
	{
	  /* Server: encrypt with keys[1] (s2c), decrypt with keys[0] (c2s) */
	  clib_memcpy_fast (keys->encrypt_key, exported_keys + 128, key_len);
	  clib_memcpy_fast (keys->decrypt_key, exported_keys, key_len);
	  /* Implicit IVs from the hmac portions */
	  clib_memcpy_fast (keys->encrypt_implicit_iv, exported_keys + 192,
			    OVPN_IMPLICIT_IV_LEN);
	  clib_memcpy_fast (keys->decrypt_implicit_iv, exported_keys + 64,
			    OVPN_IMPLICIT_IV_LEN);
	}
      else
	{
	  /* Client: encrypt with keys[0] (c2s), decrypt with keys[1] (s2c) */
	  clib_memcpy_fast (keys->encrypt_key, exported_keys, key_len);
	  clib_memcpy_fast (keys->decrypt_key, exported_keys + 128, key_len);
	  clib_memcpy_fast (keys->encrypt_implicit_iv, exported_keys + 64,
			    OVPN_IMPLICIT_IV_LEN);
	  clib_memcpy_fast (keys->decrypt_implicit_iv, exported_keys + 192,
			    OVPN_IMPLICIT_IV_LEN);
	}

      ovpn_secure_zero_memory (exported_keys, sizeof (exported_keys));
    }
  else
    {
      /*
       * OpenVPN PRF Method (traditional Key Method 2)
       */
      ovpn_key2_t key2;

      if (!key_src2)
	return -4;

      /* Generate key expansion */
      ret = ovpn_generate_key_expansion_prf (key_src2, client_sid, server_sid,
					     is_server, &key2);
      if (ret < 0)
	return -5;

      /*
       * Key assignment based on key direction:
       *
       * OpenVPN key direction (keydir option):
       * - keydir 0 (NORMAL): encrypt keys[0], decrypt keys[1]
       * - keydir 1 (INVERSE): encrypt keys[1], decrypt keys[0]
       *
       * In client/server mode:
       * - Client uses keydir 0 (NORMAL) for data channel
       * - Server uses keydir 1 (INVERSE) for data channel
       *
       * This ensures bidirectional communication works:
       * - Client encrypts with key2[0] → Server decrypts with key2[0]
       * - Server encrypts with key2[1] → Client decrypts with key2[1]
       *
       * Note: The "keydir" in client's options string refers to tls-auth
       * direction, not data channel direction. For data channel, the
       * server always uses INVERSE direction.
       */
      int our_keydir;
      if (is_server)
	{
	  /* Server always uses INVERSE direction for data channel */
	  our_keydir = 1;
	}
      else
	{
	  /* Client uses its own keydir (typically NORMAL) */
	  our_keydir = client_keydir;
	}

      int encrypt_idx = (our_keydir == 0) ? 0 : 1;
      int decrypt_idx = (our_keydir == 0) ? 1 : 0;

      clib_memcpy_fast (keys->encrypt_key, key2.keys[encrypt_idx].cipher,
			key_len);
      clib_memcpy_fast (keys->decrypt_key, key2.keys[decrypt_idx].cipher,
			key_len);
      /* Use hmac portion for implicit IV */
      clib_memcpy_fast (keys->encrypt_implicit_iv, key2.keys[encrypt_idx].hmac,
			OVPN_IMPLICIT_IV_LEN);
      clib_memcpy_fast (keys->decrypt_implicit_iv, key2.keys[decrypt_idx].hmac,
			OVPN_IMPLICIT_IV_LEN);

      /* Securely clear key2 */
      ovpn_secure_zero_memory (&key2, sizeof (key2));
    }

  return 0;
}

/*
 * Legacy interface - uses TLS-EKM by default
 * This maintains backward compatibility with existing code
 */
int
ovpn_derive_data_channel_keys (ptls_t *tls, ovpn_key_material_t *keys,
			       ovpn_cipher_alg_t cipher_alg, int is_server)
{
  /* For TLS-EKM mode, client_keydir is not used, pass default value */
  return ovpn_derive_data_channel_keys_v2 (tls, NULL, NULL, NULL, keys,
					   cipher_alg, is_server,
					   1 /* use_tls_ekm */,
					   1 /* client_keydir (unused for TLS-EKM) */);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */