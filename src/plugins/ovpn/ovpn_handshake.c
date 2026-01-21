/*
 * ovpn_handshake.c - OpenVPN control channel handshake
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
#include <ovpn/ovpn_handshake.h>
#include <ovpn/ovpn_peer.h>
#include <ovpn/ovpn_packet.h>
#include <ovpn/ovpn_ssl.h>
#include <ovpn/ovpn_options.h>
#include <ovpn/ovpn_crypto.h>
#include <ovpn/ovpn_if.h>
#include <ovpn/ovpn_mgmt.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip4_forward.h>
#include <vnet/ip/ip6_forward.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/adj/adj_nbr.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_source.h>
#include <arpa/inet.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/bio.h>
#include <vppinfra/time.h>
#include <openssl/core_names.h>

/* Default timeout for pending connections (60 seconds) */
#define OVPN_PENDING_TIMEOUT 60.0

/* Maximum pending connections */
#define OVPN_MAX_PENDING 1024

/* Control packet buffer size */
#define OVPN_CONTROL_BUF_SIZE 2048

/* Forward declarations */
static int ovpn_handshake_send_pending_packets (
  vlib_main_t *vm, ovpn_pending_connection_t *pending,
  const ip_address_t *local_addr, u16 local_port, u8 is_ip6,
  ovpn_tls_auth_t *auth, ovpn_tls_crypt_t *tls_crypt);

static int ovpn_handshake_send_peer_packets (vlib_main_t *vm,
					     ovpn_peer_t *peer,
					     const ip_address_t *local_addr,
					     u16 local_port, u8 is_ip6,
					     ovpn_tls_auth_t *auth,
					     ovpn_tls_crypt_t *tls_crypt);

static int ovpn_handshake_send_peer_packets_ex (
  vlib_main_t *vm, ovpn_peer_t *peer, const ip_address_t *local_addr,
  u16 local_port, u8 is_ip6, ovpn_tls_auth_t *auth,
  ovpn_tls_crypt_t *tls_crypt, u8 force_send);

/*
 * Initialize pending connection database
 */
void
ovpn_pending_db_init (ovpn_pending_db_t *db)
{
  clib_memset (db, 0, sizeof (*db));
  db->pending_by_remote = hash_create (0, sizeof (uword));
  db->timeout = OVPN_PENDING_TIMEOUT;
}

/*
 * Free pending connection database
 */
void
ovpn_pending_db_free (ovpn_pending_db_t *db)
{
  ovpn_pending_connection_t *pending;

  pool_foreach (pending, db->connections)
    {
      if (pending->send_reliable)
	{
	  ovpn_reliable_free (pending->send_reliable);
	  clib_mem_free (pending->send_reliable);
	}
    }

  pool_free (db->connections);
  hash_free (db->pending_by_remote);
  clib_memset (db, 0, sizeof (*db));
}

/*
 * Create a new pending connection
 */
ovpn_pending_connection_t *
ovpn_pending_connection_create (ovpn_pending_db_t *db,
				const ip_address_t *remote_addr,
				u16 remote_port,
				const ovpn_session_id_t *remote_session_id,
				u8 key_id)
{
  ovpn_pending_connection_t *pending;
  u64 remote_key;
  f64 now = vlib_time_now (vlib_get_main ());

  /* Check if already exists */
  pending = ovpn_pending_connection_lookup (db, remote_addr, remote_port);
  if (pending)
    {
      /* Update existing pending connection */
      pending->last_activity = now;
      ovpn_session_id_copy (&pending->remote_session_id, remote_session_id);
      pending->key_id = key_id;
      pending->state = OVPN_PENDING_STATE_INITIAL;
      return pending;
    }

  /* Check limit */
  if (pool_elts (db->connections) >= OVPN_MAX_PENDING)
    return NULL;

  /* Allocate new pending connection */
  pool_get_zero (db->connections, pending);

  pending->state = OVPN_PENDING_STATE_INITIAL;
  ip_address_copy (&pending->remote_addr, remote_addr);
  pending->remote_port = remote_port;
  ovpn_session_id_copy (&pending->remote_session_id, remote_session_id);
  pending->key_id = key_id;

  /* Generate our session ID */
  ovpn_session_id_generate (&pending->local_session_id);

  /* Initialize packet IDs */
  pending->packet_id_send = 0;
  pending->packet_id_recv = 0;

  /* Initialize ACK structures */
  pending->recv_ack.len = 0;
  pending->sent_ack.len = 0;

  /* Set timestamps */
  pending->created_time = now;
  pending->last_activity = now;
  pending->timeout = now + db->timeout;

  /* Initialize reliable send structure */
  pending->send_reliable = clib_mem_alloc (sizeof (ovpn_reliable_t));
  ovpn_reliable_init (pending->send_reliable, OVPN_CONTROL_BUF_SIZE,
		      128 /* header offset */, 4 /* array_size */,
		      0 /* hold */);
  ovpn_reliable_set_timeout (pending->send_reliable, 2.0);

  /* Add to hash */
  remote_key = ovpn_pending_remote_hash_key (remote_addr, remote_port);
  hash_set (db->pending_by_remote, remote_key, pending - db->connections);

  return pending;
}

/*
 * Find pending connection by remote address
 */
ovpn_pending_connection_t *
ovpn_pending_connection_lookup (ovpn_pending_db_t *db,
				const ip_address_t *remote_addr,
				u16 remote_port)
{
  uword *p;
  u64 key;

  key = ovpn_pending_remote_hash_key (remote_addr, remote_port);
  p = hash_get (db->pending_by_remote, key);
  if (!p)
    return NULL;

  return pool_elt_at_index (db->connections, p[0]);
}

/*
 * Delete pending connection
 */
void
ovpn_pending_connection_delete (ovpn_pending_db_t *db,
				ovpn_pending_connection_t *pending)
{
  u64 remote_key;

  if (!pending)
    return;

  /* Remove from hash */
  remote_key =
    ovpn_pending_remote_hash_key (&pending->remote_addr, pending->remote_port);
  hash_unset (db->pending_by_remote, remote_key);

  /* Free reliable structure */
  if (pending->send_reliable)
    {
      ovpn_reliable_free (pending->send_reliable);
      clib_mem_free (pending->send_reliable);
      pending->send_reliable = NULL;
    }

  /* Free per-client TLS-Crypt context (TLS-Crypt-V2) */
  if (pending->client_tls_crypt)
    {
      clib_mem_free (pending->client_tls_crypt);
      pending->client_tls_crypt = NULL;
    }

  /* Return to pool */
  pool_put (db->connections, pending);
}

/*
 * Delete expired pending connections
 */
void
ovpn_pending_db_expire (ovpn_pending_db_t *db, f64 now)
{
  ovpn_pending_connection_t *pending;
  u32 *indices_to_delete = NULL;

  pool_foreach (pending, db->connections)
    {
      if (now > pending->timeout)
	{
	  vec_add1 (indices_to_delete, pending - db->connections);
	}
    }

  for (int i = 0; i < vec_len (indices_to_delete); i++)
    {
      pending = pool_elt_at_index (db->connections, indices_to_delete[i]);
      ovpn_pending_connection_delete (db, pending);
    }

  vec_free (indices_to_delete);
}

/*
 * Build control packet header
 * Format: opcode | session_id | ack_array | packet_id | payload
 */
static int
ovpn_build_control_header (ovpn_reli_buffer_t *buf, u8 opcode, u8 key_id,
			   const ovpn_session_id_t *session_id,
			   ovpn_reliable_ack_t *ack,
			   const ovpn_session_id_t *ack_session_id)
{
  u8 op_byte;

  /* Write opcode + key_id */
  op_byte = ovpn_op_compose (opcode, key_id);
  if (!ovpn_buf_write_u8 (buf, op_byte))
    return -1;

  /* Write our session ID */
  if (!ovpn_session_id_write (session_id, buf))
    return -1;

  /* Write ACK array */
  if (ack && ack->len > 0)
    {
      /* Write ACK count */
      if (!ovpn_buf_write_u8 (buf, ack->len))
	return -1;

      /* Write packet IDs */
      for (int i = 0; i < ack->len; i++)
	{
	  u32 net_pid = clib_host_to_net_u32 (ack->packet_id[i]);
	  if (!ovpn_buf_write (buf, &net_pid, sizeof (net_pid)))
	    return -1;
	}

      /* Write remote session ID for ACK */
      if (!ovpn_session_id_write (ack_session_id, buf))
	return -1;
    }
  else
    {
      /* No ACKs */
      if (!ovpn_buf_write_u8 (buf, 0))
	return -1;
    }

  return 0;
}

/*
 * Build and send P_CONTROL_HARD_RESET_SERVER_V2 response
 */
int
ovpn_handshake_send_server_reset (vlib_main_t *vm,
				  ovpn_pending_connection_t *pending,
				  vlib_buffer_t *response_buf)
{
  ovpn_reli_buffer_t *buf;
  u8 opcode = OVPN_OP_CONTROL_HARD_RESET_SERVER_V2;

  /* Get a buffer from reliable layer */
  buf = ovpn_reliable_get_buf_output_sequenced (pending->send_reliable);
  if (!buf)
    return -1;

  /* Build control header with ACK for client's HARD_RESET */
  if (ovpn_build_control_header (
	buf, opcode, pending->key_id, &pending->local_session_id,
	&pending->recv_ack, &pending->remote_session_id) < 0)
    return -1;

  /* Mark as active for retransmission */
  ovpn_reliable_mark_active_outgoing (pending->send_reliable, buf, opcode);

  /* Clear the ACKs we just sent */
  pending->recv_ack.len = 0;

  /* Update state */
  pending->state = OVPN_PENDING_STATE_SENT_RESET;

  return 0;
}

/*
 * Parse control packet header
 */
static int
ovpn_parse_control_header (ovpn_reli_buffer_t *buf, u8 *opcode, u8 *key_id,
			   ovpn_session_id_t *session_id,
			   ovpn_reliable_ack_t *ack,
			   ovpn_session_id_t *ack_session_id, u32 *packet_id)
{
  u8 op_byte;
  int n;

  /* Read opcode + key_id */
  n = ovpn_buf_read_u8 (buf);
  if (n < 0)
    return -1;
  op_byte = (u8) n;

  *opcode = ovpn_op_get_opcode (op_byte);
  *key_id = ovpn_op_get_key_id (op_byte);

  /* Read session ID */
  if (!ovpn_session_id_read (session_id, buf))
    return -1;

  /* Parse ACK array */
  if (!ovpn_reliable_ack_parse (buf, ack, ack_session_id))
    return -1;

  /* For non-ACK packets, read packet ID */
  if (*opcode != OVPN_OP_ACK_V1)
    {
      if (!ovpn_reliable_ack_read_packet_id (buf, packet_id))
	return -1;
    }

  return 0;
}

/*
 * Helper function to compute HMAC-SHA256 using EVP_MAC API (OpenSSL 3.0+)
 */
static int
ovpn_hmac_sha256 (const u8 *key, u32 key_len, const u8 *data, u32 data_len,
		  u8 *out, size_t *out_len)
{
  EVP_MAC *mac = NULL;
  EVP_MAC_CTX *ctx = NULL;
  OSSL_PARAM params[2];
  int ok = 0;

  mac = EVP_MAC_fetch (NULL, "HMAC", NULL);
  if (!mac)
    return 0;

  ctx = EVP_MAC_CTX_new (mac);
  if (!ctx)
    {
      EVP_MAC_free (mac);
      return 0;
    }

  params[0] = OSSL_PARAM_construct_utf8_string (OSSL_MAC_PARAM_DIGEST,
						(char *) "SHA256", 0);
  params[1] = OSSL_PARAM_construct_end ();

  if (!EVP_MAC_init (ctx, key, key_len, params))
    goto done;
  if (!EVP_MAC_update (ctx, data, data_len))
    goto done;
  if (!EVP_MAC_final (ctx, out, out_len, OVPN_HMAC_SIZE))
    goto done;

  ok = (*out_len == OVPN_HMAC_SIZE);

done:
  EVP_MAC_CTX_free (ctx);
  EVP_MAC_free (mac);
  return ok;
}

/*
 * TLS-Auth unwrap: verify HMAC and check replay protection
 *
 * Wire format (as passed to this function, after opcode is extracted):
 *   [session_id (8)] [HMAC (32)] [packet_id (4)] [net_time (4)] [ack_len...]
 *
 * HMAC covers (OpenVPN reorders for HMAC calculation):
 *   [packet_id (4)] [net_time (4)] [opcode (1)] [session_id (8)] [ack_len...]
 *
 * Note: The opcode must be passed separately since it's extracted before
 * calling this function. OpenVPN includes the opcode in HMAC calculation
 * even though it appears before the HMAC on the wire.
 *
 * Control channel uses long-form packet_id with both packet_id and net_time
 * for replay protection (time_backtrack validation).
 */
int
ovpn_tls_auth_unwrap (ovpn_tls_auth_t *ctx, const u8 *wrapped, u32 wrapped_len,
		      u8 *plaintext, u32 plaintext_buf_len)
{
  u8 computed_hmac[OVPN_HMAC_SIZE];
  u8 hmac_input[2048];
  size_t hmac_len = 0;
  u32 packet_id, net_time;
  u32 plain_len;
  u32 hmac_input_len;

  if (!ctx || !ctx->enabled || !wrapped || !plaintext)
    {
      return -1;
    }

    /*
     * OpenVPN TLS-Auth wire format:
     * Input:  [opcode(1)] [session_id(8)] [HMAC(32)] [packet_id(4)]
     * [net_time(4)] [ack_array] [msg_pkt_id(4)] [TLS_payload] Output:
     * [opcode(1)] [session_id(8)] [ack_array] [msg_pkt_id(4)] [TLS_payload]
     *
     * HMAC covers (reordered): [packet_id] [net_time] [opcode] [session_id]
     * [ack_array] [msg_pkt_id] [TLS_payload]
     */

    /*
     * Minimum size: opcode(1) + session_id(8) + HMAC(32) + packet_id(4) +
     * net_time(4) = 49 bytes
     */
#define OVPN_TLS_AUTH_MIN_SIZE                                                \
  (1 + OVPN_SESSION_ID_SIZE + OVPN_HMAC_SIZE + OVPN_TLS_AUTH_PACKET_ID_SIZE + \
   OVPN_TLS_AUTH_NET_TIME_SIZE)

  if (wrapped_len < OVPN_TLS_AUTH_MIN_SIZE)
    return -2;

  /* Plaintext = opcode + session_id + rest (everything except HMAC + packet_id
   * + net_time) */
  plain_len = wrapped_len - (OVPN_HMAC_SIZE + OVPN_TLS_AUTH_PACKET_ID_SIZE +
			     OVPN_TLS_AUTH_NET_TIME_SIZE);
  if (plaintext_buf_len < plain_len)
    return -2;

  /* Check buffer size for HMAC input */
  if (plain_len + 8 >
      sizeof (hmac_input)) /* packet_id(4) + net_time(4) + payload */
    return -2;

  /*
   * Parse packet structure:
   *   [opcode(1)] [session_id(8)] [HMAC(32)] [packet_id(4)] [net_time(4)]
   * [rest...]
   */
  u8 opcode = wrapped[0];
  const u8 *session_id = wrapped + 1;
  const u8 *hmac = session_id + OVPN_SESSION_ID_SIZE;
  const u8 *pkt_id_ptr = hmac + OVPN_HMAC_SIZE;
  const u8 *net_time_ptr = pkt_id_ptr + 4;
  const u8 *rest = net_time_ptr + 4;
  u32 rest_len = wrapped_len - OVPN_TLS_AUTH_MIN_SIZE;

  /* Extract packet_id and net_time for replay check */
  clib_memcpy_fast (&packet_id, pkt_id_ptr, 4);
  clib_memcpy_fast (&net_time, net_time_ptr, 4);
  packet_id = clib_net_to_host_u32 (packet_id);
  net_time = clib_net_to_host_u32 (net_time);

  /*
   * Note: Per-session replay protection should be handled after HMAC
   * verification succeeds and a session is established. The HMAC already
   * includes the session_id, so different clients have unique HMACs even
   * with the same packet_id.
   */

  /*
   * Build HMAC input: packet_id || net_time || opcode || session_id || rest
   *
   * OpenVPN reorders the packet for HMAC calculation:
   * - Wire format: opcode || session_id || HMAC || packet_id || net_time ||
   * rest
   * - HMAC covers: packet_id || net_time || opcode || session_id || rest
   */
  u8 *h = hmac_input;
  clib_memcpy_fast (h, pkt_id_ptr, 4); /* packet_id (network order) */
  h += 4;
  clib_memcpy_fast (h, net_time_ptr, 4); /* net_time (network order) */
  h += 4;
  *h++ = opcode; /* opcode byte */
  clib_memcpy_fast (h, session_id, OVPN_SESSION_ID_SIZE);
  h += OVPN_SESSION_ID_SIZE;
  clib_memcpy_fast (h, rest, rest_len);
  h += rest_len;
  hmac_input_len = h - hmac_input;

  if (!ovpn_hmac_sha256 (ctx->decrypt_key, OVPN_HMAC_SIZE, hmac_input,
			 hmac_input_len, computed_hmac, &hmac_len))
    {
      return -3;
    }

  /* Verify HMAC using constant-time comparison */
  if (CRYPTO_memcmp (hmac, computed_hmac, OVPN_HMAC_SIZE) != 0)
    {
      return -3; /* HMAC verification failed */
    }

  /* Update replay window AFTER successful verification */
  ovpn_tls_auth_update_replay (ctx, packet_id, net_time);

  /*
   * Copy plaintext: opcode || session_id || rest (ack_array, packet_id,
   * payload) This reconstructs the control packet without the TLS-Auth wrapper
   */
  plaintext[0] = opcode;
  clib_memcpy_fast (plaintext + 1, session_id, OVPN_SESSION_ID_SIZE);
  clib_memcpy_fast (plaintext + 1 + OVPN_SESSION_ID_SIZE, rest, rest_len);

  return plain_len;
}

/*
 * TLS-Auth wrap: add HMAC and packet_id/net_time for outgoing packets
 *
 * The opcode must be passed separately because OpenVPN includes the opcode
 * in HMAC calculation in a specific order:
 * - HMAC covers: packet_id || net_time || opcode || session_id...payload
 * - Wire output: HMAC || packet_id || net_time || session_id...payload
 *
 * Note: The opcode is NOT included in the wrapped output - the caller must
 * prepend it to the final packet.
 */
int
ovpn_tls_auth_wrap (ovpn_tls_auth_t *ctx, const u8 *plaintext, u32 plain_len,
		    u8 *wrapped, u32 wrapped_buf_len)
{
  u8 hmac_input[2048];
  u32 hmac_input_len;
  size_t hmac_len = 0;

  if (!ctx || !ctx->enabled || !plaintext || !wrapped)
    {
      return -1;
    }

  /*
   * OpenVPN TLS-Auth wire format:
   * Input:  [opcode(1)] [session_id(8)] [ack_array] [msg_pkt_id(4)]
   * [TLS_payload] Output: [opcode(1)] [session_id(8)] [HMAC(32)]
   * [packet_id(4)] [net_time(4)] [ack_array] [msg_pkt_id(4)] [TLS_payload]
   *
   * HMAC covers (reordered): [packet_id] [net_time] [opcode] [session_id]
   * [ack_array] [msg_pkt_id] [TLS_payload]
   */

  /* Input must have at least opcode + session_id */
  if (plain_len < 1 + OVPN_SESSION_ID_SIZE)
    return -2;

  u32 wrapped_len = plain_len + OVPN_TLS_AUTH_OVERHEAD;
  if (wrapped_buf_len < wrapped_len)
    return -2;

  /* Check buffer size for HMAC input */
  if (plain_len + 8 > sizeof (hmac_input))
    return -2;

  /* Extract opcode, session_id, and rest from plaintext */
  u8 opcode = plaintext[0];
  const u8 *session_id = plaintext + 1;
  const u8 *rest = plaintext + 1 + OVPN_SESSION_ID_SIZE;
  u32 rest_len = plain_len - 1 - OVPN_SESSION_ID_SIZE;

  /* Get next packet ID and timestamp */
  u32 packet_id = ctx->packet_id_send++;
  u32 net_time = (u32) unix_time_now ();
  u32 net_packet_id = clib_host_to_net_u32 (packet_id);
  u32 net_net_time = clib_host_to_net_u32 (net_time);

  /*
   * Build output: [opcode] [session_id] [HMAC] [packet_id] [net_time] [rest]
   */
  u8 *out = wrapped;

  /* Opcode (1 byte) */
  *out++ = opcode;

  /* Session ID (8 bytes) */
  clib_memcpy_fast (out, session_id, OVPN_SESSION_ID_SIZE);
  out += OVPN_SESSION_ID_SIZE;

  /* Skip HMAC for now, fill it after calculation */
  u8 *hmac_out = out;
  out += OVPN_HMAC_SIZE;

  /* Packet ID (4 bytes) */
  clib_memcpy_fast (out, &net_packet_id, 4);
  out += 4;

  /* Net time (4 bytes) */
  clib_memcpy_fast (out, &net_net_time, 4);
  out += 4;

  /* Rest of the packet (ack_array + msg_pkt_id + TLS_payload) */
  clib_memcpy_fast (out, rest, rest_len);

  /*
   * Build HMAC input: packet_id || net_time || opcode || session_id || rest
   */
  u8 *h = hmac_input;
  clib_memcpy_fast (h, &net_packet_id, 4);
  h += 4;
  clib_memcpy_fast (h, &net_net_time, 4);
  h += 4;
  *h++ = opcode;
  clib_memcpy_fast (h, session_id, OVPN_SESSION_ID_SIZE);
  h += OVPN_SESSION_ID_SIZE;
  clib_memcpy_fast (h, rest, rest_len);
  h += rest_len;
  hmac_input_len = h - hmac_input;

  if (!ovpn_hmac_sha256 (ctx->encrypt_key, OVPN_HMAC_SIZE, hmac_input,
			 hmac_input_len, hmac_out, &hmac_len))
    return -3;

  return wrapped_len;
}

/*
 * Legacy HMAC verification for tls-auth (simple, no replay protection)
 * @deprecated Use ovpn_tls_auth_unwrap instead
 */
int
ovpn_handshake_verify_hmac (const u8 *data, u32 len,
			    const ovpn_tls_auth_t *auth)
{
  if (!auth || !auth->enabled)
    return 1; /* No tls-auth configured, always valid */

  if (len < OVPN_HMAC_SIZE)
    return 0;

  u32 signed_len = len - OVPN_HMAC_SIZE;
  u8 digest[OVPN_HMAC_SIZE];
  size_t digest_len = 0;

  if (!ovpn_hmac_sha256 (auth->decrypt_key, OVPN_HMAC_SIZE, data, signed_len,
			 digest, &digest_len))
    return 0;

  if (digest_len < OVPN_HMAC_SIZE)
    return 0;

  /* Compare with trailing HMAC using constant-time comparison */
  return CRYPTO_memcmp (digest, data + signed_len, OVPN_HMAC_SIZE) == 0;
}

/*
 * Generate HMAC for outgoing control packet
 * @deprecated Use ovpn_tls_auth_wrap instead
 */
void
ovpn_handshake_generate_hmac (u8 *data, u32 len, u8 *hmac_out,
			      const ovpn_tls_auth_t *auth)
{
  if (!auth || !auth->enabled)
    return;

  size_t digest_len = 0;
  ovpn_hmac_sha256 (auth->encrypt_key, OVPN_HMAC_SIZE, data, len, hmac_out,
		    &digest_len);
}

/*
 * TLS-Crypt implementation
 *
 * TLS-Crypt uses a 2048-bit (256 byte) pre-shared key that contains:
 *   Bytes   0- 63: Direction 1 HMAC key (we use first 32 bytes for SHA256)
 *   Bytes  64-127: Direction 2 HMAC key
 *   Bytes 128-191: Direction 1 Cipher key (we use first 32 bytes for AES-256)
 *   Bytes 192-255: Direction 2 Cipher key
 *
 * Note: OpenVPN static key files contain 16 lines of 16 hex bytes each = 256
 * bytes
 */

/*
 * Parse a hex string into binary
 * Returns number of bytes parsed, or -1 on error
 */
static int
ovpn_parse_hex_line (const char *hex, u8 *out, int max_len)
{
  int i = 0;
  while (*hex && i < max_len)
    {
      /* Skip whitespace */
      while (*hex == ' ' || *hex == '\t' || *hex == '\r' || *hex == '\n')
	hex++;

      if (*hex == '\0' || *hex == '-')
	break;

      /* Parse two hex digits */
      u8 val = 0;
      for (int j = 0; j < 2; j++)
	{
	  char c = *hex++;
	  if (c >= '0' && c <= '9')
	    val = (val << 4) | (c - '0');
	  else if (c >= 'a' && c <= 'f')
	    val = (val << 4) | (c - 'a' + 10);
	  else if (c >= 'A' && c <= 'F')
	    val = (val << 4) | (c - 'A' + 10);
	  else if (c == '\0' || c == '\n' || c == '\r')
	    {
	      hex--; /* Back up, we're at end of line */
	      break;
	    }
	  else
	    return -1; /* Invalid hex character */
	}
      out[i++] = val;
    }
  return i;
}

/*
 * Parse TLS-Auth key from raw key data
 * Supports both PEM format (with -----BEGIN/END----- markers) and raw binary
 *
 * TLS-Auth uses the same static key file format as TLS-Crypt but only
 * uses the HMAC keys (first 128 bytes), not the cipher keys.
 *
 * Key layout (256 bytes total = 2048 bits):
 *   Bytes 0-63:   Direction 0 HMAC key (first 32 bytes used for SHA256)
 *   Bytes 64-127: Direction 1 HMAC key (first 32 bytes used for SHA256)
 *   Bytes 128-255: Cipher keys (not used for TLS-Auth)
 *
 * For server mode (is_server=1):
 *   - encrypt_key = direction 0 (server sends to client)
 *   - decrypt_key = direction 1 (client sends to server)
 *
 * For client mode (is_server=0):
 *   - encrypt_key = direction 1 (client sends to server)
 *   - decrypt_key = direction 0 (server sends to client)
 */
int
ovpn_tls_auth_parse_key (const u8 *key_data, u32 key_len, ovpn_tls_auth_t *ctx,
			 u8 is_server)
{
  u8 raw_key[OVPN_TLS_CRYPT_KEY_FILE_SIZE];
  u32 raw_key_len = 0;

  if (!key_data || !ctx || key_len == 0)
    return -1;

  clib_memset (ctx, 0, sizeof (*ctx));

  /* Check if this is a PEM-formatted key file */
  const char *begin_marker = "-----BEGIN OpenVPN Static key V1-----";
  const char *end_marker = "-----END OpenVPN Static key V1-----";

  const char *begin = strstr ((const char *) key_data, begin_marker);
  const char *end = strstr ((const char *) key_data, end_marker);

  if (begin && end && end > begin)
    {
      /* PEM format - parse hex lines between markers */
      const char *ptr = begin + strlen (begin_marker);

      while (ptr < end && raw_key_len < OVPN_TLS_CRYPT_KEY_FILE_SIZE)
	{
	  /* Skip to next line */
	  while (ptr < end && (*ptr == '\n' || *ptr == '\r'))
	    ptr++;

	  if (ptr >= end)
	    break;

	  /* Skip comment lines and empty lines */
	  if (*ptr == '#' || *ptr == '\n' || *ptr == '\r')
	    {
	      while (ptr < end && *ptr != '\n')
		ptr++;
	      continue;
	    }

	  /* Parse hex line (16 bytes per line typically) */
	  int parsed =
	    ovpn_parse_hex_line (ptr, raw_key + raw_key_len,
				 OVPN_TLS_CRYPT_KEY_FILE_SIZE - raw_key_len);
	  if (parsed > 0)
	    raw_key_len += parsed;

	  /* Move to next line */
	  while (ptr < end && *ptr != '\n')
	    ptr++;
	}
    }
  else if (key_len >= OVPN_TLS_CRYPT_KEY_FILE_SIZE)
    {
      /* Raw binary format */
      clib_memcpy_fast (raw_key, key_data, OVPN_TLS_CRYPT_KEY_FILE_SIZE);
      raw_key_len = OVPN_TLS_CRYPT_KEY_FILE_SIZE;
    }
  else
    {
      return -2; /* Invalid key format or too short */
    }

  if (raw_key_len < OVPN_TLS_CRYPT_KEY_FILE_SIZE)
    {
      return -3; /* Key too short */
    }

  /*
   * Extract HMAC keys based on direction:
   *   - Direction 0: bytes 0-31
   *   - Direction 1: bytes 64-95
   */
  if (is_server)
    {
      /* Server: encrypt with dir0, decrypt with dir1 */
      clib_memcpy_fast (ctx->encrypt_key, raw_key, OVPN_HMAC_SIZE);
      clib_memcpy_fast (ctx->decrypt_key, raw_key + 64, OVPN_HMAC_SIZE);
    }
  else
    {
      /* Client: encrypt with dir1, decrypt with dir0 */
      clib_memcpy_fast (ctx->encrypt_key, raw_key + 64, OVPN_HMAC_SIZE);
      clib_memcpy_fast (ctx->decrypt_key, raw_key, OVPN_HMAC_SIZE);
    }

  ctx->enabled = 1;
  ctx->packet_id_send = 1; /* Start from 1, 0 is invalid */

  /* Securely clear the raw key */
  clib_memset (raw_key, 0, sizeof (raw_key));

  return 0;
}

/*
 * Parse TLS-Crypt key from raw key data
 * Supports both PEM format (with -----BEGIN/END----- markers) and raw binary
 */
int
ovpn_tls_crypt_parse_key (const u8 *key_data, u32 key_len,
			  ovpn_tls_crypt_t *ctx, u8 is_server)
{
  u8 raw_key[OVPN_TLS_CRYPT_KEY_FILE_SIZE];
  u32 raw_key_len = 0;

  if (!key_data || !ctx || key_len == 0)
    return -1;

  clib_memset (ctx, 0, sizeof (*ctx));

  /* Check if this is a PEM-formatted key file */
  const char *begin_marker = "-----BEGIN OpenVPN Static key V1-----";
  const char *end_marker = "-----END OpenVPN Static key V1-----";

  const char *begin = strstr ((const char *) key_data, begin_marker);
  const char *end = strstr ((const char *) key_data, end_marker);

  if (begin && end && end > begin)
    {
      /* PEM format - parse hex lines between markers */
      const char *ptr = begin + strlen (begin_marker);

      while (ptr < end && raw_key_len < OVPN_TLS_CRYPT_KEY_FILE_SIZE)
	{
	  /* Skip to next line */
	  while (ptr < end && (*ptr == '\n' || *ptr == '\r'))
	    ptr++;

	  if (ptr >= end)
	    break;

	  /* Skip comment lines and empty lines */
	  if (*ptr == '#' || *ptr == '\n' || *ptr == '\r')
	    {
	      while (ptr < end && *ptr != '\n')
		ptr++;
	      continue;
	    }

	  /* Parse hex line (16 bytes per line typically) */
	  int parsed =
	    ovpn_parse_hex_line (ptr, raw_key + raw_key_len,
				 OVPN_TLS_CRYPT_KEY_FILE_SIZE - raw_key_len);
	  if (parsed > 0)
	    raw_key_len += parsed;

	  /* Move to next line */
	  while (ptr < end && *ptr != '\n')
	    ptr++;
	}
    }
  else if (key_len >= OVPN_TLS_CRYPT_KEY_FILE_SIZE)
    {
      /* Raw binary format */
      clib_memcpy_fast (raw_key, key_data, OVPN_TLS_CRYPT_KEY_FILE_SIZE);
      raw_key_len = OVPN_TLS_CRYPT_KEY_FILE_SIZE;
    }
  else
    {
      return -2; /* Invalid key format or too short */
    }

  if (raw_key_len < OVPN_TLS_CRYPT_KEY_FILE_SIZE)
    {
      return -3; /* Key too short */
    }

  /*
   * OpenVPN Static Key file layout (256 bytes total):
   * See: https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/crypto.h
   *
   * struct key {
   *   uint8_t cipher[64];  // only first 32 bytes used for AES-256
   *   uint8_t hmac[64];    // only first 32 bytes used for SHA-256
   * }; // 128 bytes per key
   *
   * struct key2 {
   *   struct key keys[2];  // 256 bytes total
   * };
   *
   * Layout:
   *   keys[0] (bytes 0-127):   cipher at 0-31, HMAC at 64-95
   *   keys[1] (bytes 128-255): cipher at 128-159, HMAC at 192-223
   *
   * Key direction for TLS-Crypt:
   *   TLS Server (KEY_DIRECTION_NORMAL): send keys[0], recv keys[1]
   *   TLS Client (KEY_DIRECTION_INVERSE): send keys[1], recv keys[0]
   */
  if (is_server)
    {
      /* Server mode: send with keys[0], receive with keys[1] */
      /* Encrypt (send): keys[0] - cipher at 0, HMAC at 64 */
      clib_memcpy_fast (ctx->encrypt_cipher_key, raw_key,
			OVPN_TLS_CRYPT_CIPHER_SIZE);
      clib_memcpy_fast (ctx->encrypt_hmac_key, raw_key + 64,
			OVPN_TLS_CRYPT_HMAC_KEY_SIZE);

      /* Decrypt (receive): keys[1] - cipher at 128, HMAC at 192 */
      clib_memcpy_fast (ctx->decrypt_cipher_key, raw_key + 128,
			OVPN_TLS_CRYPT_CIPHER_SIZE);
      clib_memcpy_fast (ctx->decrypt_hmac_key, raw_key + 192,
			OVPN_TLS_CRYPT_HMAC_KEY_SIZE);
    }
  else
    {
      /* Client mode: send with keys[1], receive with keys[0] */
      /* Encrypt (send): keys[1] - cipher at 128, HMAC at 192 */
      clib_memcpy_fast (ctx->encrypt_cipher_key, raw_key + 128,
			OVPN_TLS_CRYPT_CIPHER_SIZE);
      clib_memcpy_fast (ctx->encrypt_hmac_key, raw_key + 192,
			OVPN_TLS_CRYPT_HMAC_KEY_SIZE);

      /* Decrypt (receive): keys[0] - cipher at 0, HMAC at 64 */
      clib_memcpy_fast (ctx->decrypt_cipher_key, raw_key,
			OVPN_TLS_CRYPT_CIPHER_SIZE);
      clib_memcpy_fast (ctx->decrypt_hmac_key, raw_key + 64,
			OVPN_TLS_CRYPT_HMAC_KEY_SIZE);
    }

  ctx->enabled = 1;
  ctx->packet_id_send = 1; /* Start from 1, 0 is invalid */

  /* Securely clear the raw key */
  clib_memset (raw_key, 0, sizeof (raw_key));

  return 0;
}

/*
 * Compute HMAC-SHA256 for TLS-Crypt using EVP_MAC API (OpenSSL 3.0+)
 */
int
ovpn_tls_crypt_hmac (const u8 *key, const u8 *data, u32 len, u8 *out)
{
  EVP_MAC *mac = NULL;
  EVP_MAC_CTX *ctx = NULL;
  OSSL_PARAM params[2];
  size_t out_len = 0;
  int ok = 0;

  mac = EVP_MAC_fetch (NULL, "HMAC", NULL);
  if (!mac)
    return -1;

  ctx = EVP_MAC_CTX_new (mac);
  if (!ctx)
    {
      EVP_MAC_free (mac);
      return -1;
    }

  params[0] = OSSL_PARAM_construct_utf8_string (OSSL_MAC_PARAM_DIGEST,
						(char *) "SHA256", 0);
  params[1] = OSSL_PARAM_construct_end ();

  if (!EVP_MAC_init (ctx, key, OVPN_TLS_CRYPT_HMAC_KEY_SIZE, params))
    goto done;
  if (!EVP_MAC_update (ctx, data, len))
    goto done;
  if (!EVP_MAC_final (ctx, out, &out_len, OVPN_TLS_CRYPT_HMAC_SIZE))
    goto done;

  ok = (out_len == OVPN_TLS_CRYPT_HMAC_SIZE);

done:
  EVP_MAC_CTX_free (ctx);
  EVP_MAC_free (mac);
  return ok ? 0 : -1;
}

/*
 * AES-256-CTR encrypt/decrypt (same operation for CTR mode)
 */
static int
ovpn_tls_crypt_aes_ctr (const u8 *key, const u8 *iv, const u8 *in, u32 in_len,
			u8 *out)
{
  EVP_CIPHER_CTX *ctx = NULL;
  int out_len = 0;
  int final_len = 0;
  int ok = 0;

  ctx = EVP_CIPHER_CTX_new ();
  if (!ctx)
    return -1;

  if (!EVP_EncryptInit_ex (ctx, EVP_aes_256_ctr (), NULL, key, iv))
    goto done;

  if (!EVP_EncryptUpdate (ctx, out, &out_len, in, in_len))
    goto done;

  if (!EVP_EncryptFinal_ex (ctx, out + out_len, &final_len))
    goto done;

  ok = 1;

done:
  EVP_CIPHER_CTX_free (ctx);
  return ok ? (out_len + final_len) : -1;
}

/*
 * Wrap (authenticate + encrypt) a control channel packet using TLS-Crypt
 *
 * OpenVPN TLS-Crypt wrap process (from ssl_pkt.c and tls_crypt.c):
 *   1. Compute HMAC over: opcode || session_id || packet_id || net_time ||
 * plaintext
 *   2. Use first 16 bytes of HMAC as IV for encryption
 *   3. Encrypt plaintext using that IV
 *   4. Output: packet_id || net_time || HMAC || ciphertext
 *
 * The HMAC covers the full header (opcode + session_id + packet_id + net_time)
 * plus the plaintext. This matches OpenVPN's TLS_CRYPT_OFF_TAG offset.
 *
 * @param ctx           TLS-Crypt context
 * @param opcode_session Opcode byte (1) + session_id (8) = 9 bytes
 * @param plaintext     Plaintext to encrypt
 * @param plain_len     Length of plaintext
 * @param wrapped       Output buffer for wrapped data
 * @param wrapped_buf_len Size of output buffer
 */
int
ovpn_tls_crypt_wrap (const ovpn_tls_crypt_t *ctx, const u8 *opcode_session,
		     const u8 *plaintext, u32 plain_len, u8 *wrapped,
		     u32 wrapped_buf_len)
{
  u8 iv[OVPN_TLS_CRYPT_IV_SIZE];
  u8 hmac_input[2048 + 17]; /* opcode(1) + session_id(8) + packet_id(4) +
			       net_time(4) + plaintext */
  u32 hmac_input_len;
  u32 wrapped_len;
  u8 *encrypted;
  int rv;

  if (!ctx || !ctx->enabled || !opcode_session || !plaintext || !wrapped)
    return -1;

  /* Check buffer size */
  wrapped_len = OVPN_TLS_CRYPT_OVERHEAD + plain_len;
  if (wrapped_buf_len < wrapped_len)
    return -2;

  if (plain_len > sizeof (hmac_input) - 17)
    return -3; /* Plaintext too large */

  /* Get next packet ID */
  u32 packet_id = ctx->packet_id_send;
  /* Note: caller should increment packet_id_send after successful wrap */

  /* Get current time */
  u32 net_time = (u32) unix_time_now ();

  /* Position output pointer and set header fields */
  ovpn_tls_crypt_header_t *hdr = (ovpn_tls_crypt_header_t *) wrapped;
  hdr->packet_id = clib_host_to_net_u32 (packet_id);
  hdr->net_time = clib_host_to_net_u32 (net_time);

  /*
   * Step 1: Build HMAC input per OpenVPN TLS-Crypt specification:
   *   HMAC = HMAC-SHA256(Ka, opcode || session_id || packet_id || net_time ||
   *                          plaintext)
   *
   * This matches OpenVPN's TLS_CRYPT_OFF_TAG (17 bytes) + plaintext.
   * See: ssl_pkt.c tls_wrap_control() and tls_crypt.c tls_crypt_wrap()
   */
  clib_memcpy_fast (hmac_input, opcode_session, 9); /* opcode + session_id */
  clib_memcpy_fast (hmac_input + 9, &hdr->packet_id,
		    4); /* packet_id (network order) */
  clib_memcpy_fast (hmac_input + 13, &hdr->net_time,
		    4); /* net_time (network order) */
  clib_memcpy_fast (hmac_input + 17, plaintext, plain_len); /* plaintext */
  hmac_input_len = 17 + plain_len;

  /* Compute HMAC and write to header */
  rv = ovpn_tls_crypt_hmac (ctx->encrypt_hmac_key, hmac_input, hmac_input_len,
			    hdr->hmac);
  if (rv < 0)
    return -5;

  /*
   * Step 2: Extract IV from HMAC (first 16 bytes)
   * OpenVPN uses the first 128 bits of the HMAC tag as the encryption IV.
   */
  clib_memcpy_fast (iv, hdr->hmac, OVPN_TLS_CRYPT_IV_SIZE);

  /*
   * Step 3: Encrypt the plaintext using the IV derived from HMAC
   */
  encrypted = wrapped + OVPN_TLS_CRYPT_OVERHEAD;
  rv = ovpn_tls_crypt_aes_ctr (ctx->encrypt_cipher_key, iv, plaintext,
			       plain_len, encrypted);
  if (rv < 0)
    return -4;

  return wrapped_len;
}

/*
 * Unwrap (decrypt + verify) a control channel packet using TLS-Crypt
 *
 * This function includes replay protection checking and updates the
 * replay window on success.
 *
 * OpenVPN TLS-Crypt unwrap process (from ssl_pkt.c and tls_crypt.c):
 *   1. Extract IV from received HMAC (first 16 bytes)
 *   2. Decrypt ciphertext using that IV
 *   3. Compute HMAC over: opcode || session_id || packet_id || net_time ||
 *      plaintext
 *   4. Compare computed HMAC with received HMAC
 *
 * The HMAC covers the full header (opcode + session_id + packet_id + net_time)
 * plus the decrypted plaintext. This matches OpenVPN's TLS_CRYPT_OFF_TAG
 * offset.
 *
 * @param ctx           TLS-Crypt context
 * @param opcode_session Opcode byte (1) + session_id (8) = 9 bytes
 * @param wrapped       TLS-Crypt header + ciphertext (after opcode+session_id)
 * @param wrapped_len   Length of wrapped data
 * @param plaintext     Output buffer for decrypted plaintext
 * @param plaintext_buf_len Size of output buffer
 */
int
ovpn_tls_crypt_unwrap (ovpn_tls_crypt_t *ctx, const u8 *opcode_session,
		       const u8 *wrapped, u32 wrapped_len, u8 *plaintext,
		       u32 plaintext_buf_len)
{
  u8 iv[OVPN_TLS_CRYPT_IV_SIZE];
  u8 computed_hmac[OVPN_TLS_CRYPT_HMAC_SIZE];
  u8 hmac_input[2048 + 17]; /* opcode(1) + session_id(8) + packet_id(4) +
			       net_time(4) + plaintext */
  u32 hmac_input_len;
  u32 plain_len;
  u32 now;
  int rv;

  if (!ctx || !ctx->enabled || !opcode_session || !wrapped || !plaintext)
    return -1;

  /* Check minimum wrapped packet size */
  if (wrapped_len < OVPN_TLS_CRYPT_OVERHEAD)
    return -2;

  /*
   * Packet format: [packet_id (4)] [net_time (4)] [HMAC (32)] [ciphertext]
   */
  plain_len = wrapped_len - OVPN_TLS_CRYPT_OVERHEAD;
  if (plaintext_buf_len < plain_len)
    return -3;

  if (plain_len > sizeof (hmac_input) - 17)
    return -4; /* Packet too large */

  /* Parse header - extract both packet_id and net_time for replay check */
  const ovpn_tls_crypt_header_t *hdr =
    (const ovpn_tls_crypt_header_t *) wrapped;
  u32 packet_id = clib_net_to_host_u32 (hdr->packet_id);
  u32 net_time = clib_net_to_host_u32 (hdr->net_time);
  const u8 *encrypted = wrapped + OVPN_TLS_CRYPT_OVERHEAD;


  /* Sanity check packet_id */
  if (packet_id == 0)
    return -5; /* Invalid packet ID */

  /* Get current unix time for time-based replay protection */
  now = (u32) unix_time_now ();

  /*
   * Replay protection check (BEFORE decryption for efficiency)
   * Both packet_id and net_time are validated.
   */
  if (!ovpn_tls_crypt_check_replay (ctx, packet_id, net_time, now))
    return -9; /* Replay detected */

  /*
   * Step 1: Extract IV from received HMAC (first 16 bytes)
   * OpenVPN uses the first 128 bits of the HMAC tag as the encryption IV.
   */
  clib_memcpy_fast (iv, hdr->hmac, OVPN_TLS_CRYPT_IV_SIZE);


  /*
   * Step 2: Decrypt the ciphertext
   */
  rv = ovpn_tls_crypt_aes_ctr (ctx->decrypt_cipher_key, iv, encrypted,
			       plain_len, plaintext);
  if (rv < 0)
    return -8;


  /*
   * Step 3: Build HMAC input per OpenVPN TLS-Crypt specification:
   *   HMAC = HMAC-SHA256(Ka, opcode || session_id || packet_id || net_time ||
   *                          plaintext)
   *
   * This matches OpenVPN's TLS_CRYPT_OFF_TAG (17 bytes) + plaintext.
   * See: ssl_pkt.c read_control_auth() and tls_crypt.c tls_crypt_unwrap()
   */
  clib_memcpy_fast (hmac_input, opcode_session, 9); /* opcode + session_id */
  clib_memcpy_fast (hmac_input + 9, &hdr->packet_id,
		    4); /* packet_id (network order) */
  clib_memcpy_fast (hmac_input + 13, &hdr->net_time,
		    4); /* net_time (network order) */
  clib_memcpy_fast (hmac_input + 17, plaintext,
		    plain_len); /* decrypted plaintext */
  hmac_input_len = 17 + plain_len;

  /* Compute HMAC */
  rv = ovpn_tls_crypt_hmac (ctx->decrypt_hmac_key, hmac_input, hmac_input_len,
			    computed_hmac);
  if (rv < 0)
    return -6;

  /*
   * Step 4: Verify HMAC using constant-time comparison
   */
  if (CRYPTO_memcmp (hdr->hmac, computed_hmac, OVPN_TLS_CRYPT_HMAC_SIZE) != 0)
    {
      /* Clear plaintext on HMAC failure for security */
      clib_memset (plaintext, 0, plain_len);
      return -7; /* HMAC verification failed */
    }

  /*
   * Update replay window AFTER successful verification
   * This ensures we don't update the window for forged packets
   */
  ovpn_tls_crypt_update_replay (ctx, packet_id, net_time);

  return plain_len;
}

/*
 * ============================================================================
 * TLS-Crypt-V2 Implementation
 * ============================================================================
 */

/*
 * Parse TLS-Crypt-V2 server key from raw key data
 *
 * Supports two formats:
 * 1. TLS-Crypt-V2 server key (Base64, 128 bytes decoded):
 *    "-----BEGIN OpenVPN tls-crypt-v2 server key-----"
 *    Key 0: bytes 0-63   (used: first 32 bytes = Ke encryption key)
 *    Key 1: bytes 64-127 (used: first 32 bytes = Ka authentication key)
 *
 * 2. OpenVPN Static key V1 (hex, 256 bytes):
 *    "-----BEGIN OpenVPN Static key V1-----"
 *    Key 0: bytes 0-63   (used: first 32 bytes = Ke encryption key)
 *    Key 1: bytes 64-127 (used: first 32 bytes = Ka authentication key)
 *    Key 2-3: unused
 */
int
ovpn_tls_crypt_v2_parse_server_key (const u8 *key_data, u32 key_len,
				    ovpn_tls_crypt_v2_t *ctx)
{
  u8 raw_key[OVPN_TLS_CRYPT_KEY_FILE_SIZE];
  u32 raw_key_len = 0;

  if (!key_data || !ctx || key_len == 0)
    return -1;

  clib_memset (ctx, 0, sizeof (*ctx));

  /* Check for TLS-Crypt-V2 server key format (Base64 encoded, 128 bytes) */
  const char *v2_begin_marker =
    "-----BEGIN OpenVPN tls-crypt-v2 server key-----";
  const char *v2_end_marker = "-----END OpenVPN tls-crypt-v2 server key-----";

  const char *begin = strstr ((const char *) key_data, v2_begin_marker);
  const char *end = strstr ((const char *) key_data, v2_end_marker);

  if (begin && end && end > begin)
    {
      /* TLS-Crypt-V2 format - Base64 decode */
      const char *ptr = begin + strlen (v2_begin_marker);
      u8 b64_buf[256];
      u32 b64_len = 0;

      /* Collect Base64 data, skipping whitespace */
      while (ptr < end && b64_len < sizeof (b64_buf))
	{
	  if (*ptr != '\n' && *ptr != '\r' && *ptr != ' ')
	    b64_buf[b64_len++] = *ptr;
	  ptr++;
	}

      /* Base64 decode using OpenSSL */
      BIO *bio = BIO_new_mem_buf (b64_buf, b64_len);
      BIO *b64 = BIO_new (BIO_f_base64 ());
      BIO_set_flags (b64, BIO_FLAGS_BASE64_NO_NL);
      bio = BIO_push (b64, bio);

      int decoded_len = BIO_read (bio, raw_key, sizeof (raw_key));
      BIO_free_all (bio);

      if (decoded_len < 128)
	return -3;

      raw_key_len = decoded_len;
    }
  else
    {
      /* Check for OpenVPN Static key V1 format (hex encoded, 256 bytes) */
      const char *v1_begin_marker = "-----BEGIN OpenVPN Static key V1-----";
      const char *v1_end_marker = "-----END OpenVPN Static key V1-----";

      begin = strstr ((const char *) key_data, v1_begin_marker);
      end = strstr ((const char *) key_data, v1_end_marker);

      if (begin && end && end > begin)
	{
	  /* PEM format - parse hex lines between markers */
	  const char *ptr = begin + strlen (v1_begin_marker);

	  while (ptr < end && raw_key_len < OVPN_TLS_CRYPT_KEY_FILE_SIZE)
	    {
	      while (ptr < end && (*ptr == '\n' || *ptr == '\r'))
		ptr++;

	      if (ptr >= end)
		break;

	      if (*ptr == '#' || *ptr == '\n' || *ptr == '\r')
		{
		  while (ptr < end && *ptr != '\n')
		    ptr++;
		  continue;
		}

	      int parsed = ovpn_parse_hex_line (ptr, raw_key + raw_key_len,
						OVPN_TLS_CRYPT_KEY_FILE_SIZE -
						  raw_key_len);
	      if (parsed > 0)
		raw_key_len += parsed;

	      while (ptr < end && *ptr != '\n')
		ptr++;
	    }
	}
      else if (key_len >= OVPN_TLS_CRYPT_KEY_FILE_SIZE)
	{
	  clib_memcpy_fast (raw_key, key_data, OVPN_TLS_CRYPT_KEY_FILE_SIZE);
	  raw_key_len = OVPN_TLS_CRYPT_KEY_FILE_SIZE;
	}
      else
	{
	  return -2;
	}
    }

  /* Need at least 64 bytes for one key (32 cipher + 32 HMAC) */
  if (raw_key_len < 64)
    {
      return -3;
    }

  /*
   * Extract server keys from key[0] (the wrapping key):
   *
   * OpenVPN's struct key layout (128 bytes per key):
   *   cipher[64]: bytes 0-63  (only first 32 bytes = Ke used)
   *   hmac[64]:   bytes 64-127 (only first 32 bytes = Ka used)
   *
   * So for tls-crypt-v2 server key (128 bytes = one key struct):
   *   Ke (cipher key) = bytes 0-31
   *   Ka (HMAC key)   = bytes 64-95
   */
  clib_memcpy_fast (ctx->server_key.encrypt_key, raw_key, 32);
  clib_memcpy_fast (ctx->server_key.auth_key, raw_key + 64, 32);

  clib_memset (raw_key, 0, sizeof (raw_key));

  ctx->enabled = 1;
  return 0;
}

/*
 * Unwrap a client key (WKc) using the server key
 *
 * WKc format:
 *   [Tag (32 bytes)] [Encrypted(Kc || metadata)] [Length (2 bytes at end)]
 *
 * Algorithm (SIV construction):
 *   1. Read length from end (2 bytes, big-endian). The stored length is
 *      tag+ciphertext length and EXCLUDES the 2-byte length field itself.
 *   2. Verify length matches (stored_len + 2 == total WKc length)
 *   3. Extract tag (first 32 bytes)
 *   4. IV = first 16 bytes of tag
 *   5. Decrypt ciphertext with AES-256-CTR using Ke and IV
 *   6. Verify HMAC: Tag should equal HMAC-SHA256(Ka, net_len(2) || plaintext)
 *   7. Extract Kc (first 256 bytes) and metadata (rest)
 */
int
ovpn_tls_crypt_v2_unwrap_client_key (
  const ovpn_tls_crypt_v2_t *ctx, const u8 *wkc, u32 wkc_len,
  ovpn_tls_crypt_v2_client_key_t *client_key)
{
  u8 decrypted[OVPN_TLS_CRYPT_V2_MAX_WKC_LEN];
  u8 computed_tag[OVPN_TLS_CRYPT_V2_TAG_SIZE];
  u32 ciphertext_len;
  u32 plaintext_len;
  u16 stored_len;
  const u8 *tag;
  const u8 *ciphertext;
  EVP_CIPHER_CTX *cipher_ctx = NULL;
  int out_len = 0, final_len = 0;
  int rv = -1;

  if (!ctx || !ctx->enabled || !wkc || !client_key)
    return -1;

  clib_memset (client_key, 0, sizeof (*client_key));

  /* Check minimum length */
  if (wkc_len < OVPN_TLS_CRYPT_V2_MIN_WKC_LEN)
    return -2;

  /* Check maximum length */
  if (wkc_len > OVPN_TLS_CRYPT_V2_MAX_WKC_LEN)
    return -3;

  /* Read stored length from end (big-endian) */
  stored_len = (wkc[wkc_len - 2] << 8) | wkc[wkc_len - 1];

  /*
   * Verify length consistency
   * The stored length includes the 2-byte length field itself,
   * so stored_len should equal wkc_len.
   */
  if ((u32) stored_len != wkc_len)
    return -2;

  /* Extract tag (first 32 bytes) */
  tag = wkc;

  /* Ciphertext follows the tag, before the length field */
  ciphertext = wkc + OVPN_TLS_CRYPT_V2_TAG_SIZE;
  ciphertext_len = wkc_len - OVPN_TLS_CRYPT_V2_TAG_SIZE - 2;

  /* Check ciphertext has at least the client key */
  if (ciphertext_len < OVPN_TLS_CRYPT_V2_CLIENT_KEY_LEN)
    return -2;

  /*
   * Decrypt using AES-256-CTR
   * IV = first 16 bytes of tag
   */
  cipher_ctx = EVP_CIPHER_CTX_new ();
  if (!cipher_ctx)
    return -5;

  if (EVP_DecryptInit_ex (cipher_ctx, EVP_aes_256_ctr (), NULL,
			  ctx->server_key.encrypt_key, tag) != 1)
    {
      EVP_CIPHER_CTX_free (cipher_ctx);
      return -5;
    }

  if (EVP_DecryptUpdate (cipher_ctx, decrypted, &out_len, ciphertext,
			 ciphertext_len) != 1)
    {
      EVP_CIPHER_CTX_free (cipher_ctx);
      return -5;
    }

  /* For CTR mode, finalize doesn't add data but we call it anyway */
  if (EVP_DecryptFinal_ex (cipher_ctx, decrypted + out_len, &final_len) != 1)
    {
      EVP_CIPHER_CTX_free (cipher_ctx);
      return -5;
    }

  EVP_CIPHER_CTX_free (cipher_ctx);
  plaintext_len = out_len + final_len;

  /*
   * Verify authentication tag
   * Tag = HMAC-SHA256(Ka, plaintext)
   */

  /*
   * Compute HMAC for verification
   * OpenVPN's tls-crypt-v2 uses: HMAC(Ka, [net_len(2)] || [plaintext])
   * where net_len is the stored WKc length field value (big-endian),
   * i.e. tag+ciphertext length excluding the 2-byte length field.
   */
  {
    u8 hmac_input[2 + OVPN_TLS_CRYPT_V2_MAX_WKC_LEN];
    u32 hmac_input_len;

    /* Network byte order length prefix */
    hmac_input[0] = (stored_len >> 8) & 0xff;
    hmac_input[1] = stored_len & 0xff;

    /* Plaintext follows */
    clib_memcpy_fast (hmac_input + 2, decrypted, plaintext_len);
    hmac_input_len = 2 + plaintext_len;

    if (ovpn_tls_crypt_hmac (ctx->server_key.auth_key, hmac_input,
			     hmac_input_len, computed_tag) < 0)
      {
	clib_memset (decrypted, 0, sizeof (decrypted));
	return -4;
      }
  }


  /* Constant-time comparison of tags */
  if (CRYPTO_memcmp (tag, computed_tag, OVPN_TLS_CRYPT_V2_TAG_SIZE) != 0)
    {
      clib_memset (decrypted, 0, sizeof (decrypted));
      return -4;
    }

  /*
   * Extract client key (first 256 bytes) and metadata (rest)
   */
  clib_memcpy_fast (client_key->key, decrypted,
		    OVPN_TLS_CRYPT_V2_CLIENT_KEY_LEN);

  if (plaintext_len > OVPN_TLS_CRYPT_V2_CLIENT_KEY_LEN)
    {
      client_key->metadata_len =
	plaintext_len - OVPN_TLS_CRYPT_V2_CLIENT_KEY_LEN;
      client_key->metadata = clib_mem_alloc (client_key->metadata_len);
      if (client_key->metadata)
	{
	  clib_memcpy_fast (client_key->metadata,
			    decrypted + OVPN_TLS_CRYPT_V2_CLIENT_KEY_LEN,
			    client_key->metadata_len);
	}
    }

  clib_memset (decrypted, 0, sizeof (decrypted));
  rv = 0;

  return rv;
}

/*
 * Free resources in client key structure
 */
void
ovpn_tls_crypt_v2_client_key_free (ovpn_tls_crypt_v2_client_key_t *client_key)
{
  if (!client_key)
    return;

  if (client_key->metadata)
    {
      clib_memset (client_key->metadata, 0, client_key->metadata_len);
      clib_mem_free (client_key->metadata);
    }

  clib_memset (client_key, 0, sizeof (*client_key));
}

/*
 * Convert unwrapped client key to TLS-Crypt context
 *
 * The client key (Kc) is a 256-byte key in the same format as a TLS-Crypt key:
 *   Bytes 0-31: HMAC key for server->client (encrypt direction for server)
 *   Bytes 32-63: HMAC key for client->server (decrypt direction for server)
 *   Bytes 64-95: AES key for server->client
 *   Bytes 96-127: AES key for client->server
 *   Bytes 128-255: (reserved/unused in current OpenVPN)
 */
int
ovpn_tls_crypt_v2_client_key_to_tls_crypt (
  const ovpn_tls_crypt_v2_client_key_t *client_key,
  ovpn_tls_crypt_t *tls_crypt, u8 is_server)
{
  if (!client_key || !tls_crypt)
    return -1;

  clib_memset (tls_crypt, 0, sizeof (*tls_crypt));

  /*
   * OpenVPN key2 layout for tls-crypt (256 bytes total):
   *
   * key[0] (client->server direction, c2s) - 128 bytes:
   *   key[0].cipher[64]: bytes 0-63   (only first 32 used as c2s cipher)
   *   key[0].hmac[64]:   bytes 64-127 (only first 32 used as c2s HMAC)
   *
   * key[1] (server->client direction, s2c) - 128 bytes:
   *   key[1].cipher[64]: bytes 128-191 (only first 32 used as s2c cipher)
   *   key[1].hmac[64]:   bytes 192-255 (only first 32 used as s2c HMAC)
   */

  /* Debug: print raw client key with correct layout */

  if (is_server)
    {
      /*
       * Server mode: OpenVPN KEY_DIRECTION_NORMAL
       *
       * From OpenVPN crypto.h:
       *   KEY_DIRECTION_NORMAL: encrypt with keys[0], decrypt with keys[1]
       *
       * Byte offsets (struct key is 128 bytes: 64 cipher + 64 hmac):
       *   key[0].cipher @ 0-31, key[0].hmac @ 64-95
       *   key[1].cipher @ 128-159, key[1].hmac @ 192-223
       *
       * For server:
       *   encrypt (sending to client) = key[0]
       *   decrypt (receiving from client) = key[1]
       */
      clib_memcpy_fast (tls_crypt->encrypt_cipher_key, client_key->key,
			OVPN_TLS_CRYPT_CIPHER_SIZE); /* key[0].cipher @ 0 */
      clib_memcpy_fast (tls_crypt->encrypt_hmac_key, client_key->key + 64,
			OVPN_TLS_CRYPT_HMAC_SIZE); /* key[0].hmac @ 64 */
      clib_memcpy_fast (tls_crypt->decrypt_cipher_key, client_key->key + 128,
			OVPN_TLS_CRYPT_CIPHER_SIZE); /* key[1].cipher @ 128 */
      clib_memcpy_fast (tls_crypt->decrypt_hmac_key, client_key->key + 192,
			OVPN_TLS_CRYPT_HMAC_SIZE); /* key[1].hmac @ 192 */

    }
  else
    {
      /*
       * Client: encrypt with key[0] (c2s), decrypt with key[1] (s2c)
       *   key[0] = client->server: cipher @ 0-31, hmac @ 64-95
       *   key[1] = server->client: cipher @ 128-159, hmac @ 192-223
       */
      clib_memcpy_fast (tls_crypt->encrypt_cipher_key, client_key->key,
			OVPN_TLS_CRYPT_CIPHER_SIZE); /* key[0].cipher @ 0 */
      clib_memcpy_fast (tls_crypt->encrypt_hmac_key, client_key->key + 64,
			OVPN_TLS_CRYPT_HMAC_SIZE); /* key[0].hmac @ 64 */
      clib_memcpy_fast (tls_crypt->decrypt_cipher_key, client_key->key + 128,
			OVPN_TLS_CRYPT_CIPHER_SIZE); /* key[1].cipher @ 128 */
      clib_memcpy_fast (tls_crypt->decrypt_hmac_key, client_key->key + 192,
			OVPN_TLS_CRYPT_HMAC_SIZE); /* key[1].hmac @ 192 */
    }

  tls_crypt->enabled = 1;
  tls_crypt->packet_id_send = 1;
  tls_crypt->replay_bitmap = 0;
  tls_crypt->replay_packet_id_floor = 0;
  /* Time-based replay protection: caller should set time_backtrack from
   * options */
  tls_crypt->time_backtrack = 0;
  tls_crypt->replay_time_floor = 0;

  return 0;
}

/*
 * Extract WKc from P_CONTROL_HARD_RESET_CLIENT_V3 packet
 *
 * Packet format:
 *   [session_id (8)] [HMAC (32)] [packet_id (4)] [net_time (4)]
 *   [encrypted control packet] [WKc]
 *
 * The WKc is identified by reading its length from the last 2 bytes.
 * The WKc length field indicates the total WKc size (tag + ciphertext).
 */
int
ovpn_tls_crypt_v2_extract_wkc (const u8 *packet, u32 packet_len,
			       const u8 **wkc_out, u32 *wkc_len_out,
			       u32 *wrapped_len_out)
{
  u16 stored_len;

  if (!packet || !wkc_out || !wkc_len_out || !wrapped_len_out ||
      packet_len < OVPN_TLS_CRYPT_V2_MIN_WKC_LEN + 10)
    return -1;

  /*
   * Read WKc length from the last 2 bytes of the packet
   * This is stored in big-endian (network byte order)
   *
   * Per OpenVPN tls-crypt-v2 spec, the length field stores the FULL WKc size
   * INCLUDING the 2-byte length field itself.
   *
   * stored_len = len(WKc) = tag(32) + ciphertext(N) + length(2)
   * total_wkc_len = stored_len
   */
  stored_len = (packet[packet_len - 2] << 8) | packet[packet_len - 1];
  u32 total_wkc_len = (u32) stored_len;

  /* Sanity checks */
  if (total_wkc_len < OVPN_TLS_CRYPT_V2_MIN_WKC_LEN)
    return -2;

  if (total_wkc_len > OVPN_TLS_CRYPT_V2_MAX_WKC_LEN)
    return -3;

  if (total_wkc_len >= packet_len)
    return -4;

  /* Calculate wrapped packet length */
  u32 wrapped_len = packet_len - total_wkc_len;

  /* Verify we have enough data for the wrapped packet */
  if (wrapped_len < OVPN_SESSION_ID_SIZE + OVPN_TLS_CRYPT_OVERHEAD)
    return -5;

  *wkc_out = packet + wrapped_len;
  *wkc_len_out = total_wkc_len;
  *wrapped_len_out = wrapped_len;

  return 0;
}

/*
 * Send control packets from pending connection's reliable buffer
 * Allocates vlib_buffer, builds IP/UDP headers, copies payload, sends to IP
 * lookup
 */
static int
ovpn_handshake_send_pending_packets_ex (
  vlib_main_t *vm, ovpn_pending_connection_t *pending,
  const ip_address_t *local_addr, u16 local_port, u8 is_ip6,
  ovpn_tls_auth_t *auth, ovpn_tls_crypt_t *tls_crypt, u8 force_send)
{
  ovpn_reli_buffer_t *buf;
  u8 opcode;
  vlib_buffer_t *b;
  u32 bi;
  u32 n_sent = 0;

  /* Schedule packets for immediate sending only if force_send is set */
  if (force_send)
    ovpn_reliable_schedule_now (vm, pending->send_reliable);

  /* Send all packets that are ready */
  while (ovpn_reliable_can_send (vm, pending->send_reliable))
    {
      buf = ovpn_reliable_send (vm, pending->send_reliable, &opcode);
      if (!buf)
	break;

      /* Allocate vlib buffer */
      if (vlib_buffer_alloc (vm, &bi, 1) != 1)
	return -1;

      b = vlib_get_buffer (vm, bi);

      /* Calculate required header space */
      u32 ip_hdr_size = is_ip6 ? sizeof (ip6_header_t) : sizeof (ip4_header_t);
      u32 udp_hdr_size = sizeof (udp_header_t);
      u32 total_hdr_size = ip_hdr_size + udp_hdr_size;

      /* Position buffer to leave room for IP/UDP headers */
      vlib_buffer_advance (b, -(i32) total_hdr_size);

      /* Get payload area (after headers) */
      u8 *payload = vlib_buffer_get_current (b) + total_hdr_size;
      u32 payload_len = OVPN_BLEN (buf);

      /* Apply TLS-Crypt or TLS-Auth wrapping */
      if (tls_crypt && tls_crypt->enabled)
	{
	  /*
	   * TLS-Crypt wrapping:
	   * Input buffer after mark_active_outgoing:
	   *   [msg_packet_id(4)] [opcode(1)] [session_id(8)] [ack_array...]
	   * [payload]
	   *
	   * Wire format:
	   *   [opcode(1)] [session_id(8)] [packet_id(4)] [net_time(4)]
	   *   [HMAC(32)] [encrypted(msg_packet_id + ack_array + payload)]
	   *
	   * HMAC is computed over: opcode || session_id || packet_id ||
	   * net_time || plaintext where plaintext = msg_packet_id || ack_array
	   * || payload
	   *
	   * The msg_packet_id was prepended by mark_active_outgoing, so we
	   * need to skip it to get the opcode+session_id, then include it in
	   * the encrypted payload.
	   */
	  u8 *buf_data = OVPN_BPTR (buf);
	  u8 *opcode_session =
	    buf_data + 4; /* Skip msg_packet_id to get opcode+session_id */
	  u8 wrapped[2048 + OVPN_TLS_CRYPT_OVERHEAD];

	  /*
	   * The plaintext to encrypt is the entire buffer content:
	   *   [msg_packet_id(4)] [ack_array...] [payload]
	   * But we need opcode+session_id from the buffer for HMAC.
	   *
	   * Actually, looking at OpenVPN format more carefully:
	   * The encrypted payload should be: [ack_array] [msg_packet_id] [TLS
	   * data] NOT including the msg_packet_id that was prepended.
	   *
	   * Let me reconsider: after build_control_header:
	   *   [opcode] [session_id] [ack_array] (no msg_packet_id yet)
	   * After mark_active_outgoing PREPENDS msg_packet_id:
	   *   [msg_packet_id] [opcode] [session_id] [ack_array]
	   *
	   * For TLS-Crypt, the plaintext should be what comes after
	   * opcode+session_id: [ack_array] [msg_packet_id] [TLS data if any]
	   *
	   * But the msg_packet_id was prepended, not appended!
	   * This is a structural issue with how the reliable layer works.
	   *
	   * For now, let's pass the original content after opcode+session_id,
	   * which is [ack_array] from position 13 (4 + 1 + 8) in the buffer.
	   */
	  u32 plaintext_offset =
	    4 + 1 + 8; /* msg_packet_id + opcode + session_id */
	  u8 *plaintext = buf_data + plaintext_offset;

	  /* But we also need to include the msg_packet_id in the plaintext!
	   * OpenVPN format: encrypted = ack_array || msg_packet_id || TLS_data
	   * So we need to build the plaintext correctly:
	   *   [ack_array] [msg_packet_id]
	   * The msg_packet_id is at buf_data[0..3]
	   */
	  u8 plaintext_with_pid[2048];
	  u32 ack_len = payload_len - plaintext_offset; /* ack_array length */
	  clib_memcpy_fast (plaintext_with_pid, plaintext, ack_len);
	  clib_memcpy_fast (plaintext_with_pid + ack_len, buf_data,
			    4); /* msg_packet_id */
	  u32 total_plaintext_len = ack_len + 4;

	  int wrapped_len = ovpn_tls_crypt_wrap (
	    tls_crypt, opcode_session, plaintext_with_pid, total_plaintext_len,
	    wrapped, sizeof (wrapped));
	  if (wrapped_len < 0)
	    {
	      vlib_buffer_free_one (vm, bi);
	      return -2;
	    }

	  /* Build wire format: [opcode][session_id][wrapped] */
	  clib_memcpy_fast (payload, opcode_session,
			    9); /* opcode + session_id */
	  clib_memcpy_fast (payload + 9, wrapped, wrapped_len);
	  payload_len = 9 + wrapped_len;

	  /* Increment packet ID for next wrap */
	  tls_crypt->packet_id_send++;
	}
      else if (auth && auth->enabled)
	{
	  /*
	   * TLS-Auth expects wire format:
	   * [opcode(1)] [session_id(8)] [ack_array] [msg_pkt_id(4)]
	   *
	   * But the reliable layer prepends packet_id, so the buffer is:
	   * [msg_pkt_id(4)] [opcode(1)] [session_id(8)] [ack_array]
	   *
	   * We need to rearrange it to the correct wire format.
	   */
	  u8 *buf_data = OVPN_BPTR (buf);
	  u32 msg_pkt_id_offset = 0;
	  u32 header_offset = 4; /* After msg_pkt_id */
	  u32 header_len = payload_len - 4;

	  /* Build correct wire format in a temp buffer */
	  u8 wire_format[2048];
	  u32 wire_len = 0;

	  /* Copy [opcode] [session_id] [ack_array] */
	  clib_memcpy_fast (wire_format + wire_len, buf_data + header_offset,
			    header_len);
	  wire_len += header_len;

	  /* Append [msg_pkt_id] */
	  clib_memcpy_fast (wire_format + wire_len,
			    buf_data + msg_pkt_id_offset, 4);
	  wire_len += 4;

	  u8 wrapped[2048 + OVPN_TLS_AUTH_OVERHEAD];
	  int wrapped_len = ovpn_tls_auth_wrap (auth, wire_format, wire_len,
						wrapped, sizeof (wrapped));
	  if (wrapped_len < 0)
	    {
	      vlib_buffer_free_one (vm, bi);
	      return -2;
	    }

	  /* Copy wrapped packet to payload area */
	  clib_memcpy_fast (payload, wrapped, wrapped_len);
	  payload_len = wrapped_len;
	}
      else
	{
	  /*
	   * No TLS-Crypt/TLS-Auth: rearrange buffer to wire format.
	   *
	   * The reliable layer prepends packet_id, so buffer is:
	   *   [msg_pkt_id(4)] [opcode(1)] [session_id(8)] [ack_array]
	   *
	   * Wire format should be:
	   *   [opcode(1)] [session_id(8)] [ack_array] [msg_pkt_id(4)]
	   */
	  u8 *buf_data = OVPN_BPTR (buf);
	  u32 msg_pkt_id_offset = 0;
	  u32 header_offset = 4; /* After msg_pkt_id */
	  u32 header_len = payload_len - 4;

	  /* Copy [opcode] [session_id] [ack_array] first */
	  clib_memcpy_fast (payload, buf_data + header_offset, header_len);
	  /* Append [msg_pkt_id] at the end */
	  clib_memcpy_fast (payload + header_len, buf_data + msg_pkt_id_offset,
			    4);
	}

      /* Build UDP header */
      udp_header_t *udp;
      if (is_ip6)
	{
	  ip6_header_t *ip6 = vlib_buffer_get_current (b);

	  /* Build IPv6 header */
	  clib_memset (ip6, 0, sizeof (*ip6));
	  ip6->ip_version_traffic_class_and_flow_label =
	    clib_host_to_net_u32 (0x60000000);
	  ip6->payload_length =
	    clib_host_to_net_u16 (udp_hdr_size + payload_len);
	  ip6->protocol = IP_PROTOCOL_UDP;
	  ip6->hop_limit = 64;

	  /* Set addresses (swap src/dst from pending connection) */
	  /* Our address is the original destination, client is src */
	  if (local_addr)
	    clib_memcpy (&ip6->src_address, &local_addr->ip.ip6,
			 sizeof (ip6_address_t));
	  clib_memcpy (&ip6->dst_address, &pending->remote_addr.ip.ip6,
		       sizeof (ip6_address_t));

	  udp = (udp_header_t *) (ip6 + 1);
	}
      else
	{
	  ip4_header_t *ip4 = vlib_buffer_get_current (b);

	  /* Build IPv4 header */
	  clib_memset (ip4, 0, sizeof (*ip4));
	  ip4->ip_version_and_header_length = 0x45;
	  ip4->ttl = 64;
	  ip4->protocol = IP_PROTOCOL_UDP;
	  ip4->length =
	    clib_host_to_net_u16 (ip_hdr_size + udp_hdr_size + payload_len);

	  /* Set addresses - swap src/dst */
	  ip4->dst_address.as_u32 = pending->remote_addr.ip.ip4.as_u32;
	  if (local_addr)
	    ip4->src_address.as_u32 = local_addr->ip.ip4.as_u32;

	  ip4->checksum = ip4_header_checksum (ip4);

	  udp = (udp_header_t *) (ip4 + 1);
	}

      /* Build UDP header */
      udp->dst_port = clib_host_to_net_u16 (pending->remote_port);
      udp->src_port = clib_host_to_net_u16 (local_port ? local_port : 1194);
      udp->length = clib_host_to_net_u16 (udp_hdr_size + payload_len);
      udp->checksum = 0;

      /* Set buffer length */
      b->current_length = total_hdr_size + payload_len;

      /* Set flags for IP output */
      b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

      /* Compute UDP checksum */
      if (is_ip6)
	{
	  ip6_header_t *ip6 = vlib_buffer_get_current (b);
	  int bogus = 0;
	  udp->checksum =
	    ip6_tcp_udp_icmp_compute_checksum (vm, b, ip6, &bogus);
	}
      else
	{
	  ip4_header_t *ip4 = vlib_buffer_get_current (b);
	  udp->checksum = ip4_tcp_udp_compute_checksum (vm, b, ip4);
	}

      /* Enqueue to IP lookup */
      vlib_frame_t *f;
      u32 *to_next;

      if (is_ip6)
	{
	  f = vlib_get_frame_to_node (vm, ip6_lookup_node.index);
	}
      else
	{
	  f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
	}

      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi;
      f->n_vectors = 1;

      if (is_ip6)
	{
	  vlib_put_frame_to_node (vm, ip6_lookup_node.index, f);
	}
      else
	{
	  vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);
	}
      n_sent++;
    }
  return n_sent;
}

/*
 * Wrapper for backwards compatibility - always forces immediate send
 */
static int
ovpn_handshake_send_pending_packets (vlib_main_t *vm,
				     ovpn_pending_connection_t *pending,
				     const ip_address_t *local_addr,
				     u16 local_port, u8 is_ip6,
				     ovpn_tls_auth_t *auth,
				     ovpn_tls_crypt_t *tls_crypt)
{
  return ovpn_handshake_send_pending_packets_ex (
    vm, pending, local_addr, local_port, is_ip6, auth, tls_crypt,
    1 /* force_send */);
}

/*
 * Send control packets from peer's TLS reliable buffer
 * Similar to pending packets but uses peer's TLS context
 */
static int
ovpn_handshake_send_peer_packets_ex (vlib_main_t *vm, ovpn_peer_t *peer,
				     const ip_address_t *local_addr,
				     u16 local_port, u8 is_ip6,
				     ovpn_tls_auth_t *auth,
				     ovpn_tls_crypt_t *tls_crypt,
				     u8 force_send)
{
  ovpn_peer_tls_t *tls_ctx = peer->tls_ctx;
  ovpn_reli_buffer_t *buf;
  u8 opcode;
  vlib_buffer_t *b;
  u32 bi;
  u32 n_sent = 0;

  if (!tls_ctx || !tls_ctx->send_reliable)
    return 0;

  /* Schedule packets for immediate sending only if force_send is set */
  if (force_send)
    ovpn_reliable_schedule_now (vm, tls_ctx->send_reliable);

  /* Send all packets that are ready */
  while (ovpn_reliable_can_send (vm, tls_ctx->send_reliable))
    {
      buf = ovpn_reliable_send (vm, tls_ctx->send_reliable, &opcode);
      if (!buf)
	{
	  break;
	}

      /* Buffer starts with packet_id prepended by mark_active_outgoing */
      u32 msg_pkt_id = 0;
      if (OVPN_BLEN (buf) >= 4)
	clib_memcpy (&msg_pkt_id, OVPN_BPTR (buf), 4);
      msg_pkt_id = clib_net_to_host_u32 (msg_pkt_id);

      /* Allocate vlib buffer */
      if (vlib_buffer_alloc (vm, &bi, 1) != 1)
	return -1;

      b = vlib_get_buffer (vm, bi);

      /* Calculate required header space */
      u32 ip_hdr_size = is_ip6 ? sizeof (ip6_header_t) : sizeof (ip4_header_t);
      u32 udp_hdr_size = sizeof (udp_header_t);
      u32 total_hdr_size = ip_hdr_size + udp_hdr_size;

      /* Build control packet header:
       * opcode | session_id | ack_array | packet_id | payload
       */
      u8 ctrl_hdr[128];
      u32 ctrl_hdr_len = 0;

      /* Opcode + key_id */
      ctrl_hdr[ctrl_hdr_len++] = ovpn_op_compose (opcode, tls_ctx->key_id);

      /* Our session ID (8 bytes) */
      clib_memcpy (&ctrl_hdr[ctrl_hdr_len], peer->session_id.id,
		   OVPN_SID_SIZE);
      ctrl_hdr_len += OVPN_SID_SIZE;

      /* ACK array */
      if (tls_ctx->recv_ack.len > 0)
	{
	  ctrl_hdr[ctrl_hdr_len++] = tls_ctx->recv_ack.len;
	  for (u32 i = 0; i < tls_ctx->recv_ack.len; i++)
	    {
	      u32 net_pid =
		clib_host_to_net_u32 (tls_ctx->recv_ack.packet_id[i]);
	      clib_memcpy (&ctrl_hdr[ctrl_hdr_len], &net_pid, sizeof (u32));
	      ctrl_hdr_len += sizeof (u32);
	    }
	  /* Remote session ID for ACK */
	  clib_memcpy (&ctrl_hdr[ctrl_hdr_len], peer->remote_session_id.id,
		       OVPN_SID_SIZE);
	  ctrl_hdr_len += OVPN_SID_SIZE;
	  tls_ctx->recv_ack.len = 0; /* Clear ACKs */
	}
      else
	{
	  ctrl_hdr[ctrl_hdr_len++] = 0; /* No ACKs */
	}

      /*
       * Note: We do NOT add packet_id to ctrl_hdr here because the reliable
       * layer already prepended it to the buffer in mark_active_outgoing().
       * The buffer format is: [packet_id(4)] [TLS_payload]
       * So we copy the entire buffer after ctrl_hdr to get:
       * [opcode] [session_id] [ack_array] [packet_id] [TLS_payload]
       */

      u32 payload_len = OVPN_BLEN (buf);
      u32 total_ctrl_len = ctrl_hdr_len + payload_len;

      /* Position buffer to leave room for IP/UDP headers */
      vlib_buffer_advance (b, -(i32) total_hdr_size);

      /* Get payload area (after headers) */
      u8 *pkt_data = vlib_buffer_get_current (b) + total_hdr_size;

      /* Copy control header */
      clib_memcpy_fast (pkt_data, ctrl_hdr, ctrl_hdr_len);
      /* Copy TLS payload */
      clib_memcpy_fast (pkt_data + ctrl_hdr_len, OVPN_BPTR (buf), payload_len);

      /* Apply TLS-Crypt or TLS-Auth wrapping */
      if (tls_crypt && tls_crypt->enabled)
	{
	  /*
	   * TLS-Crypt wrapping:
	   * pkt_data: [opcode(1)] [session_id(8)] [ack_array...] [msg_id]
	   * [payload] Wire format: [opcode(1)] [session_id(8)] [packet_id(4)]
	   * [net_time(4)] [HMAC(32)] [encrypted(ack_array...payload)]
	   */
	  u8 wrapped[2048 + OVPN_TLS_CRYPT_OVERHEAD];
	  int wrapped_len = ovpn_tls_crypt_wrap (
	    tls_crypt, pkt_data, pkt_data + 9, total_ctrl_len - 9, wrapped,
	    sizeof (wrapped));
	  if (wrapped_len < 0)
	    {
	      vlib_buffer_free_one (vm, bi);
	      return -2;
	    }

	  /* Build wire format: [opcode][session_id][wrapped] */
	  /* opcode + session_id already at pkt_data[0..8], copy wrapped after
	   */
	  clib_memcpy_fast (pkt_data + 9, wrapped, wrapped_len);
	  total_ctrl_len = 9 + wrapped_len;

	  /* Increment packet ID for next wrap */
	  tls_crypt->packet_id_send++;
	}
      else if (auth && auth->enabled)
	{
	  /* TLS-Auth: add HMAC + packet_id + net_time for replay protection */
	  u8 wrapped[2048 + OVPN_TLS_AUTH_OVERHEAD];
	  int wrapped_len = ovpn_tls_auth_wrap (auth, pkt_data, total_ctrl_len,
						wrapped, sizeof (wrapped));
	  if (wrapped_len < 0)
	    {
	      vlib_buffer_free_one (vm, bi);
	      return -2;
	    }

	  /* Copy wrapped packet back to payload area */
	  clib_memcpy_fast (pkt_data, wrapped, wrapped_len);
	  total_ctrl_len = wrapped_len;
	}

      /* Build UDP header */
      udp_header_t *udp;
      if (is_ip6)
	{
	  ip6_header_t *ip6 = vlib_buffer_get_current (b);

	  clib_memset (ip6, 0, sizeof (*ip6));
	  ip6->ip_version_traffic_class_and_flow_label =
	    clib_host_to_net_u32 (0x60000000);
	  ip6->payload_length =
	    clib_host_to_net_u16 (udp_hdr_size + total_ctrl_len);
	  ip6->protocol = IP_PROTOCOL_UDP;
	  ip6->hop_limit = 64;

	  if (local_addr)
	    clib_memcpy (&ip6->src_address, &local_addr->ip.ip6,
			 sizeof (ip6_address_t));
	  clib_memcpy (&ip6->dst_address, &peer->remote_addr.ip.ip6,
		       sizeof (ip6_address_t));

	  udp = (udp_header_t *) (ip6 + 1);
	}
      else
	{
	  ip4_header_t *ip4 = vlib_buffer_get_current (b);

	  clib_memset (ip4, 0, sizeof (*ip4));
	  ip4->ip_version_and_header_length = 0x45;
	  ip4->ttl = 64;
	  ip4->protocol = IP_PROTOCOL_UDP;
	  ip4->length =
	    clib_host_to_net_u16 (ip_hdr_size + udp_hdr_size + total_ctrl_len);

	  ip4->dst_address.as_u32 = peer->remote_addr.ip.ip4.as_u32;
	  if (local_addr)
	    ip4->src_address.as_u32 = local_addr->ip.ip4.as_u32;

	  ip4->checksum = ip4_header_checksum (ip4);

	  udp = (udp_header_t *) (ip4 + 1);
	}

      udp->dst_port = clib_host_to_net_u16 (peer->remote_port);
      udp->src_port = clib_host_to_net_u16 (local_port ? local_port : 1194);
      udp->length = clib_host_to_net_u16 (udp_hdr_size + total_ctrl_len);
      udp->checksum = 0;

      b->current_length = total_hdr_size + total_ctrl_len;
      b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

      /* Compute UDP checksum */
      if (is_ip6)
	{
	  ip6_header_t *ip6 = vlib_buffer_get_current (b);
	  int bogus = 0;
	  udp->checksum =
	    ip6_tcp_udp_icmp_compute_checksum (vm, b, ip6, &bogus);
	}
      else
	{
	  ip4_header_t *ip4 = vlib_buffer_get_current (b);
	  udp->checksum = ip4_tcp_udp_compute_checksum (vm, b, ip4);
	}

      /* Enqueue to IP lookup */
      vlib_frame_t *f;
      u32 *to_next;

      if (is_ip6)
	{
	  f = vlib_get_frame_to_node (vm, ip6_lookup_node.index);
	}
      else
	{
	  f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
	}

      to_next = vlib_frame_vector_args (f);
      to_next[0] = bi;
      f->n_vectors = 1;

      if (is_ip6)
	{
	  vlib_put_frame_to_node (vm, ip6_lookup_node.index, f);
	}
      else
	{
	  vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);
	}

      n_sent++;
    }

  return n_sent;
}

/*
 * Wrapper for backwards compatibility - always forces immediate send
 */
static int
ovpn_handshake_send_peer_packets (vlib_main_t *vm, ovpn_peer_t *peer,
				  const ip_address_t *local_addr,
				  u16 local_port, u8 is_ip6,
				  ovpn_tls_auth_t *auth,
				  ovpn_tls_crypt_t *tls_crypt)
{
  return ovpn_handshake_send_peer_packets_ex (vm, peer, local_addr, local_port,
					      is_ip6, auth, tls_crypt,
					      1 /* force_send */);
}

/*
 * Process incoming control packet
 */
int
ovpn_handshake_process_packet (vlib_main_t *vm, vlib_buffer_t *b,
			       const ip_address_t *src_addr, u16 src_port,
			       const ip_address_t *dst_addr, u16 dst_port,
			       u8 is_ip6)
{

  /* Look up instance by destination port */
  ovpn_instance_t *inst = ovpn_instance_get_by_port (dst_port);
  if (!inst)
    {
      return -100; /* No instance for this port */
    }


  ovpn_pending_db_t *pending_db = &inst->multi_context.pending_db;
  ovpn_peer_db_t *peer_db = &inst->multi_context.peer_db;
  ovpn_pending_connection_t *pending;
  ovpn_peer_t *peer;
  ovpn_reli_buffer_t buf;
  u8 opcode, key_id;
  ovpn_session_id_t session_id, ack_session_id;
  ovpn_reliable_ack_t ack;
  u32 packet_id = 0;
  u8 *data;
  u32 len;
  int rv = 0;

  data = vlib_buffer_get_current (b);
  len = b->current_length;

  /*
   * Control channel packet authentication and replay protection
   *
   * Both TLS-Crypt and TLS-Auth use a TWO packet_id scheme:
   * 1. Wrapper packet_id: In the TLS-Crypt/TLS-Auth header for REPLAY
   * PROTECTION
   * 2. Message packet_id: Inside the control packet for RELIABLE ORDERING
   *
   * The wrapper layer handles authentication and anti-replay.
   * The reliable layer handles ordering and retransmission.
   */

  /*
   * TLS-Crypt-V2 handling
   *
   * TLS-Crypt-V2 uses per-client keys:
   * - P_CONTROL_HARD_RESET_CLIENT_V3: Has WKc appended, needs to extract and
   * unwrap
   * - Subsequent packets: Use the stored client context from pending
   * connection
   *
   * We need to determine which TLS-Crypt context to use BEFORE unwrapping:
   * 1. Check if there's an existing pending connection with client_tls_crypt
   * 2. For V3 HARD_RESET, extract and unwrap the WKc
   * 3. Otherwise use the global tls_crypt context
   */
  ovpn_tls_crypt_t *tls_crypt_ctx_for_unwrap = NULL;
  ovpn_tls_crypt_t client_tls_crypt_temp;
  u8 is_tls_crypt_v2_packet = 0;
  u32 wrapped_packet_len = len;

  /*
   * Early lookup for existing TLS-Crypt-V2 connections
   * Check both pending connections and established peers for per-client context
   */
  ovpn_pending_connection_t *existing_pending =
    ovpn_pending_connection_lookup (pending_db, src_addr, src_port);
  if (existing_pending && existing_pending->client_tls_crypt)
    {
      tls_crypt_ctx_for_unwrap = existing_pending->client_tls_crypt;
    }
  else
    {
      /* Check for established peer with per-client TLS-Crypt (TLS-Crypt-V2) */
      ovpn_peer_t *existing_peer =
	ovpn_peer_lookup_by_remote (peer_db, src_addr, src_port);
      if (existing_peer && existing_peer->tls_ctx &&
	  existing_peer->tls_ctx->tls_crypt)
	{
	  tls_crypt_ctx_for_unwrap = existing_peer->tls_ctx->tls_crypt;
	}
    }

  /* Peek at opcode to check for V3 HARD_RESET */
  if (len >= 1)
    {
      u8 peek_opcode = ovpn_op_get_opcode (data[0]);


      if (peek_opcode == OVPN_OP_CONTROL_HARD_RESET_CLIENT_V3 &&
	  inst->tls_crypt_v2.enabled)
	{
	  /*
	   * P_CONTROL_HARD_RESET_CLIENT_V3 with TLS-Crypt-V2
	   *
	   * Packet format: [opcode+keyid] [tls-crypt wrapped] [WKc]
	   * We need to extract WKc, unwrap it, then use the client key
	   */
	  const u8 *wkc;
	  u32 wkc_len;
	  ovpn_tls_crypt_v2_client_key_t client_key;


	  /* Extract WKc from the end of the packet (pass data after opcode) */
	  rv = ovpn_tls_crypt_v2_extract_wkc (data + 1, len - 1, &wkc,
					      &wkc_len, &wrapped_packet_len);
	  if (rv < 0)
	    {
	      return -10; /* Failed to extract WKc */
	    }


	  /* Add back the opcode byte to wrapped_packet_len */
	  wrapped_packet_len += 1;

	  /* Unwrap the client key */
	  rv = ovpn_tls_crypt_v2_unwrap_client_key (&inst->tls_crypt_v2, wkc,
						    wkc_len, &client_key);
	  if (rv < 0)
	    {
	      return -11; /* Failed to unwrap client key */
	    }


	  /* Convert client key to TLS-Crypt context */
	  rv = ovpn_tls_crypt_v2_client_key_to_tls_crypt (
	    &client_key, &client_tls_crypt_temp, 1 /* is_server */);
	  ovpn_tls_crypt_v2_client_key_free (&client_key);

	  if (rv < 0)
	    {
	      return -12; /* Failed to create client TLS-Crypt context */
	    }


	  /* Set time_backtrack from instance options for replay protection */
	  if (inst->options.replay_protection)
	    client_tls_crypt_temp.time_backtrack = inst->options.replay_time;

	  tls_crypt_ctx_for_unwrap = &client_tls_crypt_temp;
	  is_tls_crypt_v2_packet = 1;

	  /*
	   * Adjust length to exclude WKc for subsequent processing.
	   * wrapped_packet_len already includes the opcode byte (added above).
	   */
	  len = wrapped_packet_len;
	  b->current_length = len;
	}
    }

  /*
   * Check if TLS-Crypt is enabled - it takes precedence over TLS-Auth.
   *
   * IMPORTANT: For TLS-Crypt-V2 HARD_RESET_CLIENT_V3, the initial packet
   * is NOT TLS-Crypt encrypted. The format is:
   *   [opcode] [session_id] [packet_id] [net_time] [ack_array] [msg_pkt_id] [WKc]
   *
   * The WKc provides authentication. We skip TLS-Crypt unwrap for V3 packets.
   * Subsequent control packets WILL be TLS-Crypt wrapped using the per-client key.
   */
  if ((tls_crypt_ctx_for_unwrap && !is_tls_crypt_v2_packet) ||
      inst->tls_crypt.enabled)
    {
      /*
       * TLS-Crypt packet format on wire:
       *   [opcode+keyid (1)] [session_id (8)] [HMAC (32)] [packet_id (4)]
       *   [net_time (4)] [encrypted payload]
       *
       * The unwrap function expects data starting from HMAC, so we skip
       * the opcode and session_id (9 bytes total). The encrypted payload
       * contains the control message which we need to reconstruct with
       * the opcode prepended.
       *
       * Steps:
       * 1. Save opcode byte
       * 2. Call unwrap with data after opcode+session_id
       * 3. Reconstruct: [opcode] [session_id from plaintext] [rest...]
       */
      ovpn_tls_crypt_t *ctx =
	tls_crypt_ctx_for_unwrap ? tls_crypt_ctx_for_unwrap : &inst->tls_crypt;
      u8 plaintext[2048];

      /* Minimum size: opcode(1) + session_id(8) + HMAC(32) + packet_id(4) +
       * net_time(4) */
      if (len < 1 + 8 + OVPN_TLS_CRYPT_OVERHEAD)
	return -2;

      u8 opcode_byte = data[0];

      /* Unwrap: pass opcode+session_id for HMAC, then wrapped data */
      int plain_len = ovpn_tls_crypt_unwrap (ctx, data, data + 9, len - 9,
					     plaintext, sizeof (plaintext));
      if (plain_len < 0)
	{
	  if (plain_len == -9)
	    return -5; /* Replay detected */
	  return -2;   /* TLS-Crypt unwrap failed */
	}

      /*
       * Reconstruct the control packet:
       *   [opcode+keyid (1)] [session_id (8)] [decrypted payload...]
       *
       * The session_id is at data[1..8] in the original wire packet and
       * must be preserved. The encrypted payload contains the control
       * message content (ack_array, msg_packet_id, TLS data) that comes
       * AFTER the session_id in the reconstructed packet.
       */
      data[0] = opcode_byte;
      /* session_id already at data[1..8], copy plaintext after it */
      clib_memcpy_fast (data + 9, plaintext, plain_len);
      len = 9 + plain_len;
      b->current_length = len;
    }
  else if (inst->tls_auth.enabled)
    {
      /*
       * TLS-Auth packet format on wire:
       *   [opcode+keyid (1)] [session_id (8)] [HMAC (32)] [packet_id (4)]
       * [net_time (4)] [ack_array...] [msg_packet_id (4)] [payload]
       *
       * The unwrap function verifies HMAC and removes the wrapper:
       *   Input:  [opcode] [session_id] [HMAC] [packet_id] [net_time]
       * [rest...] Output: [opcode] [session_id] [rest...]
       */
      u8 plaintext[2048];

      /* Minimum size: opcode(1) + session_id(8) + HMAC(32) + packet_id(4) +
       * net_time(4) = 49 */
      if (len < OVPN_TLS_AUTH_MIN_SIZE)
	return -2;

      int plain_len = ovpn_tls_auth_unwrap (&inst->tls_auth, data, len,
					    plaintext, sizeof (plaintext));
      if (plain_len < 0)
	{
	  if (plain_len == -4)
	    return -5; /* Replay detected */
	  return -2;   /* TLS-Auth unwrap failed */
	}

      /*
       * Copy unwrapped plaintext back to data buffer:
       *   [opcode+keyid] [session_id] [ack_array...] [msg_packet_id] [payload]
       */
      clib_memcpy_fast (data, plaintext, plain_len);
      len = plain_len;
      b->current_length = len;
    }

  clib_memset (&ack_session_id, 0, sizeof (ack_session_id));

  /* Set up buffer for parsing */
  ovpn_buf_set_read (&buf, data, 0);
  buf.len = len;
  buf.offset = 0;

  /*
   * For TLS-Crypt-V2 V3 HARD_RESET, the packet format is:
   *   [opcode+keyid (1)] [session_id (8)] [packet_id (4)] [net_time (4)]
   *   [ack_array] [msg_packet_id (4)]
   *
   * Note: No HMAC - the WKc provides authentication.
   */
  if (is_tls_crypt_v2_packet)
    {
      u8 op_byte;
      u32 v3_packet_id, v3_net_time;


      /* Read opcode + key_id */
      if (ovpn_buf_read_u8 (&buf) < 0)
	{
	  return -1;
	}
      op_byte = buf.data[0];
      opcode = ovpn_op_get_opcode (op_byte);
      key_id = ovpn_op_get_key_id (op_byte);

      /* Read session ID */
      if (!ovpn_session_id_read (&session_id, &buf))
	{
	  return -1;
	}

      /* Read packet_id (4 bytes) - for replay protection */
      if (!ovpn_reliable_ack_read_packet_id (&buf, &v3_packet_id))
	{
	  return -1;
	}

      /* Read net_time (4 bytes) */
      if (!ovpn_reliable_ack_read_packet_id (&buf, &v3_net_time))
	{
	  return -1;
	}

      /* Parse ACK array */
      if (!ovpn_reliable_ack_parse (&buf, &ack, &ack_session_id))
	{
	  return -1;
	}

      /* For non-ACK packets, read msg_packet_id */
      if (opcode != OVPN_OP_ACK_V1)
	{
	  if (!ovpn_reliable_ack_read_packet_id (&buf, &packet_id))
	    {
	      return -1;
	    }
	}

    }
  else
    {
      /* Standard control packet parsing (after TLS-Crypt/TLS-Auth unwrap) */
      if (ovpn_parse_control_header (&buf, &opcode, &key_id, &session_id, &ack,
				     &ack_session_id, &packet_id) < 0)
	{
	  return -1;
	}

    }

  /* Check if we have an existing peer for this address */
  peer = ovpn_peer_lookup_by_remote (peer_db, src_addr, src_port);

  /* No established peer - check pending connections */
  pending = ovpn_pending_connection_lookup (pending_db, src_addr, src_port);

  /*
   * Process ACKs embedded in any control packet (not just ACK_V1).
   * This is crucial for promoting pending connections to peers when
   * the client sends P_CONTROL_V1 with ACKs for our HARD_RESET_SERVER.
   */
  if (ack.len > 0)
    {
      /* ACKs for pending connection - may promote to peer */
      if (pending && pending->state == OVPN_PENDING_STATE_SENT_RESET)
	{
	  /* Verify ACK is for our session */
	  if (ovpn_session_id_equal (&ack_session_id,
				     &pending->local_session_id))
	    {
	      /* Process ACKs - remove acknowledged packets */
	      ovpn_reliable_send_purge (pending->send_reliable, &ack);

	      /* Check if our HARD_RESET_SERVER was acknowledged */
	      if (ovpn_reliable_empty (pending->send_reliable))
		{
		  /*
		   * All our packets were ACKed - promote to peer!
		   */
		  u32 peer_id;

		  pending->state = OVPN_PENDING_STATE_ESTABLISHED;

		  /* Create the real peer */
		  peer_id = ovpn_peer_create (peer_db, src_addr, src_port);
		  if (peer_id != ~0)
		    {
		      peer = ovpn_peer_get (peer_db, peer_id);
		      if (peer)
			{
			  /* Copy session IDs to peer */
			  ovpn_session_id_copy (&peer->session_id,
						&pending->local_session_id);
			  ovpn_session_id_copy (&peer->remote_session_id,
						&pending->remote_session_id);

			  /* Set peer state to handshake */
			  peer->state = OVPN_PEER_STATE_HANDSHAKE;

			  /* Initialize TLS context for this peer */
			  if (inst->ptls_ctx)
			    {
			      int tls_rv = ovpn_peer_tls_init (
				peer, inst->ptls_ctx, pending->key_id);
			      if (tls_rv < 0)
				{
				  ovpn_peer_delete (peer_db, peer_id);
				  peer = NULL;
				}
			      else
				{
				  /*
				   * Set recv_reliable to expect packet_id=1.
				   * The client's HARD_RESET used packet_id=0,
				   * so the next packet (P_CONTROL_V1) will be
				   * packet_id=1.
				   */
				  peer->tls_ctx->recv_reliable->packet_id = 1;

				  /*
				   * Copy send_reliable packet_id from pending.
				   * The pending sent HARD_RESET_SERVER with
				   * packet_id=0, so the peer's next send
				   * should use packet_id=1. Otherwise, the
				   * client will see duplicate packet_id=0 and
				   * ignore it.
				   */
				  peer->tls_ctx->send_reliable->packet_id =
				    pending->send_reliable->packet_id;

				  /*
				   * Transfer per-client TLS-Crypt context
				   * (TLS-Crypt-V2) This must happen before
				   * pending is deleted to avoid double-free.
				   */
				  if (pending->client_tls_crypt)
				    {
				      peer->tls_ctx->tls_crypt =
					pending->client_tls_crypt;
				      pending->client_tls_crypt =
					NULL; /* Prevent double-free */
				    }
				}
			    }
			}
		    }

		  /* Clean up pending connection */
		  ovpn_pending_connection_delete (pending_db, pending);
		  pending = NULL;
		}
	    }
	}
      /* ACKs for peer in TLS handshake */
      else if (peer && peer->tls_ctx && peer->tls_ctx->send_reliable)
	{
	  if (ovpn_session_id_equal (&ack_session_id, &peer->session_id))
	    {
	      ovpn_reliable_send_purge (peer->tls_ctx->send_reliable, &ack);
	    }
	}
    }

  /* Handle based on opcode */
  switch (opcode)
    {
    case OVPN_OP_CONTROL_HARD_RESET_CLIENT_V1:
    case OVPN_OP_CONTROL_HARD_RESET_CLIENT_V2:
    case OVPN_OP_CONTROL_HARD_RESET_CLIENT_V3:
      {
	/*
	 * Client is initiating connection or reconnecting
	 *
	 * If peer already exists for this remote address, it means client
	 * is reconnecting. We need to:
	 * 1. Delete the existing peer (clean up old state)
	 * 2. Create a new pending connection
	 * 3. Send P_CONTROL_HARD_RESET_SERVER_V2 with ACK
	 */

	/* Check if peer already exists - client is reconnecting */
	if (peer)
	  {
	    /*
	     * Client sent HARD_RESET but we have existing peer.
	     * This is a reconnection scenario - delete the old peer.
	     *
	     * Use worker barrier to ensure no data plane workers are
	     * accessing this peer during deletion.
	     */
	    u32 old_peer_id = peer->peer_id;

	    vlib_worker_thread_barrier_sync (vm);
	    ovpn_peer_delete (peer_db, old_peer_id);
	    vlib_worker_thread_barrier_release (vm);

	    peer = NULL; /* Peer no longer valid */
	  }

	/* Create or update pending connection */
	pending = ovpn_pending_connection_create (
	  pending_db, src_addr, src_port, &session_id, key_id);
	if (!pending)
	  {
	    return -3;
	  }

	/*
	 * For TLS-Crypt-V2 (V3 packets), store the per-client TLS-Crypt
	 * context This context will be used for all subsequent control channel
	 * packets
	 */
	if (is_tls_crypt_v2_packet && tls_crypt_ctx_for_unwrap)
	  {
	    /* Free any existing client context from a previous connection
	     * attempt */
	    if (pending->client_tls_crypt)
	      {
		clib_mem_free (pending->client_tls_crypt);
	      }

	    /* Allocate and copy the client TLS-Crypt context */
	    pending->client_tls_crypt =
	      clib_mem_alloc (sizeof (ovpn_tls_crypt_t));
	    clib_memcpy_fast (pending->client_tls_crypt,
			      tls_crypt_ctx_for_unwrap,
			      sizeof (ovpn_tls_crypt_t));
	    pending->is_tls_crypt_v2 = 1;
	  }

	/* Record the packet ID we need to ACK */
	ovpn_reliable_ack_acknowledge_packet_id (&pending->recv_ack,
						 packet_id);

	/* Build server reset response in reliable buffer */
	rv = ovpn_handshake_send_server_reset (vm, pending, NULL);
	if (rv < 0)
	  {
	    ovpn_pending_connection_delete (pending_db, pending);
	    return rv;
	  }

	/*
	 * Actually send the packet out
	 * For TLS-Crypt-V2, use the per-client context
	 */
	ovpn_tls_crypt_t *tls_crypt_ptr = NULL;
	if (pending->client_tls_crypt)
	  {
	    tls_crypt_ptr = pending->client_tls_crypt;
	  }
	else if (inst->tls_crypt.enabled)
	  {
	    tls_crypt_ptr = &inst->tls_crypt;
	  }
	ovpn_tls_auth_t *tls_auth_ptr =
	  inst->tls_auth.enabled ? &inst->tls_auth : NULL;
	rv = ovpn_handshake_send_pending_packets (vm, pending, dst_addr,
						  dst_port, is_ip6,
						  tls_auth_ptr, tls_crypt_ptr);
	if (rv < 0)
	  {
	    ovpn_pending_connection_delete (pending_db, pending);
	    return rv;
	  }

	pending->last_activity = vlib_time_now (vm);
	break;
      }

    case OVPN_OP_CONTROL_SOFT_RESET_V1:
      {
	/*
	 * Client is requesting a rekey
	 * Only valid for established peers
	 */
	if (!peer)
	  {
	    /* No established peer for soft reset */
	    return -20;
	  }

	if (peer->state != OVPN_PEER_STATE_ESTABLISHED)
	  {
	    /* Peer not in correct state for rekey */
	    return -21;
	  }

	/* Start rekey process */
	rv = ovpn_peer_start_rekey (vm, peer, inst->ptls_ctx, key_id);
	if (rv < 0)
	  {
	    return -22;
	  }

	/* Record that client initiated the rekey */
	peer->rekey_initiated = 0; /* We're responding to client's rekey */

	/* Record packet ID for ACK */
	ovpn_reliable_ack_acknowledge_packet_id (&peer->tls_ctx->recv_ack,
						 packet_id);

	/* Send SOFT_RESET response with ACK */
	{
	  ovpn_reli_buffer_t *buf;
	  buf = ovpn_reliable_get_buf_output_sequenced (
	    peer->tls_ctx->send_reliable);
	  if (buf)
	    {
	      ovpn_buf_init (buf, 128);
	      ovpn_reliable_mark_active_outgoing (
		peer->tls_ctx->send_reliable, buf,
		OVPN_OP_CONTROL_SOFT_RESET_V1);
	    }
	}

	/* Send response */
	{
	  /* Use peer's per-client TLS-Crypt (V2) if available, else instance */
	  ovpn_tls_crypt_t *tls_crypt_ptr =
	    (peer->tls_ctx && peer->tls_ctx->tls_crypt) ?
	      peer->tls_ctx->tls_crypt :
	      (inst->tls_crypt.enabled ? &inst->tls_crypt : NULL);
	  ovpn_tls_auth_t *tls_auth_ptr =
	    inst->tls_auth.enabled ? &inst->tls_auth : NULL;
	  ovpn_handshake_send_peer_packets (
	    vm, peer, dst_addr, dst_port, is_ip6, tls_auth_ptr, tls_crypt_ptr);
	}

	rv = 1;
	break;
      }

    case OVPN_OP_ACK_V1:
      {
	/*
	 * Handle ACKs for:
	 * 1. Pending connections (acknowledging our HARD_RESET_SERVER)
	 * 2. Peers in TLS handshake (acknowledging our TLS packets)
	 */

	/* First check if this is an ACK for a peer in TLS handshake */
	if (peer && peer->tls_ctx && peer->tls_ctx->send_reliable)
	  {
	    /* Verify ACK is for our session */
	    if (ovpn_session_id_equal (&ack_session_id, &peer->session_id))
	      {
		/* Process ACKs - remove acknowledged packets */
		for (u32 i = 0; i < ack.len; i++)
		  ovpn_reliable_send_purge (peer->tls_ctx->send_reliable,
					    &ack);
		rv = 0;
	      }
	    break;
	  }

	if (!pending)
	  {
	    /* No pending connection or peer for this ACK */
	    return -4;
	  }

	if (pending->state != OVPN_PENDING_STATE_SENT_RESET)
	  {
	    /* Not expecting ACK in this state */
	    return -5;
	  }

	/* Verify ACK is for our session */
	if (!ovpn_session_id_equal (&ack_session_id,
				    &pending->local_session_id))
	  {
	    return -6;
	  }

	/* Process ACKs - remove acknowledged packets from send_reliable */
	ovpn_reliable_send_purge (pending->send_reliable, &ack);

	/* Check if our HARD_RESET_SERVER was acknowledged */
	if (ovpn_reliable_empty (pending->send_reliable))
	  {
	    /*
	     * All our packets were ACKed - connection established!
	     * Now create the real peer and start TLS handshake
	     */
	    u32 peer_id;

	    pending->state = OVPN_PENDING_STATE_ESTABLISHED;

	    /* Create the real peer */
	    peer_id = ovpn_peer_create (peer_db, src_addr, src_port);
	    if (peer_id == ~0)
	      {
		ovpn_pending_connection_delete (pending_db, pending);
		return -7;
	      }

	    peer = ovpn_peer_get (peer_db, peer_id);
	    if (!peer)
	      {
		ovpn_pending_connection_delete (pending_db, pending);
		return -8;
	      }

	    /* Copy session IDs to peer */
	    ovpn_session_id_copy (&peer->session_id,
				  &pending->local_session_id);
	    ovpn_session_id_copy (&peer->remote_session_id,
				  &pending->remote_session_id);

	    /* Set peer state to handshake */
	    peer->state = OVPN_PEER_STATE_HANDSHAKE;

	    /* Initialize TLS context for this peer */
	    if (inst->ptls_ctx)
	      {
		int tls_rv =
		  ovpn_peer_tls_init (peer, inst->ptls_ctx, pending->key_id);
		if (tls_rv < 0)
		  {
		    ovpn_peer_delete (peer_db, peer_id);
		    ovpn_pending_connection_delete (pending_db, pending);
		    return -9;
		  }

		/*
		 * Transfer per-client TLS-Crypt context (TLS-Crypt-V2)
		 * This must happen after TLS init and before pending is
		 * deleted.
		 */
		if (pending->client_tls_crypt && peer->tls_ctx)
		  {
		    peer->tls_ctx->tls_crypt = pending->client_tls_crypt;
		    pending->client_tls_crypt = NULL; /* Prevent double-free */
		  }
	      }

	    /* Clean up pending connection */
	    ovpn_pending_connection_delete (pending_db, pending);

	    rv = 1; /* Success - peer created */
	  }
	break;
      }

    case OVPN_OP_CONTROL_V1:
      {
	/*
	 * P_CONTROL_V1 packet handling depends on peer state:
	 *
	 * 1. HANDSHAKE/REKEYING state:
	 *    - TLS handshake data that must be processed in order
	 *    - Use reliable layer to buffer out-of-order packets
	 *
	 * 2. ESTABLISHED state:
	 *    - Control messages like PUSH_REQUEST, ping, etc.
	 *    - Use TLS context for encrypt/decrypt
	 */
	u8 *tls_data;
	u32 tls_len;

	/* Handle peer with TLS context (HANDSHAKE, REKEYING, or ESTABLISHED)
	 */
	if (peer && peer->tls_ctx)
	  {
	    ovpn_peer_tls_t *tls_ctx = peer->tls_ctx;
	    ovpn_reliable_t *recv_rel = tls_ctx->recv_reliable;

	    /* Record packet ID for ACK */
	    ovpn_reliable_ack_acknowledge_packet_id (&tls_ctx->recv_ack,
						     packet_id);

	    /* Check for replay/duplicate */
	    if (!ovpn_reliable_not_replay (recv_rel, packet_id))
	      {
		/* Duplicate or old packet - ignore but still ACK */
		rv = 0;
		break;
	      }

	    /* Check if packet would break sequentiality (too far ahead) */
	    if (!ovpn_reliable_wont_break_sequentiality (recv_rel, packet_id))
	      {
		/* Packet ID too far ahead - cannot buffer */
		rv = -14;
		break;
	      }

	    /* Store packet in receive reliable buffer */
	    ovpn_reli_buffer_t *recv_buf = ovpn_reliable_get_buf (recv_rel);
	    if (!recv_buf)
	      {
		/* No space in receive buffer */
		rv = -15;
		break;
	      }

	    /* Copy payload to reliable buffer */
	    tls_data = OVPN_BPTR (&buf);
	    tls_len = OVPN_BLEN (&buf);
	    ovpn_buf_init (recv_buf, 0);
	    ovpn_buf_write (recv_buf, tls_data, tls_len);

	    /* Mark as active incoming */
	    ovpn_reliable_mark_active_incoming (recv_rel, recv_buf, packet_id,
						opcode);

	    /*
	     * Process all in-sequence packets from the receive buffer
	     */
	    ovpn_reliable_entry_t *entry;
	    while ((entry = ovpn_reliable_get_entry_sequenced (recv_rel)) !=
		   NULL)
	      {
		ovpn_reli_buffer_t *seq_buf = ovpn_buf_get (entry->buf_index);
		tls_data = OVPN_BPTR (seq_buf);
		tls_len = OVPN_BLEN (seq_buf);

		/* Process TLS data */
		rv = ovpn_peer_tls_process (peer, tls_data, tls_len);

		/* Mark entry as processed and advance sequence */
		ovpn_reliable_mark_deleted (recv_rel, seq_buf);

		/* Send response if TLS produced data */
		if (rv > 0)
		  {
		    /* Use peer's per-client TLS-Crypt (V2) if available */
		    ovpn_tls_crypt_t *tls_crypt_ptr =
		      (peer->tls_ctx && peer->tls_ctx->tls_crypt) ?
			peer->tls_ctx->tls_crypt :
			(inst->tls_crypt.enabled ? &inst->tls_crypt : NULL);
		    ovpn_tls_auth_t *tls_auth_ptr =
		      inst->tls_auth.enabled ? &inst->tls_auth : NULL;
		    ovpn_handshake_send_peer_packets (
		      vm, peer, dst_addr, dst_port, is_ip6, tls_auth_ptr,
		      tls_crypt_ptr);
		  }

		/*
		 * For ESTABLISHED peers, check if decrypted data is a
		 * control message (PUSH_REQUEST, ping, etc.)
		 */
		if (peer->state == OVPN_PEER_STATE_ESTABLISHED)
		  {
		    u8 *ctrl_data = OVPN_BPTR (&tls_ctx->plaintext_read_buf);
		    u32 ctrl_len = OVPN_BLEN (&tls_ctx->plaintext_read_buf);

		    if (ctrl_len > 0)
		      {
			u8 response[512];
			u32 response_len = sizeof (response);

			int msg_rv = ovpn_control_message_process (
			  vm, peer, ctrl_data, ctrl_len, response,
			  &response_len);

			/* Clear the read buffer - use reset_len to preserve
			 * capacity */
			ovpn_reli_buf_reset_len (&tls_ctx->plaintext_read_buf);

			if (msg_rv > 0 && response_len > 0)
			  {
			    /* Encrypt and send response */
			    ptls_buffer_t sendbuf;
			    ptls_buffer_init (&sendbuf, "", 0);

			    int send_rv = ptls_send (tls_ctx->tls, &sendbuf,
						     response, response_len);
			    if (send_rv == 0 && sendbuf.off > 0)
			      {
				ovpn_reli_buffer_t *out_buf =
				  ovpn_reliable_get_buf_output_sequenced (
				    tls_ctx->send_reliable);
				if (out_buf)
				  {
				    ovpn_buf_init (out_buf, 128);
				    ovpn_buf_write (out_buf, sendbuf.base,
						    sendbuf.off);
				    ovpn_reliable_mark_active_outgoing (
				      tls_ctx->send_reliable, out_buf,
				      OVPN_OP_CONTROL_V1);

				    ovpn_tls_auth_t *auth =
				      inst->tls_auth.enabled ?
					&inst->tls_auth :
					NULL;
				    /* Use peer's per-client TLS-Crypt (V2) */
				    ovpn_tls_crypt_t *crypt =
				      (peer->tls_ctx && peer->tls_ctx->tls_crypt)
					? peer->tls_ctx->tls_crypt
					: (inst->tls_crypt.enabled ?
					     &inst->tls_crypt :
					     NULL);
				    ovpn_handshake_send_peer_packets (
				      vm, peer, dst_addr, dst_port, is_ip6,
				      auth, crypt);
				  }
			      }
			    ptls_buffer_dispose (&sendbuf);
			  }
			rv = 1;
		      }
		    break; /* ESTABLISHED peer handled */
		  }

		/* Check if TLS handshake completed */
		if (ovpn_peer_tls_is_established (peer))
		  {
		    /*
		     * TLS handshake complete!
		     *
		     * Now we need to exchange Key Method 2 data over the
		     * encrypted TLS channel. The sequence is:
		     * 1. Client sends key_method_2 data (pre_master + randoms)
		     * 2. Server receives and sends its own randoms
		     * 3. Both sides derive keys from combined random material
		     *
		     * The decrypted Key Method 2 data is stored in
		     * tls_ctx->plaintext_read_buf by ovpn_peer_tls_process().
		     */

		    /* Try to read client's Key Method 2 data from decrypted
		     * plaintext buffer */
		    u8 *km_data = OVPN_BPTR (&tls_ctx->plaintext_read_buf);
		    u32 km_len = OVPN_BLEN (&tls_ctx->plaintext_read_buf);

		    if (!tls_ctx->key_method_received && km_len > 0)
		      {
			char *peer_opts = NULL;
			char *username = NULL;
			char *password = NULL;
			int km_rv = ovpn_key_method_2_read_with_auth (
			  km_data, km_len, tls_ctx->key_src2,
			  1 /* is_server */, &peer_opts, &username, &password);
			if (km_rv > 0)
			  {
			    int auth_ok = 1; /* Assume auth ok by default */


			    /*
			     * Authenticate user if auth-user-pass is required
			     */
			    if (inst->options.auth_user_pass_required)
			      {
				auth_ok = 0;

				if (username && password)
				  {
				    /*
				     * Try verification methods in order:
				     * 1. Management interface
				     * (management-client-auth)
				     * 2. Password file (auth-user-pass-file)
				     * 3. Accept all if no method configured
				     */
				    if (inst->options.management_client_auth)
				      {
					/*
					 * Async auth via management interface.
					 * Store credentials and set peer to
					 * PENDING_AUTH. Management will respond
					 * with client-auth or client-deny.
					 */
					ovpn_mgmt_t *mgmt =
					  ovpn_mgmt_get_by_instance (
					    inst->instance_id);
					if (mgmt && mgmt->is_active)
					  {
					    /* Store pending auth data */
					    vec_free (
					      peer->pending_auth_username);
					    peer->pending_auth_username =
					      (u8 *) username;
					    username = NULL;

					    vec_free (
					      peer->pending_auth_password);
					    peer->pending_auth_password =
					      (u8 *) password;
					    password = NULL;

					    peer->pending_auth_key_id = key_id;

					    /* Store peer_opts in tls_ctx */
					    tls_ctx->key_method_received = 1;
					    tls_ctx->peer_options = peer_opts;
					    peer_opts = NULL;

					    /* Send auth request to management
					     */
					    const char *cn = NULL;
					    if (peer->tls_ctx &&
						peer->tls_ctx
						  ->client_common_name)
					      cn = peer->tls_ctx
						     ->client_common_name;

					    ovpn_mgmt_send_client_auth_request (
					      mgmt, peer->peer_id, key_id, cn,
					      (const char *)
						peer->pending_auth_username,
					      src_addr, src_port);

					    /* Set state and return - handshake
					     * continues when auth response
					     * arrives */
					    peer->state =
					      OVPN_PEER_STATE_PENDING_AUTH;
					    rv = 1; /* Pending, not error */
					    break;
					  }
					else
					  {
					    /* Management not active, reject */
					  }
				      }
				    else if (inst->options.auth_user_pass_file)
				      {
					/* Verify against password file */
					int auth_rv = ovpn_verify_user_pass (
					  (const char *)
					    inst->options.auth_user_pass_file,
					  username, password);
					if (auth_rv == 0)
					  auth_ok = 1;
				      }
				    else
				      {
					/* No verification method configured -
					 * accept all */
					auth_ok = 1;
				      }
				  }
				else if (inst->options.auth_user_pass_optional)
				  {
				    /* Client didn't send credentials but
				     * they're optional */
				    auth_ok = 1;
				  }
				else
				  {
				    /* Auth required but not provided */
				  }
			      }

			    if (!auth_ok)
			      {
				/* Authentication failed - reject */
				if (username)
				  clib_mem_free (username);
				if (password)
				  {
				    ovpn_secure_zero_memory (
				      password, strlen (password));
				    clib_mem_free (password);
				  }
				if (peer_opts)
				  clib_mem_free (peer_opts);
				peer->state = OVPN_PEER_STATE_DEAD;
				rv = -14; /* Authentication failed */
				break;	  /* Exit while loop */
			      }

			    /* Store username for later use (e.g., CCD lookup)
			     */
			    if (username)
			      {
				/* Store in peer for later reference */
				vec_free (peer->username);
				peer->username = (u8 *) username;
				username = NULL; /* Ownership transferred */
			      }

			    /* Clear sensitive password from memory */
			    if (password)
			      {
				ovpn_secure_zero_memory (password,
							 strlen (password));
				clib_mem_free (password);
			      }

			    tls_ctx->key_method_received = 1;
			    tls_ctx->peer_options = peer_opts;

			    /* Clear the buffer after consuming Key Method 2 */
			    ovpn_reli_buf_reset_len (
			      &tls_ctx->plaintext_read_buf);

			    /*
			     * Negotiate data channel cipher from client
			     * options
			     *
			     * The client sends its supported ciphers via:
			     * 1. IV_CIPHERS=cipher1:cipher2:... (OpenVPN 2.5+)
			     * 2. cipher <name> in options string (legacy)
			     *
			     * If server has data-ciphers configured, negotiate
			     * the first mutually supported cipher. Otherwise,
			     * accept client's preferred cipher.
			     */
			    ovpn_cipher_alg_t negotiated_cipher =
			      OVPN_CIPHER_ALG_NONE;

			    if (peer_opts)
			      {
				/* Try to extract IV_CIPHERS first (modern
				 * clients) */
				char *iv_ciphers =
				  ovpn_options_string_extract_option (
				    peer_opts, "IV_CIPHERS");
				if (iv_ciphers)
				  {
				    /*
				     * IV_CIPHERS format:
				     * cipher1:cipher2:cipher3
				     *
				     * If server has data-ciphers configured,
				     * use negotiation to find mutually
				     * supported cipher. Server's preference
				     * order takes precedence.
				     */
				    if (inst->options.n_data_ciphers > 0)
				      {
					/* Use server's data-ciphers for
					 * negotiation */
					const char *negotiated_name =
					  ovpn_options_negotiate_cipher (
					    &inst->options, iv_ciphers);
					if (negotiated_name)
					  {
					    negotiated_cipher =
					      ovpn_crypto_cipher_alg_from_name (
						negotiated_name);
					  }
				      }
				    else
				      {
					/*
					 * No server data-ciphers configured,
					 * accept client's first supported
					 * cipher
					 */
					char *cipher_list = iv_ciphers;
					char *cipher_name;
					char *saveptr = NULL;

					while ((cipher_name =
						  strtok_r (cipher_list, ":",
							    &saveptr)) != NULL)
					  {
					    cipher_list = NULL;
					    ovpn_cipher_alg_t alg =
					      ovpn_crypto_cipher_alg_from_name (
						cipher_name);
					    if (alg != OVPN_CIPHER_ALG_NONE)
					      {
						negotiated_cipher = alg;
						break;
					      }
					  }
				      }
				    clib_mem_free (iv_ciphers);
				  }

				/* Fall back to legacy "cipher" option */
				if (negotiated_cipher == OVPN_CIPHER_ALG_NONE)
				  {
				    char *cipher_opt =
				      ovpn_options_string_extract_option (
					peer_opts, "cipher");
				    if (cipher_opt)
				      {
					negotiated_cipher =
					  ovpn_crypto_cipher_alg_from_name (
					    cipher_opt);
					clib_mem_free (cipher_opt);
				      }
				  }

				/* Check for key-derivation tls-ekm support */
				char *key_deriv =
				  ovpn_options_string_extract_option (
				    peer_opts, "key-derivation");
				if (key_deriv)
				  {
				    if (strcmp (key_deriv, "tls-ekm") == 0)
				      tls_ctx->use_tls_ekm = 1;
				    clib_mem_free (key_deriv);
				  }

				/* Parse client's key direction */
				char *keydir_str =
				  ovpn_options_string_extract_option (
				    peer_opts, "keydir");
				if (keydir_str)
				  {
				    tls_ctx->client_keydir = atoi (keydir_str);
				    clib_mem_free (keydir_str);
				  }
				else
				  {
				    /* Use configured keydir or default */
				    if (inst->options.data_channel_keydir ==
					255)
				      {
					/* Auto: default to keydir 1 (inverse)
					 */
					tls_ctx->client_keydir = 1;
				      }
				    else
				      {
					tls_ctx->client_keydir =
					  inst->options.data_channel_keydir;
				      }
				  }

				/*
				 * Parse client's requested virtual IP
				 * (ifconfig)
				 *
				 * OpenVPN clients can specify their desired
				 * virtual IP using the ifconfig option in
				 * their options string. If valid and within
				 * pool range, honor the request.
				 */
				ip_address_t client_virtual_ip;
				int ifconfig_rv =
				  ovpn_options_parse_client_ifconfig (
				    peer_opts, &client_virtual_ip);
				if (ifconfig_rv == 0)
				  {
				    /*
				     * Client requested a specific virtual IP
				     * Validate against pool range if
				     * configured
				     */
				    int ip_valid = ovpn_options_ip_in_pool (
				      &client_virtual_ip,
				      &inst->options.pool_start,
				      &inst->options.pool_end);

				    if (ip_valid)
				      {
					/* Try to assign the requested IP */
					int set_rv = ovpn_peer_set_virtual_ip (
					  peer_db, peer, &client_virtual_ip);
					if (set_rv == 0)
					  {
					    /* Successfully assigned client's
					     * requested IP */
					  }
					/* If set_rv < 0, IP is already in use
					 * - will fall back to pool allocation
					 * below */
				      }
				  }
			      }

			    /*
			     * If peer doesn't have a virtual IP yet (client
			     * didn't request one, or request was
			     * invalid/unavailable), allocate from pool
			     */
			    /* Check if pool is configured (IP address is
			     * non-zero) */
			    int pool_configured =
			      (inst->options.pool_start.ip.ip4.as_u32 != 0 ||
			       !ip6_address_is_zero (
				 &inst->options.pool_start.ip.ip6));
			    if (!peer->virtual_ip_set && pool_configured)
			      {
				int alloc_rv =
				  ovpn_peer_allocate_virtual_ip_with_persist (
				    peer_db, peer, &inst->options.pool_start,
				    &inst->options.pool_end,
				    tls_ctx->client_common_name);
				if (alloc_rv < 0)
				  {
				  }
				else
				  {
				    u8 ip_str[INET_ADDRSTRLEN];
				    inet_ntop (
				      AF_INET, &peer->virtual_ip.ip.ip4,
				      (char *) ip_str, sizeof (ip_str));
				  }
			      }

			    /*
			     * Use negotiated cipher if valid, otherwise fall
			     * back to server's configured cipher
			     */
			    if (negotiated_cipher != OVPN_CIPHER_ALG_NONE)
			      tls_ctx->negotiated_cipher_alg =
				negotiated_cipher;
			    else
			      tls_ctx->negotiated_cipher_alg =
				inst->cipher_alg;
			  }
		      }

		    /* Send our Key Method 2 data if not already sent */
		    if (!tls_ctx->key_method_sent &&
			tls_ctx->key_method_received)
		      {
			u8 km_buf[512];
			char options_buf[512];

			/* Build server options string with negotiated cipher
			 * and virtual IP */
			const char *cipher_name = ovpn_cipher_alg_to_name (
			  tls_ctx->negotiated_cipher_alg);

			/*
			 * Pass virtual IP if assigned to this peer
			 * The virtual_ip field should have been set during IP
			 * pool allocation
			 */
			int opt_len = ovpn_options_string_build_server (
			  options_buf, sizeof (options_buf), cipher_name,
			  tls_ctx->use_tls_ekm, peer->peer_id,
			  peer->virtual_ip_set ? &peer->virtual_ip : NULL,
			  NULL /* netmask - use default */);

			int km_len = ovpn_key_method_2_write (
			  km_buf, sizeof (km_buf), tls_ctx->key_src2,
			  peer->session_id.id, 1 /* is_server */,
			  opt_len > 0 ? options_buf : NULL);

			if (km_len > 0)
			  {
			    /* Send Key Method 2 data over TLS */
			    ptls_buffer_t sendbuf;
			    ptls_buffer_init (&sendbuf, "", 0);

			    int tls_rv = ptls_send (tls_ctx->tls, &sendbuf,
						    km_buf, km_len);
			    if (tls_rv == 0 && sendbuf.off > 0)
			      {
				/* Queue TLS data for sending */
				ovpn_reli_buffer_t *out_buf =
				  ovpn_reliable_get_buf_output_sequenced (
				    tls_ctx->send_reliable);
				if (out_buf)
				  {
				    ovpn_buf_init (out_buf, 128);
				    ovpn_buf_write (out_buf, sendbuf.base,
						    sendbuf.off);
				    ovpn_reliable_mark_active_outgoing (
				      tls_ctx->send_reliable, out_buf,
				      OVPN_OP_CONTROL_V1);
				    tls_ctx->key_method_sent = 1;

				    /* Send the queued Key Method 2 data */
				    {
				      ovpn_tls_auth_t *km_tls_auth =
					inst->tls_auth.enabled ?
					  &inst->tls_auth :
					  NULL;
				      /* Use peer's per-client TLS-Crypt (V2) */
				      ovpn_tls_crypt_t *km_tls_crypt =
					(peer->tls_ctx &&
					 peer->tls_ctx->tls_crypt) ?
					  peer->tls_ctx->tls_crypt :
					  (inst->tls_crypt.enabled ?
					     &inst->tls_crypt :
					     NULL);
				      ovpn_handshake_send_peer_packets (
					vm, peer, dst_addr, dst_port, is_ip6,
					km_tls_auth, km_tls_crypt);
				    }
				  }
			      }
			    ptls_buffer_dispose (&sendbuf);
			  }
		      }

		    /* Check if key exchange is complete */
		    if (tls_ctx->key_method_sent &&
			tls_ctx->key_method_received)
		      {
			/*
			 * Key Method 2 exchange complete!
			 * Now derive data channel keys.
			 */
			ovpn_cipher_alg_t cipher_alg =
			  (ovpn_cipher_alg_t) tls_ctx->negotiated_cipher_alg;

			if (peer->state == OVPN_PEER_STATE_REKEYING)
			  {
			    /*
			     * Rekey TLS handshake complete
			     * Install new keys and return to ESTABLISHED
			     */
			    int key_rv;

			    key_rv = ovpn_peer_complete_rekey (
			      vm, peer_db, peer, cipher_alg);
			    if (key_rv == 0)
			      {
				rv = 3; /* Rekey complete */
			      }
			    else
			      {
				/* Rekey failed - peer stays in REKEYING state
				 */
				peer->state = OVPN_PEER_STATE_ESTABLISHED;
				ovpn_peer_tls_free (peer);
				rv = -13;
			      }
			  }
			else
			  {
			    /*
			     * Initial TLS handshake complete
			     * Derive data channel keys and transition to
			     * ESTABLISHED
			     */
			    ovpn_key_material_t keys;
			    int key_rv;

			    key_rv = ovpn_derive_data_channel_keys_v2 (
			      tls_ctx->tls, tls_ctx->key_src2,
			      peer->remote_session_id.id, peer->session_id.id,
			      &keys, cipher_alg, 1 /* is_server */,
			      tls_ctx->use_tls_ekm, tls_ctx->client_keydir);

			    if (key_rv == 0)
			      {
				/* Set up crypto context for this peer */
				key_rv = ovpn_peer_set_key (
				  vm, peer_db, peer, OVPN_KEY_SLOT_PRIMARY,
				  cipher_alg, &keys, tls_ctx->key_id,
				  inst->options.replay_window);

				/* Enable DATA_V2 format for TLS mode - OpenVPN
				 * clients expect it */
				if (key_rv == 0)
				  {
				    peer->keys[OVPN_KEY_SLOT_PRIMARY]
				      .crypto.use_data_v2 = 1;
				  }
			      }

			    if (key_rv == 0)
			      {
				/*
				 * Check max-clients limit before establishing
				 */
				if (inst->options.max_clients > 0 &&
				    peer_db->n_established >=
				      inst->options.max_clients)
				  {
				    peer->state = OVPN_PEER_STATE_DEAD;
				    rv = -14; /* Max clients reached */
				    ovpn_secure_zero_memory (&keys,
							     sizeof (keys));
				    break;
				  }

				f64 now = vlib_time_now (vm);

				peer->state = OVPN_PEER_STATE_ESTABLISHED;
				peer_db->n_established++;
				peer->established_time = now;
				peer->current_key_slot = OVPN_KEY_SLOT_PRIMARY;

				/*
				 * Load per-client config from
				 * client-config-dir if configured. Use the
				 * Common Name (CN) extracted from client
				 * certificate for lookup.
				 */
				if (inst->options.client_config_dir)
				  {
				    const char *client_id = NULL;
				    char fallback_id[32];

				    /*
				     * Try to get CN from TLS certificate
				     * (stored in ptls user data during
				     * verification)
				     */
				    if (peer->tls_ctx && peer->tls_ctx->tls)
				      {
					void **data_ptr = ptls_get_data_ptr (
					  peer->tls_ctx->tls);
					if (data_ptr && *data_ptr)
					  {
					    client_id =
					      (const char *) *data_ptr;
					    /* Store CN in peer for later use
					     */
					    if (peer->tls_ctx
						  ->client_common_name)
					      clib_mem_free (
						peer->tls_ctx
						  ->client_common_name);
					    peer->tls_ctx->client_common_name =
					      clib_mem_alloc (
						strlen (client_id) + 1);
					    if (peer->tls_ctx
						  ->client_common_name)
					      strcpy (peer->tls_ctx
							->client_common_name,
						      client_id);

					    /*
					     * Handle duplicate-cn:
					     * If disabled, disconnect existing
					     * peer with same CN
					     */
					    if (!inst->options.duplicate_cn)
					      {
						u32 old_peer_id =
						  ovpn_peer_lookup_by_cn (
						    peer_db, client_id);
						if (old_peer_id != ~0 &&
						    old_peer_id !=
						      peer->peer_id)
						  {
						    ovpn_peer_t *old_peer =
						      ovpn_peer_get (
							peer_db, old_peer_id);
						    if (old_peer)
						      old_peer->state =
							OVPN_PEER_STATE_DEAD;
						  }
					      }

					    /* Add this peer to CN hash */
					    ovpn_peer_cn_hash_add (
					      peer_db, client_id,
					      peer->peer_id);
					  }
				      }

				    /* Fallback to peer_X if no CN available */
				    if (!client_id)
				      {
					snprintf (fallback_id,
						  sizeof (fallback_id),
						  "peer_%u", peer->peer_id);
					client_id = fallback_id;
				      }

				    peer->client_push_opts =
				      ovpn_peer_load_client_config (
					(const char *)
					  inst->options.client_config_dir,
					client_id);

				    /* Check if client is disabled */
				    if (peer->client_push_opts &&
					peer->client_push_opts->disable)
				      {
					ovpn_peer_push_options_free (
					  peer->client_push_opts);
					peer->client_push_opts = NULL;
					peer->state = OVPN_PEER_STATE_DEAD;
					rv = -15; /* Client disabled */
					ovpn_secure_zero_memory (&keys,
								 sizeof (keys));
					break;
				      }

				    /* ccd-exclusive: require CCD file */
				    if (inst->options.ccd_exclusive &&
					!peer->client_push_opts)
				      {
					peer->state = OVPN_PEER_STATE_DEAD;
					rv = -16; /* No CCD file (ccd-exclusive)
					           */
					ovpn_secure_zero_memory (&keys,
								 sizeof (keys));
					break;
				      }

				    /* Apply ifconfig-push if set */
				    if (peer->client_push_opts &&
					peer->client_push_opts
					  ->has_ifconfig_push)
				      {
					peer->virtual_ip =
					  peer->client_push_opts
					    ->ifconfig_push_ip;
					peer->virtual_ip_set = 1;
				      }
				  }

				/* Set up rekey timer from options */
				if (inst->options.renegotiate_seconds > 0)
				  {
				    peer->rekey_interval =
				      (f64) inst->options.renegotiate_seconds;
				    peer->next_rekey_time =
				      now + peer->rekey_interval;
				  }

				/* Build rewrite for output path (IP/UDP
				 * headers) */
				ovpn_peer_build_rewrite (peer, dst_addr,
							 dst_port);

				/*
				 * Create neighbor adjacency and FIB entry for
				 * peer's virtual IP. For NBMA interfaces like
				 * OpenVPN, VPP doesn't automatically create
				 * adjacencies or /32 host routes - we must
				 * explicitly create both.
				 */
				if (peer->virtual_ip_set)
				  {
				    ip46_address_t nh;
				    fib_protocol_t fproto;

				    fproto = ip_address_to_46 (
				      &peer->virtual_ip, &nh);

				    /*
				     * Create neighbor adjacency - this
				     * triggers update_adjacency callback which
				     * converts it to a midchain adjacency
				     */
				    (void) adj_nbr_add_or_lock (
				      fproto, fib_proto_to_link (fproto), &nh,
				      peer->sw_if_index);

				    /*
				     * Add /32 host route for peer's virtual
				     * IP. For NBMA interfaces, the connected
				     * route (e.g. 10.8.0.0/24) uses dpo-drop.
				     * We need an explicit /32 route to reach
				     * the peer.
				     */
				    fib_prefix_t pfx;
				    clib_memset (&pfx, 0, sizeof (pfx));
				    pfx.fp_proto = fproto;
				    pfx.fp_len =
				      (fproto == FIB_PROTOCOL_IP4) ? 32 : 128;
				    pfx.fp_addr = nh;

				    u32 fib_index =
				      fib_table_get_index_for_sw_if_index (
					fproto, peer->sw_if_index);

				    ovpn_main_t *omp = &ovpn_main;
				    fib_table_entry_path_add (
				      fib_index, &pfx, omp->fib_src_hi,
				      FIB_ENTRY_FLAG_NONE,
				      fib_proto_to_dpo (fproto), &nh,
				      peer->sw_if_index, ~0, /* fib_index */
				      1,		     /* weight */
				      NULL,		     /* label stack */
				      FIB_ROUTE_PATH_FLAG_NONE);
				  }

				/*
				 * Update adjacencies on the interface
				 * This associates the peer with any
				 * adjacencies pointing to its virtual IP,
				 * enabling TX path
				 */
				ovpn_if_update_adj_for_peer (
				  peer->sw_if_index);

				/* Send connect event to API subscribers */
				ovpn_api_send_peer_event (inst->instance_id,
							  peer,
							  OVPN_PEER_EVENT_CONNECTED);

				/*
				 * Keep TLS context alive for control messages
				 * (PUSH_REQUEST/PUSH_REPLY, ping, etc.)
				 * It will be freed when peer is deleted.
				 *
				 * However, key_src2 contains sensitive
				 * pre-master secrets and is no longer needed
				 * after key derivation - free it now to
				 * prevent memory leak.
				 */
				if (tls_ctx->key_src2)
				  {
				    ovpn_key_source2_free (tls_ctx->key_src2);
				    tls_ctx->key_src2 = NULL;
				  }

				rv = 2; /* Handshake complete */

				/* Securely clear key material and exit loop */
				ovpn_secure_zero_memory (&keys, sizeof (keys));
				break; /* Exit while loop */
			      }
			    else
			      {
				/* Key derivation failed */
				peer->state = OVPN_PEER_STATE_DEAD;
				rv = -12;
			      }

			    /* Securely clear key material */
			    ovpn_secure_zero_memory (&keys, sizeof (keys));
			  }
		      }
		  }
	      } /* end while (get_entry_sequenced) */

	    break;
	  }

	/* Check pending connection */
	if (!pending)
	  {
	    return -10;
	  }

	/* For pending connections, we shouldn't receive CONTROL_V1 yet */
	return -11;
      }

    case OVPN_OP_CONTROL_WKC_V1:
      {
	/*
	 * P_CONTROL_WKC_V1 - Wrapped Client Key packet
	 *
	 * This packet type is used in TLS-Crypt-V2 stateless server mode.
	 * When the server uses HMAC cookies (stateless), the client
	 * needs to resend the WKc blob in this separate packet type.
	 *
	 * Packet format:
	 *   [opcode+keyid] [session_id] [WKc blob]
	 *
	 * The WKc is NOT tls-crypt wrapped in this case - it's sent in clear
	 * so the server can unwrap it and establish the per-client key.
	 */
	if (!inst->tls_crypt_v2.enabled)
	  {
	    /* TLS-Crypt-V2 not enabled */
	    return -20;
	  }

	/* Check if we have a pending connection */
	if (!pending)
	  {
	    /* No pending connection for WKC packet */
	    return -21;
	  }

	/* Check if this pending connection already has a client key */
	if (pending->client_tls_crypt)
	  {
	    /* Already have client key, ignore duplicate WKC */
	    break;
	  }

	/*
	 * Extract the WKc blob from the packet
	 * After opcode and session_id, the rest is the WKc blob
	 */
	u8 *wkc_data = OVPN_BPTR (&buf);
	u32 wkc_data_len = OVPN_BLEN (&buf);

	if (wkc_data_len < OVPN_TLS_CRYPT_V2_MIN_WKC_LEN)
	  {
	    return -22; /* WKc too short */
	  }

	ovpn_tls_crypt_v2_client_key_t client_key;

	/* Unwrap the client key */
	rv = ovpn_tls_crypt_v2_unwrap_client_key (
	  &inst->tls_crypt_v2, wkc_data, wkc_data_len, &client_key);
	if (rv < 0)
	  {
	    return -23; /* Failed to unwrap client key */
	  }

	/* Create per-client TLS-Crypt context */
	ovpn_tls_crypt_t *client_ctx =
	  clib_mem_alloc (sizeof (ovpn_tls_crypt_t));
	rv = ovpn_tls_crypt_v2_client_key_to_tls_crypt (
	  &client_key, client_ctx, 1 /* is_server */);
	ovpn_tls_crypt_v2_client_key_free (&client_key);

	if (rv < 0)
	  {
	    clib_mem_free (client_ctx);
	    return -24; /* Failed to create client TLS-Crypt context */
	  }

	/* Set time_backtrack from instance options for replay protection */
	if (inst->options.replay_protection)
	  client_ctx->time_backtrack = inst->options.replay_time;

	/* Store the client context in pending connection */
	pending->client_tls_crypt = client_ctx;
	pending->is_tls_crypt_v2 = 1;

	rv = 0; /* Success */
	break;
      }

    default:
      /* Unknown or unsupported opcode for handshake */
      return -10;
    }

  return rv;
}

/*
 * OpenVPN ping string - magic 16-byte pattern for keepalive
 */
const u8 ovpn_ping_string[OVPN_PING_STRING_SIZE] = {
  0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
  0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48
};

/*
 * Build PUSH_REPLY message for a peer
 *
 * Format: "PUSH_REPLY,option1,option2,...,END"
 *
 * Common options:
 *   - route <network> <netmask> [gateway]
 *   - route-gateway <gateway>
 *   - ifconfig <local> <remote>
 *   - dhcp-option DNS <server>
 *   - redirect-gateway [flags]
 *   - ping <seconds>
 *   - ping-restart <seconds>
 *   - peer-id <id>
 */
int
ovpn_build_push_reply (ovpn_peer_t *peer, char *buf, u32 buf_len)
{
  /* Get instance from peer's sw_if_index */
  ovpn_instance_t *inst = ovpn_instance_get_by_sw_if_index (peer->sw_if_index);
  int offset = 0;
  int written;
  ovpn_peer_push_options_t *client_opts = peer->client_push_opts;

  if (!buf || buf_len < 64 || !inst)
    return -1;

  /* Start with PUSH_REPLY */
  written = snprintf (buf + offset, buf_len - offset, "PUSH_REPLY");
  if (written < 0 || (u32) written >= buf_len - offset)
    return -1;
  offset += written;

  /*
   * Add ifconfig - prioritize in this order:
   * 1. ifconfig-push from client-config-dir
   * 2. Virtual IP assigned from pool
   */
  if (client_opts && client_opts->has_ifconfig_push)
    {
      /* Use ifconfig-push from per-client config */
      u8 ip_str[INET_ADDRSTRLEN];
      u8 mask_str[INET_ADDRSTRLEN];

      inet_ntop (AF_INET, &client_opts->ifconfig_push_ip.ip.ip4,
		 (char *) ip_str, sizeof (ip_str));
      inet_ntop (AF_INET, &client_opts->ifconfig_push_netmask.ip.ip4,
		 (char *) mask_str, sizeof (mask_str));

      written = snprintf (buf + offset, buf_len - offset, ",ifconfig %s %s",
			  ip_str, mask_str);
      if (written < 0 || (u32) written >= buf_len - offset)
	return -2;
      offset += written;
    }
  else if (peer->virtual_ip_set && !ip_address_is_zero (&peer->virtual_ip))
    {
      /* Use pool-assigned virtual IP */
      if (peer->virtual_ip.version == AF_IP4)
	{
	  u8 ip_str[INET_ADDRSTRLEN];
	  inet_ntop (AF_INET, &peer->virtual_ip.ip.ip4, (char *) ip_str,
		     sizeof (ip_str));

	  /* TUN mode with topology subnet: ifconfig <local-ip> <netmask> */
	  written = snprintf (buf + offset, buf_len - offset,
			      ",ifconfig %s 255.255.255.0", ip_str);
	  if (written < 0 || (u32) written >= buf_len - offset)
	    return -2;
	  offset += written;
	}
      else
	{
	  u8 ip_str[INET6_ADDRSTRLEN];
	  inet_ntop (AF_INET6, &peer->virtual_ip.ip.ip6, (char *) ip_str,
		     sizeof (ip_str));

	  written = snprintf (buf + offset, buf_len - offset,
			      ",ifconfig-ipv6 %s/64 ::", ip_str);
	  if (written < 0 || (u32) written >= buf_len - offset)
	    return -2;
	  offset += written;
	}
    }

  /* Add peer-id for DATA_V2 format */
  written =
    snprintf (buf + offset, buf_len - offset, ",peer-id %u", peer->peer_id);
  if (written < 0 || (u32) written >= buf_len - offset)
    return -3;
  offset += written;

  /* Add ping/ping-restart for keepalive from configuration */
  u32 ping_interval =
    inst->options.keepalive_ping > 0 ? inst->options.keepalive_ping : 10;
  u32 ping_timeout =
    inst->options.keepalive_timeout > 0 ? inst->options.keepalive_timeout : 60;

  written = snprintf (buf + offset, buf_len - offset,
		      ",ping %u,ping-restart %u", ping_interval, ping_timeout);
  if (written < 0 || (u32) written >= buf_len - offset)
    return -4;
  offset += written;

  /* Add topology setting (subnet mode for TUN) */
  written = snprintf (buf + offset, buf_len - offset, ",topology subnet");
  if (written < 0 || (u32) written >= buf_len - offset)
    return -5;
  offset += written;

  /*
   * Add configured push options from instance options
   * Now uses per-client push options for filtering/overriding:
   *   - push-reset: Skip all inherited global options
   *   - push-remove: Filter out matching global options
   *   - Per-client push options are appended
   *
   * This includes:
   *   - DHCP options (DNS, WINS, DOMAIN, etc.)
   *   - Push routes
   *   - redirect-gateway
   *   - Custom push options
   */
  if (inst->options.n_dhcp_options > 0 || inst->options.n_push_routes > 0 ||
      inst->options.n_push_options > 0 || inst->options.redirect_gateway ||
      (client_opts && client_opts->n_push_options > 0))
    {
      char push_buf[2048];
      int push_len = ovpn_options_build_push_reply_for_peer (
	&inst->options, client_opts, push_buf, sizeof (push_buf));
      if (push_len > 0)
	{
	  written = snprintf (buf + offset, buf_len - offset, ",%s", push_buf);
	  if (written > 0 && (u32) written < buf_len - offset)
	    offset += written;
	}
    }

  /* Null terminate */
  if ((u32) offset < buf_len)
    buf[offset] = '\0';

  return offset;
}

/*
 * Process control channel message (after TLS decryption)
 *
 * These messages are plaintext strings sent over the encrypted TLS channel.
 * After the TLS handshake and Key Method 2 exchange, the client may send
 * additional control messages like PUSH_REQUEST.
 */
int
ovpn_control_message_process (vlib_main_t *vm, ovpn_peer_t *peer,
			      const u8 *data, u32 len, u8 *response,
			      u32 *response_len)
{
  /* Check for PUSH_REQUEST */
  if (len >= sizeof (OVPN_MSG_PUSH_REQUEST) - 1 &&
      clib_memcmp (data, OVPN_MSG_PUSH_REQUEST,
		   sizeof (OVPN_MSG_PUSH_REQUEST) - 1) == 0)
    {
      /*
       * Client is requesting pushed configuration options
       * Build and send PUSH_REPLY
       */
      int reply_len =
	ovpn_build_push_reply (peer, (char *) response, *response_len);
      if (reply_len > 0)
	{
	  /* Include null terminator - OpenVPN expects it */
	  *response_len = reply_len + 1;
	  return 1; /* Response should be sent */
	}
      return -1; /* Failed to build reply */
    }

  /* Check for ping (magic byte pattern) */
  if (ovpn_is_ping_packet (data, len))
    {
      /*
       * Respond with the same ping pattern (echo)
       * This keeps the connection alive
       */
      if (*response_len >= OVPN_PING_STRING_SIZE)
	{
	  clib_memcpy_fast (response, ovpn_ping_string, OVPN_PING_STRING_SIZE);
	  *response_len = OVPN_PING_STRING_SIZE;
	  return 1; /* Response should be sent */
	}
      return 0; /* No space for response */
    }

  /* Check for OCC string (Options Compatibility Check) */
  if (len >= sizeof (OVPN_OCC_STRING) - 1 &&
      clib_memcmp (data, OVPN_OCC_STRING, sizeof (OVPN_OCC_STRING) - 1) == 0)
    {
      /* OCC messages are informational, no response needed */
      return 0;
    }

  /* Unknown message - no response */
  return 0;
}

/*
 * Process control channel retransmission for an instance.
 * Checks all pending connections and established peers for control
 * packets that need retransmitting (timeout expired).
 *
 * This function uses force_send=0 so packets are only sent if their
 * retransmission timeout has naturally expired (exponential backoff).
 *
 * Returns total number of packets retransmitted.
 */
int
ovpn_control_channel_retransmit (vlib_main_t *vm, ovpn_instance_t *inst)
{
  int total_sent = 0;
  ovpn_pending_connection_t *pending;
  ovpn_peer_t *peer;

  if (!inst)
    return 0;

  /* Get TLS-Auth and TLS-Crypt pointers from instance */
  ovpn_tls_auth_t *tls_auth_ptr =
    inst->tls_auth.enabled ? &inst->tls_auth : NULL;
  ovpn_tls_crypt_t *tls_crypt_ptr =
    inst->tls_crypt.enabled ? &inst->tls_crypt : NULL;

  /* Determine IP version from instance configuration */
  u8 is_ip6 = (inst->local_addr.version == AF_IP6);

  /* Process all pending connections */
  pool_foreach (pending, inst->multi_context.pending_db.connections)
    {
      /* Use per-client TLS-Crypt if available (TLS-Crypt-V2) */
      ovpn_tls_crypt_t *pending_tls_crypt =
	pending->client_tls_crypt ? pending->client_tls_crypt : tls_crypt_ptr;

      /* Check if this pending connection has packets to retransmit */
      int sent = ovpn_handshake_send_pending_packets_ex (
	vm, pending, &inst->local_addr, inst->local_port, is_ip6, tls_auth_ptr,
	pending_tls_crypt, 0 /* don't force - only send if timeout expired */);

      if (sent > 0)
	{
	  total_sent += sent;
	  pending->last_activity = vlib_time_now (vm);
	}
    }

  /* Process all established peers */
  pool_foreach (peer, inst->multi_context.peer_db.peers)
    {
      /* Use peer's per-client TLS-Crypt (V2) if available */
      ovpn_tls_crypt_t *peer_tls_crypt =
	(peer->tls_ctx && peer->tls_ctx->tls_crypt) ? peer->tls_ctx->tls_crypt :
						      tls_crypt_ptr;

      /* Check if this peer has control packets to retransmit */
      int sent = ovpn_handshake_send_peer_packets_ex (
	vm, peer, &inst->local_addr, inst->local_port, is_ip6, tls_auth_ptr,
	peer_tls_crypt, 0 /* don't force - only send if timeout expired */);

      if (sent > 0)
	total_sent += sent;
    }

  return total_sent;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
