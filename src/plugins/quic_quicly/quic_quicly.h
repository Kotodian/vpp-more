/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_quic_quicly_h__
#define __included_quic_quicly_h__

#include <quic/quic.h>
#include <quic_quicly/ptls_certs.h>
#include <vnet/session/session.h>
#include <quicly.h>
#include <quicly/constants.h>
#include <quicly/defaults.h>
#include <picotls.h>
#include <picotls/openssl.h>

/* Taken from quicly.c */
#define QUICLY_QUIC_BIT 0x40

#define QUICLY_PACKET_TYPE_INITIAL                                            \
  (QUICLY_LONG_HEADER_BIT | QUICLY_QUIC_BIT | 0)
#define QUICLY_PACKET_TYPE_0RTT                                               \
  (QUICLY_LONG_HEADER_BIT | QUICLY_QUIC_BIT | 0x10)
#define QUICLY_PACKET_TYPE_HANDSHAKE                                          \
  (QUICLY_LONG_HEADER_BIT | QUICLY_QUIC_BIT | 0x20)
#define QUICLY_PACKET_TYPE_RETRY                                              \
  (QUICLY_LONG_HEADER_BIT | QUICLY_QUIC_BIT | 0x30)
#define QUICLY_PACKET_TYPE_BITMASK 0xf0

typedef struct quic_quicly_rx_packet_ctx_
{
#define _(type, name) type name;
  foreach_quic_rx_pkt_ctx_field
#undef _
    quicly_decoded_packet_t packet;
  u8 data[QUIC_MAX_PACKET_SIZE + QUIC_PACKET_TRANSFORM_MAX_EXTRA];
  union
  {
    struct sockaddr sa;
    struct sockaddr_in6 sa6;
  };
  socklen_t salen;
  session_dgram_hdr_t ph;
} quic_quicly_rx_packet_ctx_t;

#define QUIC_SESSION_CACHE_MAX_ENTRIES 4096

typedef struct quic_session_cache_entry_
{
  u8 id[32];
  u8 *data;
  u32 data_len;
} quic_session_cache_entry_t;

/* Multi-entry session ticket cache for TLS resumption / 0-RTT */
typedef struct quic_quicly_session_cache_
{
  ptls_encrypt_ticket_t super;
  quic_session_cache_entry_t *entries; /**< pool of cached tickets */
  clib_bihash_24_8_t id_hash;	       /**< session_id[0:24] -> pool index */
  u32 *evict_fifo;		       /**< FIFO ring of pool indices for eviction order */
  u32 evict_head;		       /**< next index to read from evict_fifo */
  u32 evict_count;		       /**< number of valid entries in fifo */
  clib_spinlock_t lock;
} quic_quicly_session_cache_t;

/* Address token context for 0-RTT resumption tokens (NEW_TOKEN frames) */
typedef struct quic_quicly_token_ctx_
{
  quicly_generate_resumption_token_t super;
  ptls_aead_context_t *aead_enc; /**< encrypt context for token generation */
  ptls_aead_context_t *aead_dec; /**< decrypt context for token validation */
} quic_quicly_token_ctx_t;

typedef struct quic_quicly_main_
{
  quic_main_t *qm;
  clib_bihash_16_8_t connection_hash; /**< quic connection id -> conn handle */
  /* to handle packets that do not use the server generated CID, src CID ->
   * conn handle, NOTE: we use only connected UDP for now */
  clib_bihash_24_8_t conn_accepting_hash;
  quic_quicly_session_cache_t session_cache;
  quic_quicly_token_ctx_t token_ctx;
  quicly_cid_plaintext_t *next_cid;
  quic_quicly_rx_packet_ctx_t **rx_packets;
  struct iovec **tx_packets;
  u8 **tx_bufs;
} quic_quicly_main_t;

extern quic_quicly_main_t quic_quicly_main;
extern quic_ctx_t *quic_quicly_get_conn_ctx (void *conn);
extern void quic_quicly_check_quic_session_connected (quic_ctx_t *ctx);

static_always_inline quic_ctx_t *
quic_quicly_get_quic_ctx (u32 ctx_index, u32 thread_index)
{
  return pool_elt_at_index (
    quic_wrk_ctx_get (quic_quicly_main.qm, thread_index)->ctx_pool, ctx_index);
}

static_always_inline quic_session_connected_t
quic_quicly_is_session_connected (quic_ctx_t *ctx)
{
  quic_session_connected_t session_connected = QUIC_SESSION_CONNECTED_NONE;

  if (quicly_connection_is_ready (ctx->conn))
    {
      session_connected = quicly_is_client (ctx->conn) ?
			    QUIC_SESSION_CONNECTED_CLIENT :
			    QUIC_SESSION_CONNECTED_SERVER;
    }

  return (session_connected);
}

#endif /* __included_quic_quicly_h__ */
