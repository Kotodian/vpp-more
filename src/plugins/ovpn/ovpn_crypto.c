/*
 * ovpn_crypto.c - OpenVPN data channel crypto implementation
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

#include <ovpn/ovpn_crypto.h>
#include <vnet/crypto/crypto.h>

/* Per-thread crypto data */
static ovpn_per_thread_crypto_t *ovpn_per_thread_crypto;

ovpn_per_thread_crypto_t *
ovpn_crypto_get_ptd (u32 thread_index)
{
  return &ovpn_per_thread_crypto[thread_index];
}

clib_error_t *
ovpn_crypto_init (vlib_main_t *vm)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 n_threads = tm->n_vlib_mains;

  vec_validate_aligned (ovpn_per_thread_crypto, n_threads - 1,
			CLIB_CACHE_LINE_BYTES);

  for (u32 i = 0; i < n_threads; i++)
    {
      ovpn_per_thread_crypto_t *ptd = &ovpn_per_thread_crypto[i];
      vec_validate_aligned (ptd->crypto_ops, 0, CLIB_CACHE_LINE_BYTES);
      vec_validate_aligned (ptd->chained_crypto_ops, 0, CLIB_CACHE_LINE_BYTES);
      vec_validate_aligned (ptd->chunks, 0, CLIB_CACHE_LINE_BYTES);
      vec_validate_aligned (ptd->ivs, 0, CLIB_CACHE_LINE_BYTES);
      vec_reset_length (ptd->crypto_ops);
      vec_reset_length (ptd->chained_crypto_ops);
      vec_reset_length (ptd->chunks);
      vec_reset_length (ptd->ivs);
    }

  return 0;
}

ovpn_cipher_alg_t
ovpn_crypto_cipher_alg_from_name (const char *name)
{
  if (!name)
    return OVPN_CIPHER_ALG_NONE;

  if (strncasecmp (name, "AES-128-GCM", 11) == 0)
    return OVPN_CIPHER_ALG_AES_128_GCM;
  if (strncasecmp (name, "AES-256-GCM", 11) == 0)
    return OVPN_CIPHER_ALG_AES_256_GCM;
  if (strncasecmp (name, "CHACHA20-POLY1305", 17) == 0)
    return OVPN_CIPHER_ALG_CHACHA20_POLY1305;
  if (strncasecmp (name, "AES-256-CBC", 11) == 0)
    return OVPN_CIPHER_ALG_AES_256_CBC;

  return OVPN_CIPHER_ALG_NONE;
}

static vnet_crypto_alg_t
ovpn_crypto_get_vnet_alg (ovpn_cipher_alg_t alg)
{
  switch (alg)
    {
    case OVPN_CIPHER_ALG_AES_128_GCM:
      return VNET_CRYPTO_ALG_AES_128_GCM;
    case OVPN_CIPHER_ALG_AES_256_GCM:
      return VNET_CRYPTO_ALG_AES_256_GCM;
    case OVPN_CIPHER_ALG_CHACHA20_POLY1305:
      return VNET_CRYPTO_ALG_CHACHA20_POLY1305;
    case OVPN_CIPHER_ALG_AES_256_CBC:
      return VNET_CRYPTO_ALG_AES_256_CBC;
    default:
      return VNET_CRYPTO_ALG_NONE;
    }
}

static vnet_crypto_op_id_t
ovpn_crypto_get_enc_op (ovpn_cipher_alg_t alg)
{
  switch (alg)
    {
    case OVPN_CIPHER_ALG_AES_128_GCM:
      return VNET_CRYPTO_OP_AES_128_GCM_ENC;
    case OVPN_CIPHER_ALG_AES_256_GCM:
      return VNET_CRYPTO_OP_AES_256_GCM_ENC;
    case OVPN_CIPHER_ALG_CHACHA20_POLY1305:
      return VNET_CRYPTO_OP_CHACHA20_POLY1305_ENC;
    case OVPN_CIPHER_ALG_AES_256_CBC:
      return VNET_CRYPTO_OP_AES_256_CBC_ENC;
    default:
      return VNET_CRYPTO_OP_NONE;
    }
}

static vnet_crypto_op_id_t
ovpn_crypto_get_dec_op (ovpn_cipher_alg_t alg)
{
  switch (alg)
    {
    case OVPN_CIPHER_ALG_AES_128_GCM:
      return VNET_CRYPTO_OP_AES_128_GCM_DEC;
    case OVPN_CIPHER_ALG_AES_256_GCM:
      return VNET_CRYPTO_OP_AES_256_GCM_DEC;
    case OVPN_CIPHER_ALG_CHACHA20_POLY1305:
      return VNET_CRYPTO_OP_CHACHA20_POLY1305_DEC;
    case OVPN_CIPHER_ALG_AES_256_CBC:
      return VNET_CRYPTO_OP_AES_256_CBC_DEC;
    default:
      return VNET_CRYPTO_OP_NONE;
    }
}

int
ovpn_crypto_context_init (ovpn_crypto_context_t *ctx,
			  ovpn_cipher_alg_t cipher_alg,
			  const ovpn_key_material_t *keys, u32 replay_window)
{
  vnet_crypto_alg_t vnet_alg;
  u8 key_len;

  clib_memset (ctx, 0, sizeof (*ctx));

  if (cipher_alg == OVPN_CIPHER_ALG_NONE)
    return -1;

  vnet_alg = ovpn_crypto_get_vnet_alg (cipher_alg);
  if (vnet_alg == VNET_CRYPTO_ALG_NONE)
    return -1;

  key_len = ovpn_crypto_key_size (cipher_alg);
  if (key_len == 0 || key_len != keys->key_len)
    return -1;

  ctx->cipher_alg = cipher_alg;
  ctx->is_aead = OVPN_CIPHER_IS_AEAD (cipher_alg);

  /* Add encryption key */
  ctx->encrypt_key_index =
    vnet_crypto_key_add (vlib_get_main (), vnet_alg,
			 (u8 *) keys->encrypt_key, key_len);

  /* Add decryption key */
  ctx->decrypt_key_index =
    vnet_crypto_key_add (vlib_get_main (), vnet_alg,
			 (u8 *) keys->decrypt_key, key_len);

  /* Set up operation IDs */
  ctx->encrypt_op_id = ovpn_crypto_get_enc_op (cipher_alg);
  ctx->decrypt_op_id = ovpn_crypto_get_dec_op (cipher_alg);

  if (ctx->is_aead)
    {
      /* AEAD mode: Copy implicit IVs */
      clib_memcpy_fast (ctx->encrypt_implicit_iv, keys->encrypt_implicit_iv,
			OVPN_IMPLICIT_IV_LEN);
      clib_memcpy_fast (ctx->decrypt_implicit_iv, keys->decrypt_implicit_iv,
			OVPN_IMPLICIT_IV_LEN);
    }
  else
    {
      /* CBC mode: Add HMAC keys and set up HMAC operation */
      if (keys->hmac_key_len == 0)
	return -1; /* HMAC key required for CBC mode */

      ctx->encrypt_hmac_key_index =
	vnet_crypto_key_add (vlib_get_main (), VNET_CRYPTO_ALG_HMAC_SHA256,
			     (u8 *) keys->encrypt_hmac_key, keys->hmac_key_len);

      ctx->decrypt_hmac_key_index =
	vnet_crypto_key_add (vlib_get_main (), VNET_CRYPTO_ALG_HMAC_SHA256,
			     (u8 *) keys->decrypt_hmac_key, keys->hmac_key_len);

      ctx->hmac_op_id = VNET_CRYPTO_OP_SHA256_HMAC;
    }

  /* Initialize counters */
  ctx->packet_id_send = 1;
  ctx->replay_bitmap = 0;
  ctx->replay_bitmap_ext = NULL;
  ctx->replay_packet_id_floor = 0;

  /* Configure replay window size */
  if (replay_window == 0)
    replay_window = OVPN_REPLAY_WINDOW_SIZE_DEFAULT;
  else if (replay_window < OVPN_REPLAY_WINDOW_SIZE_MIN)
    replay_window = OVPN_REPLAY_WINDOW_SIZE_MIN;
  else if (replay_window > OVPN_REPLAY_WINDOW_SIZE_MAX)
    replay_window = OVPN_REPLAY_WINDOW_SIZE_MAX;

  /* Round up to multiple of 64 for bitmap alignment */
  replay_window = (replay_window + 63) & ~63;
  ctx->replay_window_size = replay_window;

  /* Allocate extended bitmap for windows larger than 64 */
  if (replay_window > 64)
    {
      u32 n_words = replay_window / 64;
      vec_validate_aligned (ctx->replay_bitmap_ext, n_words - 1,
			    CLIB_CACHE_LINE_BYTES);
      clib_memset (ctx->replay_bitmap_ext, 0, n_words * sizeof (u64));
    }

  ctx->is_valid = 1;

  return 0;
}

void
ovpn_crypto_context_free (ovpn_crypto_context_t *ctx)
{
  if (!ctx->is_valid)
    return;

  vnet_crypto_key_del (vlib_get_main (), ctx->encrypt_key_index);
  vnet_crypto_key_del (vlib_get_main (), ctx->decrypt_key_index);

  /* Free HMAC keys for CBC mode */
  if (!ctx->is_aead)
    {
      vnet_crypto_key_del (vlib_get_main (), ctx->encrypt_hmac_key_index);
      vnet_crypto_key_del (vlib_get_main (), ctx->decrypt_hmac_key_index);
    }

  /* Free extended replay bitmap if allocated */
  if (ctx->replay_bitmap_ext)
    vec_free (ctx->replay_bitmap_ext);

  clib_memset (ctx, 0, sizeof (*ctx));
}

int
ovpn_crypto_set_static_key (ovpn_crypto_context_t *ctx,
			    ovpn_cipher_alg_t cipher_alg, const u8 *key,
			    u8 key_len, const u8 *implicit_iv)
{
  ovpn_key_material_t keys;

  clib_memset (&keys, 0, sizeof (keys));
  keys.key_len = key_len;

  /* For static key mode, use same key for both directions */
  clib_memcpy_fast (keys.encrypt_key, key, key_len);
  clib_memcpy_fast (keys.decrypt_key, key, key_len);

  if (implicit_iv)
    {
      clib_memcpy_fast (keys.encrypt_implicit_iv, implicit_iv,
			OVPN_IMPLICIT_IV_LEN);
      clib_memcpy_fast (keys.decrypt_implicit_iv, implicit_iv,
			OVPN_IMPLICIT_IV_LEN);
    }

  return ovpn_crypto_context_init (ctx, cipher_alg, &keys,
				   0 /* use default replay window */);
}

/*
 * Helper: Check bit in extended bitmap
 */
static_always_inline int
ovpn_replay_bitmap_ext_check (const u64 *bitmap, u32 bit_pos)
{
  u32 word_idx = bit_pos / 64;
  u32 bit_idx = bit_pos % 64;
  return (bitmap[word_idx] & (1ULL << bit_idx)) != 0;
}

/*
 * Helper: Set bit in extended bitmap
 */
static_always_inline void
ovpn_replay_bitmap_ext_set (u64 *bitmap, u32 bit_pos)
{
  u32 word_idx = bit_pos / 64;
  u32 bit_idx = bit_pos % 64;
  bitmap[word_idx] |= (1ULL << bit_idx);
}

/*
 * Helper: Shift extended bitmap right by n bits
 */
static_always_inline void
ovpn_replay_bitmap_ext_shift (u64 *bitmap, u32 n_words, u32 shift)
{
  if (shift >= n_words * 64)
    {
      clib_memset (bitmap, 0, n_words * sizeof (u64));
      return;
    }

  u32 word_shift = shift / 64;
  u32 bit_shift = shift % 64;

  if (word_shift > 0)
    {
      for (u32 i = 0; i < n_words - word_shift; i++)
	bitmap[i] = bitmap[i + word_shift];
      for (u32 i = n_words - word_shift; i < n_words; i++)
	bitmap[i] = 0;
    }

  if (bit_shift > 0)
    {
      for (u32 i = 0; i < n_words - 1; i++)
	bitmap[i] = (bitmap[i] >> bit_shift) | (bitmap[i + 1] << (64 - bit_shift));
      bitmap[n_words - 1] >>= bit_shift;
    }
}

int
ovpn_crypto_check_replay (ovpn_crypto_context_t *ctx, u32 packet_id)
{
  u32 diff;
  u32 window_size = ctx->replay_window_size;

  if (packet_id == 0)
    return 0; /* packet_id 0 is never valid */

  if (packet_id < ctx->replay_packet_id_floor)
    return 0; /* Too old */

  diff = packet_id - ctx->replay_packet_id_floor;

  if (diff >= window_size)
    return 1; /* Ahead of window, OK */

  /* Check bitmap - use fast path for small windows */
  if (window_size <= 64)
    {
      if (ctx->replay_bitmap & (1ULL << diff))
	return 0; /* Already seen */
    }
  else
    {
      if (ovpn_replay_bitmap_ext_check (ctx->replay_bitmap_ext, diff))
	return 0; /* Already seen */
    }

  return 1;
}

void
ovpn_crypto_update_replay (ovpn_crypto_context_t *ctx, u32 packet_id)
{
  u32 diff;
  u32 window_size = ctx->replay_window_size;

  if (packet_id < ctx->replay_packet_id_floor)
    return;

  diff = packet_id - ctx->replay_packet_id_floor;

  if (diff >= window_size)
    {
      /* Advance window */
      u32 shift = diff - window_size + 1;

      if (window_size <= 64)
	{
	  if (shift >= 64)
	    ctx->replay_bitmap = 0;
	  else
	    ctx->replay_bitmap >>= shift;
	}
      else
	{
	  u32 n_words = window_size / 64;
	  ovpn_replay_bitmap_ext_shift (ctx->replay_bitmap_ext, n_words, shift);
	}

      ctx->replay_packet_id_floor += shift;
      diff = packet_id - ctx->replay_packet_id_floor;
    }

  /* Mark as seen */
  if (window_size <= 64)
    ctx->replay_bitmap |= (1ULL << diff);
  else
    ovpn_replay_bitmap_ext_set (ctx->replay_bitmap_ext, diff);
}

/*
 * Build chunks for chained buffer crypto operations
 * This creates chunk descriptors for each buffer in the chain
 */
static_always_inline void
ovpn_crypto_chain_chunks (vlib_main_t *vm, ovpn_per_thread_crypto_t *ptd,
			  vlib_buffer_t *b, vlib_buffer_t *lb, u8 *start,
			  u32 start_len, u16 *n_ch, i32 last_buf_adj)
{
  vnet_crypto_op_chunk_t *ch;
  vlib_buffer_t *cb = b;
  u32 n_chunks = 1;

  /* First chunk from the first buffer */
  vec_add2 (ptd->chunks, ch, 1);
  ch->len = start_len;
  ch->src = ch->dst = start;

  /* Move to next buffer in chain */
  if (cb->flags & VLIB_BUFFER_NEXT_PRESENT)
    cb = vlib_get_buffer (vm, cb->next_buffer);
  else
    goto done;

  /* Process remaining buffers in chain */
  while (1)
    {
      vec_add2 (ptd->chunks, ch, 1);
      n_chunks += 1;

      /* Last buffer may need adjustment (e.g., exclude tag) */
      if (lb == cb)
	ch->len = cb->current_length + last_buf_adj;
      else
	ch->len = cb->current_length;

      ch->src = ch->dst = vlib_buffer_get_current (cb);

      if (!(cb->flags & VLIB_BUFFER_NEXT_PRESENT))
	break;

      cb = vlib_get_buffer (vm, cb->next_buffer);
    }

done:
  if (n_ch)
    *n_ch = n_chunks;
}

/*
 * Find the last buffer in a chain
 */
static_always_inline vlib_buffer_t *
ovpn_find_last_buffer (vlib_main_t *vm, vlib_buffer_t *b)
{
  while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    b = vlib_get_buffer (vm, b->next_buffer);
  return b;
}

/*
 * Prepare encryption operation for a buffer (supports chained buffers)
 * Supports both DATA_V1 (without peer_id) and DATA_V2 (with peer_id) formats
 */
int
ovpn_crypto_encrypt_prepare (vlib_main_t *vm, ovpn_per_thread_crypto_t *ptd,
			     ovpn_crypto_context_t *ctx, vlib_buffer_t *b,
			     u32 bi, u32 peer_id, u8 key_id)
{
  vlib_buffer_t *lb;
  vnet_crypto_op_t *op;
  u32 n_bufs;
  u32 packet_id;
  u8 *payload;
  u32 payload_len;
  u8 *tag;
  u8 *iv;
  u8 *aad;
  u32 aad_len;

  if (!ctx->is_valid)
    return -1;

  /* Linearize buffer chain if needed */
  lb = b;
  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_NEXT_PRESENT))
    {
      n_bufs = vlib_buffer_chain_linearize (vm, b);
      if (n_bufs == 0)
	return -2; /* No buffers available */

      /* Find last buffer in chain */
      if (n_bufs > 1)
	lb = ovpn_find_last_buffer (vm, b);

      /* Calculate payload length from chain before modifying */
      payload_len = vlib_buffer_length_in_chain (vm, b);
    }
  else
    {
      n_bufs = 1;
      payload_len = b->current_length;
    }

  /* Get next packet ID */
  packet_id = ovpn_crypto_get_next_packet_id (ctx);

  /*
   * OpenVPN AEAD wire format (same for both DATA_V1 and DATA_V2):
   *   [header][tag:16][ciphertext]
   * Tag is ALWAYS after header, before ciphertext.
   */
  if (ctx->use_data_v2)
    {
      /*
       * DATA_V2 AEAD format: [header:8][tag:16][ciphertext]
       * Tag is AFTER header, BEFORE ciphertext (same as DATA_V1)
       * AAD = full 8-byte header
       */
      u8 *hdr_start;
      ovpn_data_v2_header_t *hdr_v2;

      /* Push header + tag space at front */
      hdr_start =
	vlib_buffer_push_uninit (b, sizeof (*hdr_v2) + OVPN_TAG_SIZE);
      hdr_v2 = (ovpn_data_v2_header_t *) hdr_start;

      hdr_v2->opcode_keyid = ovpn_op_compose (OVPN_OP_DATA_V2, key_id);
      ovpn_data_v2_set_peer_id (hdr_v2, peer_id);
      hdr_v2->packet_id = clib_host_to_net_u32 (packet_id);

      /* AAD = full 8-byte header */
      aad = hdr_start;
      aad_len = 8;

      /* Tag is right after header */
      tag = hdr_start + sizeof (*hdr_v2);

      /* Payload starts after header + tag */
      payload = tag + OVPN_TAG_SIZE;
    }
  else
    {
      /*
       * DATA_V1 format: opcode(1) + packet_id(4) + tag(16)
       * AAD for DATA_V1 is just packet_id (4 bytes), NOT opcode.
       */
      u8 *hdr_start;
      ovpn_data_v1_header_t *hdr_v1;

      /* Push header + tag space at front */
      hdr_start =
	vlib_buffer_push_uninit (b, sizeof (*hdr_v1) + OVPN_TAG_SIZE);
      hdr_v1 = (ovpn_data_v1_header_t *) hdr_start;

      hdr_v1->opcode_keyid = ovpn_op_compose (OVPN_OP_DATA_V1, key_id);
      hdr_v1->packet_id = clib_host_to_net_u32 (packet_id);

      /* AAD starts at packet_id, not opcode */
      aad = (u8 *) &hdr_v1->packet_id;
      aad_len = sizeof (hdr_v1->packet_id);

      /* Tag is right after header */
      tag = hdr_start + sizeof (*hdr_v1);

      /* Payload starts after header + tag */
      payload = tag + OVPN_TAG_SIZE;
    }

  /* Allocate IV storage */
  vec_add2 (ptd->ivs, iv, OVPN_NONCE_SIZE);
  ovpn_aead_nonce_build ((ovpn_aead_nonce_t *) iv, packet_id,
			 ctx->encrypt_implicit_iv);

  /* Set up crypto operation */
  if (b != lb)
    {
      /* Chained buffers - use chunked crypto */
      vec_add2_aligned (ptd->chained_crypto_ops, op, 1, CLIB_CACHE_LINE_BYTES);
      vnet_crypto_op_init (op, ctx->encrypt_op_id);

      op->flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
      op->chunk_index = vec_len (ptd->chunks);
      /* Tag is now in header area, no tag adjustment needed at end */
      ovpn_crypto_chain_chunks (vm, ptd, b, lb, payload, payload_len,
				&op->n_chunks, 0);
    }
  else
    {
      /* Single buffer */
      vec_add2_aligned (ptd->crypto_ops, op, 1, CLIB_CACHE_LINE_BYTES);
      vnet_crypto_op_init (op, ctx->encrypt_op_id);

      op->src = payload;
      op->dst = payload;
      op->len = payload_len;
    }

  op->key_index = ctx->encrypt_key_index;
  op->iv = iv;
  op->aad = aad;
  op->aad_len = aad_len;
  op->tag = tag;
  op->tag_len = OVPN_TAG_SIZE;
  op->user_data = bi;

  return 0;
}

/*
 * Prepare decryption operation for a buffer (supports chained buffers)
 */
int
ovpn_crypto_decrypt_prepare (vlib_main_t *vm, ovpn_per_thread_crypto_t *ptd,
			     ovpn_crypto_context_t *ctx, vlib_buffer_t *b,
			     u32 bi, u32 *packet_id_out)
{
  vlib_buffer_t *lb;
  vnet_crypto_op_t *op;
  u32 n_bufs;
  u32 packet_id;
  u8 *aad;
  u32 aad_len;
  u32 hdr_len; /* Full header length for buffer advance */
  u8 *src;
  u32 src_len;
  u32 total_len;
  u8 *tag;
  u8 *iv;

  if (!ctx->is_valid)
    return -1;

  /* Linearize buffer chain if needed */
  lb = b;
  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_NEXT_PRESENT))
    {
      n_bufs = vlib_buffer_chain_linearize (vm, b);
      if (n_bufs == 0)
	return -2; /* No buffers available */

      /* Find last buffer in chain */
      if (n_bufs > 1)
	{
	  vlib_buffer_t *before_last = b;
	  lb = b;

	  while (lb->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      before_last = lb;
	      lb = vlib_get_buffer (vm, lb->next_buffer);
	    }

	  /*
	   * Ensure auth tag is contiguous in the last buffer
	   * (not split across the last two buffers)
	   */
	  if (PREDICT_FALSE (lb->current_length < OVPN_TAG_SIZE))
	    {
	      u32 len_diff = OVPN_TAG_SIZE - lb->current_length;

	      before_last->current_length -= len_diff;
	      if (before_last == b)
		before_last->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;

	      vlib_buffer_advance (lb, (signed) -len_diff);
	      clib_memcpy_fast (vlib_buffer_get_current (lb),
				vlib_buffer_get_tail (before_last), len_diff);
	    }
	}

      /* Get total length from chain */
      total_len = vlib_buffer_length_in_chain (vm, b);
    }
  else
    {
      n_bufs = 1;
      total_len = b->current_length;
    }

  /*
   * Buffer should point to start of OpenVPN packet (opcode byte)
   * Layout varies by format:
   *   DATA_V1: [opcode+keyid:1][packet_id:4][ciphertext][tag:16]
   *   DATA_V2: [opcode+keyid:1][peer_id:3][packet_id:4][ciphertext][tag:16]
   */
  u8 *pkt_start = vlib_buffer_get_current (b);
  u8 opcode = pkt_start[0] >> 3;

  if (opcode == OVPN_OP_DATA_V2)
    {
      /* DATA_V2: AAD = full 8-byte header (opcode_keyid + peer_id + packet_id) */
      if (total_len < OVPN_DATA_V2_MIN_SIZE + OVPN_TAG_SIZE)
	return -3;
      ovpn_data_v2_header_t *hdr_v2 = (ovpn_data_v2_header_t *) pkt_start;
      aad = pkt_start;  /* Full header from opcode */
      aad_len = 8;  /* Complete header */
      hdr_len = sizeof (ovpn_data_v2_header_t);
      packet_id = clib_net_to_host_u32 (hdr_v2->packet_id);
    }
  else if (opcode == OVPN_OP_DATA_V1)
    {
      /*
       * DATA_V1: AAD is just packet_id (4 bytes), NOT opcode.
       * This matches OpenVPN's behavior where the opcode is stripped
       * before setting ad_start for AEAD authentication.
       * But hdr_len is full header for buffer advance.
       */
      if (total_len < OVPN_DATA_V1_MIN_SIZE + OVPN_TAG_SIZE)
	return -3;
      ovpn_data_v1_header_t *hdr_v1 = (ovpn_data_v1_header_t *) pkt_start;
      aad = (u8 *) &hdr_v1->packet_id;
      aad_len = sizeof (hdr_v1->packet_id);
      hdr_len = sizeof (ovpn_data_v1_header_t);
      packet_id = clib_net_to_host_u32 (hdr_v1->packet_id);
    }
  else
    {
      return -5; /* Unknown opcode */
    }

  /* Check replay */
  if (!ovpn_crypto_check_replay (ctx, packet_id))
    return -4; /* Replay detected */

  /*
   * Wire format for AEAD (both DATA_V1 and DATA_V2):
   *   DATA_V1: [opcode:1][packet_id:4][tag:16][ciphertext:N]
   *   DATA_V2: [opcode:1][peer_id:3][packet_id:4][tag:16][ciphertext:N]
   * Tag is ALWAYS after header, before ciphertext in OpenVPN AEAD mode.
   */
  tag = pkt_start + hdr_len;
  src = pkt_start + hdr_len + OVPN_TAG_SIZE;
  src_len = total_len - hdr_len - OVPN_TAG_SIZE;

  /* Allocate IV storage */
  vec_add2 (ptd->ivs, iv, OVPN_NONCE_SIZE);
  ovpn_aead_nonce_build ((ovpn_aead_nonce_t *) iv, packet_id,
			 ctx->decrypt_implicit_iv);

  /* Set up crypto operation */
  if (b != lb)
    {
      /* Chained buffers - use chunked crypto */
      vec_add2_aligned (ptd->chained_crypto_ops, op, 1, CLIB_CACHE_LINE_BYTES);
      vnet_crypto_op_init (op, ctx->decrypt_op_id);

      op->flags |= (VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS |
		    VNET_CRYPTO_OP_FLAG_HMAC_CHECK);
      op->chunk_index = vec_len (ptd->chunks);

      /* Decrypt the ciphertext (after header + tag) */
      ovpn_crypto_chain_chunks (vm, ptd, b, lb, src, src_len, &op->n_chunks,
				0);
    }
  else
    {
      /* Single buffer */
      vec_add2_aligned (ptd->crypto_ops, op, 1, CLIB_CACHE_LINE_BYTES);
      vnet_crypto_op_init (op, ctx->decrypt_op_id);

      op->src = src;
      op->dst = src;
      op->len = src_len;
      op->flags |= VNET_CRYPTO_OP_FLAG_HMAC_CHECK;
    }

  op->key_index = ctx->decrypt_key_index;
  op->iv = iv;
  op->aad = aad;
  op->aad_len = aad_len;
  op->tag = tag;
  op->tag_len = OVPN_TAG_SIZE;
  op->user_data = bi;

  if (packet_id_out)
    *packet_id_out = packet_id;

  return 0;
}

/*
 * Process all pending encryption operations
 */
void
ovpn_crypto_encrypt_process (vlib_main_t *vm, vlib_node_runtime_t *node,
			     ovpn_per_thread_crypto_t *ptd,
			     vlib_buffer_t *bufs[], u16 *nexts, u16 drop_next)
{
  u32 n_ops, n_chained_ops;
  u32 n_fail;
  vnet_crypto_op_t *op;

  /* Process single-buffer operations */
  n_ops = vec_len (ptd->crypto_ops);
  if (n_ops > 0)
    {
      op = ptd->crypto_ops;
      n_fail = n_ops - vnet_crypto_process_ops (vm, op, n_ops);

      while (n_fail)
	{
	  ASSERT (op - ptd->crypto_ops < n_ops);

	  if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	    {
	      u32 bi = op->user_data;
	      bufs[bi]->error = node->errors[0]; /* Encrypt failed */
	      nexts[bi] = drop_next;
	      n_fail--;
	    }
	  op++;
	}
    }

  /* Process chained-buffer operations */
  n_chained_ops = vec_len (ptd->chained_crypto_ops);
  if (n_chained_ops > 0)
    {
      op = ptd->chained_crypto_ops;
      n_fail = n_chained_ops -
	       vnet_crypto_process_chained_ops (vm, op, ptd->chunks,
						n_chained_ops);

      while (n_fail)
	{
	  ASSERT (op - ptd->chained_crypto_ops < n_chained_ops);

	  if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	    {
	      u32 bi = op->user_data;
	      bufs[bi]->error = node->errors[0]; /* Encrypt failed */
	      nexts[bi] = drop_next;
	      n_fail--;
	    }
	  op++;
	}
    }
}

/*
 * Process all pending decryption operations
 */
void
ovpn_crypto_decrypt_process (vlib_main_t *vm, vlib_node_runtime_t *node,
			     ovpn_per_thread_crypto_t *ptd,
			     vlib_buffer_t *bufs[], u16 *nexts, u16 drop_next)
{
  u32 n_ops, n_chained_ops;
  u32 n_fail;
  vnet_crypto_op_t *op;

  /* Process single-buffer operations */
  n_ops = vec_len (ptd->crypto_ops);
  if (n_ops > 0)
    {
      op = ptd->crypto_ops;
      u32 n_success = vnet_crypto_process_ops (vm, op, n_ops);
      n_fail = n_ops - n_success;

      while (n_fail)
	{
	  ASSERT (op - ptd->crypto_ops < n_ops);

	  if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	    {
	      u32 bi = op->user_data;
	      bufs[bi]->error = node->errors[0]; /* Decrypt failed */
	      nexts[bi] = drop_next;
	      n_fail--;
	    }
	  op++;
	}
    }

  /* Process chained-buffer operations */
  n_chained_ops = vec_len (ptd->chained_crypto_ops);
  if (n_chained_ops > 0)
    {
      op = ptd->chained_crypto_ops;
      n_fail = n_chained_ops -
	       vnet_crypto_process_chained_ops (vm, op, ptd->chunks,
						n_chained_ops);

      while (n_fail)
	{
	  ASSERT (op - ptd->chained_crypto_ops < n_chained_ops);

	  if (op->status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	    {
	      u32 bi = op->user_data;
	      bufs[bi]->error = node->errors[0]; /* Decrypt failed */
	      nexts[bi] = drop_next;
	      n_fail--;
	    }
	  op++;
	}
    }
}

/*
 * Legacy single-packet encrypt function (kept for compatibility)
 * Uses the new batch infrastructure internally
 */
int
ovpn_crypto_encrypt (vlib_main_t *vm, ovpn_crypto_context_t *ctx,
		     vlib_buffer_t *b, u32 peer_id, u8 key_id)
{
  u32 thread_index = vm->thread_index;
  ovpn_per_thread_crypto_t *ptd = &ovpn_per_thread_crypto[thread_index];
  int rv;

  ovpn_crypto_reset_ptd (ptd);

  rv = ovpn_crypto_encrypt_prepare (vm, ptd, ctx, b, 0, peer_id, key_id);
  if (rv < 0)
    return rv;

  /* Process single-buffer ops */
  if (vec_len (ptd->crypto_ops) > 0)
    {
      vnet_crypto_process_ops (vm, ptd->crypto_ops, vec_len (ptd->crypto_ops));
      if (ptd->crypto_ops[0].status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	return -1;
    }

  /* Process chained-buffer ops */
  if (vec_len (ptd->chained_crypto_ops) > 0)
    {
      vnet_crypto_process_chained_ops (vm, ptd->chained_crypto_ops,
				       ptd->chunks,
				       vec_len (ptd->chained_crypto_ops));
      if (ptd->chained_crypto_ops[0].status !=
	  VNET_CRYPTO_OP_STATUS_COMPLETED)
	return -1;
    }

  /*
   * For DATA_V1 (non-epoch) format, OpenVPN expects tag BEFORE ciphertext:
   *   [opcode:1][packet_id:4][tag:16][ciphertext:N]
   * But crypto produces:
   *   [opcode:1][packet_id:4][ciphertext:N][tag:16]
   * We need to reorder the packet.
   */
  if (!ctx->use_data_v2)
    {
      u8 *pkt = vlib_buffer_get_current (b);
      u32 pkt_len = b->current_length;
      u32 hdr_len = sizeof (ovpn_data_v1_header_t);
      u8 *ciphertext = pkt + hdr_len;
      u32 ciphertext_len = pkt_len - hdr_len - OVPN_TAG_SIZE;
      u8 *tag_at_end = pkt + pkt_len - OVPN_TAG_SIZE;

      /* Save tag */
      u8 tag_tmp[OVPN_TAG_SIZE];
      clib_memcpy_fast (tag_tmp, tag_at_end, OVPN_TAG_SIZE);

      /* Move ciphertext forward by 16 bytes to make room for tag */
      memmove (ciphertext + OVPN_TAG_SIZE, ciphertext, ciphertext_len);

      /* Copy tag to right after header */
      clib_memcpy_fast (ciphertext, tag_tmp, OVPN_TAG_SIZE);
    }

  return 0;
}

/*
 * CBC+HMAC mode decrypt for single packet (static key mode).
 * Packet format: [opcode:1][HMAC:32][IV:16][encrypted(packet_id:4 + timestamp:4 + payload)]
 * Note: Uses "long form" packet IDs with timestamp (default with replay-window).
 */
int
ovpn_crypto_cbc_decrypt (vlib_main_t *vm, ovpn_crypto_context_t *ctx,
			 vlib_buffer_t *b, u32 *packet_id_out)
{
  u8 *data;
  u32 len;
  u8 *hmac_received;
  u8 *iv;
  u8 *ciphertext;
  u32 ciphertext_len;
  u8 hmac_computed[OVPN_HMAC_SIZE];
  vnet_crypto_op_t hmac_op;
  vnet_crypto_op_t decrypt_op;
  u32 packet_id;

  if (!ctx->is_valid || ctx->is_aead)
    return -1; /* Only for CBC mode */

  data = vlib_buffer_get_current (b);
  len = b->current_length;

  /* Check minimum length: opcode(1) + HMAC(20) + IV(16) + packet_id(4) */
  if (len < OVPN_DATA_V1_CBC_MIN_SIZE)
    return -2;

  /* Parse packet structure */
  /* data[0] = opcode + key_id */
  hmac_received = data + 1; /* HMAC starts after opcode */
  iv = hmac_received + OVPN_CBC_HMAC_SIZE;
  ciphertext = iv + OVPN_IV_SIZE;
  ciphertext_len = len - 1 - OVPN_CBC_HMAC_SIZE - OVPN_IV_SIZE;

  /* Ciphertext must be at least packet_id + some data, and multiple of 16 */
  if (ciphertext_len < 16 || (ciphertext_len & 0xF) != 0)
    return -3;

  /*
   * Step 1: Verify HMAC
   * HMAC is computed over: IV + ciphertext
   * Note: For HMAC operations, use integ_src/integ_len (not src/len)
   */
  vnet_crypto_op_init (&hmac_op, ctx->hmac_op_id);
  hmac_op.key_index = ctx->decrypt_hmac_key_index;
  hmac_op.integ_src = iv; /* HMAC covers IV + ciphertext */
  hmac_op.integ_len = OVPN_IV_SIZE + ciphertext_len;
  hmac_op.digest = hmac_computed;
  hmac_op.digest_len = OVPN_HMAC_SIZE;
  hmac_op.flags = 0;

  vnet_crypto_process_ops (vm, &hmac_op, 1);

  if (hmac_op.status != VNET_CRYPTO_OP_STATUS_COMPLETED)
    return -4; /* HMAC computation failed */

  /* Compare HMAC with received */
  if (clib_memcmp (hmac_computed, hmac_received, OVPN_CBC_HMAC_SIZE) != 0)
    return -5; /* HMAC verification failed */

  /*
   * Step 2: Decrypt ciphertext in place
   */
  vnet_crypto_op_init (&decrypt_op, ctx->decrypt_op_id);
  decrypt_op.key_index = ctx->decrypt_key_index;
  decrypt_op.iv = iv;
  decrypt_op.src = ciphertext;
  decrypt_op.dst = ciphertext; /* Decrypt in place */
  decrypt_op.len = ciphertext_len;
  decrypt_op.flags = 0;

  vnet_crypto_process_ops (vm, &decrypt_op, 1);

  if (decrypt_op.status != VNET_CRYPTO_OP_STATUS_COMPLETED)
    return -6; /* Decryption failed */

  /*
   * Step 3: Extract packet_id from beginning of decrypted data
   * Decrypted format: [packet_id:4][plaintext payload]
   */
  packet_id = clib_net_to_host_u32 (*(u32 *) ciphertext);

  /* Check replay */
  if (!ovpn_crypto_check_replay (ctx, packet_id))
    return -7; /* Replay detected */

  /* Update replay window */
  ovpn_crypto_update_replay (ctx, packet_id);

  if (packet_id_out)
    *packet_id_out = packet_id;

  /*
   * Step 4: Advance buffer to plaintext payload
   * Skip: opcode(1) + HMAC(32) + IV(16) + packet_id(4) + timestamp(4) = 57 bytes
   * Note: OpenVPN uses "long form" packet IDs with timestamp when
   * replay-window is enabled (the default).
   */
  vlib_buffer_advance (b, 1 + OVPN_CBC_HMAC_SIZE + OVPN_IV_SIZE + 8);

  /* Update buffer length to exclude PKCS7 padding
   * For now, we don't strip padding - VPP IP input will ignore extra bytes
   * This is safe because IP header contains the actual length
   */

  return 0;
}

/*
 * CBC+HMAC mode decrypt for static key mode packets WITHOUT opcode byte.
 * This is the format used by OpenVPN static key mode.
 * Packet format: [HMAC:32][IV:16][encrypted(packet_id:4 + timestamp:4 + payload)]
 *
 * Note: Uses "long form" packet IDs with timestamp (default with replay-window).
 */
int
ovpn_crypto_cbc_decrypt_no_opcode (vlib_main_t *vm, ovpn_crypto_context_t *ctx,
				   vlib_buffer_t *b, u32 *packet_id_out)
{
  u8 *data;
  u32 len;
  u8 *hmac_received;
  u8 *iv;
  u8 *ciphertext;
  u32 ciphertext_len;
  u8 hmac_computed[OVPN_HMAC_SIZE];
  vnet_crypto_op_t hmac_op;
  vnet_crypto_op_t decrypt_op;
  u32 packet_id;

  if (!ctx->is_valid || ctx->is_aead)
    return -1; /* Only for CBC mode */

  data = vlib_buffer_get_current (b);
  len = b->current_length;

  /* Minimum length: HMAC(32) + IV(16) + encrypted(packet_id:4 + min_payload) */
  if (len < (OVPN_CBC_HMAC_SIZE + OVPN_IV_SIZE + 16))
    return -2;

  /* Parse packet structure - no opcode byte in this format */
  hmac_received = data;
  iv = hmac_received + OVPN_CBC_HMAC_SIZE;
  ciphertext = iv + OVPN_IV_SIZE;
  ciphertext_len = len - OVPN_CBC_HMAC_SIZE - OVPN_IV_SIZE;

  /* Ciphertext must be at least 16 bytes (one AES block) and multiple of 16 */
  if (ciphertext_len < 16 || (ciphertext_len & 0xF) != 0)
    return -3;

  /*
   * Step 1: Verify HMAC
   * HMAC is computed over: IV + ciphertext
   * Use integ_src/integ_len for HMAC operations (different union from src/len)
   */
  vnet_crypto_op_init (&hmac_op, ctx->hmac_op_id);
  hmac_op.key_index = ctx->decrypt_hmac_key_index;
  hmac_op.integ_src = iv; /* HMAC covers IV + ciphertext */
  hmac_op.integ_len = OVPN_IV_SIZE + ciphertext_len;
  hmac_op.digest = hmac_computed;
  hmac_op.digest_len = OVPN_CBC_HMAC_SIZE;
  hmac_op.iv = 0;
  hmac_op.flags = 0;

  vnet_crypto_process_ops (vm, &hmac_op, 1);

  if (hmac_op.status != VNET_CRYPTO_OP_STATUS_COMPLETED)
    return -4;

  /* Compare HMAC */
  if (clib_memcmp (hmac_computed, hmac_received, OVPN_CBC_HMAC_SIZE) != 0)
    return -5;

  /*
   * Step 2: Decrypt ciphertext in place
   */
  vnet_crypto_op_init (&decrypt_op, ctx->decrypt_op_id);
  decrypt_op.key_index = ctx->decrypt_key_index;
  decrypt_op.iv = iv;
  decrypt_op.src = ciphertext;
  decrypt_op.dst = ciphertext; /* Decrypt in place */
  decrypt_op.len = ciphertext_len;
  decrypt_op.flags = 0;

  vnet_crypto_process_ops (vm, &decrypt_op, 1);

  if (decrypt_op.status != VNET_CRYPTO_OP_STATUS_COMPLETED)
    return -6;

  /*
   * Step 3: Extract packet_id from beginning of decrypted data
   * Decrypted format (short form): [packet_id:4][plaintext payload]
   * Note: No timestamp in short form (static key mode)
   */
  packet_id = clib_net_to_host_u32 (*(u32 *) ciphertext);

  /* Check replay */
  if (!ovpn_crypto_check_replay (ctx, packet_id))
    return -7;

  /* Update replay window */
  ovpn_crypto_update_replay (ctx, packet_id);

  if (packet_id_out)
    *packet_id_out = packet_id;

  /*
   * Step 4: Advance buffer to plaintext payload
   * Skip: HMAC(32) + IV(16) + packet_id(4) + timestamp(4) = 56 bytes
   * Note: OpenVPN uses "long form" packet IDs with timestamp when
   * replay-window is enabled (the default).
   */
  vlib_buffer_advance (b, OVPN_CBC_HMAC_SIZE + OVPN_IV_SIZE + 8);

  return 0;
}

/*
 * Legacy single-packet decrypt function (kept for compatibility)
 * Uses the new batch infrastructure internally
 */
int
ovpn_crypto_decrypt (vlib_main_t *vm, ovpn_crypto_context_t *ctx,
		     vlib_buffer_t *b, u32 *packet_id_out)
{
  u32 thread_index = vm->thread_index;
  ovpn_per_thread_crypto_t *ptd = &ovpn_per_thread_crypto[thread_index];
  vlib_buffer_t *lb;
  u32 hdr_len;
  int rv;

  /* Determine header length from opcode before decrypt modifies buffer */
  u8 *pkt = vlib_buffer_get_current (b);
  u8 opcode = pkt[0] >> 3;
  if (opcode == OVPN_OP_DATA_V2)
    hdr_len = sizeof (ovpn_data_v2_header_t);
  else
    hdr_len = sizeof (ovpn_data_v1_header_t);

  ovpn_crypto_reset_ptd (ptd);

  rv = ovpn_crypto_decrypt_prepare (vm, ptd, ctx, b, 0, packet_id_out);
  if (rv < 0)
    return rv;

  /* Process single-buffer ops */
  if (vec_len (ptd->crypto_ops) > 0)
    {
      vnet_crypto_process_ops (vm, ptd->crypto_ops, vec_len (ptd->crypto_ops));
      if (ptd->crypto_ops[0].status != VNET_CRYPTO_OP_STATUS_COMPLETED)
	return -3;
    }

  /* Process chained-buffer ops */
  if (vec_len (ptd->chained_crypto_ops) > 0)
    {
      vnet_crypto_process_chained_ops (vm, ptd->chained_crypto_ops,
				       ptd->chunks,
				       vec_len (ptd->chained_crypto_ops));
      if (ptd->chained_crypto_ops[0].status !=
	  VNET_CRYPTO_OP_STATUS_COMPLETED)
	return -3;
    }

  /* Update replay window */
  if (packet_id_out && *packet_id_out)
    ovpn_crypto_update_replay (ctx, *packet_id_out);

  /* Find last buffer */
  lb = ovpn_find_last_buffer (vm, b);

  /*
   * Advance buffer past header and tag (for DATA_V1) to plaintext.
   * DATA_V1: [opcode:1][packet_id:4][tag:16][ciphertext/plaintext:N]
   * DATA_V2: [opcode:1][peer_id:3][packet_id:4][ciphertext/plaintext:N][tag:16]
   */
  if (opcode == OVPN_OP_DATA_V1)
    vlib_buffer_advance (b, hdr_len + OVPN_TAG_SIZE);
  else
    {
      vlib_buffer_advance (b, hdr_len);
      /* Remove tag from chain length (only for DATA_V2 where tag is at end) */
      vlib_buffer_chain_increase_length (b, lb, -OVPN_TAG_SIZE);
    }

  return 0;
}

/*
 * CBC+HMAC mode encrypt for single packet (static key mode).
 * Packet format: [HMAC:32][IV:16][encrypted(packet_id:4 + timestamp:4 + payload)]
 * Note: Uses "long form" packet IDs with timestamp (default with replay-window).
 *
 * @param vm VPP main
 * @param ctx Crypto context (must be CBC mode, not AEAD)
 * @param b Buffer containing plaintext payload
 * @return 0 on success, <0 on error
 */
int
ovpn_crypto_cbc_encrypt (vlib_main_t *vm, ovpn_crypto_context_t *ctx,
			 vlib_buffer_t *b)
{
  u8 *payload;
  u32 payload_len;
  u32 packet_id;
  u8 iv[OVPN_IV_SIZE];
  u8 *hmac_slot;
  u8 *iv_slot;
  u8 *ciphertext_slot;
  u32 padded_len;
  u8 pad_len;
  vnet_crypto_op_t encrypt_op;
  vnet_crypto_op_t hmac_op;

  if (!ctx->is_valid || ctx->is_aead)
    return -1; /* Only for CBC mode */

  /* Get current payload */
  payload = vlib_buffer_get_current (b);
  payload_len = b->current_length;

  /* Get next packet ID */
  packet_id = ovpn_crypto_get_next_packet_id (ctx);

  /* Get current time for long-form packet ID */
  u32 timestamp = (u32) vlib_time_now (vm);

  /*
   * Calculate padded length for CBC (PKCS7 padding)
   * plaintext = packet_id(4) + timestamp(4) + payload (long form)
   * Must be multiple of 16 (AES block size)
   */
  u32 plaintext_len = 8 + payload_len;
  padded_len = (plaintext_len + 15) & ~15;
  if (padded_len == plaintext_len)
    padded_len += 16; /* Always add at least 1 byte of padding */
  pad_len = padded_len - plaintext_len;

  /*
   * Ensure enough space in buffer for padding.
   * Header: HMAC(32) + IV(16) = 48 bytes (prepended later)
   * Note: Static key mode CBC does NOT include opcode byte!
   * Padding: up to 16 bytes (appended to payload)
   */
  u32 header_size = OVPN_CBC_HMAC_SIZE + OVPN_IV_SIZE;

  if (PREDICT_FALSE (vlib_buffer_space_left_at_end (vm, b) < (i32) pad_len))
    return -2; /* Not enough space for padding */

  /* First, move payload to make room for header + packet_id + timestamp */
  u8 *new_data = vlib_buffer_push_uninit (b, header_size + 8);

  /* Copy payload after packet_id + timestamp slots */
  clib_memmove (new_data + header_size + 8, payload, payload_len);

  /* Set up packet structure pointers */
  hmac_slot = new_data;
  iv_slot = hmac_slot + OVPN_CBC_HMAC_SIZE;
  ciphertext_slot = iv_slot + OVPN_IV_SIZE;

  /* Write packet_id and timestamp at start of plaintext (will be encrypted) */
  *(u32 *) ciphertext_slot = clib_host_to_net_u32 (packet_id);
  *(u32 *) (ciphertext_slot + 4) = clib_host_to_net_u32 (timestamp);

  /* Add PKCS7 padding */
  u8 *plaintext_end = ciphertext_slot + plaintext_len;
  for (u32 i = 0; i < pad_len; i++)
    plaintext_end[i] = pad_len;

  /* Update buffer length to include padding */
  b->current_length = header_size + padded_len;

  /* Generate random IV */
  u8 *random_iv =
    clib_random_buffer_get_data (&vm->random_buffer, OVPN_IV_SIZE);
  clib_memcpy_fast (iv, random_iv, OVPN_IV_SIZE);
  clib_memcpy_fast (iv_slot, iv, OVPN_IV_SIZE);

  /*
   * Step 1: Encrypt plaintext (packet_id + payload + padding)
   * CBC encrypts in-place
   */
  vnet_crypto_op_init (&encrypt_op, ctx->encrypt_op_id);
  encrypt_op.key_index = ctx->encrypt_key_index;
  encrypt_op.src = ciphertext_slot;
  encrypt_op.dst = ciphertext_slot;
  encrypt_op.len = padded_len;
  encrypt_op.iv = iv;
  encrypt_op.flags = 0;

  vnet_crypto_process_ops (vm, &encrypt_op, 1);

  if (encrypt_op.status != VNET_CRYPTO_OP_STATUS_COMPLETED)
    return -3; /* Encryption failed */

  /*
   * Step 2: Compute HMAC over IV + ciphertext
   */
  vnet_crypto_op_init (&hmac_op, ctx->hmac_op_id);
  hmac_op.key_index = ctx->encrypt_hmac_key_index;
  hmac_op.integ_src = iv_slot;
  hmac_op.integ_len = OVPN_IV_SIZE + padded_len;
  hmac_op.digest = hmac_slot;
  hmac_op.digest_len = OVPN_CBC_HMAC_SIZE;
  hmac_op.iv = 0;
  hmac_op.flags = 0;

  vnet_crypto_process_ops (vm, &hmac_op, 1);

  if (hmac_op.status != VNET_CRYPTO_OP_STATUS_COMPLETED)
    return -4; /* HMAC computation failed */

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
