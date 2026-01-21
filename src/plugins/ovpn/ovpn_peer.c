/*
 * ovpn_peer.c - OpenVPN peer management implementation
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
#include <ovpn/ovpn_peer.h>
#include <ovpn/ovpn_ssl.h>
#include <ovpn/ovpn_session_id.h>
#include <ovpn/ovpn_handshake.h>
#include <ovpn/ovpn_crypto.h>
#include <ovpn/ovpn_fragment.h>
#include <ovpn/ovpn_if.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip_format_fns.h>
#include <picotls/openssl.h>
#include <stdio.h>
#include <arpa/inet.h>

/* Global mapping from adjacency index to peer index */
u32 *ovpn_peer_by_adj_index;

/* Control channel buffer sizes */
#define OVPN_TLS_BUF_SIZE     4096
#define OVPN_TLS_RELIABLE_CAP 8

void
ovpn_peer_db_init (ovpn_peer_db_t *db, u32 sw_if_index, u32 max_clients)
{
  clib_memset (db, 0, sizeof (*db));
  db->sw_if_index = sw_if_index;
  db->peer_index_by_virtual_ip = hash_create (0, sizeof (uword));
  db->next_peer_id = 1; /* Start from 1, 0 is reserved */

  /*
   * Initialize bihash for remote address -> peer_id lookup (lock-free)
   * If max_clients is 0, use heap allocation for dynamic sizing.
   * Otherwise, size based on max_clients.
   */
  if (max_clients == 0)
    {
      /* Heap-allocated bihash - grows automatically */
      clib_bihash_init2_args_24_8_t args24 = { 0 };
      args24.h = &db->remote_hash;
      args24.name = "ovpn peer remote hash";
      args24.dont_add_to_all_bihash_list = 0;
      args24.instantiate_immediately = 0;
      clib_bihash_init2_24_8 (&args24);

      clib_bihash_init2_args_8_8_t args8 = { 0 };
      args8.h = &db->key_hash;
      args8.name = "ovpn peer key hash";
      args8.dont_add_to_all_bihash_list = 0;
      args8.instantiate_immediately = 0;
      clib_bihash_init2_8_8 (&args8);

      args8.h = &db->session_hash;
      args8.name = "ovpn peer session hash";
      clib_bihash_init2_8_8 (&args8);
    }
  else
    {
      /* Fixed-size bihash based on max_clients */
      u32 nbuckets = clib_max (CLIB_CACHE_LINE_BYTES, max_clients * 2);
      nbuckets = 1 << max_log2 (nbuckets);
      uword memory_size = nbuckets * 256; /* ~256 bytes per bucket */

      clib_bihash_init_24_8 (&db->remote_hash, "ovpn peer remote hash",
			     nbuckets, memory_size);
      clib_bihash_init_8_8 (&db->key_hash, "ovpn peer key hash", nbuckets,
			    memory_size);
      clib_bihash_init_8_8 (&db->session_hash, "ovpn peer session hash",
			    nbuckets, memory_size);
    }

  /* MAC hash for TAP mode is initialized on-demand when first MAC is learned */
  db->mac_hash_initialized = 0;
}

void
ovpn_peer_db_free (ovpn_peer_db_t *db)
{
  ovpn_peer_t *peer;

  pool_foreach (peer, db->peers)
    {
      /* Free crypto contexts */
      for (int i = 0; i < OVPN_KEY_SLOT_COUNT; i++)
	{
	  if (peer->keys[i].crypto.is_valid)
	    ovpn_crypto_context_free (&peer->keys[i].crypto);
	}
      /* Free rewrite */
      vec_free (peer->rewrite);
    }

  pool_free (db->peers);
  hash_free (db->peer_index_by_virtual_ip);

  /* Free bihashes */
  clib_bihash_free_24_8 (&db->remote_hash);
  clib_bihash_free_8_8 (&db->key_hash);
  clib_bihash_free_8_8 (&db->session_hash);

  /* Free MAC hash if initialized */
  if (db->mac_hash_initialized)
    clib_bihash_free_8_8 (&db->mac_hash);

  /* Free persist resources */
  ovpn_peer_persist_free (db);

  /* Free CN hash */
  if (db->peer_id_by_cn_hash)
    {
      hash_pair_t *hp;
      hash_foreach_pair (hp, db->peer_id_by_cn_hash, ({
			   u8 *key = (u8 *) hp->key;
			   vec_free (key);
			 }));
      hash_free (db->peer_id_by_cn_hash);
    }

  clib_memset (db, 0, sizeof (*db));
}

u32
ovpn_peer_create (ovpn_peer_db_t *db, const ip_address_t *remote_addr,
		  u16 remote_port)
{
  ovpn_peer_t *peer;
  u32 peer_id;
  clib_bihash_kv_24_8_t kv;

  /* Check if peer already exists */
  peer = ovpn_peer_lookup_by_remote (db, remote_addr, remote_port);
  if (peer)
    return peer->peer_id; /* Return existing peer */

  /* Allocate new peer */
  pool_get_zero (db->peers, peer);
  peer_id = peer - db->peers;

  /* Ensure peer_id fits in 24 bits */
  if (peer_id > OVPN_MAX_PEER_ID)
    {
      pool_put (db->peers, peer);
      return ~0;
    }

  peer->peer_id = peer_id;
  peer->state = OVPN_PEER_STATE_INITIAL;
  peer->sw_if_index = db->sw_if_index;
  peer->generation = 0;

  /* Set remote address */
  ip_address_copy (&peer->remote_addr, remote_addr);
  peer->remote_port = remote_port;
  peer->is_ipv6 = (remote_addr->version == AF_IP6);

  /* Generate session ID */
  ovpn_session_id_generate (&peer->session_id);

  /* Add to session ID hash for NAT/float lookup */
  ovpn_peer_add_to_session_hash (db, peer);

  /* Initialize timestamps */
  peer->last_rx_time = vlib_time_now (vlib_get_main ());
  peer->last_tx_time = peer->last_rx_time;

  /* Initialize adjacency index */
  peer->adj_index = ADJ_INDEX_INVALID;

  /* Thread index unassigned - will be set on first packet */
  peer->input_thread_index = ~0;

  /* Initialize fragment state */
  ovpn_frag_state_init (&peer->frag_state);

  /* Add to remote address bihash (lock-free) */
  ovpn_peer_remote_hash_make_key (&kv, remote_addr, remote_port);
  kv.value = peer_id;
  clib_bihash_add_del_24_8 (&db->remote_hash, &kv, 1 /* is_add */);

  return peer_id;
}

/*
 * Delete a peer
 *
 * IMPORTANT: Caller MUST hold worker barrier (vlib_worker_thread_barrier_sync)
 * to ensure no data plane workers are accessing this peer.
 */
void
ovpn_peer_delete (ovpn_peer_db_t *db, u32 peer_id)
{
  ovpn_peer_t *peer;
  clib_bihash_kv_8_8_t kv;
  clib_bihash_kv_24_8_t kv24;

  peer = ovpn_peer_get (db, peer_id);
  if (!peer)
    return;

  /*
   * Execute client-disconnect script if configured and peer was established
   */
  if (peer->state == OVPN_PEER_STATE_ESTABLISHED)
    {
      /* Decrement established peer count */
      if (db->n_established > 0)
	db->n_established--;

      /* Send disconnect event to API subscribers */
      ovpn_instance_t *inst =
	ovpn_instance_get_by_sw_if_index (peer->sw_if_index);
      ovpn_api_send_peer_event (inst ? inst->instance_id : ~0, peer,
				OVPN_PEER_EVENT_DISCONNECTED);
    }

  /*
   * Mark peer as DEAD first.
   * Any data plane code that somehow runs (shouldn't happen with barrier)
   * will see DEAD state and skip processing.
   */
  ovpn_peer_set_state (peer, OVPN_PEER_STATE_DEAD);
  ovpn_peer_increment_generation (peer);

  /* Remove from remote address bihash */
  ovpn_peer_remote_hash_make_key (&kv24, &peer->remote_addr, peer->remote_port);
  clib_bihash_add_del_24_8 (&db->remote_hash, &kv24, 0 /* is_add */);

  /* Remove from session ID hash */
  if (ovpn_session_id_defined (&peer->session_id))
    {
      kv.key = *(u64 *) peer->session_id.id;
      clib_bihash_add_del_8_8 (&db->session_hash, &kv, 0 /* is_add */);
    }

  /* Remove from virtual IP hash if set */
  if (peer->virtual_ip_set)
    {
      u64 vip_key;
      if (peer->virtual_ip.version == AF_IP4)
	vip_key = peer->virtual_ip.ip.ip4.as_u32;
      else
	vip_key = peer->virtual_ip.ip.ip6.as_u64[0] ^
		  peer->virtual_ip.ip.ip6.as_u64[1];
      hash_unset (db->peer_index_by_virtual_ip, vip_key);
    }

  /* Remove from CN hash if peer has a common name */
  if (peer->tls_ctx && peer->tls_ctx->client_common_name)
    ovpn_peer_cn_hash_del (db, peer->tls_ctx->client_common_name);

  /* Free TLS context if exists */
  if (peer->tls_ctx)
    ovpn_peer_tls_free (peer);

  /* Remove key entries from bihash and free crypto contexts */
  for (int i = 0; i < OVPN_KEY_SLOT_COUNT; i++)
    {
      if (peer->keys[i].is_active)
	{
	  kv.key = ovpn_peer_key_hash_key (peer_id, peer->keys[i].key_id);
	  clib_bihash_add_del_8_8 (&db->key_hash, &kv, 0 /* is_add */);
	}
      if (peer->keys[i].crypto.is_valid)
	ovpn_crypto_context_free (&peer->keys[i].crypto);
    }

  /* Free rewrite */
  vec_free (peer->rewrite);

  /* Free per-client push options */
  if (peer->client_push_opts)
    {
      ovpn_peer_push_options_free (peer->client_push_opts);
      peer->client_push_opts = NULL;
    }

  /* Remove all MAC entries for this peer (TAP mode) */
  ovpn_peer_mac_delete_all (db, peer_id);

  /* Free username if stored */
  vec_free (peer->username);

  /* Free fragment state */
  ovpn_frag_state_free (&peer->frag_state);

  /* Release adjacency */
  if (peer->adj_index != ADJ_INDEX_INVALID)
    adj_unlock (peer->adj_index);

  /* Increment database generation */
  db->generation++;

  /* Return to pool */
  pool_put (db->peers, peer);
}

/*
 * Lookup peer by remote address + port (lock-free via bihash)
 * Used for P_DATA_V1 packets and handshake.
 */
ovpn_peer_t *
ovpn_peer_lookup_by_remote (ovpn_peer_db_t *db, const ip_address_t *addr,
			    u16 port)
{
  clib_bihash_kv_24_8_t kv, value;

  ovpn_peer_remote_hash_make_key (&kv, addr, port);
  if (clib_bihash_search_24_8 (&db->remote_hash, &kv, &value) == 0)
    {
      u32 peer_id = (u32) value.value;
      if (peer_id < pool_elts (db->peers))
	return pool_elt_at_index (db->peers, peer_id);
    }
  return NULL;
}

ovpn_peer_t *
ovpn_peer_lookup_by_virtual_ip (ovpn_peer_db_t *db, const ip_address_t *addr)
{
  uword *p;
  u64 key;

  if (addr->version == AF_IP4)
    key = addr->ip.ip4.as_u32;
  else
    key = addr->ip.ip6.as_u64[0] ^ addr->ip.ip6.as_u64[1];

  p = hash_get (db->peer_index_by_virtual_ip, key);
  if (!p)
    return NULL;

  return pool_elt_at_index (db->peers, p[0]);
}

/*
 * Set peer's virtual IP address
 *
 * Assigns a virtual IP to the peer and registers it in the lookup hash.
 * If the IP is already assigned to another peer, returns an error.
 *
 * @param db Peer database
 * @param peer Peer to assign IP to
 * @param virtual_ip IP address to assign
 * @return 0 on success, <0 on error:
 *   -1: invalid parameters
 *   -2: IP already assigned to another peer
 */
int
ovpn_peer_set_virtual_ip (ovpn_peer_db_t *db, ovpn_peer_t *peer,
			  const ip_address_t *virtual_ip)
{
  u64 vip_key;
  uword *p;

  if (!db || !peer || !virtual_ip || ip_address_is_zero (virtual_ip))
    return -1;

  /* Generate hash key for the IP */
  if (virtual_ip->version == AF_IP4)
    vip_key = virtual_ip->ip.ip4.as_u32;
  else
    vip_key = virtual_ip->ip.ip6.as_u64[0] ^ virtual_ip->ip.ip6.as_u64[1];

  /* Check if IP is already assigned to another peer */
  p = hash_get (db->peer_index_by_virtual_ip, vip_key);
  if (p && p[0] != peer->peer_id)
    return -2; /* IP already in use by another peer */

  /* Remove old virtual IP from hash if this peer had one */
  if (peer->virtual_ip_set && ip_address_cmp (&peer->virtual_ip, virtual_ip) != 0)
    {
      u64 old_key;
      if (peer->virtual_ip.version == AF_IP4)
	old_key = peer->virtual_ip.ip.ip4.as_u32;
      else
	old_key = peer->virtual_ip.ip.ip6.as_u64[0] ^
		  peer->virtual_ip.ip.ip6.as_u64[1];
      hash_unset (db->peer_index_by_virtual_ip, old_key);
    }

  /* Set the new virtual IP */
  ip_address_copy (&peer->virtual_ip, virtual_ip);
  peer->virtual_ip_set = 1;

  /* Register in hash */
  hash_set (db->peer_index_by_virtual_ip, vip_key, peer->peer_id);

  return 0;
}

/*
 * Allocate virtual IP from pool for a peer
 * Iterates through the pool range and finds the first available IP
 */
int
ovpn_peer_allocate_virtual_ip_from_pool (ovpn_peer_db_t *db, ovpn_peer_t *peer,
					 const ip_address_t *pool_start,
					 const ip_address_t *pool_end)
{
  if (!db || !peer || !pool_start || !pool_end)
    return -1;

  /* Only support IPv4 for now - check if IPv4 address is set */
  if (pool_start->ip.ip4.as_u32 == 0 || pool_end->ip.ip4.as_u32 == 0)
    return -1;

  u32 start_val = clib_net_to_host_u32 (pool_start->ip.ip4.as_u32);
  u32 end_val = clib_net_to_host_u32 (pool_end->ip.ip4.as_u32);

  if (start_val > end_val)
    return -1;

  /* Iterate through the pool looking for an available IP */
  for (u32 ip_val = start_val; ip_val <= end_val; ip_val++)
    {
      ip_address_t candidate;
      candidate.version = AF_IP4;
      candidate.ip.ip4.as_u32 = clib_host_to_net_u32 (ip_val);

      /* Check if this IP is already assigned */
      u64 vip_key = candidate.ip.ip4.as_u32;
      uword *p = hash_get (db->peer_index_by_virtual_ip, vip_key);
      if (p == NULL)
	{
	  /* IP is available, assign it to this peer */
	  return ovpn_peer_set_virtual_ip (db, peer, &candidate);
	}
    }

  /* Pool exhausted */
  return -2;
}

/*
 * Allocate virtual IP from pool with persist support
 *
 * Checks persist cache first for the common name, then falls back to
 * regular pool allocation.
 */
int
ovpn_peer_allocate_virtual_ip_with_persist (ovpn_peer_db_t *db,
					    ovpn_peer_t *peer,
					    const ip_address_t *pool_start,
					    const ip_address_t *pool_end,
					    const char *common_name)
{
  ip_address_t persisted_ip;
  int rv;

  if (!db || !peer || !pool_start || !pool_end)
    return -1;

  /* Only support IPv4 for now */
  if (pool_start->ip.ip4.as_u32 == 0 || pool_end->ip.ip4.as_u32 == 0)
    return -1;

  /*
   * Check persist cache if common name is provided
   */
  if (common_name && ovpn_peer_persist_lookup (db, common_name, &persisted_ip))
    {
      /* Found persisted IP - verify it's in pool range and available */
      u32 ip_val = clib_net_to_host_u32 (persisted_ip.ip.ip4.as_u32);
      u32 start_val = clib_net_to_host_u32 (pool_start->ip.ip4.as_u32);
      u32 end_val = clib_net_to_host_u32 (pool_end->ip.ip4.as_u32);

      if (ip_val >= start_val && ip_val <= end_val)
	{
	  /* IP is in pool range - try to assign it */
	  rv = ovpn_peer_set_virtual_ip (db, peer, &persisted_ip);
	  if (rv == 0)
	    return 0;
	  /* IP already in use by another peer, fall through to regular
	   * allocation */
	}
    }

  /*
   * Fall back to regular pool allocation
   */
  rv = ovpn_peer_allocate_virtual_ip_from_pool (db, peer, pool_start, pool_end);
  if (rv == 0 && common_name && peer->virtual_ip_set)
    {
      /* Successfully allocated - store in persist cache */
      ovpn_peer_persist_store (db, common_name, &peer->virtual_ip);
    }

  return rv;
}

/*
 * Add peer to session ID hash
 */
void
ovpn_peer_add_to_session_hash (ovpn_peer_db_t *db, ovpn_peer_t *peer)
{
  clib_bihash_kv_8_8_t kv;

  if (!ovpn_session_id_defined (&peer->session_id))
    return;

  kv.key = *(u64 *) peer->session_id.id;
  kv.value = peer->peer_id;
  clib_bihash_add_del_8_8 (&db->session_hash, &kv, 1 /* is_add */);
}

/*
 * Lookup peer by session ID (NAT/float support)
 */
ovpn_peer_t *
ovpn_peer_lookup_by_session_id (ovpn_peer_db_t *db,
				const ovpn_session_id_t *session_id)
{
  clib_bihash_kv_8_8_t kv, value;

  if (!ovpn_session_id_defined (session_id))
    return NULL;

  kv.key = *(u64 *) session_id->id;
  if (clib_bihash_search_8_8 (&db->session_hash, &kv, &value) == 0)
    {
      u32 peer_id = (u32) value.value;
      if (!pool_is_free_index (db->peers, peer_id))
	return pool_elt_at_index (db->peers, peer_id);
    }
  return NULL;
}

/*
 * Update peer remote address (NAT/float support)
 *
 * IMPORTANT: Caller MUST hold worker barrier (vlib_worker_thread_barrier_sync)
 * to ensure no data plane workers are accessing this peer.
 */
int
ovpn_peer_update_remote (ovpn_peer_db_t *db, ovpn_peer_t *peer,
			 const ip_address_t *new_addr, u16 new_port)
{
  clib_bihash_kv_24_8_t kv;

  /* Check if address actually changed */
  if (ip_address_cmp (&peer->remote_addr, new_addr) == 0 &&
      peer->remote_port == new_port)
    return 0; /* No change */

  /* Log the address change */

  /* Remove old entry from remote_hash */
  ovpn_peer_remote_hash_make_key (&kv, &peer->remote_addr, peer->remote_port);
  clib_bihash_add_del_24_8 (&db->remote_hash, &kv, 0 /* is_add */);

  /* Update peer fields */
  ip_address_copy (&peer->remote_addr, new_addr);
  peer->remote_port = new_port;
  peer->is_ipv6 = (new_addr->version == AF_IP6);

  /* Add new entry to remote_hash */
  ovpn_peer_remote_hash_make_key (&kv, new_addr, new_port);
  kv.value = peer->peer_id;
  clib_bihash_add_del_24_8 (&db->remote_hash, &kv, 1 /* is_add */);

  /* Rebuild rewrite buffer with new destination */
  if (peer->rewrite)
    {
      ovpn_if_t *oif = ovpn_if_get_from_sw_if_index (peer->sw_if_index);
      if (oif)
	ovpn_peer_build_rewrite (peer, &oif->local_addr, oif->local_port);
    }

  /* Increment generation to signal data plane */
  ovpn_peer_increment_generation (peer);

  return 0;
}

/*
 * Set peer crypto key
 *
 * Updates bihash for lock-free data plane lookup.
 * Must be called from main thread or with worker barrier held.
 */
int
ovpn_peer_set_key (vlib_main_t *vm, ovpn_peer_db_t *db, ovpn_peer_t *peer,
		   u8 key_slot, ovpn_cipher_alg_t cipher_alg,
		   const ovpn_key_material_t *keys, u8 key_id,
		   u32 replay_window)
{
  ovpn_peer_key_t *pkey;
  clib_bihash_kv_8_8_t kv;
  int rv;

  if (key_slot >= OVPN_KEY_SLOT_COUNT)
    return -1;

  pkey = &peer->keys[key_slot];

  /* Remove old bihash entry if key was active */
  if (pkey->is_active)
    {
      kv.key = ovpn_peer_key_hash_key (peer->peer_id, pkey->key_id);
      clib_bihash_add_del_8_8 (&db->key_hash, &kv, 0 /* is_add */);
    }

  /* Free existing crypto context if any */
  if (pkey->crypto.is_valid)
    ovpn_crypto_context_free (&pkey->crypto);

  /* Initialize new key */
  rv = ovpn_crypto_context_init (&pkey->crypto, cipher_alg, keys,
				 replay_window);
  if (rv < 0)
    return rv;

  pkey->key_id = key_id;
  pkey->is_active = 1;
  pkey->created_at = vlib_time_now (vm);
  pkey->expires_at = 0; /* Set by caller based on config */

  /* Add new entry to bihash for lock-free lookup */
  kv.key = ovpn_peer_key_hash_key (peer->peer_id, key_id);
  kv.value = (u64) (uword) pkey;
  clib_bihash_add_del_8_8 (&db->key_hash, &kv, 1 /* is_add */);

  /* Increment generation to signal key change */
  ovpn_peer_increment_generation (peer);

  return 0;
}

/*
 * Get crypto context by key_id using bihash lookup (lock-free)
 */
ovpn_crypto_context_t *
ovpn_peer_get_crypto_by_key_id (ovpn_peer_db_t *db, u32 peer_id, u8 key_id)
{
  clib_bihash_kv_8_8_t kv, value;

  kv.key = ovpn_peer_key_hash_key (peer_id, key_id);

  if (clib_bihash_search_8_8 (&db->key_hash, &kv, &value) == 0)
    {
      ovpn_peer_key_t *pkey = (ovpn_peer_key_t *) (uword) value.value;
      if (pkey->is_active && pkey->crypto.is_valid)
	return &pkey->crypto;
    }

  return NULL;
}

int
ovpn_peer_build_rewrite (ovpn_peer_t *peer, const ip_address_t *local_addr,
			 u16 local_port)
{
  u8 *rewrite = NULL;

  if (peer->is_ipv6)
    {
      ip6_header_t *ip6;
      udp_header_t *udp;

      vec_validate (rewrite,
		    sizeof (ip6_header_t) + sizeof (udp_header_t) - 1);

      ip6 = (ip6_header_t *) rewrite;
      udp = (udp_header_t *) (ip6 + 1);

      ip6->ip_version_traffic_class_and_flow_label =
	clib_host_to_net_u32 (0x60000000);
      ip6->payload_length = 0; /* Set per-packet */
      ip6->protocol = IP_PROTOCOL_UDP;
      ip6->hop_limit = 64;
      clib_memcpy_fast (&ip6->src_address, &local_addr->ip.ip6,
			sizeof (ip6_address_t));
      clib_memcpy_fast (&ip6->dst_address, &peer->remote_addr.ip.ip6,
			sizeof (ip6_address_t));

      udp->src_port = clib_host_to_net_u16 (local_port);
      udp->dst_port = clib_host_to_net_u16 (peer->remote_port);
      udp->length = 0;	 /* Set per-packet */
      udp->checksum = 0; /* Optional for IPv6 */
    }
  else
    {
      ip4_header_t *ip4;
      udp_header_t *udp;

      vec_validate (rewrite,
		    sizeof (ip4_header_t) + sizeof (udp_header_t) - 1);

      ip4 = (ip4_header_t *) rewrite;
      udp = (udp_header_t *) (ip4 + 1);

      ip4->ip_version_and_header_length = 0x45;
      ip4->tos = 0;
      ip4->length = 0; /* Set per-packet */
      ip4->fragment_id = 0;
      ip4->flags_and_fragment_offset = 0;
      ip4->ttl = 64;
      ip4->protocol = IP_PROTOCOL_UDP;
      ip4->checksum = 0; /* Computed per-packet or offloaded */
      clib_memcpy_fast (&ip4->src_address, &local_addr->ip.ip4,
			sizeof (ip4_address_t));
      clib_memcpy_fast (&ip4->dst_address, &peer->remote_addr.ip.ip4,
			sizeof (ip4_address_t));

      udp->src_port = clib_host_to_net_u16 (local_port);
      udp->dst_port = clib_host_to_net_u16 (peer->remote_port);
      udp->length = 0;	 /* Set per-packet */
      udp->checksum = 0; /* Computed per-packet or offloaded */
    }

  /* Free old rewrite */
  vec_free (peer->rewrite);

  peer->rewrite = rewrite;
  peer->rewrite_len = vec_len (rewrite);

  return 0;
}

u8 *
format_ovpn_peer (u8 *s, va_list *args)
{
  ovpn_peer_t *peer = va_arg (*args, ovpn_peer_t *);
  const char *state_str;

  switch (peer->state)
    {
    case OVPN_PEER_STATE_INITIAL:
      state_str = "initial";
      break;
    case OVPN_PEER_STATE_HANDSHAKE:
      state_str = "handshake";
      break;
    case OVPN_PEER_STATE_ESTABLISHED:
      state_str = "established";
      break;
    case OVPN_PEER_STATE_REKEYING:
      state_str = "rekeying";
      break;
    case OVPN_PEER_STATE_DEAD:
      state_str = "dead";
      break;
    default:
      state_str = "unknown";
      break;
    }

  s = format (s, "peer %u [%s]", peer->peer_id, state_str);
  s = format (s, "\n  remote: %U:%u", format_ip_address, &peer->remote_addr,
	      peer->remote_port);

  if (peer->virtual_ip_set)
    s = format (s, "\n  virtual-ip: %U", format_ip_address, &peer->virtual_ip);

  s = format (s, "\n  rx: %lu packets, %lu bytes", peer->rx_packets,
	      peer->rx_bytes);
  s = format (s, "\n  tx: %lu packets, %lu bytes", peer->tx_packets,
	      peer->tx_bytes);

  for (int i = 0; i < OVPN_KEY_SLOT_COUNT; i++)
    {
      if (peer->keys[i].is_active)
	{
	  s = format (s, "\n  key[%d]: id=%u valid=%d", i,
		      peer->keys[i].key_id, peer->keys[i].crypto.is_valid);
	}
    }

  return s;
}

/*
 * Initialize TLS handshake context for a peer
 */
int
ovpn_peer_tls_init (ovpn_peer_t *peer, ptls_context_t *ptls_ctx, u8 key_id)
{
  ovpn_peer_tls_t *tls_ctx;

  /* Free existing context if any */
  if (peer->tls_ctx)
    ovpn_peer_tls_free (peer);

  /* Allocate TLS context */
  tls_ctx = clib_mem_alloc (sizeof (ovpn_peer_tls_t));
  if (!tls_ctx)
    return -1;

  clib_memset (tls_ctx, 0, sizeof (*tls_ctx));

  tls_ctx->state = OVPN_TLS_STATE_INITIAL;
  tls_ctx->key_id = key_id;
  tls_ctx->packet_id_send = 0;

  /* Initialize reliable structures for control channel */
  tls_ctx->send_reliable = clib_mem_alloc (sizeof (ovpn_reliable_t));
  if (!tls_ctx->send_reliable)
    goto error;
  ovpn_reliable_init (tls_ctx->send_reliable, OVPN_TLS_BUF_SIZE,
		      128 /* header offset */, OVPN_TLS_RELIABLE_CAP,
		      0 /* hold */);
  ovpn_reliable_set_timeout (tls_ctx->send_reliable, 2.0);

  tls_ctx->recv_reliable = clib_mem_alloc (sizeof (ovpn_reliable_t));
  if (!tls_ctx->recv_reliable)
    goto error;
  ovpn_reliable_init (tls_ctx->recv_reliable, OVPN_TLS_BUF_SIZE,
		      0 /* header offset */, OVPN_TLS_RELIABLE_CAP,
		      0 /* hold */);

  /* Create picotls server context */
  tls_ctx->tls = ptls_new (ptls_ctx, 1 /* is_server */);
  if (!tls_ctx->tls)
    goto error;

  /* Allocate key source for Key Method 2 exchange */
  tls_ctx->key_src2 = ovpn_key_source2_alloc ();
  if (!tls_ctx->key_src2)
    goto error;

  /* Initialize key exchange flags */
  tls_ctx->key_method_sent = 0;
  tls_ctx->key_method_received = 0;
  tls_ctx->use_tls_ekm = 0; /* Use PRF-based key derivation for compatibility */

  /* Initialize plaintext read buffer for decrypted application data */
  tls_ctx->plaintext_read_buf.capacity = 2048;
  tls_ctx->plaintext_read_buf.data =
    clib_mem_alloc (tls_ctx->plaintext_read_buf.capacity);
  if (!tls_ctx->plaintext_read_buf.data)
    goto error;
  tls_ctx->plaintext_read_buf.len = 0;
  tls_ctx->plaintext_read_buf.offset = 0;

  tls_ctx->state = OVPN_TLS_STATE_HANDSHAKE;
  peer->tls_ctx = tls_ctx;

  return 0;

error:
  if (tls_ctx->key_src2)
    {
      ovpn_key_source2_free (tls_ctx->key_src2);
      tls_ctx->key_src2 = NULL;
    }
  if (tls_ctx->send_reliable)
    {
      ovpn_reliable_free (tls_ctx->send_reliable);
      clib_mem_free (tls_ctx->send_reliable);
    }
  if (tls_ctx->recv_reliable)
    {
      ovpn_reliable_free (tls_ctx->recv_reliable);
      clib_mem_free (tls_ctx->recv_reliable);
    }
  if (tls_ctx->plaintext_read_buf.data)
    clib_mem_free (tls_ctx->plaintext_read_buf.data);
  clib_mem_free (tls_ctx);
  return -1;
}

/*
 * Free TLS handshake context
 */
void
ovpn_peer_tls_free (ovpn_peer_t *peer)
{
  ovpn_peer_tls_t *tls_ctx = peer->tls_ctx;

  if (!tls_ctx)
    return;

  /* Free picotls context */
  if (tls_ctx->tls)
    ptls_free (tls_ctx->tls);

  /* Free key source */
  if (tls_ctx->key_src2)
    {
      ovpn_key_source2_free (tls_ctx->key_src2);
      tls_ctx->key_src2 = NULL;
    }

  /* Free peer options string */
  if (tls_ctx->peer_options)
    clib_mem_free (tls_ctx->peer_options);

  /* Free reliable structures */
  if (tls_ctx->send_reliable)
    {
      ovpn_reliable_free (tls_ctx->send_reliable);
      clib_mem_free (tls_ctx->send_reliable);
    }
  if (tls_ctx->recv_reliable)
    {
      ovpn_reliable_free (tls_ctx->recv_reliable);
      clib_mem_free (tls_ctx->recv_reliable);
    }

  /* Free plaintext read buffer */
  if (tls_ctx->plaintext_read_buf.data)
    clib_mem_free (tls_ctx->plaintext_read_buf.data);

  /* Free per-client TLS-Crypt context (for TLS-Crypt-V2) */
  if (tls_ctx->tls_crypt)
    {
      clib_mem_free (tls_ctx->tls_crypt);
      tls_ctx->tls_crypt = NULL;
    }

  clib_mem_free (tls_ctx);
  peer->tls_ctx = NULL;
}

/*
 * Process incoming TLS data from control channel
 *
 * This function handles both:
 * 1. TLS handshake data (before handshake completes)
 * 2. TLS application data (after handshake completes, e.g., Key Method 2)
 *
 * Returns: >0 if TLS data was produced for sending
 *          0 if no data to send
 *          <0 on error
 */
int
ovpn_peer_tls_process (ovpn_peer_t *peer, u8 *data, u32 len)
{
  ovpn_peer_tls_t *tls_ctx = peer->tls_ctx;
  ptls_buffer_t sendbuf;
  int ret;

  if (!tls_ctx || !tls_ctx->tls)
    return -1;

  /* Initialize send buffer */
  ptls_buffer_init (&sendbuf, "", 0);

  /*
   * If TLS handshake is not yet complete, use ptls_handshake
   * Otherwise, use ptls_receive to decrypt application data
   */
  if (tls_ctx->state != OVPN_TLS_STATE_ESTABLISHED)
    {
      /* TLS handshake phase */
      size_t consumed = len;
      ret = ptls_handshake (tls_ctx->tls, &sendbuf, data, &consumed, NULL);

      if (ret == 0)
	{
	  /* Handshake complete */
	  tls_ctx->state = OVPN_TLS_STATE_ESTABLISHED;

	  /*
	   * There may be application data following the handshake in the same
	   * buffer. Process any remaining data with ptls_receive.
	   */
	  if (consumed < len)
	    {
	      ptls_buffer_t plaintext;
	      ptls_buffer_init (&plaintext, "", 0);

	      size_t remaining = len - consumed;
	      int recv_ret = ptls_receive (tls_ctx->tls, &plaintext,
					   data + consumed, &remaining);
	      if (recv_ret == 0 && plaintext.off > 0)
		{
		  /* Store decrypted data in plaintext read buffer */
		  ovpn_buf_write (&tls_ctx->plaintext_read_buf, plaintext.base,
				  plaintext.off);
		}
	      /* Ignore recv_ret errors here - handshake succeeded,
	       * remaining data may be incomplete record */
	      ptls_buffer_dispose (&plaintext);
	    }
	}
      else if (ret == PTLS_ERROR_IN_PROGRESS)
	{
	  /* Handshake still in progress - this is normal */
	  ret = 0;
	}
      else if (ret < 0)
	{
	  /* Error */
	  tls_ctx->state = OVPN_TLS_STATE_ERROR;
	  ptls_buffer_dispose (&sendbuf);
	  return -1;
	}
    }
  else
    {
      /*
       * TLS handshake already complete - decrypt application data
       * This is used for Key Method 2 data exchange
       *
       * ptls_receive returns:
       *   0 on success (check plaintext.off for data length)
       *   negative on error
       */
      ptls_buffer_t plaintext;
      ptls_buffer_init (&plaintext, "", 0);

      size_t consumed = len;
      ret = ptls_receive (tls_ctx->tls, &plaintext, data, &consumed);

      if (ret != 0)
	{
	  /* Error decrypting */
	  ptls_buffer_dispose (&plaintext);
	  ptls_buffer_dispose (&sendbuf);
	  return -1;
	}

      /* ret == 0: success, check if we got any plaintext */
      if (plaintext.off > 0)
	{
	  /* Store decrypted data in plaintext read buffer */
	  ovpn_buf_write (&tls_ctx->plaintext_read_buf, plaintext.base,
			  plaintext.off);
	  ret = plaintext.off;
	}
      else
	{
	  /* No complete record yet, need more data */
	  ret = 0;
	}

      ptls_buffer_dispose (&plaintext);
    }

  /* If we have data to send, queue it in the reliable layer */
  if (sendbuf.off > 0)
    {
      ovpn_reli_buffer_t *buf =
	ovpn_reliable_get_buf_output_sequenced (tls_ctx->send_reliable);
      if (buf)
	{
	  /* Copy TLS data to reliable buffer */
	  ovpn_buf_init (buf, 128); /* Leave room for headers */
	  ovpn_buf_write (buf, sendbuf.base, sendbuf.off);
	  ovpn_reliable_mark_active_outgoing (tls_ctx->send_reliable, buf,
					      OVPN_OP_CONTROL_V1);
	  ret = sendbuf.off;
	}
      else
	{
	}
    }
  else
    {
    }

  ptls_buffer_dispose (&sendbuf);
  return ret;
}

/*
 * Get TLS data to send on control channel
 */
u8 *
ovpn_peer_tls_get_sendbuf (vlib_main_t *vm, ovpn_peer_t *peer, u32 *len)
{
  ovpn_peer_tls_t *tls_ctx = peer->tls_ctx;
  ovpn_reli_buffer_t *buf;
  u8 opcode;

  if (!tls_ctx)
    return NULL;

  if (!ovpn_reliable_can_send (vm, tls_ctx->send_reliable))
    return NULL;

  buf = ovpn_reliable_send (vm, tls_ctx->send_reliable, &opcode);
  if (!buf)
    return NULL;

  *len = OVPN_BLEN (buf);
  return OVPN_BPTR (buf);
}

/*
 * Start a rekey for an established peer
 */
int
ovpn_peer_start_rekey (vlib_main_t *vm, ovpn_peer_t *peer,
		       ptls_context_t *ptls_ctx, u8 key_id)
{
  int rv;

  /* Can only rekey from ESTABLISHED state */
  if (peer->state != OVPN_PEER_STATE_ESTABLISHED)
    return -1;

  /*
   * Note: tls_ctx may still exist from initial handshake (kept alive for
   * control channel). ovpn_peer_tls_init() will free and reinitialize it.
   */

  /* Initialize TLS context for rekey */
  rv = ovpn_peer_tls_init (peer, ptls_ctx, key_id);
  if (rv < 0)
    return rv;

  /* Set up rekey state */
  peer->rekey_key_id = key_id;
  peer->pending_key_slot =
    (peer->current_key_slot == OVPN_KEY_SLOT_PRIMARY) ? OVPN_KEY_SLOT_SECONDARY
						      : OVPN_KEY_SLOT_PRIMARY;

  /* Transition to REKEYING state */
  peer->state = OVPN_PEER_STATE_REKEYING;

  return 0;
}

/*
 * Complete a rekey - activate new keys
 */
int
ovpn_peer_complete_rekey (vlib_main_t *vm, ovpn_peer_db_t *db,
			  ovpn_peer_t *peer, ovpn_cipher_alg_t cipher_alg)
{
  ovpn_key_material_t keys;
  int rv;
  f64 now = vlib_time_now (vm);
  ovpn_peer_tls_t *tls_ctx = peer->tls_ctx;

  /* Must be in REKEYING state with TLS context */
  if (peer->state != OVPN_PEER_STATE_REKEYING || !tls_ctx)
    return -1;

  /* TLS handshake must be complete */
  if (!ovpn_peer_tls_is_established (peer))
    return -2;

  /* Key Method 2 data must be exchanged */
  if (!tls_ctx->key_method_sent || !tls_ctx->key_method_received)
    return -3;

  /* Derive new keys using Key Method 2 */
  rv = ovpn_derive_data_channel_keys_v2 (
    tls_ctx->tls, tls_ctx->key_src2, peer->remote_session_id.id,
    peer->session_id.id, &keys, cipher_alg, 1 /* is_server */,
    tls_ctx->use_tls_ekm, tls_ctx->client_keydir);

  if (rv < 0)
    {
      clib_memset (&keys, 0, sizeof (keys));
      return -4;
    }

  /* Install new keys in the pending slot - get options from instance */
  ovpn_instance_t *inst = ovpn_instance_get_by_sw_if_index (peer->sw_if_index);
  u32 replay_window = inst ? inst->options.replay_window : 64;
  rv = ovpn_peer_set_key (vm, db, peer, peer->pending_key_slot, cipher_alg,
			  &keys, peer->rekey_key_id, replay_window);

  /* Securely clear key material */
  clib_memset (&keys, 0, sizeof (keys));

  if (rv < 0)
    return -5;

  /*
   * Old key transitions to "lame duck" state.
   * Keep it active during the transition window to decrypt in-flight packets.
   * The periodic timer will cleanup when expires_at is reached.
   */
  u8 old_slot = peer->current_key_slot;
  ovpn_peer_key_t *old_key = &peer->keys[old_slot];

  /* Set expiration time for old key (lame duck) */
  f64 transition_window =
    inst ? (f64) inst->options.transition_window : 60.0;
  if (transition_window <= 0)
    transition_window = 60.0; /* Default 60 seconds */
  old_key->expires_at = now + transition_window;

  /* Old key remains active until it expires - can still decrypt packets */

  /* Switch to new keys for encryption */
  peer->current_key_slot = peer->pending_key_slot;

  /* Update timestamps */
  peer->last_rekey_time = now;
  if (peer->rekey_interval > 0)
    peer->next_rekey_time = now + peer->rekey_interval;

  /* Reset bytes/packets counters for reneg-bytes/reneg-pkts */
  peer->bytes_since_rekey = 0;
  peer->packets_since_rekey = 0;

  /* Free TLS context */
  ovpn_peer_tls_free (peer);

  /* Return to ESTABLISHED state */
  peer->state = OVPN_PEER_STATE_ESTABLISHED;
  peer->rekey_initiated = 0;

  return 0;
}

/*
 * Associate a peer with an adjacency index
 */
void
ovpn_peer_adj_index_add (u32 peer_id, adj_index_t ai)
{
  vec_validate_init_empty (ovpn_peer_by_adj_index, ai, ~0);
  ovpn_peer_by_adj_index[ai] = peer_id;
}

/*
 * Remove peer-adjacency association
 */
void
ovpn_peer_adj_index_del (adj_index_t ai)
{
  if (ai < vec_len (ovpn_peer_by_adj_index))
    ovpn_peer_by_adj_index[ai] = ~0;
}

/*
 * Stack the peer's adjacency to reach the endpoint
 *
 * This function stacks the midchain adjacency on the FIB entry for the
 * peer's remote address. adj_midchain_delegate_stack handles:
 * 1. Creating a delegate that tracks the FIB entry for back-walk notifications
 * 2. Calling adj_nbr_midchain_stack_on_fib_entry which properly handles
 *    load-balance DPOs by extracting a single bucket and setting up
 *    adj->sub_type.midchain.adj_dpo for adj-midchain-tx
 */
void
ovpn_peer_adj_stack (ovpn_peer_t *peer, adj_index_t ai)
{
  fib_protocol_t fib_proto;
  u32 fib_index;

  if (peer->is_ipv6)
    fib_proto = FIB_PROTOCOL_IP6;
  else
    fib_proto = FIB_PROTOCOL_IP4;

  fib_index = fib_table_find (fib_proto, peer->fib_index);

  if (fib_index != ~0)
    {
      fib_prefix_t dst = {
	.fp_len = peer->is_ipv6 ? 128 : 32,
	.fp_proto = fib_proto,
      };

      if (peer->is_ipv6)
	dst.fp_addr.ip6 = peer->remote_addr.ip.ip6;
      else
	dst.fp_addr.ip4 = peer->remote_addr.ip.ip4;

      /*
       * Use adj_midchain_delegate_stack which:
       * 1. Creates a delegate for back-walk notifications when route changes
       * 2. Calls adj_nbr_midchain_stack_on_fib_entry which properly handles
       *    load-balance DPOs by extracting a single bucket
       * 3. Sets up adj->sub_type.midchain.adj_dpo for adj-midchain-tx
       *
       * Do NOT call adj_nbr_midchain_stack manually after this - it would
       * overwrite the correctly-set DPO with a raw load-balance DPO that
       * has dpo_next=0 (error-drop) in the adj-midchain-tx context.
       */
      adj_midchain_delegate_stack (ai, fib_index, &dst);
    }
}

/*
 * Cleanup expired keys for a peer
 *
 * Removes "lame duck" keys whose transition window has expired.
 * Keys are removed from the bihash and crypto context is freed.
 */
int
ovpn_peer_cleanup_expired_keys (vlib_main_t *vm, ovpn_peer_db_t *db,
				ovpn_peer_t *peer, f64 now)
{
  clib_bihash_kv_8_8_t kv;
  int cleaned = 0;

  for (int i = 0; i < OVPN_KEY_SLOT_COUNT; i++)
    {
      ovpn_peer_key_t *pkey = &peer->keys[i];

      /* Skip inactive keys or keys that haven't expired yet */
      if (!pkey->is_active)
	continue;

      /* Skip the current key slot (always keep it) */
      if (i == peer->current_key_slot)
	continue;

      /* Check if key has expired */
      if (pkey->expires_at > 0 && now >= pkey->expires_at)
	{
	  /* Remove from bihash */
	  kv.key = ovpn_peer_key_hash_key (peer->peer_id, pkey->key_id);
	  clib_bihash_add_del_8_8 (&db->key_hash, &kv, 0 /* is_add */);

	  /* Free crypto context */
	  if (pkey->crypto.is_valid)
	    ovpn_crypto_context_free (&pkey->crypto);

	  /* Mark as inactive */
	  pkey->is_active = 0;
	  pkey->expires_at = 0;

	  cleaned++;
	}
    }

  return cleaned;
}

/*
 * Cleanup expired keys for all peers in database
 */
int
ovpn_peer_db_cleanup_expired_keys (vlib_main_t *vm, ovpn_peer_db_t *db, f64 now)
{
  ovpn_peer_t *peer;
  int total_cleaned = 0;

  pool_foreach (peer, db->peers)
    {
      /* Skip dead peers */
      if (peer->state == OVPN_PEER_STATE_DEAD)
	continue;

      total_cleaned += ovpn_peer_cleanup_expired_keys (vm, db, peer, now);
    }

  return total_cleaned;
}

/*
 * Send ping packet to peer
 * Encrypts the OpenVPN ping magic pattern and sends on data channel
 */
void
ovpn_peer_send_ping (vlib_main_t *vm, ovpn_peer_t *peer)
{
  extern vlib_node_registration_t ip4_lookup_node;
  extern vlib_node_registration_t ip6_lookup_node;
  extern const u8 ovpn_ping_string[OVPN_PING_STRING_SIZE];

  ovpn_crypto_context_t *crypto;
  vlib_buffer_t *b;
  u32 bi;
  int rv;

  /* Must be established with valid crypto */
  if (peer->state != OVPN_PEER_STATE_ESTABLISHED)
    return;

  crypto = ovpn_peer_get_crypto (peer);
  if (!crypto || !crypto->is_valid)
    return;

  /* Allocate buffer */
  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    return;

  b = vlib_get_buffer (vm, bi);

  /* Leave room for IP + UDP headers */
  u32 hdr_space = peer->is_ipv6 ? sizeof (ip6_header_t) + sizeof (udp_header_t)
				: sizeof (ip4_header_t) + sizeof (udp_header_t);
  b->current_data = hdr_space;
  b->current_length = 0;

  /* Write ping magic pattern as payload */
  u8 *payload = vlib_buffer_put_uninit (b, OVPN_PING_STRING_SIZE);
  clib_memcpy_fast (payload, ovpn_ping_string, OVPN_PING_STRING_SIZE);

  /*
   * When fragmentation is enabled, ALL data channel packets must have
   * a fragment header. For ping packets (which are small), we use
   * FRAG_WHOLE (type=0) to indicate no fragmentation is needed.
   */
  ovpn_instance_t *inst = ovpn_instance_get_by_sw_if_index (peer->sw_if_index);
  if (inst && inst->options.fragment_size > 0)
    {
      /* Prepend FRAG_WHOLE header before the ping payload */
      u32 frag_hdr = ovpn_frag_make_header (OVPN_FRAG_WHOLE, 0, 0, 0);
      vlib_buffer_advance (b, -OVPN_FRAG_HDR_SIZE);
      u8 *frag_hdr_ptr = vlib_buffer_get_current (b);
      clib_memcpy_fast (frag_hdr_ptr, &frag_hdr, OVPN_FRAG_HDR_SIZE);
    }

  /* Get key_id from current key slot */
  u8 key_id = peer->keys[peer->current_key_slot].key_id;

  /* Encrypt the ping packet based on cipher mode */
  if (crypto->is_aead)
    {
      /* AEAD mode - adds DATA_V2 header and tag */
      rv = ovpn_crypto_encrypt (vm, crypto, b, peer->peer_id, key_id);
    }
  else
    {
      /* CBC+HMAC mode - adds HMAC + IV header */
      rv = ovpn_crypto_cbc_encrypt (vm, crypto, b);
    }
  if (rv < 0)
    {
      vlib_buffer_free_one (vm, bi);
      return;
    }

  /* Prepend IP + UDP headers using the peer's rewrite template */
  if (!peer->rewrite || peer->rewrite_len == 0)
    {
      vlib_buffer_free_one (vm, bi);
      return;
    }

  /* Push the rewrite (IP + UDP header) */
  u8 *hdr = vlib_buffer_push_uninit (b, peer->rewrite_len);
  clib_memcpy_fast (hdr, peer->rewrite, peer->rewrite_len);

  /* Fix up lengths in headers */
  u16 total_len = b->current_length;

  if (peer->is_ipv6)
    {
      ip6_header_t *ip6 = (ip6_header_t *) hdr;
      udp_header_t *udp = (udp_header_t *) (ip6 + 1);

      ip6->payload_length =
	clib_host_to_net_u16 (total_len - sizeof (ip6_header_t));
      udp->length = ip6->payload_length;
    }
  else
    {
      ip4_header_t *ip4 = (ip4_header_t *) hdr;
      udp_header_t *udp = (udp_header_t *) (ip4 + 1);

      ip4->length = clib_host_to_net_u16 (total_len);
      udp->length =
	clib_host_to_net_u16 (total_len - sizeof (ip4_header_t));
      ip4->checksum = ip4_header_checksum (ip4);
    }

  /* Set flags for locally originated packet */
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

  /* Enqueue to IP lookup */
  vlib_frame_t *f;
  u32 *to_next;

  if (peer->is_ipv6)
    f = vlib_get_frame_to_node (vm, ip6_lookup_node.index);
  else
    f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);

  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;

  if (peer->is_ipv6)
    vlib_put_frame_to_node (vm, ip6_lookup_node.index, f);
  else
    vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);

  /* Update TX statistics and timestamp */
  peer->tx_packets++;
  peer->tx_bytes += total_len;
  peer->last_tx_time = vlib_time_now (vm);
}

/*
 * Per-client push options implementation
 */

ovpn_peer_push_options_t *
ovpn_peer_push_options_alloc (const char *common_name)
{
  ovpn_peer_push_options_t *opts;

  opts = clib_mem_alloc_aligned (sizeof (*opts), CLIB_CACHE_LINE_BYTES);
  if (!opts)
    return NULL;

  clib_memset (opts, 0, sizeof (*opts));

  if (common_name)
    opts->common_name = (u8 *) vec_dup ((u8 *) common_name);

  return opts;
}

void
ovpn_peer_push_options_free (ovpn_peer_push_options_t *opts)
{
  if (!opts)
    return;

  /* Free push-remove patterns */
  for (u32 i = 0; i < opts->n_push_remove_patterns; i++)
    vec_free (opts->push_remove_patterns[i]);
  vec_free (opts->push_remove_patterns);

  /* Free push options */
  for (u32 i = 0; i < opts->n_push_options; i++)
    vec_free (opts->push_options[i]);
  vec_free (opts->push_options);

  /* Free iroutes */
  vec_free (opts->iroutes);

  /* Free common name */
  vec_free (opts->common_name);

  clib_mem_free (opts);
}

int
ovpn_peer_push_options_add_remove (ovpn_peer_push_options_t *opts,
				   const char *pattern)
{
  if (!opts || !pattern)
    return -1;

  u8 *pattern_copy = (u8 *) vec_dup ((u8 *) pattern);
  vec_add1 (opts->push_remove_patterns, pattern_copy);
  opts->n_push_remove_patterns++;

  return 0;
}

int
ovpn_peer_push_options_add_push (ovpn_peer_push_options_t *opts,
				 const char *option)
{
  if (!opts || !option)
    return -1;

  u8 *option_copy = (u8 *) vec_dup ((u8 *) option);
  vec_add1 (opts->push_options, option_copy);
  opts->n_push_options++;

  return 0;
}

int
ovpn_peer_push_options_add_iroute (ovpn_peer_push_options_t *opts,
				   const fib_prefix_t *prefix)
{
  if (!opts || !prefix)
    return -1;

  vec_add1 (opts->iroutes, *prefix);
  opts->n_iroutes++;

  return 0;
}

int
ovpn_peer_push_options_should_remove (const ovpn_peer_push_options_t *opts,
				      const char *option)
{
  if (!opts || !option || opts->n_push_remove_patterns == 0)
    return 0;

  for (u32 i = 0; i < opts->n_push_remove_patterns; i++)
    {
      const char *pattern = (const char *) opts->push_remove_patterns[i];
      size_t pattern_len = strlen (pattern);

      /* Match if option starts with pattern */
      if (strncmp (option, pattern, pattern_len) == 0)
	{
	  /* Pattern must match at word boundary */
	  if (option[pattern_len] == '\0' || option[pattern_len] == ' ')
	    return 1;
	}
    }

  return 0;
}

/* Forward declaration for recursive config file parsing */
static int ovpn_peer_parse_config_file (ovpn_peer_push_options_t *opts,
					const char *path, int depth);

/* Maximum config file include depth to prevent infinite recursion */
#define OVPN_CCD_MAX_INCLUDE_DEPTH 10

/*
 * Parse a single line from client config file
 * depth: current include depth (0 = top-level file)
 */
static int
ovpn_peer_parse_client_config_line_depth (ovpn_peer_push_options_t *opts,
					  const char *line, int depth)
{
  char *p = (char *) line;

  /* Skip leading whitespace */
  while (*p && (*p == ' ' || *p == '\t'))
    p++;

  /* Skip empty lines and comments */
  if (*p == '\0' || *p == '#' || *p == ';')
    return 0;

  /* config <path> - include another config file */
  if (strncmp (p, "config", 6) == 0 && (p[6] == ' ' || p[6] == '\t'))
    {
      p += 6;
      while (*p == ' ' || *p == '\t')
	p++;

      /* Remove trailing whitespace/newline */
      char *end = p;
      while (*end && *end != '\n' && *end != '\r' && *end != ' ' && *end != '\t')
	end++;
      *end = '\0';

      if (*p)
	{
	  if (depth >= OVPN_CCD_MAX_INCLUDE_DEPTH)
	    {
	      clib_warning ("ovpn: config include depth exceeded at '%s'", p);
	      return -1;
	    }
	  return ovpn_peer_parse_config_file (opts, p, depth + 1);
	}
      return 0;
    }

  /* push-reset */
  if (strncmp (p, "push-reset", 10) == 0 &&
      (p[10] == '\0' || p[10] == ' ' || p[10] == '\t' || p[10] == '\n'))
    {
      opts->push_reset = 1;
      return 0;
    }

  /* push-remove <pattern> */
  if (strncmp (p, "push-remove", 11) == 0 && (p[11] == ' ' || p[11] == '\t'))
    {
      p += 11;
      while (*p == ' ' || *p == '\t')
	p++;

      /* Remove trailing newline */
      char *end = p;
      while (*end && *end != '\n' && *end != '\r')
	end++;
      *end = '\0';

      if (*p)
	ovpn_peer_push_options_add_remove (opts, p);
      return 0;
    }

  /* push "<option>" */
  if (strncmp (p, "push", 4) == 0 && (p[4] == ' ' || p[4] == '\t'))
    {
      p += 4;
      while (*p == ' ' || *p == '\t')
	p++;

      /* Expect quoted string */
      if (*p == '"')
	{
	  p++;
	  char *end = strchr (p, '"');
	  if (end)
	    {
	      *end = '\0';
	      ovpn_peer_push_options_add_push (opts, p);
	    }
	}
      return 0;
    }

  /* ifconfig-push <ip> <netmask> */
  if (strncmp (p, "ifconfig-push", 13) == 0 &&
      (p[13] == ' ' || p[13] == '\t'))
    {
      p += 13;
      while (*p == ' ' || *p == '\t')
	p++;

      char ip_str[64], mask_str[64];
      if (sscanf (p, "%63s %63s", ip_str, mask_str) == 2)
	{
	  ip4_address_t ip4, mask4;
	  if (inet_pton (AF_INET, ip_str, &ip4) == 1 &&
	      inet_pton (AF_INET, mask_str, &mask4) == 1)
	    {
	      opts->ifconfig_push_ip.version = AF_IP4;
	      opts->ifconfig_push_ip.ip.ip4 = ip4;
	      opts->ifconfig_push_netmask.version = AF_IP4;
	      opts->ifconfig_push_netmask.ip.ip4 = mask4;
	      opts->has_ifconfig_push = 1;
	    }
	}
      return 0;
    }

  /* iroute <network> <netmask> */
  if (strncmp (p, "iroute", 6) == 0 && (p[6] == ' ' || p[6] == '\t'))
    {
      p += 6;
      while (*p == ' ' || *p == '\t')
	p++;

      char net_str[64], mask_str[64];
      if (sscanf (p, "%63s %63s", net_str, mask_str) == 2)
	{
	  ip4_address_t net4, mask4;
	  if (inet_pton (AF_INET, net_str, &net4) == 1 &&
	      inet_pton (AF_INET, mask_str, &mask4) == 1)
	    {
	      fib_prefix_t prefix;
	      clib_memset (&prefix, 0, sizeof (prefix));
	      prefix.fp_proto = FIB_PROTOCOL_IP4;
	      prefix.fp_addr.ip4 = net4;
	      /* Count bits set in netmask to get prefix length */
	      prefix.fp_len = __builtin_popcount (mask4.as_u32);
	      ovpn_peer_push_options_add_iroute (opts, &prefix);
	    }
	}
      return 0;
    }

  /* disable */
  if (strncmp (p, "disable", 7) == 0 &&
      (p[7] == '\0' || p[7] == ' ' || p[7] == '\t' || p[7] == '\n'))
    {
      opts->disable = 1;
      return 0;
    }

  return 0;
}

/*
 * Wrapper for top-level parsing (depth = 0)
 */
static int
ovpn_peer_parse_client_config_line (ovpn_peer_push_options_t *opts,
				    const char *line)
{
  return ovpn_peer_parse_client_config_line_depth (opts, line, 0);
}

/*
 * Parse an included config file with depth tracking
 */
static int
ovpn_peer_parse_config_file (ovpn_peer_push_options_t *opts, const char *path,
			     int depth)
{
  FILE *f;
  char line[1024];

  f = fopen (path, "r");
  if (!f)
    return -1;

  while (fgets (line, sizeof (line), f))
    {
      if (ovpn_peer_parse_client_config_line_depth (opts, line, depth) < 0)
	{
	  fclose (f);
	  return -1;
	}
    }

  fclose (f);
  return 0;
}

ovpn_peer_push_options_t *
ovpn_peer_load_client_config (const char *config_dir, const char *common_name)
{
  FILE *f = NULL;
  u8 *path = NULL;

  if (!config_dir || !common_name)
    return NULL;

  /* Build path: config_dir/common_name */
  path = format (0, "%s/%s%c", config_dir, common_name, 0);

  /* Try to open the file named after Common Name */
  f = fopen ((char *) path, "r");
  if (!f)
    {
      vec_free (path);

      /*
       * Per OpenVPN documentation:
       * "If no matching file is found, OpenVPN will instead try to open
       * and parse a default file called 'DEFAULT'"
       */
      path = format (0, "%s/DEFAULT%c", config_dir, 0);
      f = fopen ((char *) path, "r");
      if (!f)
	{
	  vec_free (path);
	  return NULL;
	}
    }

  ovpn_peer_push_options_t *opts = ovpn_peer_push_options_alloc (common_name);
  if (!opts)
    {
      fclose (f);
      vec_free (path);
      return NULL;
    }

  /* Parse file line by line */
  char line[1024];
  while (fgets (line, sizeof (line), f))
    {
      ovpn_peer_parse_client_config_line (opts, line);
    }

  fclose (f);
  vec_free (path);

  return opts;
}

/*
 * MAC-to-peer lookup functions for TAP mode L2 forwarding
 */

/*
 * Learn MAC address for a peer
 *
 * Called when receiving decrypted Ethernet frames from a peer.
 * Associates the source MAC address with the peer_id for future TX lookups.
 *
 * This uses a lock-free bihash which is safe for concurrent access from
 * multiple worker threads.
 */
void
ovpn_peer_mac_learn (ovpn_peer_db_t *db, const u8 *mac, u32 peer_id)
{
  clib_bihash_kv_8_8_t kv;

  if (!db || !mac)
    return;

  /* Initialize MAC hash on first use */
  if (!db->mac_hash_initialized)
    {
      clib_bihash_init_8_8 (&db->mac_hash, "ovpn peer mac hash",
			    1024 /* nbuckets */, 64 << 10 /* memory_size */);
      db->mac_hash_initialized = 1;
    }

  /* Build key from MAC address (6 bytes padded to 8) */
  kv.key = ovpn_peer_mac_to_key (mac);
  kv.value = peer_id;

  /* Add or update the mapping */
  clib_bihash_add_del_8_8 (&db->mac_hash, &kv, 1 /* is_add */);
}

/*
 * Lookup peer by destination MAC address
 *
 * Called when transmitting Ethernet frames to find which peer
 * should receive the encrypted packet.
 *
 * Returns peer_id or ~0 if not found.
 */
u32
ovpn_peer_mac_lookup (ovpn_peer_db_t *db, const u8 *mac)
{
  clib_bihash_kv_8_8_t kv, value;

  if (!db || !mac || !db->mac_hash_initialized)
    return ~0;

  /* Build key from MAC address */
  kv.key = ovpn_peer_mac_to_key (mac);

  /* Lock-free bihash search */
  if (clib_bihash_search_8_8 (&db->mac_hash, &kv, &value) == 0)
    return (u32) value.value;

  return ~0;
}

/*
 * Remove all MAC entries for a peer
 *
 * Called when a peer is deleted. We need to walk the bihash
 * and remove all entries that map to this peer_id.
 *
 * Note: This is O(n) where n is the number of MAC entries.
 * For production use with many MACs, consider maintaining
 * a per-peer list of learned MACs.
 */
typedef struct
{
  ovpn_peer_db_t *db;
  u32 peer_id;
  u64 *keys_to_delete;
} ovpn_mac_delete_ctx_t;

static int
ovpn_mac_delete_walk_cb (clib_bihash_kv_8_8_t *kv, void *arg)
{
  ovpn_mac_delete_ctx_t *ctx = arg;

  if ((u32) kv->value == ctx->peer_id)
    vec_add1 (ctx->keys_to_delete, kv->key);

  return BIHASH_WALK_CONTINUE;
}

void
ovpn_peer_mac_delete_all (ovpn_peer_db_t *db, u32 peer_id)
{
  ovpn_mac_delete_ctx_t ctx = {
    .db = db,
    .peer_id = peer_id,
    .keys_to_delete = NULL,
  };
  clib_bihash_kv_8_8_t kv;

  if (!db || !db->mac_hash_initialized)
    return;

  /* Walk the hash to find all MACs for this peer */
  clib_bihash_foreach_key_value_pair_8_8 (&db->mac_hash,
					  ovpn_mac_delete_walk_cb, &ctx);

  /* Delete the found entries */
  for (u32 i = 0; i < vec_len (ctx.keys_to_delete); i++)
    {
      kv.key = ctx.keys_to_delete[i];
      clib_bihash_add_del_8_8 (&db->mac_hash, &kv, 0 /* is_add */);
    }

  vec_free (ctx.keys_to_delete);
}

/*
 * ifconfig-pool-persist implementation
 */

/*
 * Load ifconfig-pool-persist file into peer database
 *
 * File format: common_name,ip_address (one per line)
 * Lines starting with # are treated as comments.
 */
int
ovpn_peer_persist_load (ovpn_peer_db_t *db, const char *file_path)
{
  FILE *f;
  char line[1024];

  if (!db || !file_path)
    return -1;

  f = fopen (file_path, "r");
  if (!f)
    {
      /* File not found is not an error - may be first run */
      return 0;
    }

  /* Initialize hash if needed */
  if (!db->persist_ip_by_cn_hash)
    db->persist_ip_by_cn_hash = hash_create_string (0, sizeof (u32));

  /* Save the file path for later saves */
  vec_free (db->persist_file_path);
  db->persist_file_path = (u8 *) vec_dup ((u8 *) file_path);

  while (fgets (line, sizeof (line), f))
    {
      char *p = line;
      char *cn_start, *cn_end, *ip_start;
      ip4_address_t ip4;

      /* Skip leading whitespace */
      while (*p && (*p == ' ' || *p == '\t'))
	p++;

      /* Skip empty lines and comments */
      if (*p == '\0' || *p == '#' || *p == ';' || *p == '\n')
	continue;

      /* Find common name (before comma) */
      cn_start = p;
      cn_end = strchr (p, ',');
      if (!cn_end)
	continue;

      *cn_end = '\0';
      ip_start = cn_end + 1;

      /* Skip whitespace around IP */
      while (*ip_start == ' ' || *ip_start == '\t')
	ip_start++;

      /* Remove trailing whitespace from IP */
      char *ip_end = ip_start;
      while (*ip_end && *ip_end != '\n' && *ip_end != '\r' &&
	     *ip_end != ' ' && *ip_end != '\t')
	ip_end++;
      *ip_end = '\0';

      /* Parse IP address */
      if (inet_pton (AF_INET, ip_start, &ip4) != 1)
	continue;

      /* Store in hash: cn -> ip (network byte order) */
      hash_set_mem (db->persist_ip_by_cn_hash, vec_dup ((u8 *) cn_start),
		    ip4.as_u32);
    }

  fclose (f);

  return 0;
}

/*
 * Save ifconfig-pool-persist data to file
 */
int
ovpn_peer_persist_save (ovpn_peer_db_t *db)
{
  FILE *f;
  hash_pair_t *hp;

  if (!db || !db->persist_file_path || !db->persist_ip_by_cn_hash)
    return -1;

  /* Only save if dirty */
  if (!db->persist_dirty)
    return 0;

  f = fopen ((char *) db->persist_file_path, "w");
  if (!f)
    return -1;

  /* Write header */
  fprintf (f, "# ifconfig-pool-persist data\n");
  fprintf (f, "# Format: common_name,ip_address\n");

  /* Write each CN->IP mapping */
  hash_foreach_pair (hp, db->persist_ip_by_cn_hash, ({
		       u8 *cn = (u8 *) hp->key;
		       u32 ip_net = (u32) hp->value[0];
		       ip4_address_t ip4;
		       ip4.as_u32 = ip_net;
		       char ip_str[INET_ADDRSTRLEN];
		       inet_ntop (AF_INET, &ip4, ip_str, sizeof (ip_str));
		       fprintf (f, "%s,%s\n", cn, ip_str);
		     }));

  fclose (f);
  db->persist_dirty = 0;

  return 0;
}

/*
 * Lookup persisted IP for a common name
 */
int
ovpn_peer_persist_lookup (ovpn_peer_db_t *db, const char *common_name,
			  ip_address_t *ip_out)
{
  uword *p;

  if (!db || !common_name || !ip_out || !db->persist_ip_by_cn_hash)
    return 0;

  p = hash_get_mem (db->persist_ip_by_cn_hash, common_name);
  if (!p)
    return 0;

  /* Found - return IPv4 address */
  ip_out->version = AF_IP4;
  ip_out->ip.ip4.as_u32 = (u32) p[0];

  return 1;
}

/*
 * Store IP assignment in persist cache (marks dirty)
 */
void
ovpn_peer_persist_store (ovpn_peer_db_t *db, const char *common_name,
			 const ip_address_t *ip)
{
  if (!db || !common_name || !ip)
    return;

  /* Only support IPv4 for now */
  if (ip->version != AF_IP4)
    return;

  /* Initialize hash if needed */
  if (!db->persist_ip_by_cn_hash)
    db->persist_ip_by_cn_hash = hash_create_string (0, sizeof (u32));

  /* Check if this CN already exists with same IP */
  uword *existing = hash_get_mem (db->persist_ip_by_cn_hash, common_name);
  if (existing && (u32) existing[0] == ip->ip.ip4.as_u32)
    return; /* No change needed */

  /* Store CN -> IP mapping */
  u8 *cn_copy = (u8 *) vec_dup ((u8 *) common_name);
  hash_set_mem (db->persist_ip_by_cn_hash, cn_copy, ip->ip.ip4.as_u32);

  /* Mark as dirty */
  db->persist_dirty = 1;
}

/*
 * Free persist resources
 */
void
ovpn_peer_persist_free (ovpn_peer_db_t *db)
{
  if (!db)
    return;

  /* Save any unsaved changes */
  if (db->persist_dirty)
    ovpn_peer_persist_save (db);

  /* Free hash and its string keys */
  if (db->persist_ip_by_cn_hash)
    {
      hash_pair_t *hp;
      hash_foreach_pair (hp, db->persist_ip_by_cn_hash, ({
			   u8 *key = (u8 *) hp->key;
			   vec_free (key);
			 }));
      hash_free (db->persist_ip_by_cn_hash);
      db->persist_ip_by_cn_hash = NULL;
    }

  vec_free (db->persist_file_path);
  db->persist_dirty = 0;
}

/*
 * Common name hash functions for duplicate-cn detection
 */

/*
 * Lookup peer by common name
 */
u32
ovpn_peer_lookup_by_cn (ovpn_peer_db_t *db, const char *common_name)
{
  uword *p;

  if (!db || !common_name || !db->peer_id_by_cn_hash)
    return ~0;

  p = hash_get_mem (db->peer_id_by_cn_hash, common_name);
  if (!p)
    return ~0;

  return (u32) p[0];
}

/*
 * Add peer to CN hash
 */
void
ovpn_peer_cn_hash_add (ovpn_peer_db_t *db, const char *common_name,
		       u32 peer_id)
{
  if (!db || !common_name)
    return;

  /* Initialize hash if needed */
  if (!db->peer_id_by_cn_hash)
    db->peer_id_by_cn_hash = hash_create_string (0, sizeof (u32));

  /* Remove existing entry if present (shouldn't happen normally) */
  uword *existing = hash_get_mem (db->peer_id_by_cn_hash, common_name);
  if (existing)
    {
      u8 *old_key = (u8 *) existing[-1];
      hash_unset_mem (db->peer_id_by_cn_hash, common_name);
      vec_free (old_key);
    }

  /* Add new entry */
  u8 *cn_copy = (u8 *) vec_dup ((u8 *) common_name);
  hash_set_mem (db->peer_id_by_cn_hash, cn_copy, peer_id);
}

/*
 * Remove peer from CN hash
 */
void
ovpn_peer_cn_hash_del (ovpn_peer_db_t *db, const char *common_name)
{
  if (!db || !common_name || !db->peer_id_by_cn_hash)
    return;

  uword *p = hash_get_mem (db->peer_id_by_cn_hash, common_name);
  if (p)
    {
      u8 *key = (u8 *) p[-1];
      hash_unset_mem (db->peer_id_by_cn_hash, common_name);
      vec_free (key);
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
