/*
 * ovpn_peer.h - OpenVPN peer management
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

#ifndef __included_ovpn_peer_h__
#define __included_ovpn_peer_h__

#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#include <vnet/adj/adj.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_24_8.h>
#include <ovpn/ovpn_crypto.h>
#include <ovpn/ovpn_session_id.h>
#include <ovpn/ovpn_packet.h>
#include <ovpn/ovpn_reliable.h>
#include <ovpn/ovpn_buffer.h>
#include <ovpn/ovpn_fragment.h>
#include <picotls.h>

/*
 * Synchronization for multi-threaded access
 *
 * Race conditions addressed:
 * 1. Peer add/delete - control plane modifies while data plane reads
 * 2. Rekey - key slots change while data plane uses them
 * 3. Peer lookup - hash table modified during lookup
 *
 * Strategy:
 * - Generation counter: detect stale peer references
 * - Soft delete: mark DEAD, defer actual free until safe
 * - Bihash for key lookup: lock-free (peer_id, key_id) -> crypto context
 * - Worker barrier for peer add/delete operations
 */

/*
 * Per-client push options (from client-config-dir)
 *
 * These override or extend the global push options for a specific client.
 * Loaded from a file named after the client's Common Name (CN).
 *
 * Supported directives:
 *   push-reset        - Clear all inherited push options
 *   push-remove <opt> - Remove options matching pattern
 *   push "<option>"   - Add client-specific push option
 *   ifconfig-push <ip> <netmask> - Assign specific virtual IP
 *   iroute <network> <netmask>   - Internal route for this client
 */
typedef struct ovpn_peer_push_options_t_
{
  /*
   * push-reset flag
   * If set, do not inherit any push options from global config.
   * Only per-client push options will be sent.
   */
  u8 push_reset;

  /*
   * push-remove patterns
   * Array of option prefixes to remove from inherited options.
   * E.g., "route" removes all "route ..." options.
   */
  u8 **push_remove_patterns; /* vec of pattern strings */
  u32 n_push_remove_patterns;

  /*
   * Per-client push options
   * Additional options to push to this specific client.
   */
  u8 **push_options; /* vec of option strings */
  u32 n_push_options;

  /*
   * Fixed virtual IP from ifconfig-push
   * If set, overrides pool allocation.
   */
  ip_address_t ifconfig_push_ip;
  ip_address_t ifconfig_push_netmask;
  u8 has_ifconfig_push;

  /*
   * Internal routes (iroute)
   * Networks behind this client that should be routed through it.
   * These create routes in the server's routing table.
   */
  fib_prefix_t *iroutes;
  u32 n_iroutes;

  /*
   * Client's Common Name (from certificate)
   * Used for client-config-dir lookup.
   */
  u8 *common_name;

  /*
   * Disable flag (from client-config-dir)
   * If set, reject this client's connection.
   */
  u8 disable;

} ovpn_peer_push_options_t;

/* Peer state */
typedef enum
{
  OVPN_PEER_STATE_INITIAL = 0,
  OVPN_PEER_STATE_HANDSHAKE,
  OVPN_PEER_STATE_PENDING_AUTH, /* Waiting for management auth response */
  OVPN_PEER_STATE_ESTABLISHED,
  OVPN_PEER_STATE_REKEYING,
  OVPN_PEER_STATE_DEAD,
} ovpn_peer_state_t;

/* Key slot indices */
#define OVPN_KEY_SLOT_PRIMARY	0
#define OVPN_KEY_SLOT_SECONDARY 1
#define OVPN_KEY_SLOT_COUNT	2

/*
 * Per-peer key state
 * Each peer can have up to 2 active keys for seamless rekeying
 */
typedef struct ovpn_peer_key_t_
{
  ovpn_crypto_context_t crypto;
  u8 key_id;
  u8 is_active;
  f64 created_at;
  f64 expires_at;
} ovpn_peer_key_t;

/*
 * TLS handshake state for a peer
 * Used during the TLS negotiation phase
 */
typedef enum
{
  OVPN_TLS_STATE_INITIAL = 0,
  OVPN_TLS_STATE_HANDSHAKE,
  OVPN_TLS_STATE_ESTABLISHED,
  OVPN_TLS_STATE_ERROR,
} ovpn_tls_state_t;

/* Forward declaration for key_source2 */
struct ovpn_key_source2_t_;

/* Forward declaration for TLS-Crypt context */
struct ovpn_tls_crypt_t_;

typedef struct ovpn_peer_tls_t_
{
  /* TLS state */
  ovpn_tls_state_t state;

  /* Picotls context for this peer */
  ptls_t *tls;

  /* Per-client TLS-Crypt context for TLS-Crypt-V2 (may be NULL) */
  struct ovpn_tls_crypt_t_ *tls_crypt;

  /* Key ID for this handshake */
  u8 key_id;

  /* Reliable layer for control channel */
  ovpn_reliable_t *send_reliable;
  ovpn_reliable_t *recv_reliable;

  /* ACK tracking */
  ovpn_reliable_ack_t recv_ack; /* Packet IDs we need to ACK */
  ovpn_reliable_ack_t sent_ack; /* Our packet IDs waiting for ACK */
  ovpn_reliable_ack_t lru_acks; /* Recently ACKed packet IDs */

  /* Buffers for TLS data */
  ovpn_reli_buffer_t plaintext_read_buf;
  ovpn_reli_buffer_t ack_write_buf;

  /* Next packet ID to send */
  u32 packet_id_send;

  /*
   * Key Method 2 state
   * Holds random material exchanged between client and server
   */
  struct ovpn_key_source2_t_ *key_src2;

  /* Flags for key exchange state */
  u8 key_method_sent : 1;     /* We have sent our key method data */
  u8 key_method_received : 1; /* We have received peer's key method data */
  u8 use_tls_ekm : 1;	      /* Use TLS-EKM instead of PRF for key derivation */

  /*
   * Client's key direction from options string (keydir option)
   * 0 = normal, 1 = inverse, -1 = not specified (default to 1)
   */
  i8 client_keydir;

  /*
   * Negotiated data channel cipher from client options
   * This is determined from the "cipher" option in the client's
   * Key Method 2 options string during negotiation.
   */
  u8 negotiated_cipher_alg; /* ovpn_cipher_alg_t */

  /* Client's options string (parsed from Key Method 2 data) */
  char *peer_options;

  /*
   * Client's Common Name extracted from X.509 certificate
   * Used for client-config-dir file lookup.
   * Populated during certificate verification callback.
   */
  char *client_common_name;

} ovpn_peer_tls_t;

/*
 * OpenVPN peer structure
 *
 * Cache line layout optimized for data plane performance:
 * - Cacheline 0: Hot read-only data (peer lookup, crypto access)
 * - Cacheline 1: Hot read-write data (statistics, timestamps)
 * - Cacheline 2+: Cold data (TLS context, auth, rekey state)
 */
typedef struct ovpn_peer_t_
{
  /* CACHELINE 0: Hot read-only data path fields */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* Peer identification - accessed on every packet */
  u32 peer_id;		/* 24-bit peer ID for DATA_V2 packets */
  u32 sw_if_index;	/* Associated interface */
  u8 current_key_slot;	/* Which key slot is currently active */
  u8 is_ipv6;		/* Remote endpoint IP version */
  u16 remote_port;	/* Remote UDP port */

  /*
   * Fast key_id to key slot mapping (OpenVPN key IDs are 0-7, 3-bit).
   * Updated during rekey. Avoids bihash lookup on every data packet.
   * Value 0xFF means no mapping (fall back to bihash).
   */
  u8 key_id_to_slot[8];

  /* Peer state - use atomic access */
  volatile ovpn_peer_state_t state;

  /* Generation counter for detecting stale references */
  volatile u32 generation;

  /* Thread index for input processing */
  u32 input_thread_index;

  /* Adjacency for reaching this peer */
  adj_index_t adj_index;

  /* Remote endpoint address */
  ip_address_t remote_addr;

  /* CACHELINE 1: Hot read-write data (statistics) */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);

  /* Statistics - updated on every packet */
  u64 rx_bytes;
  u64 tx_bytes;
  u64 rx_packets;
  u64 tx_packets;

  /* Timestamps - updated frequently */
  f64 last_rx_time;
  f64 last_tx_time;

  /* Bytes/packets since last rekey (for reneg-bytes/reneg-pkts) */
  u64 bytes_since_rekey;
  u64 packets_since_rekey;

  /* CACHELINE 2+: Cold data (control plane, handshake) */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline2);

  /* Key slots for data channel crypto */
  ovpn_peer_key_t keys[OVPN_KEY_SLOT_COUNT];

  /* Session IDs */
  ovpn_session_id_t session_id;	      /* Our session ID */
  ovpn_session_id_t remote_session_id; /* Peer's session ID */

  /* TLS handshake context (allocated during handshake, freed after) */
  ovpn_peer_tls_t *tls_ctx;

  /* Virtual IP assigned to this peer (for server mode) */
  ip_address_t virtual_ip;
  u8 virtual_ip_set;

  /*
   * Per-client push options (from client-config-dir)
   * NULL if no client-specific config exists.
   * Allocated when client connects and CN is looked up.
   */
  ovpn_peer_push_options_t *client_push_opts;

  /*
   * Client authentication info
   */
  u8 *username; /* Username from auth-user-pass (NULL if not authenticated) */

  /*
   * Pending management auth state (for management-client-auth)
   * These are set when awaiting async auth response from management interface.
   * Password is securely zeroed after auth completes or times out.
   */
  u8 *pending_auth_username;
  u8 *pending_auth_password;
  u32 pending_auth_key_id; /* Key ID to use after auth succeeds */

  /* Timers */
  f64 established_time;

  /* Rekey state */
  f64 rekey_interval;	 /* Seconds between rekeys (0 = disabled) */
  f64 next_rekey_time;	 /* When to initiate next rekey */
  f64 last_rekey_time;	 /* When last rekey completed */
  u8 rekey_key_id;	 /* Key ID for current/pending rekey */
  u8 rekey_initiated;	 /* 1 if we initiated the rekey */
  u8 pending_key_slot;	 /* Key slot for pending rekey keys */

  /* Rewrite data for output */
  u8 *rewrite;
  u32 rewrite_len;

  /* FIB table */
  u32 fib_index;

  /*
   * NAT/Float support: pending address for event-driven update.
   * Data plane stores new address here and signals event.
   * Control plane applies the update with worker barrier.
   */
  ip_address_t pending_remote_addr;
  u16 pending_remote_port;

  /*
   * Fragment state for this peer
   * Used when fragment option is enabled to fragment large packets
   * and reassemble incoming fragments.
   */
  ovpn_frag_state_t frag_state;

} ovpn_peer_t;

/*
 * Assign thread index to peer if not already assigned
 * Returns the assigned thread index
 */
always_inline u32
ovpn_peer_assign_thread (ovpn_peer_t *peer, u32 thread_index)
{
  /* Use compare-and-swap to assign thread only once */
  u32 unassigned = ~0;
  __atomic_compare_exchange_n (&peer->input_thread_index, &unassigned,
			       thread_index, 0, __ATOMIC_RELAXED,
			       __ATOMIC_RELAXED);
  return peer->input_thread_index;
}

/*
 * Peer database
 */
typedef struct ovpn_peer_db_t_
{
  /* Pool of peers */
  ovpn_peer_t *peers;

  /* Lookup by peer_id (direct index, peer_id = pool index) */
  /* For large deployments, might need a hash table */

  /*
   * Bihash for lock-free lookup by remote address + port.
   * Key: 24 bytes (ip_address_t + port padded)
   * Value: peer_id
   * Used for P_DATA_V1 and handshake packets.
   */
  clib_bihash_24_8_t remote_hash;

  /* Lookup by virtual IP (control plane only, not performance critical) */
  uword *peer_index_by_virtual_ip;

  /*
   * Bihash for lock-free key lookup by (peer_id, key_id).
   * Key: (peer_id << 8) | key_id
   * Value: pointer to ovpn_peer_key_t
   * Provides lock-free concurrent access for data plane crypto lookups.
   */
  clib_bihash_8_8_t key_hash;

  /*
   * Bihash for lock-free lookup by session ID.
   * Key: 8-byte session ID
   * Value: peer_id
   * Used for NAT/float support when address lookup fails.
   */
  clib_bihash_8_8_t session_hash;

  /* Next peer_id to allocate */
  u32 next_peer_id;

  /* Associated interface sw_if_index */
  u32 sw_if_index;

  /*
   * Global generation counter.
   * Incremented on any structural change to help detect stale state.
   */
  u32 generation;

  /*
   * NOTE: Peer add/delete operations use worker thread barrier
   * (vlib_worker_thread_barrier_sync/release) for synchronization.
   * This pauses all worker threads, ensuring no stale references.
   * No spinlock needed - barrier provides stronger guarantee.
   */

  /*
   * MAC address to peer_id hash for TAP mode L2 forwarding.
   * Key: 6-byte MAC address padded to 8 bytes
   * Value: peer_id
   *
   * When receiving decrypted Ethernet frames, we learn the source MAC.
   * When transmitting, we lookup the destination MAC to find the peer.
   */
  clib_bihash_8_8_t mac_hash;

  /* Flag indicating MAC hash is initialized */
  u8 mac_hash_initialized;

  /*
   * Common name to peer_id hash for duplicate-cn detection.
   * Key: hash of common_name string
   * Value: peer_id
   * Used to find existing peer with same CN when duplicate-cn is disabled.
   */
  uword *peer_id_by_cn_hash;

  /*
   * ifconfig-pool-persist: CN -> IP mapping
   * Loaded from persist file on startup, updated when IPs are assigned.
   * Key: hash of common_name string
   * Value: IPv4 address (network byte order)
   */
  uword *persist_ip_by_cn_hash; /* hash(cn) -> ip */

  /* Path to persist file (NULL if not configured) */
  u8 *persist_file_path;

  /* Flag indicating persist data was modified and needs saving */
  u8 persist_dirty;

  /* Last time persist file was saved (for interval-based saving) */
  f64 persist_last_save_time;

  /* Number of currently established peers (for max-clients enforcement) */
  u32 n_established;

} ovpn_peer_db_t;

/*
 * Global mapping from adjacency index to peer index
 * Used by output nodes to find the peer for a given adjacency
 */
extern u32 *ovpn_peer_by_adj_index;

/*
 * Lookup peer by adjacency index
 */
always_inline u32
ovpn_peer_get_by_adj_index (adj_index_t ai)
{
  if (ai >= vec_len (ovpn_peer_by_adj_index))
    return ~0;
  return ovpn_peer_by_adj_index[ai];
}

/*
 * Associate a peer with an adjacency index
 */
void ovpn_peer_adj_index_add (u32 peer_id, adj_index_t ai);

/*
 * Remove peer-adjacency association
 */
void ovpn_peer_adj_index_del (adj_index_t ai);

/*
 * Stack the peer's adjacency to reach the endpoint
 */
void ovpn_peer_adj_stack (ovpn_peer_t *peer, adj_index_t ai);

/*
 * Initialize peer database
 * @param max_clients If 0, use heap allocation for bihash (dynamic sizing)
 *                    If > 0, use fixed sizing based on max_clients
 */
void ovpn_peer_db_init (ovpn_peer_db_t *db, u32 sw_if_index, u32 max_clients);

/*
 * Free peer database
 */
void ovpn_peer_db_free (ovpn_peer_db_t *db);

/*
 * Create a new peer
 * Returns peer_id on success, ~0 on failure
 */
u32 ovpn_peer_create (ovpn_peer_db_t *db, const ip_address_t *remote_addr,
		      u16 remote_port);

/*
 * Delete a peer
 * MUST be called with worker barrier held (vlib_worker_thread_barrier_sync)
 */
void ovpn_peer_delete (ovpn_peer_db_t *db, u32 peer_id);

/*
 * Lookup peer by peer_id
 */
always_inline ovpn_peer_t *
ovpn_peer_get (ovpn_peer_db_t *db, u32 peer_id)
{
  if (!db || !db->peers)
    {
      clib_warning ("ovpn_peer_get: db=%p db->peers=%p peer_id=%u",
		    db, db ? db->peers : NULL, peer_id);
      return NULL;
    }
  if (pool_is_free_index (db->peers, peer_id))
    {
      clib_warning (
	"ovpn_peer_get: peer_id=%u is free (pool_elts=%u pool_len=%u)",
	peer_id, pool_elts (db->peers), vec_len (db->peers));
      return NULL;
    }
  return pool_elt_at_index (db->peers, peer_id);
}

/*
 * Atomic state access functions
 */
always_inline ovpn_peer_state_t
ovpn_peer_get_state (ovpn_peer_t *peer)
{
  return __atomic_load_n (&peer->state, __ATOMIC_ACQUIRE);
}

always_inline void
ovpn_peer_set_state (ovpn_peer_t *peer, ovpn_peer_state_t state)
{
  __atomic_store_n (&peer->state, state, __ATOMIC_RELEASE);
}

always_inline int
ovpn_peer_is_valid (ovpn_peer_t *peer)
{
  ovpn_peer_state_t state = ovpn_peer_get_state (peer);
  return state != OVPN_PEER_STATE_DEAD && state != OVPN_PEER_STATE_INITIAL;
}

/*
 * Generation counter functions
 */
always_inline u32
ovpn_peer_get_generation (ovpn_peer_t *peer)
{
  return __atomic_load_n (&peer->generation, __ATOMIC_ACQUIRE);
}

always_inline void
ovpn_peer_increment_generation (ovpn_peer_t *peer)
{
  __atomic_add_fetch (&peer->generation, 1, __ATOMIC_RELEASE);
}

/*
 * Bihash key helper for (peer_id, key_id) -> crypto context lookup
 */
always_inline u64
ovpn_peer_key_hash_key (u32 peer_id, u8 key_id)
{
  return ((u64) peer_id << 8) | key_id;
}

/*
 * Check if peer is usable by data plane
 * Returns 1 if peer is in a valid state for data processing
 */
always_inline int
ovpn_peer_is_established (ovpn_peer_t *peer)
{
  ovpn_peer_state_t state = ovpn_peer_get_state (peer);
  return state == OVPN_PEER_STATE_ESTABLISHED ||
	 state == OVPN_PEER_STATE_REKEYING;
}

/*
 * Lookup peer by remote address and port
 */
ovpn_peer_t *ovpn_peer_lookup_by_remote (ovpn_peer_db_t *db,
					 const ip_address_t *addr, u16 port);

/*
 * Lookup peer by virtual IP
 */
ovpn_peer_t *ovpn_peer_lookup_by_virtual_ip (ovpn_peer_db_t *db,
					     const ip_address_t *addr);

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
int ovpn_peer_set_virtual_ip (ovpn_peer_db_t *db, ovpn_peer_t *peer,
			      const ip_address_t *virtual_ip);

/*
 * Allocate virtual IP from pool for a peer
 * Finds the next available IP in the range [pool_start, pool_end]
 * and assigns it to the peer.
 *
 * @param db Peer database
 * @param peer Peer to assign IP to
 * @param pool_start Start of IP pool (inclusive)
 * @param pool_end End of IP pool (inclusive)
 * @return 0 on success, <0 on error:
 *   -1: invalid parameters
 *   -2: pool exhausted (no available IPs)
 */
int ovpn_peer_allocate_virtual_ip_from_pool (ovpn_peer_db_t *db,
					     ovpn_peer_t *peer,
					     const ip_address_t *pool_start,
					     const ip_address_t *pool_end);

/*
 * Allocate virtual IP from pool for a peer with persist support
 *
 * If common_name is provided and a persisted IP exists for this CN,
 * that IP will be used (if still in pool range and available).
 * Otherwise, allocates next available IP from pool.
 *
 * When an IP is successfully allocated, it's stored in the persist cache.
 *
 * @param db Peer database
 * @param peer Peer to assign IP to
 * @param pool_start Start of IP pool (inclusive)
 * @param pool_end End of IP pool (inclusive)
 * @param common_name Client's common name (can be NULL)
 * @return 0 on success, <0 on error
 */
int ovpn_peer_allocate_virtual_ip_with_persist (ovpn_peer_db_t *db,
						ovpn_peer_t *peer,
						const ip_address_t *pool_start,
						const ip_address_t *pool_end,
						const char *common_name);

/*
 * Lookup peer by session ID (for NAT/float support)
 * Used when address-based lookup fails due to NAT rebinding
 */
ovpn_peer_t *ovpn_peer_lookup_by_session_id (ovpn_peer_db_t *db,
					     const ovpn_session_id_t *session_id);

/*
 * Update peer remote address (NAT/float support)
 * Called when peer's source address changes after successful authentication.
 * MUST be called with worker barrier held.
 * Returns 0 on success, <0 on error.
 */
int ovpn_peer_update_remote (ovpn_peer_db_t *db, ovpn_peer_t *peer,
			     const ip_address_t *new_addr, u16 new_port);

/*
 * Add peer to session ID hash (called after session ID is set)
 */
void ovpn_peer_add_to_session_hash (ovpn_peer_db_t *db, ovpn_peer_t *peer);

/*
 * Set peer crypto key (updates bihash for lock-free lookup)
 * @param replay_window Replay protection window size (0 for default)
 */
int ovpn_peer_set_key (vlib_main_t *vm, ovpn_peer_db_t *db, ovpn_peer_t *peer,
		       u8 key_slot, ovpn_cipher_alg_t cipher_alg,
		       const ovpn_key_material_t *keys, u8 key_id,
		       u32 replay_window);

/*
 * Get active crypto context for peer
 */
always_inline ovpn_crypto_context_t *
ovpn_peer_get_crypto (ovpn_peer_t *peer)
{
  return &peer->keys[peer->current_key_slot].crypto;
}

/*
 * Get crypto context by key_id using bihash lookup
 * Returns pointer to crypto context or NULL if not found
 */
ovpn_crypto_context_t *ovpn_peer_get_crypto_by_key_id (ovpn_peer_db_t *db,
						       u32 peer_id, u8 key_id);

/*
 * Update peer activity timestamp
 */
always_inline void
ovpn_peer_update_rx (ovpn_peer_t *peer, f64 now, u32 bytes)
{
  peer->last_rx_time = now;
  peer->rx_bytes += bytes;
  peer->rx_packets++;
  /* Track for reneg-bytes/reneg-pkts */
  peer->bytes_since_rekey += bytes;
  peer->packets_since_rekey++;
}

always_inline void
ovpn_peer_update_tx (ovpn_peer_t *peer, f64 now, u32 bytes)
{
  peer->last_tx_time = now;
  peer->tx_bytes += bytes;
  peer->tx_packets++;
  /* Track for reneg-bytes/reneg-pkts */
  peer->bytes_since_rekey += bytes;
  peer->packets_since_rekey++;
}

/*
 * Build rewrite for peer (UDP + outer IP header)
 */
int ovpn_peer_build_rewrite (ovpn_peer_t *peer, const ip_address_t *local_addr,
			     u16 local_port);

/*
 * Format peer for display
 */
u8 *format_ovpn_peer (u8 *s, va_list *args);

/*
 * MAC-to-peer lookup functions for TAP mode L2 forwarding
 */

/**
 * Build 8-byte key from 6-byte MAC address for bihash lookup
 */
always_inline u64
ovpn_peer_mac_to_key (const u8 *mac)
{
  u64 key = 0;
  clib_memcpy_fast (&key, mac, 6);
  return key;
}

/**
 * Learn MAC address for a peer (called on RX path)
 * Associates source MAC with peer_id for future TX lookups.
 *
 * @param db Peer database
 * @param mac 6-byte source MAC address
 * @param peer_id Peer that sent this MAC
 */
void ovpn_peer_mac_learn (ovpn_peer_db_t *db, const u8 *mac, u32 peer_id);

/**
 * Lookup peer by destination MAC address (called on TX path)
 * Returns peer_id or ~0 if not found.
 *
 * @param db Peer database
 * @param mac 6-byte destination MAC address
 * @return peer_id or ~0 if not found
 */
u32 ovpn_peer_mac_lookup (ovpn_peer_db_t *db, const u8 *mac);

/**
 * Remove all MAC entries for a peer (called on peer delete)
 *
 * @param db Peer database
 * @param peer_id Peer being deleted
 */
void ovpn_peer_mac_delete_all (ovpn_peer_db_t *db, u32 peer_id);

/*
 * Cleanup expired keys for a peer
 * Called by periodic timer to remove "lame duck" keys after transition window
 * Returns number of keys cleaned up
 */
int ovpn_peer_cleanup_expired_keys (vlib_main_t *vm, ovpn_peer_db_t *db,
				    ovpn_peer_t *peer, f64 now);

/*
 * Cleanup expired keys for all peers in database
 * Called by periodic timer process
 * Returns number of keys cleaned up
 */
int ovpn_peer_db_cleanup_expired_keys (vlib_main_t *vm, ovpn_peer_db_t *db,
				       f64 now);

/*
 * Initialize TLS handshake context for a peer
 * Called when transitioning to HANDSHAKE state
 * Returns 0 on success, <0 on error
 */
int ovpn_peer_tls_init (ovpn_peer_t *peer, ptls_context_t *ptls_ctx,
			u8 key_id);

/*
 * Free TLS handshake context
 * Called when handshake completes or fails
 */
void ovpn_peer_tls_free (ovpn_peer_t *peer);

/*
 * Process incoming TLS data from control channel
 * Returns: >0 if TLS data was produced for sending
 *          0 if no data to send
 *          <0 on error
 */
int ovpn_peer_tls_process (ovpn_peer_t *peer, u8 *data, u32 len);

/*
 * Get TLS data to send on control channel
 * Returns pointer to data and sets len, or NULL if no data
 */
u8 *ovpn_peer_tls_get_sendbuf (vlib_main_t *vm, ovpn_peer_t *peer, u32 *len);

/*
 * Check if TLS handshake is complete
 */
always_inline int
ovpn_peer_tls_is_established (ovpn_peer_t *peer)
{
  return peer->tls_ctx && peer->tls_ctx->state == OVPN_TLS_STATE_ESTABLISHED;
}

/*
 * Start a rekey for an established peer
 * Allocates TLS context and transitions to REKEYING state
 * Returns 0 on success, <0 on error
 */
int ovpn_peer_start_rekey (vlib_main_t *vm, ovpn_peer_t *peer,
			   ptls_context_t *ptls_ctx, u8 key_id);

/*
 * Complete a rekey - activate new keys and retire old ones
 * Called after TLS handshake completes during rekey
 * Returns 0 on success, <0 on error
 */
int ovpn_peer_complete_rekey (vlib_main_t *vm, ovpn_peer_db_t *db,
			      ovpn_peer_t *peer, ovpn_cipher_alg_t cipher_alg);

/*
 * Get the next key_id for rekey
 * Cycles through 0-7 (3 bits)
 */
always_inline u8
ovpn_peer_next_key_id (ovpn_peer_t *peer)
{
  u8 current_key_id = peer->keys[peer->current_key_slot].key_id;
  return (current_key_id + 1) & OVPN_OP_KEY_ID_MASK;
}

/*
 * Check if peer needs rekey based on time, bytes, or packets
 * Following OpenVPN: reneg-sec, reneg-bytes, reneg-pkts
 */
always_inline int
ovpn_peer_needs_rekey (ovpn_peer_t *peer, f64 now, u64 reneg_bytes,
		       u64 reneg_pkts)
{
  if (peer->state != OVPN_PEER_STATE_ESTABLISHED)
    return 0;
  if (peer->rekey_initiated)
    return 0; /* Already rekeying */

  /* Check time-based rekey (reneg-sec) */
  if (peer->rekey_interval > 0 && now >= peer->next_rekey_time)
    return 1;

  /* Check bytes-based rekey (reneg-bytes) */
  if (reneg_bytes > 0 && peer->bytes_since_rekey >= reneg_bytes)
    return 1;

  /* Check packets-based rekey (reneg-pkts) */
  if (reneg_pkts > 0 && peer->packets_since_rekey >= reneg_pkts)
    return 1;

  return 0;
}

/*
 * Build 24-byte key for remote address bihash lookup
 * Key structure: [ip_address (16 bytes)] [port (2 bytes)] [is_ipv6 (1 byte)] [padding (5 bytes)]
 */
always_inline void
ovpn_peer_remote_hash_make_key (clib_bihash_kv_24_8_t *kv,
				const ip_address_t *addr, u16 port)
{
  clib_memset (kv, 0, sizeof (*kv));
  if (addr->version == AF_IP4)
    {
      /* IPv4: store in first 4 bytes */
      kv->key[0] = addr->ip.ip4.as_u32;
      kv->key[1] = port;
      kv->key[2] = 0; /* is_ipv6 = 0 */
    }
  else
    {
      /* IPv6: store full 16 bytes */
      kv->key[0] = addr->ip.ip6.as_u64[0];
      kv->key[1] = addr->ip.ip6.as_u64[1];
      kv->key[2] = ((u64) port) | (1ULL << 16); /* port + is_ipv6 flag */
    }
}

/*
 * Send ping packet to peer
 * Used for keepalive - sends encrypted ping magic pattern on data channel
 */
void ovpn_peer_send_ping (vlib_main_t *vm, ovpn_peer_t *peer);

/*
 * Per-client push options management
 */

/**
 * Allocate and initialize per-client push options structure
 *
 * @param common_name Client's Common Name from certificate (copied)
 * @return Allocated structure, or NULL on error
 */
ovpn_peer_push_options_t *ovpn_peer_push_options_alloc (const char *common_name);

/**
 * Free per-client push options structure
 *
 * @param opts Structure to free (can be NULL)
 */
void ovpn_peer_push_options_free (ovpn_peer_push_options_t *opts);

/**
 * Load per-client config from client-config-dir
 *
 * Looks up a file named after the client's Common Name in the
 * client-config-dir directory and parses it for push options.
 *
 * Supported directives:
 *   push-reset               - Clear inherited push options
 *   push-remove <pattern>    - Remove matching inherited options
 *   push "<option>"          - Add client-specific option
 *   ifconfig-push <ip> <mask> - Assign specific virtual IP
 *   iroute <net> <mask>      - Add internal route
 *   disable                  - Reject this client
 *
 * @param config_dir Path to client-config-dir
 * @param common_name Client's Common Name
 * @return Allocated and populated structure, or NULL if no config found
 */
ovpn_peer_push_options_t *
ovpn_peer_load_client_config (const char *config_dir, const char *common_name);

/**
 * Add a push-remove pattern to per-client options
 *
 * @param opts Per-client options structure
 * @param pattern Pattern to remove (e.g., "route", "dhcp-option")
 * @return 0 on success, <0 on error
 */
int ovpn_peer_push_options_add_remove (ovpn_peer_push_options_t *opts,
				       const char *pattern);

/**
 * Add a push option to per-client options
 *
 * @param opts Per-client options structure
 * @param option Option string to push
 * @return 0 on success, <0 on error
 */
int ovpn_peer_push_options_add_push (ovpn_peer_push_options_t *opts,
				     const char *option);

/**
 * Add an internal route (iroute) to per-client options
 *
 * @param opts Per-client options structure
 * @param prefix Route prefix
 * @return 0 on success, <0 on error
 */
int ovpn_peer_push_options_add_iroute (ovpn_peer_push_options_t *opts,
				       const fib_prefix_t *prefix);

/**
 * Check if an option should be removed based on push-remove patterns
 *
 * @param opts Per-client options structure (can be NULL)
 * @param option Option string to check
 * @return 1 if option should be removed, 0 otherwise
 */
int ovpn_peer_push_options_should_remove (const ovpn_peer_push_options_t *opts,
					  const char *option);

/*
 * ifconfig-pool-persist functions
 */

/**
 * Load ifconfig-pool-persist file into peer database
 *
 * File format: common_name,ip_address (one per line)
 * Lines starting with # are treated as comments.
 *
 * @param db Peer database
 * @param file_path Path to persist file
 * @return 0 on success, <0 on error (file not found is not an error)
 */
int ovpn_peer_persist_load (ovpn_peer_db_t *db, const char *file_path);

/**
 * Save ifconfig-pool-persist data to file
 *
 * @param db Peer database
 * @return 0 on success, <0 on error
 */
int ovpn_peer_persist_save (ovpn_peer_db_t *db);

/**
 * Lookup persisted IP for a common name
 *
 * @param db Peer database
 * @param common_name Client's common name
 * @param ip_out Output: persisted IP address (if found)
 * @return 1 if found, 0 if not found
 */
int ovpn_peer_persist_lookup (ovpn_peer_db_t *db, const char *common_name,
			      ip_address_t *ip_out);

/**
 * Store IP assignment in persist cache (marks dirty)
 *
 * @param db Peer database
 * @param common_name Client's common name
 * @param ip IP address assigned
 */
void ovpn_peer_persist_store (ovpn_peer_db_t *db, const char *common_name,
			      const ip_address_t *ip);

/**
 * Free persist resources
 *
 * @param db Peer database
 */
void ovpn_peer_persist_free (ovpn_peer_db_t *db);

/*
 * Common name hash functions for duplicate-cn detection
 */

/**
 * Lookup peer by common name
 *
 * @param db Peer database
 * @param common_name Client's common name
 * @return peer_id if found, ~0 if not found
 */
u32 ovpn_peer_lookup_by_cn (ovpn_peer_db_t *db, const char *common_name);

/**
 * Add peer to CN hash
 *
 * @param db Peer database
 * @param common_name Client's common name
 * @param peer_id Peer ID to associate with CN
 */
void ovpn_peer_cn_hash_add (ovpn_peer_db_t *db, const char *common_name,
			    u32 peer_id);

/**
 * Remove peer from CN hash
 *
 * @param db Peer database
 * @param common_name Client's common name
 */
void ovpn_peer_cn_hash_del (ovpn_peer_db_t *db, const char *common_name);

#endif /* __included_ovpn_peer_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
