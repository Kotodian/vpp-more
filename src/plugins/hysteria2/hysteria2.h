/* SPDX-License-Identifier: Apache-2.0 */

#ifndef __included_hysteria2_h__
#define __included_hysteria2_h__

#include <http/http.h>
#include <http/http_header_names.h>
#include <http/http_status_codes.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/lock.h>

#define HYSTERIA2_MAX_ADDR_LEN		 2048
#define HYSTERIA2_QUIC_DGRAM_MTU	 1100
#define HYSTERIA2_FRAGMENT_TIMEOUT	 10.0
#define HYSTERIA2_MAX_FRAGMENTS_PER_CONN 256

#define H2_TCP_RELAY_TAG  (1u << 31)
#define H2_MASQ_RELAY_TAG (1u << 30)
#define H2_RELAY_TAG_MASK (H2_TCP_RELAY_TAG | H2_MASQ_RELAY_TAG)
#define H2_TCP_REQUEST_ID 0x401

typedef enum
{
  H2_TCP_STATE_WAIT_REQUEST = 0,
  H2_TCP_STATE_CONNECTING,
  H2_TCP_STATE_FORWARDING,
  H2_TCP_STATE_CLOSING,
} hysteria2_tcp_state_t;

typedef enum
{
  H2_MASQ_STATE_BUFFERING_REQUEST = 0,
  H2_MASQ_STATE_CONNECTING,
  H2_MASQ_STATE_FORWARDING,
  H2_MASQ_STATE_CLOSING,
} hysteria2_masq_state_t;

typedef struct
{
  u32 conn_index;
  session_handle_t stream_sh;
  session_handle_t tcp_sh;
  ip46_address_t target_ip;
  u16 target_port;
  u8 target_is_ip4;
  u8 state;
} hysteria2_tcp_relay_t;

typedef struct
{
  session_handle_t client_sh;
  session_handle_t backend_sh;
  u32 server_index;
  u8 state;
  u8 close_pending;
  u8 backend_pending;
  u8 response_truncated;
  u16 backend_refs;
  u64 request_body_left;
  u32 request_offset;
  u8 *request;
  u8 *response;
  u8 *response_tx;
  u32 response_tx_offset;
} hysteria2_masq_relay_t;

typedef struct
{
  u32 server_index;
  session_handle_t quic_session_handle;
  u32 n_relays;
  u32 n_fragments;
  f64 last_activity;
  u64 negotiated_tx_rate;
  u64 rx_dgrams;
  u64 tx_dgrams;
  u8 is_closing;
} hysteria2_conn_t;

typedef struct
{
  u32 conn_index;
  u32 session_id;
  session_handle_t udp_session_handle;
  u32 outbound_index;
  ip46_address_t target_ip;
  u16 target_port;
  u8 target_is_ip4;
  u8 *target_name;
  u8 **pending_tx;
  f64 last_activity;
  u16 next_packet_id;
  u8 is_connecting;
  u8 is_connected;
  u8 is_closing;
} hysteria2_relay_t;

typedef struct
{
  u32 conn_index;
  u32 session_id;
  u16 packet_id;
  u8 frag_count;
  u8 *addr;
  u8 *received;
  u8 **fragments;
  f64 last_activity;
} hysteria2_fragment_t;

/* --- ACL / Outbound types --- */

typedef enum
{
  H2_ACL_ACTION_DIRECT = 0,
  H2_ACL_ACTION_BLOCK,
  H2_ACL_ACTION_HIJACK,
} h2_acl_action_t;

typedef struct
{
  h2_acl_action_t action;
  u32 outbound_index;
  ip46_address_t hijack_ip;
  u16 hijack_port;
  u8 hijack_is_ip4;
} h2_acl_rule_t;

typedef struct
{
  u8 *suffix;
  u32 suffix_len;
  h2_acl_rule_t rule;
} h2_acl_suffix_rule_t;

typedef struct
{
  u8 *keyword;
  u32 keyword_len;
  h2_acl_rule_t rule;
} h2_acl_keyword_rule_t;

typedef struct
{
  ip_prefix_t prefix;
  h2_acl_rule_t rule;
} h2_acl_cidr_rule_t;

typedef struct
{
  u8 *name;
  u32 table_id;
  u8 is_active;
} h2_outbound_t;

typedef struct
{
  h2_acl_rule_t *rules;			/**< pool of rules */
  uword *exact_domain_hash;		/**< domain → rule pool index */
  h2_acl_suffix_rule_t *suffix_rules;	/**< vec of suffix rules */
  h2_acl_keyword_rule_t *keyword_rules; /**< vec of keyword rules */
  h2_acl_cidr_rule_t *cidr_rules;	/**< vec of CIDR rules */
  u32 ip4_acl_fib_index;		/**< FIB for IPv4 CIDR rules */
  u32 ip6_acl_fib_index;		/**< FIB for IPv6 CIDR rules */
  h2_acl_rule_t default_rule;		/**< fallback when no match */
  u64 n_blocks;
  u64 n_hijacks;
  u64 n_directs;
} h2_acl_ctx_t;

typedef struct
{
  session_endpoint_cfg_t sep;
  session_handle_t handle;
  u32 ckpair_index;
  u32 table_id;
  u32 idle_timeout;
  u64 max_tx_rate;
  u64 auth_successes;
  u64 auth_failures;
  u8 *uri;
  u8 *auth_secret;
  u8 *salamander_password;
  u8 *masq_url;
  u8 *masq_host;
  ip46_address_t masq_ip;
  u16 masq_port;
  u8 masq_is_ip4;
  h2_acl_ctx_t acl;
} hysteria2_server_t;

/* Callback typedefs matching quic plugin signatures.
 * We resolve these at init time via vlib_get_plugin_symbol
 * since plugins are loaded with RTLD_LAZY (no cross-plugin linking). */
typedef void (h2_quic_dgram_rx_fn_t) (session_handle_t, const u8 *, u32, void *);
typedef void (h2_quic_dgram_closed_fn_t) (session_handle_t, void *);
typedef int (h2_quic_stream_accept_fn_t) (session_t *, void *);

typedef int (*h2_quic_datagram_bind_fn_t) (session_handle_t, h2_quic_dgram_rx_fn_t *,
					   h2_quic_dgram_closed_fn_t *, void *);
typedef int (*h2_quic_datagram_send_fn_t) (session_handle_t, const u8 *, u32);
typedef int (*h2_quic_stream_bind_fn_t) (session_handle_t, h2_quic_stream_accept_fn_t *, void *,
					 u32);
typedef int (*h2_quic_cc_brutal_set_fn_t) (session_handle_t, u64);

typedef struct
{
  vlib_main_t *vlib_main;
  u32 app_index;
  u32 msg_id_base;
  u32 fifo_size;
  u32 prealloc_fifos;
  u64 private_segment_size;
  hysteria2_server_t *servers;
  hysteria2_conn_t *conns;
  hysteria2_relay_t *relays;
  hysteria2_fragment_t *fragments;
  hysteria2_tcp_relay_t *tcp_relays;
  hysteria2_masq_relay_t *masq_relays;
  uword *server_index_by_uri;
  clib_bihash_8_8_t server_by_handle;
  clib_bihash_8_8_t conn_by_quic_handle;
  clib_bihash_8_8_t relay_by_conn_session;
  clib_bihash_16_8_t frag_by_conn_key;
  h2_outbound_t *outbounds;
  uword *outbound_by_name;
  clib_rwlock_t lock;
  f64 next_gc_time;

  /* Resolved quic plugin function pointers */
  h2_quic_datagram_bind_fn_t quic_datagram_bind;
  h2_quic_datagram_send_fn_t quic_datagram_send;
  h2_quic_stream_bind_fn_t quic_stream_bind;
  h2_quic_cc_brutal_set_fn_t quic_cc_brutal_set;
} hysteria2_main_t;

extern hysteria2_main_t hysteria2_main;

#endif
