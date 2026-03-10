/* SPDX-License-Identifier: Apache-2.0 */

#include <netdb.h>

#include <vlib/unix/plugin.h>
#include <vnet/fib/fib_table.h>
#include <vnet/plugin/plugin.h>
#include <vnet/session/session.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

#include <hysteria2/hysteria2.h>

#include <hysteria2/hysteria2.api_enum.h>
#include <hysteria2/hysteria2.api_types.h>

#define REPLY_MSG_ID_BASE h2m->msg_id_base
#include <vlibapi/api_helper_macros.h>

hysteria2_main_t hysteria2_main;

static const char h2_auth_path[] = "auth";
static const char h2_auth_hdr[] = "hysteria-auth";
static const char h2_udp_hdr[] = "hysteria-udp";
static const char h2_cc_rx_hdr[] = "hysteria-cc-rx";
static const char h2_host_value[] = "hysteria";

static_always_inline hysteria2_server_t *
h2_server_get (u32 index)
{
  return pool_elt_at_index (hysteria2_main.servers, index);
}

static_always_inline hysteria2_conn_t *
h2_conn_get (u32 index)
{
  return pool_elt_at_index (hysteria2_main.conns, index);
}

static_always_inline hysteria2_relay_t *
h2_relay_get (u32 index)
{
  return pool_elt_at_index (hysteria2_main.relays, index);
}

static_always_inline hysteria2_fragment_t *
h2_fragment_get (u32 index)
{
  return pool_elt_at_index (hysteria2_main.fragments, index);
}

static_always_inline f64
h2_now (void)
{
  return vlib_time_now (hysteria2_main.vlib_main);
}

static_always_inline u64
h2_frag_key (u32 session_id, u16 packet_id)
{
  return ((u64) session_id << 16) | packet_id;
}

static_always_inline u64
h2_relay_bihash_key (u32 conn_index, u32 session_id)
{
  return ((u64) conn_index << 32) | session_id;
}

static_always_inline void
h2_frag_bihash_key (clib_bihash_kv_16_8_t *kv, u32 conn_index,
		    u32 session_id, u16 packet_id)
{
  kv->key[0] = conn_index;
  kv->key[1] = h2_frag_key (session_id, packet_id);
}

static void
h2_send_http_resp (session_t *s, http_status_code_t sc,
		   http_headers_ctx_t *headers)
{
  http_msg_t msg = {};
  svm_fifo_seg_t segs[2];
  u32 n_segs = 1;
  int rv;

  msg.type = HTTP_MSG_REPLY;
  msg.code = sc;
  msg.data.type = HTTP_MSG_DATA_INLINE;
  if (headers)
    {
      msg.data.headers_len = headers->tail_offset;
      segs[1].data = headers->buf;
      segs[1].len = headers->tail_offset;
      n_segs = 2;
    }
  segs[0].data = (u8 *) &msg;
  segs[0].len = sizeof (msg);

  rv =
    svm_fifo_enqueue_segments (s->tx_fifo, segs, n_segs, 0 /* allow partial */);
  ASSERT (rv ==
	  (int) (sizeof (msg) + (n_segs == 2 ? headers->tail_offset : 0)));
  if (svm_fifo_set_event (s->tx_fifo))
    session_program_tx_io_evt (s->handle, SESSION_IO_EVT_TX);
}

static int
h2_add_segment_cb (u32 client_index, u64 segment_handle)
{
  return 0;
}

static int
h2_del_segment_cb (u32 client_index, u64 segment_handle)
{
  return 0;
}

static void
h2_fragment_free_locked (u32 frag_index)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  hysteria2_fragment_t *frag;
  u32 i;

  if (pool_is_free_index (h2m->fragments, frag_index))
    return;

  frag = h2_fragment_get (frag_index);
  {
    clib_bihash_kv_16_8_t fkv;
    h2_frag_bihash_key (&fkv, frag->conn_index, frag->session_id,
			frag->packet_id);
    clib_bihash_add_del_16_8 (&h2m->frag_by_conn_key, &fkv, 0 /* is_del */);
  }
  if (!pool_is_free_index (h2m->conns, frag->conn_index))
    {
      hysteria2_conn_t *conn = h2_conn_get (frag->conn_index);
      if (conn->n_fragments)
	conn->n_fragments--;
    }

  vec_free (frag->addr);
  vec_free (frag->received);
  for (i = 0; i < vec_len (frag->fragments); i++)
    vec_free (frag->fragments[i]);
  vec_free (frag->fragments);
  pool_put (h2m->fragments, frag);
}

static void
h2_conn_maybe_free_locked (u32 conn_index)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  hysteria2_conn_t *conn;

  if (pool_is_free_index (h2m->conns, conn_index))
    return;

  conn = h2_conn_get (conn_index);
  if (!conn->is_closing || conn->n_relays)
    return;

  if (conn->quic_session_handle != SESSION_INVALID_HANDLE)
    {
      clib_bihash_kv_8_8_t kv = { .key = conn->quic_session_handle };
      clib_bihash_add_del_8_8 (&h2m->conn_by_quic_handle, &kv,
				0 /* is_del */);
    }
  pool_put (h2m->conns, conn);
}

static void
h2_relay_free_locked (u32 relay_index)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  hysteria2_relay_t *relay;
  u32 i;

  if (pool_is_free_index (h2m->relays, relay_index))
    return;

  relay = h2_relay_get (relay_index);
  {
    clib_bihash_kv_8_8_t rkv = {
      .key = h2_relay_bihash_key (relay->conn_index, relay->session_id)
    };
    clib_bihash_add_del_8_8 (&h2m->relay_by_conn_session, &rkv,
			      0 /* is_del */);
  }
  if (!pool_is_free_index (h2m->conns, relay->conn_index))
    {
      hysteria2_conn_t *conn = h2_conn_get (relay->conn_index);
      if (conn->n_relays)
	conn->n_relays--;
    }

  for (i = 0; i < vec_len (relay->pending_tx); i++)
    vec_free (relay->pending_tx[i]);
  vec_free (relay->pending_tx);
  vec_free (relay->target_name);
  {
    u32 ci = relay->conn_index;
    pool_put (h2m->relays, relay);
    if (!pool_is_free_index (h2m->conns, ci))
      h2_conn_maybe_free_locked (ci);
  }
}

static int
h2_resolve_target_host (u8 *host, u8 *port_str, ip46_address_t *ip, u8 *is_ip4)
{
  struct addrinfo hints = { 0 }, *res = 0;
  unformat_input_t input;
  int rv = -1;

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  unformat_init_string (&input, (char *) host, vec_len (host));
  if (unformat (&input, "%U", unformat_ip4_address, &ip->ip4) &&
      unformat_check_input (&input) == UNFORMAT_END_OF_INPUT)
    {
      *is_ip4 = 1;
      rv = 0;
    }
  else
    {
      unformat_free (&input);
      unformat_init_string (&input, (char *) host, vec_len (host));
      if (unformat (&input, "%U", unformat_ip6_address, &ip->ip6) &&
	  unformat_check_input (&input) == UNFORMAT_END_OF_INPUT)
	{
	  *is_ip4 = 0;
	  rv = 0;
	}
    }
  unformat_free (&input);

  if (!rv)
    return 0;

  vec_terminate_c_string (host);
  vec_terminate_c_string (port_str);
  if (getaddrinfo ((char *) host, (char *) port_str, &hints, &res))
    return -1;

  if (res->ai_family == AF_INET)
    {
      struct sockaddr_in *sa4 = (struct sockaddr_in *) res->ai_addr;
      ip->ip4.as_u32 = sa4->sin_addr.s_addr;
      *is_ip4 = 1;
      rv = 0;
    }
  else if (res->ai_family == AF_INET6)
    {
      struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) res->ai_addr;
      clib_memcpy_fast (&ip->ip6, &sa6->sin6_addr, sizeof (ip->ip6));
      *is_ip4 = 0;
      rv = 0;
    }

  freeaddrinfo (res);
  return rv;
}

static int
h2_parse_target_address (u8 *addr, ip46_address_t *ip, u16 *port, u8 *is_ip4)
{
  u8 *host = 0, *port_str = 0;
  char *endptr = 0;
  long parsed_port;
  word pos;

  if (!vec_len (addr))
    return -1;

  if (addr[0] == '[')
    {
      pos = vec_search (addr, ']');
      if (pos <= 1 || (u32) pos + 2 >= vec_len (addr) || addr[pos + 1] != ':')
	return -1;
      vec_validate (host, pos - 2);
      clib_memcpy_fast (host, addr + 1, pos - 1);
      vec_validate (port_str, vec_len (addr) - pos - 3);
      clib_memcpy_fast (port_str, addr + pos + 2, vec_len (addr) - pos - 2);
    }
  else
    {
      pos = vec_len (addr) - 1;
      while (pos >= 0 && addr[pos] != ':')
	pos--;
      if (pos <= 0 || (u32) pos + 1 >= vec_len (addr))
	return -1;
      vec_validate (host, pos - 1);
      clib_memcpy_fast (host, addr, pos);
      vec_validate (port_str, vec_len (addr) - pos - 2);
      clib_memcpy_fast (port_str, addr + pos + 1, vec_len (addr) - pos - 1);
    }

  if (!vec_len (host) || !vec_len (port_str) ||
      h2_resolve_target_host (host, port_str, ip, is_ip4))
    goto fail;

  parsed_port = strtol ((char *) port_str, &endptr, 10);
  if (!endptr || *endptr != 0 || parsed_port <= 0 || parsed_port > 65535)
    goto fail;

  *port = clib_host_to_net_u16 ((u16) parsed_port);
  vec_free (host);
  vec_free (port_str);
  return 0;

fail:
  vec_free (host);
  vec_free (port_str);
  return -1;
}

static u8 *
h2_format_target_address (ip46_address_t *ip, u16 port, u8 is_ip4)
{
  if (is_ip4)
    return format (0, "%U:%u", format_ip46_address, ip, 1,
		   clib_net_to_host_u16 (port));
  return format (0, "[%U]:%u", format_ip46_address, ip, 0,
		 clib_net_to_host_u16 (port));
}

static int
h2_udp_send_payload (session_t *us, const u8 *data, u32 data_len)
{
  transport_endpoint_t tep_rmt = TRANSPORT_ENDPOINT_NULL;
  transport_endpoint_t tep_lcl = TRANSPORT_ENDPOINT_NULL;
  app_session_transport_t at;

  session_get_endpoint (us, &tep_rmt, &tep_lcl);
  clib_memset (&at, 0, sizeof (at));
  at.rmt_ip = tep_rmt.ip;
  at.rmt_port = tep_rmt.port;
  at.lcl_ip = tep_lcl.ip;
  at.lcl_port = tep_lcl.port;
  at.is_ip4 = tep_rmt.is_ip4;

  return app_send_dgram_raw (us->tx_fifo, &at,
			     session_main_get_vpp_event_queue (us->thread_index),
			     (u8 *) data, data_len, SESSION_IO_EVT_TX,
			     1 /* do_evt */, 0 /* noblock */);
}

static void
h2_relay_queue_payload_locked (hysteria2_relay_t *relay, const u8 *data,
			       u32 data_len)
{
  u8 *payload = 0;

  if (data_len)
    {
      vec_validate (payload, data_len - 1);
      clib_memcpy (payload, data, data_len);
    }
  vec_add1 (relay->pending_tx, payload);
}

static int
h2_relay_connect_start (u32 relay_index)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  hysteria2_relay_t *relay;
  hysteria2_conn_t *conn;
  hysteria2_server_t *srv;
  vnet_connect_args_t a = {};
  fib_protocol_t fproto;
  u32 fib_index;

  relay = h2_relay_get (relay_index);
  conn = h2_conn_get (relay->conn_index);
  srv = h2_server_get (h2_conn_get (relay->conn_index)->server_index);

  a.app_index = h2m->app_index;
  a.api_context = relay_index;
  a.sep_ext = (session_endpoint_cfg_t) SESSION_ENDPOINT_CFG_NULL;
  a.sep.transport_proto = TRANSPORT_PROTO_UDP;
  a.sep_ext.transport_flags = TRANSPORT_CFG_F_CONNECTED;
  a.sep.ip = relay->target_ip;
  a.sep.port = relay->target_port;
  a.sep.is_ip4 = relay->target_is_ip4;
  fproto = relay->target_is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
  fib_index = fib_table_find (fproto, srv->table_id);
  if (fib_index == ~0)
    return SESSION_E_INVALID;
  a.sep.fib_index = fib_index;

  relay->is_connecting = 1;
  relay->last_activity = h2_now ();
  conn->last_activity = relay->last_activity;
  return vnet_connect (&a);
}

static void
h2_relay_disconnect (u32 relay_index)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  session_handle_t udp_sh = SESSION_INVALID_HANDLE;
  int free_now = 0;

  clib_rwlock_writer_lock (&h2m->lock);
  if (!pool_is_free_index (h2m->relays, relay_index))
    {
      hysteria2_relay_t *relay = h2_relay_get (relay_index);

      relay->is_closing = 1;
      udp_sh = relay->udp_session_handle;
      if (udp_sh == SESSION_INVALID_HANDLE)
	{
	  relay->is_connected = 0;
	  relay->is_connecting = 0;
	  free_now = 1;
	}
    }
  clib_rwlock_writer_unlock (&h2m->lock);

  if (udp_sh != SESSION_INVALID_HANDLE)
    {
      vnet_disconnect_args_t a = {
	.handle = udp_sh,
	.app_index = h2m->app_index,
      };
      vnet_disconnect_session (&a);
      return;
    }

  if (free_now)
    {
      clib_rwlock_writer_lock (&h2m->lock);
      h2_relay_free_locked (relay_index);
      clib_rwlock_writer_unlock (&h2m->lock);
    }
}

static void
h2_gc (void)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  hysteria2_relay_t *relay;
  hysteria2_fragment_t *frag;
  u32 *fi, *ri;
  u32 *stale_relays = 0, *stale_frags = 0;
  f64 now = h2_now ();

  if (now < h2m->next_gc_time)
    return;
  h2m->next_gc_time = now + 1.0;

  /* Read-only scan: collect stale indices without modifying pools */
  clib_rwlock_reader_lock (&h2m->lock);
  pool_foreach (relay, h2m->relays)
    {
      hysteria2_server_t *srv;
      hysteria2_conn_t *conn;

      if (relay->is_closing || pool_is_free_index (h2m->conns, relay->conn_index))
	continue;
      conn = h2_conn_get (relay->conn_index);
      srv = h2_server_get (conn->server_index);
      if (srv->idle_timeout &&
	  now - relay->last_activity >= (f64) srv->idle_timeout)
	vec_add1 (stale_relays, relay - h2m->relays);
    }
  pool_foreach (frag, h2m->fragments)
    {
      if (now - frag->last_activity >= HYSTERIA2_FRAGMENT_TIMEOUT)
	vec_add1 (stale_frags, frag - h2m->fragments);
    }
  clib_rwlock_reader_unlock (&h2m->lock);

  vec_foreach (fi, stale_frags)
    {
      clib_rwlock_writer_lock (&h2m->lock);
      h2_fragment_free_locked (*fi);
      clib_rwlock_writer_unlock (&h2m->lock);
    }
  vec_foreach (ri, stale_relays)
    h2_relay_disconnect (*ri);
  vec_free (stale_frags);
  vec_free (stale_relays);
}

static int
h2_get_quic_connection_handle (session_t *s, session_handle_t *quic_sh)
{
  transport_endpt_attr_t attr = {
    .type = TRANSPORT_ENDPT_ATTR_NEXT_TRANSPORT,
  };
  session_t *ts;

  if (session_transport_attribute (s, 1 /* is_get */, &attr))
    return -1;
  ts = session_get_from_handle_if_valid (attr.next_transport);
  if (!ts)
    return -1;
  if (session_transport_attribute (ts, 1 /* is_get */, &attr))
    return -1;
  *quic_sh = attr.next_transport;
  return 0;
}

static int
h2_check_auth (hysteria2_server_t *srv, http_header_table_t *ht)
{
  const http_token_t *auth;

  auth = http_get_header (ht, h2_auth_hdr, sizeof (h2_auth_hdr) - 1);
  if (!auth || !vec_len (srv->auth_secret))
    return 0;
  return http_token_is (auth->base, auth->len, (char *) srv->auth_secret,
			vec_len (srv->auth_secret) - 1);
}

static int
h2_conn_get_or_create (u32 server_index, session_handle_t quic_sh, u32 *conn_index)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  hysteria2_conn_t *conn;
  clib_bihash_kv_8_8_t kv;

  kv.key = quic_sh;
  if (!clib_bihash_search_8_8 (&h2m->conn_by_quic_handle, &kv, &kv))
    {
      *conn_index = kv.value;
      return 0;
    }

  clib_rwlock_writer_lock (&h2m->lock);
  pool_get_zero (h2m->conns, conn);
  conn->server_index = server_index;
  conn->quic_session_handle = quic_sh;
  conn->last_activity = h2_now ();
  *conn_index = conn - h2m->conns;
  kv.key = quic_sh;
  kv.value = *conn_index;
  clib_bihash_add_del_8_8 (&h2m->conn_by_quic_handle, &kv, 1 /* is_add */);
  clib_rwlock_writer_unlock (&h2m->lock);
  return 0;
}

static int
h2_datagram_parse (const u8 *data, u32 data_len, u32 *session_id, u16 *packet_id,
		   u8 *frag_id, u8 *frag_count, u8 **addr, u8 **payload)
{
  u8 *p = (u8 *) data, *end = (u8 *) data + data_len;
  u64 addr_len;
  u32 sid_net;
  u16 pid_net;

  if (data_len < 8)
    return -1;

  clib_memcpy_fast (&sid_net, p, sizeof (sid_net));
  *session_id = clib_net_to_host_u32 (sid_net);
  p += sizeof (sid_net);

  clib_memcpy_fast (&pid_net, p, sizeof (pid_net));
  *packet_id = clib_net_to_host_u16 (pid_net);
  p += sizeof (pid_net);

  *frag_id = *p++;
  *frag_count = *p++;
  if (*frag_count == 0 || *frag_id >= *frag_count)
    return -1;

  addr_len = http_decode_varint (&p, end);
  if (addr_len == HTTP_INVALID_VARINT || addr_len == 0 ||
      addr_len > HYSTERIA2_MAX_ADDR_LEN ||
      (uword) (end - p) < addr_len)
    return -1;

  vec_validate (*addr, addr_len - 1);
  clib_memcpy_fast (*addr, p, addr_len);
  p += addr_len;

  if (end - p)
    {
      vec_validate (*payload, end - p - 1);
      clib_memcpy_fast (*payload, p, end - p);
    }
  return 0;
}

static u8 *
h2_datagram_encode (u32 session_id, u16 packet_id, u8 frag_id, u8 frag_count,
		    u8 *addr, const u8 *payload, u32 payload_len)
{
  u8 *buf = 0, *p;
  u32 total_len;

  total_len =
    4 + 2 + 1 + 1 + http_varint_len (vec_len (addr)) + vec_len (addr) +
    payload_len;
  vec_validate (buf, total_len - 1);
  p = buf;

  session_id = clib_host_to_net_u32 (session_id);
  clib_memcpy_fast (p, &session_id, sizeof (session_id));
  p += sizeof (session_id);

  packet_id = clib_host_to_net_u16 (packet_id);
  clib_memcpy_fast (p, &packet_id, sizeof (packet_id));
  p += sizeof (packet_id);

  *p++ = frag_id;
  *p++ = frag_count;
  p = http_encode_varint (p, vec_len (addr));
  clib_memcpy_fast (p, addr, vec_len (addr));
  p += vec_len (addr);
  if (payload_len)
    clib_memcpy_fast (p, payload, payload_len);
  return buf;
}

static void
h2_send_quic_datagram (session_handle_t quic_sh, u8 *payload)
{
  hysteria2_main.quic_datagram_send (quic_sh, payload, vec_len (payload));
}

static void
h2_relay_send_to_client (u32 relay_index, app_session_transport_t *src,
			 const u8 *payload, u32 payload_len)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  hysteria2_relay_t *relay;
  hysteria2_conn_t *conn;
  u8 *addr = 0;
  u8 *dgram;
  u32 frag_payload, offset = 0, frag_count, i;
  u16 packet_id;

  clib_rwlock_writer_lock (&h2m->lock);
  if (pool_is_free_index (h2m->relays, relay_index))
    {
      clib_rwlock_writer_unlock (&h2m->lock);
      return;
    }
  relay = h2_relay_get (relay_index);
  if (pool_is_free_index (h2m->conns, relay->conn_index))
    {
      clib_rwlock_writer_unlock (&h2m->lock);
      return;
    }
  conn = h2_conn_get (relay->conn_index);
  relay->last_activity = h2_now ();
  conn->last_activity = relay->last_activity;
  packet_id = relay->next_packet_id++;
  clib_rwlock_writer_unlock (&h2m->lock);

  addr = h2_format_target_address (&src->rmt_ip, src->rmt_port, src->is_ip4);
  if (!addr)
    return;

  frag_payload = HYSTERIA2_QUIC_DGRAM_MTU -
		 (4 + 2 + 1 + 1 + http_varint_len (vec_len (addr)) +
		  vec_len (addr));
  if ((i32) frag_payload <= 0)
    goto done;
  frag_count = clib_max (1, (payload_len + frag_payload - 1) / frag_payload);
  if (frag_count > 255)
    goto done;

  for (i = 0; i < frag_count; i++)
    {
      u32 chunk = clib_min (frag_payload, payload_len - offset);

      dgram = h2_datagram_encode (relay->session_id, packet_id, i,
				  (u8) frag_count, addr, payload + offset,
				  chunk);
      h2_send_quic_datagram (conn->quic_session_handle, dgram);
      vec_free (dgram);
      offset += chunk;
    }

  clib_rwlock_writer_lock (&h2m->lock);
  if (!pool_is_free_index (h2m->conns, relay->conn_index))
    h2_conn_get (relay->conn_index)->tx_dgrams += frag_count;
  clib_rwlock_writer_unlock (&h2m->lock);

done:
  vec_free (addr);
}

static void
h2_relay_send_payload (u32 relay_index, const u8 *payload, u32 payload_len)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  hysteria2_relay_t *relay;
  session_handle_t udp_sh;
  session_t *us;

  clib_rwlock_writer_lock (&h2m->lock);
  if (pool_is_free_index (h2m->relays, relay_index))
    {
      clib_rwlock_writer_unlock (&h2m->lock);
      return;
    }
  relay = h2_relay_get (relay_index);
  relay->last_activity = h2_now ();
  udp_sh = relay->udp_session_handle;
  if (!relay->is_connected || udp_sh == SESSION_INVALID_HANDLE)
    {
      h2_relay_queue_payload_locked (relay, payload, payload_len);
      clib_rwlock_writer_unlock (&h2m->lock);
      return;
    }
  clib_rwlock_writer_unlock (&h2m->lock);

  us = session_get_from_handle_if_valid (udp_sh);
  if (!us || h2_udp_send_payload (us, payload, payload_len) < 0)
    {
      clib_rwlock_writer_lock (&h2m->lock);
      if (!pool_is_free_index (h2m->relays, relay_index))
	h2_relay_queue_payload_locked (h2_relay_get (relay_index), payload,
				       payload_len);
      clib_rwlock_writer_unlock (&h2m->lock);
    }
}

static void
h2_quic_dgram_closed (session_handle_t quic_session_handle, void *opaque)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  u32 conn_index = pointer_to_uword (opaque);
  u32 *relay_indices = 0, *frag_indices = 0;
  u32 *fi, *ri;
  hysteria2_conn_t *conn;
  hysteria2_relay_t *relay;
  hysteria2_fragment_t *frag;
  clib_bihash_kv_8_8_t kv;

  clib_rwlock_writer_lock (&h2m->lock);
  if (pool_is_free_index (h2m->conns, conn_index))
    {
      clib_rwlock_writer_unlock (&h2m->lock);
      return;
    }

  conn = h2_conn_get (conn_index);
  conn->is_closing = 1;
  kv.key = quic_session_handle;
  clib_bihash_add_del_8_8 (&h2m->conn_by_quic_handle, &kv, 0 /* is_del */);
  conn->quic_session_handle = SESSION_INVALID_HANDLE;
  pool_foreach (relay, h2m->relays)
    {
      if (relay->conn_index == conn_index)
	vec_add1 (relay_indices, relay - h2m->relays);
    }
  pool_foreach (frag, h2m->fragments)
    {
      if (frag->conn_index == conn_index)
	vec_add1 (frag_indices, frag - h2m->fragments);
    }
  clib_rwlock_writer_unlock (&h2m->lock);

  vec_foreach (fi, frag_indices)
    {
      clib_rwlock_writer_lock (&h2m->lock);
      h2_fragment_free_locked (*fi);
      clib_rwlock_writer_unlock (&h2m->lock);
    }
  vec_foreach (ri, relay_indices)
    h2_relay_disconnect (*ri);
  vec_free (relay_indices);
  vec_free (frag_indices);

  clib_rwlock_writer_lock (&h2m->lock);
  h2_conn_maybe_free_locked (conn_index);
  clib_rwlock_writer_unlock (&h2m->lock);
}

static u32
h2_relay_get_or_create (u32 conn_index, u32 session_id, u8 *addr,
			const u8 *payload, u32 payload_len)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  hysteria2_conn_t *conn;
  hysteria2_relay_t *relay;
  ip46_address_t target_ip;
  u16 target_port;
  u8 target_is_ip4;
  clib_bihash_kv_8_8_t rkv;
  u32 relay_index;
  int need_connect = 0;
  session_handle_t old_udp_sh = SESSION_INVALID_HANDLE;

  /* Fast path: bihash lookup is lock-free for readers */
  rkv.key = h2_relay_bihash_key (conn_index, session_id);
  if (!clib_bihash_search_8_8 (&h2m->relay_by_conn_session, &rkv, &rkv))
    {
      clib_rwlock_writer_lock (&h2m->lock);
      if (!pool_is_free_index (h2m->relays, rkv.value))
	{
	  relay = h2_relay_get (rkv.value);
	  if (relay->target_name && vec_is_equal (relay->target_name, addr))
	    {
	      h2_relay_queue_payload_locked (relay, payload, payload_len);
	      relay->last_activity = h2_now ();
	      clib_rwlock_writer_unlock (&h2m->lock);
	      return rkv.value;
	    }
	}
      clib_rwlock_writer_unlock (&h2m->lock);
    }

  /* Slow path: resolve target address (may block on DNS) */
  if (h2_parse_target_address (addr, &target_ip, &target_port, &target_is_ip4))
    return ~0;

  rkv.key = h2_relay_bihash_key (conn_index, session_id);
  if (!clib_bihash_search_8_8 (&h2m->relay_by_conn_session, &rkv, &rkv))
    {
      clib_rwlock_writer_lock (&h2m->lock);
      if (pool_is_free_index (h2m->relays, rkv.value))
	{
	  clib_rwlock_writer_unlock (&h2m->lock);
	  return ~0;
	}
      relay_index = rkv.value;
      relay = h2_relay_get (relay_index);
      if (!relay->target_name ||
	  !vec_is_equal (relay->target_name, addr))
	{
	  old_udp_sh = relay->udp_session_handle;
	  relay->target_ip = target_ip;
	  relay->target_port = target_port;
	  relay->target_is_ip4 = target_is_ip4;
	  vec_free (relay->target_name);
	  relay->target_name = vec_dup (addr);
	  relay->udp_session_handle = SESSION_INVALID_HANDLE;
	  relay->is_connected = 0;
	  relay->is_connecting = 0;
	  need_connect = 1;
	}
      h2_relay_queue_payload_locked (relay, payload, payload_len);
      relay->last_activity = h2_now ();
      clib_rwlock_writer_unlock (&h2m->lock);
      if (old_udp_sh != SESSION_INVALID_HANDLE)
	{
	  vnet_disconnect_args_t a = {
	    .handle = old_udp_sh,
	    .app_index = h2m->app_index,
	  };
	  vnet_disconnect_session (&a);
	}
      if (need_connect)
	h2_relay_connect_start (relay_index);
      return relay_index;
    }

  clib_rwlock_writer_lock (&h2m->lock);
  if (pool_is_free_index (h2m->conns, conn_index))
    {
      clib_rwlock_writer_unlock (&h2m->lock);
      return ~0;
    }
  conn = h2_conn_get (conn_index);
  pool_get_zero (h2m->relays, relay);
  relay_index = relay - h2m->relays;
  relay->conn_index = conn_index;
  relay->session_id = session_id;
  relay->target_ip = target_ip;
  relay->target_port = target_port;
  relay->target_is_ip4 = target_is_ip4;
  relay->target_name = vec_dup (addr);
  relay->last_activity = h2_now ();
  h2_relay_queue_payload_locked (relay, payload, payload_len);
  rkv.key = h2_relay_bihash_key (conn_index, session_id);
  rkv.value = relay_index;
  clib_bihash_add_del_8_8 (&h2m->relay_by_conn_session, &rkv, 1 /* is_add */);
  conn->n_relays++;
  clib_rwlock_writer_unlock (&h2m->lock);

  if (h2_relay_connect_start (relay_index))
    {
      clib_rwlock_writer_lock (&h2m->lock);
      h2_relay_free_locked (relay_index);
      clib_rwlock_writer_unlock (&h2m->lock);
      return ~0;
    }
  return relay_index;
}

static void
h2_datagram_process (u32 conn_index, const u8 *data, u32 data_len)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  hysteria2_conn_t *conn;
  hysteria2_fragment_t *frag;
  u8 *addr = 0, *payload = 0, *assembled = 0;
  u32 session_id, relay_index;
  u16 packet_id;
  u8 frag_id, frag_count;
  clib_bihash_kv_16_8_t fkv;
  u32 i;

  h2_gc ();
  if (h2_datagram_parse (data, data_len, &session_id, &packet_id, &frag_id,
			 &frag_count, &addr, &payload))
    goto done;

  clib_rwlock_writer_lock (&h2m->lock);
  if (pool_is_free_index (h2m->conns, conn_index))
    {
      clib_rwlock_writer_unlock (&h2m->lock);
      goto done;
    }
  conn = h2_conn_get (conn_index);
  conn->last_activity = h2_now ();
  conn->rx_dgrams++;
  clib_rwlock_writer_unlock (&h2m->lock);

  if (frag_count == 1)
    {
      relay_index =
	h2_relay_get_or_create (conn_index, session_id, addr, payload,
				vec_len (payload));
      if (relay_index != ~0)
	h2_relay_send_payload (relay_index, payload, vec_len (payload));
      goto done;
    }

  h2_frag_bihash_key (&fkv, conn_index, session_id, packet_id);
  if (!clib_bihash_search_16_8 (&h2m->frag_by_conn_key, &fkv, &fkv))
    {
      clib_rwlock_writer_lock (&h2m->lock);
      if (pool_is_free_index (h2m->fragments, fkv.value))
	{
	  clib_rwlock_writer_unlock (&h2m->lock);
	  goto done;
	}
      frag = h2_fragment_get (fkv.value);
      if (frag->frag_count != frag_count || !vec_is_equal (frag->addr, addr))
	{
	  clib_rwlock_writer_unlock (&h2m->lock);
	  goto done;
	}
    }
  else
    {
      clib_rwlock_writer_lock (&h2m->lock);
      if (pool_is_free_index (h2m->conns, conn_index))
	{
	  clib_rwlock_writer_unlock (&h2m->lock);
	  goto done;
	}
      conn = h2_conn_get (conn_index);
      if (conn->n_fragments >= HYSTERIA2_MAX_FRAGMENTS_PER_CONN)
	{
	  clib_rwlock_writer_unlock (&h2m->lock);
	  goto done;
	}
      pool_get_zero (h2m->fragments, frag);
      frag->conn_index = conn_index;
      frag->session_id = session_id;
      frag->packet_id = packet_id;
      frag->frag_count = frag_count;
      frag->addr = vec_dup (addr);
      vec_validate (frag->received, frag_count - 1);
      vec_validate (frag->fragments, frag_count - 1);
      h2_frag_bihash_key (&fkv, conn_index, session_id, packet_id);
      fkv.value = frag - h2m->fragments;
      clib_bihash_add_del_16_8 (&h2m->frag_by_conn_key, &fkv,
				1 /* is_add */);
      conn->n_fragments++;
    }
  frag->last_activity = h2_now ();
  if (frag_id < vec_len (frag->received) && !frag->received[frag_id])
    {
      frag->received[frag_id] = 1;
      frag->fragments[frag_id] = payload;
      payload = 0;
    }

  for (i = 0; i < frag->frag_count; i++)
    if (!frag->received[i])
      break;

  if (i == frag->frag_count)
    {
      for (i = 0; i < frag->frag_count; i++)
	vec_append (assembled, frag->fragments[i]);
      relay_index =
	h2_relay_get_or_create (conn_index, session_id, frag->addr, assembled,
				vec_len (assembled));
      if (relay_index != ~0)
	h2_relay_send_payload (relay_index, assembled, vec_len (assembled));
      h2_fragment_free_locked (frag - h2m->fragments);
    }
  clib_rwlock_writer_unlock (&h2m->lock);

done:
  vec_free (assembled);
  vec_free (addr);
  vec_free (payload);
}

static_always_inline hysteria2_tcp_relay_t *
h2_tcp_relay_get (u32 index)
{
  return pool_elt_at_index (hysteria2_main.tcp_relays, index);
}

static void
h2_tcp_relay_free_locked (u32 tcp_relay_index)
{
  hysteria2_main_t *h2m = &hysteria2_main;

  if (pool_is_free_index (h2m->tcp_relays, tcp_relay_index))
    return;
  pool_put_index (h2m->tcp_relays, tcp_relay_index);
}

static void
h2_tcp_relay_close (u32 tcp_relay_index)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  hysteria2_tcp_relay_t *tr;
  session_handle_t stream_sh = SESSION_INVALID_HANDLE;
  session_handle_t tcp_sh = SESSION_INVALID_HANDLE;

  if (pool_is_free_index (h2m->tcp_relays, tcp_relay_index))
    return;
  tr = h2_tcp_relay_get (tcp_relay_index);
  if (__atomic_exchange_n (&tr->state, H2_TCP_STATE_CLOSING,
			   __ATOMIC_ACQ_REL) == H2_TCP_STATE_CLOSING)
    return;
  stream_sh = tr->stream_sh;
  tcp_sh = tr->tcp_sh;
  tr->stream_sh = SESSION_INVALID_HANDLE;
  tr->tcp_sh = SESSION_INVALID_HANDLE;
  clib_rwlock_writer_lock (&h2m->lock);
  h2_tcp_relay_free_locked (tcp_relay_index);
  clib_rwlock_writer_unlock (&h2m->lock);

  if (stream_sh != SESSION_INVALID_HANDLE)
    {
      vnet_disconnect_args_t a = {
	.handle = stream_sh,
	.app_index = h2m->app_index,
      };
      vnet_disconnect_session (&a);
    }
  if (tcp_sh != SESSION_INVALID_HANDLE)
    {
      vnet_disconnect_args_t a = {
	.handle = tcp_sh,
	.app_index = h2m->app_index,
      };
      vnet_disconnect_session (&a);
    }
}

static int
h2_tcp_send_response (session_t *stream_session, u8 status, const char *msg)
{
  u32 msg_len = msg ? strlen (msg) : 0;
  u32 total_len = 1 + http_varint_len (msg_len) + msg_len +
		  http_varint_len (0);
  u8 *buf = 0, *p;
  int rv;

  vec_validate (buf, total_len - 1);
  p = buf;
  *p++ = status;
  p = http_encode_varint (p, msg_len);
  if (msg_len)
    {
      clib_memcpy_fast (p, msg, msg_len);
      p += msg_len;
    }
  p = http_encode_varint (p, 0); /* padding length = 0 */

  rv = svm_fifo_enqueue (stream_session->tx_fifo, total_len, buf);
  vec_free (buf);
  if (rv != (int) total_len)
    return -1;
  if (svm_fifo_set_event (stream_session->tx_fifo))
    session_program_tx_io_evt (stream_session->handle, SESSION_IO_EVT_TX);
  return 0;
}

static int
h2_tcp_parse_request (session_t *stream_session, u8 **out_addr)
{
  u32 max_deq = svm_fifo_max_dequeue_cons (stream_session->rx_fifo);
  u8 *buf = 0;
  u8 *p, *end;
  u64 request_id, addr_len, padding_len;

  if (max_deq < 3)
    return -1;

  vec_validate (buf, max_deq - 1);
  svm_fifo_peek (stream_session->rx_fifo, 0, max_deq, buf);
  p = buf;
  end = buf + max_deq;

  request_id = http_decode_varint (&p, end);
  if (request_id != H2_TCP_REQUEST_ID)
    {
      vec_free (buf);
      return -1;
    }

  addr_len = http_decode_varint (&p, end);
  if (addr_len == HTTP_INVALID_VARINT || addr_len == 0 ||
      addr_len > HYSTERIA2_MAX_ADDR_LEN || (uword) (end - p) < addr_len)
    {
      vec_free (buf);
      return -1;
    }

  vec_validate (*out_addr, addr_len - 1);
  clib_memcpy_fast (*out_addr, p, addr_len);
  p += addr_len;

  padding_len = http_decode_varint (&p, end);
  if (padding_len == HTTP_INVALID_VARINT || (uword) (end - p) < padding_len)
    {
      vec_free (*out_addr);
      *out_addr = 0;
      vec_free (buf);
      return -1;
    }
  p += padding_len;

  svm_fifo_dequeue_drop (stream_session->rx_fifo, p - buf);
  vec_free (buf);
  return 0;
}

static int
h2_handle_stream_rx (session_t *ts)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  hysteria2_tcp_relay_t *tr;
  u32 tcp_relay_index = ts->opaque;
  u8 state;
  session_handle_t tcp_sh;

  /* Lock-free read: tcp_relay state and tcp_sh are stable once FORWARDING.
   * Pool index validity is guaranteed by session lifecycle — the session
   * callback won't fire after cleanup frees the relay. */
  if (PREDICT_FALSE (pool_is_free_index (h2m->tcp_relays, tcp_relay_index)))
    return 0;
  tr = h2_tcp_relay_get (tcp_relay_index);
  state = __atomic_load_n (&tr->state, __ATOMIC_ACQUIRE);
  tcp_sh = tr->tcp_sh;

  if (state == H2_TCP_STATE_WAIT_REQUEST)
    {
      hysteria2_conn_t *conn;
      hysteria2_server_t *srv;
      u8 *addr = 0;
      ip46_address_t target_ip;
      u16 target_port;
      u8 target_is_ip4;
      vnet_connect_args_t cargs = {};
      fib_protocol_t fproto;
      u32 fib_index, conn_index;

      if (h2_tcp_parse_request (ts, &addr))
	{
	  h2_tcp_relay_close (tcp_relay_index);
	  return 0;
	}

      if (h2_parse_target_address (addr, &target_ip, &target_port,
				   &target_is_ip4))
	{
	  h2_tcp_send_response (ts, 0x01, "invalid address");
	  vec_free (addr);
	  h2_tcp_relay_close (tcp_relay_index);
	  return 0;
	}
      vec_free (addr);

      if (pool_is_free_index (h2m->tcp_relays, tcp_relay_index))
	return 0;
      tr = h2_tcp_relay_get (tcp_relay_index);
      tr->target_ip = target_ip;
      tr->target_port = target_port;
      tr->target_is_ip4 = target_is_ip4;
      __atomic_store_n (&tr->state, H2_TCP_STATE_CONNECTING,
			__ATOMIC_RELEASE);
      conn_index = tr->conn_index;

      if (pool_is_free_index (h2m->conns, conn_index))
	{
	  h2_tcp_relay_close (tcp_relay_index);
	  return 0;
	}
      conn = h2_conn_get (conn_index);
      srv = h2_server_get (conn->server_index);

      fproto = target_is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
      fib_index = fib_table_find (fproto, srv->table_id);

      if (fib_index == ~0)
	{
	  h2_tcp_send_response (ts, 0x01, "no fib");
	  h2_tcp_relay_close (tcp_relay_index);
	  return 0;
	}

      cargs.app_index = h2m->app_index;
      cargs.api_context = tcp_relay_index | H2_TCP_RELAY_TAG;
      cargs.sep_ext = (session_endpoint_cfg_t) SESSION_ENDPOINT_CFG_NULL;
      cargs.sep.transport_proto = TRANSPORT_PROTO_TCP;
      cargs.sep.ip = target_ip;
      cargs.sep.port = target_port;
      cargs.sep.is_ip4 = target_is_ip4;
      cargs.sep.fib_index = fib_index;

      if (vnet_connect (&cargs))
	{
	  h2_tcp_send_response (ts, 0x01, "connect failed");
	  h2_tcp_relay_close (tcp_relay_index);
	}
      return 0;
    }

  if (state == H2_TCP_STATE_FORWARDING)
    {
      session_t *tcp_session;
      u32 max_deq, max_enq, n_xfer;
      int rv;

      tcp_session = session_get_from_handle_if_valid (tcp_sh);
      if (!tcp_session)
	{
	  h2_tcp_relay_close (tcp_relay_index);
	  return 0;
	}

      max_deq = svm_fifo_max_dequeue_cons (ts->rx_fifo);
      max_enq = svm_fifo_max_enqueue_prod (tcp_session->tx_fifo);
      n_xfer = clib_min (max_deq, max_enq);
      if (n_xfer)
	{
	  u8 *xfer_buf = clib_mem_alloc (n_xfer);
	  rv = svm_fifo_dequeue (ts->rx_fifo, n_xfer, xfer_buf);
	  if (rv > 0)
	    {
	      svm_fifo_enqueue (tcp_session->tx_fifo, rv, xfer_buf);
	      if (svm_fifo_set_event (tcp_session->tx_fifo))
		session_program_tx_io_evt (tcp_session->handle,
					   SESSION_IO_EVT_TX);
	    }
	  clib_mem_free (xfer_buf);
	}
      return 0;
    }

  return 0;
}

static int
h2_handle_tcp_rx (session_t *ts)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  hysteria2_tcp_relay_t *tr;
  u32 tcp_relay_index = ts->opaque;
  session_handle_t stream_sh;
  session_t *stream_session;
  u32 max_deq, max_enq, n_xfer;
  int rv;

  /* Lock-free read: stream_sh is stable in FORWARDING state */
  if (PREDICT_FALSE (pool_is_free_index (h2m->tcp_relays, tcp_relay_index)))
    return 0;
  tr = h2_tcp_relay_get (tcp_relay_index);
  if (__atomic_load_n (&tr->state, __ATOMIC_ACQUIRE) !=
      H2_TCP_STATE_FORWARDING)
    return 0;
  stream_sh = tr->stream_sh;

  stream_session = session_get_from_handle_if_valid (stream_sh);
  if (!stream_session)
    {
      h2_tcp_relay_close (tcp_relay_index);
      return 0;
    }

  max_deq = svm_fifo_max_dequeue_cons (ts->rx_fifo);
  max_enq = svm_fifo_max_enqueue_prod (stream_session->tx_fifo);
  n_xfer = clib_min (max_deq, max_enq);
  if (n_xfer)
    {
      u8 *xfer_buf = clib_mem_alloc (n_xfer);
      rv = svm_fifo_dequeue (ts->rx_fifo, n_xfer, xfer_buf);
      if (rv > 0)
	{
	  svm_fifo_enqueue (stream_session->tx_fifo, rv, xfer_buf);
	  if (svm_fifo_set_event (stream_session->tx_fifo))
	    session_program_tx_io_evt (stream_session->handle,
				       SESSION_IO_EVT_TX);
	}
      clib_mem_free (xfer_buf);
    }
  return 0;
}

static int
h2_stream_accept_cb (session_t *stream_session, void *opaque)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  hysteria2_tcp_relay_t *tr;
  u32 tcp_relay_index;
  u32 conn_index = pointer_to_uword (opaque);

  clib_rwlock_writer_lock (&h2m->lock);
  pool_get_zero (h2m->tcp_relays, tr);
  tcp_relay_index = tr - h2m->tcp_relays;
  tr->conn_index = conn_index;
  tr->stream_sh = session_handle (stream_session);
  tr->tcp_sh = SESSION_INVALID_HANDLE;
  tr->state = H2_TCP_STATE_WAIT_REQUEST;
  clib_rwlock_writer_unlock (&h2m->lock);

  stream_session->opaque = tcp_relay_index;
  stream_session->session_state = SESSION_STATE_READY;
  return 0;
}

static void
h2_quic_dgram_rx (session_handle_t quic_session_handle, const u8 *data,
		  u32 data_len, void *opaque)
{
  h2_datagram_process (pointer_to_uword (opaque), data, data_len);
}

static int
h2_handle_http_auth (session_t *ts)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  hysteria2_server_t *srv;
  http_msg_t msg;
  http_header_table_t ht = HTTP_HEADER_TABLE_NULL;
  http_headers_ctx_t resp_headers = {};
  session_handle_t quic_sh;
  u8 *headers_buf = 0, *path = 0, *authority = 0;
  u32 conn_index;
  int rv, ok = 0;

  if (pool_is_free_index (h2m->servers, ts->opaque))
    return 0;
  srv = h2_server_get (ts->opaque);

  rv = svm_fifo_dequeue (ts->rx_fifo, sizeof (msg), (u8 *) &msg);
  ASSERT (rv == sizeof (msg));

  if (msg.type != HTTP_MSG_REQUEST || msg.method_type != HTTP_REQ_POST ||
      msg.data.target_path_len != sizeof (h2_auth_path) - 1)
    goto done;

  vec_validate (path, msg.data.target_path_len - 1);
  rv = svm_fifo_peek (ts->rx_fifo, msg.data.target_path_offset,
		      msg.data.target_path_len, path);
  ASSERT (rv == msg.data.target_path_len);
  if (!http_token_is ((char *) path, vec_len (path), h2_auth_path,
		      sizeof (h2_auth_path) - 1))
    goto done;

  if (msg.data.target_authority_len)
    {
      vec_validate (authority, msg.data.target_authority_len - 1);
      rv = svm_fifo_peek (ts->rx_fifo, msg.data.target_authority_offset,
			  msg.data.target_authority_len, authority);
      ASSERT (rv == msg.data.target_authority_len);
      if (!http_token_is_case ((char *) authority, vec_len (authority),
			       h2_host_value, sizeof (h2_host_value) - 1))
	goto done;
    }

  if (msg.data.headers_len)
    {
      http_init_header_table_buf (&ht, msg);
      rv = svm_fifo_peek (ts->rx_fifo, msg.data.headers_offset,
			  msg.data.headers_len, ht.buf);
      ASSERT (rv == msg.data.headers_len);
      http_build_header_table (&ht, msg);
    }

  if (!h2_check_auth (srv, &ht) || h2_get_quic_connection_handle (ts, &quic_sh))
    {
      srv->auth_failures++;
      goto done;
    }

  if (h2_conn_get_or_create (ts->opaque, quic_sh, &conn_index))
    {
      srv->auth_failures++;
      goto done;
    }
  {
    int dgram_rv = h2m->quic_datagram_bind (
      quic_sh, h2_quic_dgram_rx, h2_quic_dgram_closed,
      uword_to_pointer (conn_index, void *));
    if (dgram_rv)
      {
	srv->auth_failures++;
	goto done;
      }
  }

  {
    app_worker_t *h2_wrk =
      application_get_default_worker (application_get (h2m->app_index));
    if (h2_wrk)
      h2m->quic_stream_bind (quic_sh, h2_stream_accept_cb,
			     uword_to_pointer (conn_index, void *),
			     h2_wrk->wrk_index);
  }

  vec_validate (headers_buf, 255);
  http_init_headers_ctx (&resp_headers, headers_buf, vec_len (headers_buf));
  http_add_custom_header (&resp_headers, h2_udp_hdr, sizeof (h2_udp_hdr) - 1,
			  "true", 4);
  http_add_custom_header (&resp_headers, h2_cc_rx_hdr,
			  sizeof (h2_cc_rx_hdr) - 1, "0", 1);
  h2_send_http_resp (ts, HTTP_STATUS_HY_OK, &resp_headers);
  srv->auth_successes++;
  ok = 1;

done:
  if (!ok)
    h2_send_http_resp (ts, HTTP_STATUS_NOT_FOUND, 0);
  svm_fifo_dequeue_drop (ts->rx_fifo, msg.data.len);
  http_free_header_table (&ht);
  vec_free (headers_buf);
  vec_free (path);
  vec_free (authority);
  return 0;
}

static int
h2_handle_udp_rx (session_t *us)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  hysteria2_relay_t *relay;
  session_dgram_pre_hdr_t ph;
  app_session_transport_t src = {};
  u8 *buf = 0;
  u32 max_deq;
  int n_read;

  h2_gc ();
  max_deq = svm_fifo_max_dequeue_cons (us->rx_fifo);
  if (max_deq <= sizeof (session_dgram_hdr_t))
    return 0;

  svm_fifo_peek (us->rx_fifo, 0, sizeof (ph), (u8 *) &ph);
  if (max_deq < ph.data_length + SESSION_CONN_HDR_LEN)
    return 0;
  if (ph.data_length < ph.data_offset)
    return 0;

  if (ph.data_length > ph.data_offset)
    vec_validate (buf, ph.data_length - ph.data_offset - 1);
  n_read = app_recv_dgram_raw (us->rx_fifo, buf, vec_len (buf), &src,
			       1 /* clear_evt */, 0 /* peek */);
  if (n_read < 0)
    goto done;

  clib_rwlock_writer_lock (&h2m->lock);
  if (pool_is_free_index (h2m->relays, us->opaque))
    {
      clib_rwlock_writer_unlock (&h2m->lock);
      goto done;
    }
  relay = h2_relay_get (us->opaque);
  relay->last_activity = h2_now ();
  clib_rwlock_writer_unlock (&h2m->lock);

  h2_relay_send_to_client (us->opaque, &src, buf, vec_len (buf));

done:
  vec_free (buf);
  return 0;
}

static int
h2_ts_accept_callback (session_t *s)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  clib_bihash_kv_8_8_t kv;

  kv.key = s->listener_handle;
  if (clib_bihash_search_8_8 (&h2m->server_by_handle, &kv, &kv))
    {
      /* For HTTP/3 stream sessions, listener_handle points to the parent
       * (connection) session, not the original listener. Look up server_index
       * from the parent session's opaque field instead. */
      session_t *parent = session_get_from_handle_if_valid (s->listener_handle);
      if (!parent || pool_is_free_index (h2m->servers, parent->opaque))
	return SESSION_E_NOAPP;
      s->opaque = parent->opaque;
      s->session_state = SESSION_STATE_READY;
      return 0;
    }
  s->opaque = kv.value;
  s->session_state = SESSION_STATE_READY;
  return 0;
}

static int
h2_ts_tcp_connected_callback (u32 tcp_relay_index, session_t *s,
			      session_error_t err)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  hysteria2_tcp_relay_t *tr;
  session_handle_t stream_sh;
  session_t *stream_session;

  if (err || !s)
    {
      clib_rwlock_writer_lock (&h2m->lock);
      if (!pool_is_free_index (h2m->tcp_relays, tcp_relay_index))
	{
	  tr = h2_tcp_relay_get (tcp_relay_index);
	  stream_sh = tr->stream_sh;
	  stream_session = session_get_from_handle_if_valid (stream_sh);
	  if (stream_session)
	    h2_tcp_send_response (stream_session, 0x01, "connect failed");
	}
      clib_rwlock_writer_unlock (&h2m->lock);
      h2_tcp_relay_close (tcp_relay_index);
      return 0;
    }

  s->opaque = tcp_relay_index;
  s->session_state = SESSION_STATE_READY;

  if (pool_is_free_index (h2m->tcp_relays, tcp_relay_index))
    return 0;
  tr = h2_tcp_relay_get (tcp_relay_index);
  tr->tcp_sh = session_handle (s);
  stream_sh = tr->stream_sh;
  /* Store tcp_sh before making state visible to data-path readers */
  __atomic_store_n (&tr->state, H2_TCP_STATE_FORWARDING, __ATOMIC_RELEASE);

  stream_session = session_get_from_handle_if_valid (stream_sh);
  if (stream_session)
    h2_tcp_send_response (stream_session, 0x00, "ok");
  return 0;
}

static int
h2_ts_connected_callback (u32 app_index, u32 api_context, session_t *s,
			  session_error_t err)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  hysteria2_relay_t *relay;
  u8 **pending = 0, **p;

  if (api_context & H2_TCP_RELAY_TAG)
    return h2_ts_tcp_connected_callback (api_context & ~H2_TCP_RELAY_TAG, s,
					 err);

  if (err || !s)
    {
      clib_rwlock_writer_lock (&h2m->lock);
      if (!pool_is_free_index (h2m->relays, api_context))
	{
	  relay = h2_relay_get (api_context);
	  relay->is_connecting = 0;
	  relay->is_connected = 0;
	  relay->udp_session_handle = SESSION_INVALID_HANDLE;
	  relay->is_closing = 1;
	}
      clib_rwlock_writer_unlock (&h2m->lock);
      h2_relay_disconnect (api_context);
      return 0;
    }

  s->opaque = api_context;
  s->session_state = SESSION_STATE_READY;

  clib_rwlock_writer_lock (&h2m->lock);
  if (pool_is_free_index (h2m->relays, api_context))
    {
      clib_rwlock_writer_unlock (&h2m->lock);
      return 0;
    }
  relay = h2_relay_get (api_context);
  relay->udp_session_handle = session_handle (s);
  relay->is_connecting = 0;
  relay->is_connected = 1;
  relay->last_activity = h2_now ();
  pending = relay->pending_tx;
  relay->pending_tx = 0;
  clib_rwlock_writer_unlock (&h2m->lock);

  vec_foreach (p, pending)
    {
      h2_udp_send_payload (s, *p, vec_len (*p));
      vec_free (*p);
    }
  vec_free (pending);
  return 0;
}

static void
h2_ts_disconnect_callback (session_t *s)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  transport_proto_t tp = session_get_transport_proto (s);

  if (tp == TRANSPORT_PROTO_UDP)
    return;

  if (tp == TRANSPORT_PROTO_QUIC || tp == TRANSPORT_PROTO_TCP)
    {
      h2_tcp_relay_close (s->opaque);
      return;
    }

  vnet_disconnect_args_t a = {
    .handle = session_handle (s),
    .app_index = h2m->app_index,
  };
  vnet_disconnect_session (&a);
}

static void
h2_ts_reset_callback (session_t *s)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  hysteria2_relay_t *relay;
  transport_proto_t tp = session_get_transport_proto (s);

  if (tp == TRANSPORT_PROTO_QUIC || tp == TRANSPORT_PROTO_TCP)
    {
      h2_tcp_relay_close (s->opaque);
      return;
    }

  if (tp != TRANSPORT_PROTO_UDP)
    {
      h2_ts_disconnect_callback (s);
      return;
    }

  clib_rwlock_writer_lock (&h2m->lock);
  if (!pool_is_free_index (h2m->relays, s->opaque))
    {
      relay = h2_relay_get (s->opaque);
      relay->udp_session_handle = SESSION_INVALID_HANDLE;
      relay->is_connected = 0;
      relay->is_connecting = 0;
      if (relay->is_closing)
	h2_relay_free_locked (s->opaque);
      else
	relay->is_closing = 1;
    }
  clib_rwlock_writer_unlock (&h2m->lock);
}

static void
h2_ts_cleanup_callback (session_t *s, session_cleanup_ntf_t ntf)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  hysteria2_relay_t *relay;
  transport_proto_t tp;

  if (ntf != SESSION_CLEANUP_SESSION)
    return;

  tp = session_get_transport_proto (s);

  if (tp == TRANSPORT_PROTO_QUIC || tp == TRANSPORT_PROTO_TCP)
    {
      h2_tcp_relay_close (s->opaque);
      return;
    }

  if (tp != TRANSPORT_PROTO_UDP)
    return;

  clib_rwlock_writer_lock (&h2m->lock);
  if (!pool_is_free_index (h2m->relays, s->opaque))
    {
      relay = h2_relay_get (s->opaque);
      relay->udp_session_handle = SESSION_INVALID_HANDLE;
      relay->is_connected = 0;
      relay->is_connecting = 0;
      if (relay->is_closing)
	h2_relay_free_locked (s->opaque);
    }
  clib_rwlock_writer_unlock (&h2m->lock);
}

static int
h2_ts_tx_callback (session_t *s)
{
  return 0;
}

static int
h2_ts_rx_callback (session_t *ts)
{
  transport_proto_t tp = session_get_transport_proto (ts);

  if (tp == TRANSPORT_PROTO_UDP)
    return h2_handle_udp_rx (ts);
  if (tp == TRANSPORT_PROTO_QUIC)
    return h2_handle_stream_rx (ts);
  if (tp == TRANSPORT_PROTO_TCP)
    return h2_handle_tcp_rx (ts);
  return h2_handle_http_auth (ts);
}

static session_cb_vft_t h2_session_cb_vft = {
  .session_accept_callback = h2_ts_accept_callback,
  .session_connected_callback = h2_ts_connected_callback,
  .session_disconnect_callback = h2_ts_disconnect_callback,
  .session_reset_callback = h2_ts_reset_callback,
  .session_cleanup_callback = h2_ts_cleanup_callback,
  .builtin_app_rx_callback = h2_ts_rx_callback,
  .builtin_app_tx_callback = h2_ts_tx_callback,
  .add_segment_callback = h2_add_segment_cb,
  .del_segment_callback = h2_del_segment_cb,
};

static int
h2_resolve_quic_symbols (void)
{
  hysteria2_main_t *h2m = &hysteria2_main;

  if (h2m->quic_datagram_bind)
    return 0;

#define H2_RESOLVE(field, name)                                               \
  h2m->field = vlib_get_plugin_symbol ("quic_plugin.so", #name);              \
  if (!h2m->field)                                                            \
    {                                                                         \
      clib_warning ("hysteria2: cannot resolve %s from quic plugin", #name);  \
      return -1;                                                              \
    }

  H2_RESOLVE (quic_datagram_bind, quic_custom_datagram_bind)
  H2_RESOLVE (quic_datagram_send, quic_custom_datagram_send)
  H2_RESOLVE (quic_stream_bind, quic_custom_stream_bind)
#undef H2_RESOLVE
  return 0;
}

static int
h2_attach_if_needed (void)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  u64 options[APP_OPTIONS_N_OPTIONS] = {};
  vnet_app_attach_args_t a = {};

  if (h2m->app_index != APP_INVALID_INDEX)
    return 0;

  a.api_client_index = APP_INVALID_INDEX;
  a.name = format (0, "hysteria2");
  a.session_cb_vft = &h2_session_cb_vft;
  a.options = options;
  a.options[APP_OPTIONS_SEGMENT_SIZE] =
    h2m->private_segment_size ? h2m->private_segment_size : (128 << 20);
  a.options[APP_OPTIONS_ADD_SEGMENT_SIZE] = a.options[APP_OPTIONS_SEGMENT_SIZE];
  a.options[APP_OPTIONS_RX_FIFO_SIZE] = h2m->fifo_size ? h2m->fifo_size :
						 (16 << 10);
  a.options[APP_OPTIONS_TX_FIFO_SIZE] = h2m->fifo_size ? h2m->fifo_size :
						 (64 << 10);
  a.options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = h2m->prealloc_fifos;
  a.options[APP_OPTIONS_TLS_ENGINE] = CRYPTO_ENGINE_OPENSSL;
  a.options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;

  if (vnet_application_attach (&a))
    {
      vec_free (a.name);
      return -1;
    }
  vec_free (a.name);
  h2m->app_index = a.app_index;
  return 0;
}

static void
h2_detach_if_unused (void)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  vnet_app_detach_args_t a = {};

  if (h2m->app_index == APP_INVALID_INDEX || pool_elts (h2m->servers))
    return;
  a.app_index = h2m->app_index;
  a.api_client_index = APP_INVALID_INDEX;
  vnet_application_detach (&a);
  h2m->app_index = APP_INVALID_INDEX;
}

static int
h2_enable_session_layer (void)
{
  session_enable_disable_args_t args = {
    .is_en = 1,
    .rt_engine_type = RT_BACKEND_ENGINE_RULE_TABLE,
  };
  return vnet_session_enable_disable (hysteria2_main.vlib_main, &args) ? -1 :
									 0;
}

static int
h2_server_add (u8 *uri, u8 *auth_secret, u8 *salamander_password,
	       u32 ckpair_index, u32 table_id, u32 idle_timeout)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  session_endpoint_cfg_t sep = SESSION_ENDPOINT_CFG_NULL;
  vnet_listen_args_t a = {};
  transport_endpt_ext_cfg_t *ext_cfg;
  transport_endpt_cfg_http_t *http_cfg;
  hysteria2_server_t *srv;

  if (hash_get_mem (h2m->server_index_by_uri, uri))
    return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
  if (parse_uri ((char *) uri, &sep) || !(sep.flags & SESSION_ENDPT_CFG_F_SECURE))
    return VNET_API_ERROR_INVALID_VALUE;
  if (!vec_len (auth_secret))
    return VNET_API_ERROR_INVALID_VALUE;
  if (h2_resolve_quic_symbols () || h2_enable_session_layer () ||
      h2_attach_if_needed ())
    return VNET_API_ERROR_INIT_FAILED;

  a.app_index = h2m->app_index;
  sep.transport_proto = TRANSPORT_PROTO_HTTP;
  clib_memcpy (&a.sep_ext, &sep, sizeof (sep));
  ext_cfg = session_endpoint_add_ext_cfg (&a.sep_ext, TRANSPORT_ENDPT_EXT_CFG_CRYPTO,
					  sizeof (transport_endpt_crypto_cfg_t));
  ext_cfg->crypto.ckpair_index = ckpair_index;
  ext_cfg->crypto.alpn_protos[0] = TLS_ALPN_PROTO_HTTP_3;
  ext_cfg->crypto.alpn_protos[1] = TLS_ALPN_PROTO_HTTP_2;
  ext_cfg->crypto.alpn_protos[2] = TLS_ALPN_PROTO_HTTP_1_1;

  ext_cfg = session_endpoint_add_ext_cfg (&a.sep_ext, TRANSPORT_ENDPT_EXT_CFG_HTTP,
					  sizeof (transport_endpt_cfg_http_t));
  http_cfg = (transport_endpt_cfg_http_t *) ext_cfg->data;
  http_cfg->timeout = idle_timeout ? idle_timeout : 60;

  ext_cfg = session_endpoint_add_ext_cfg (&a.sep_ext,
					  TRANSPORT_ENDPT_EXT_CFG_QUIC,
					  sizeof (transport_endpt_cfg_quic_t));
  ext_cfg->quic.enable_datagrams = 1;
  if (vec_len (salamander_password))
    {
      ext_cfg->quic.packet_transform =
	TRANSPORT_ENDPT_QUIC_PACKET_TRANSFORM_SALAMANDER;
      ext_cfg->quic.password_len =
	clib_min ((u32) vec_len (salamander_password) - 1,
		  (u32) TRANSPORT_ENDPT_QUIC_PASSWORD_MAX);
      clib_memcpy (ext_cfg->quic.password, salamander_password,
		   ext_cfg->quic.password_len);
    }

  if (vnet_listen (&a))
    {
      session_endpoint_free_ext_cfgs (&a.sep_ext);
      h2_detach_if_unused ();
      return VNET_API_ERROR_INVALID_VALUE;
    }
  session_endpoint_free_ext_cfgs (&a.sep_ext);

  pool_get_zero (h2m->servers, srv);
  srv->sep = sep;
  srv->handle = a.handle;
  srv->uri = vec_dup (uri);
  srv->auth_secret = vec_dup (auth_secret);
  srv->salamander_password = vec_dup (salamander_password);
  srv->ckpair_index = ckpair_index;
  srv->table_id = table_id;
  srv->idle_timeout = idle_timeout;
  hash_set_mem (h2m->server_index_by_uri, srv->uri, srv - h2m->servers);
  {
    clib_bihash_kv_8_8_t kv = { .key = srv->handle,
				.value = srv - h2m->servers };
    clib_bihash_add_del_8_8 (&h2m->server_by_handle, &kv, 1 /* is_add */);
  }
  return 0;
}

static int
h2_server_del (u8 *uri)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  uword *p;
  hysteria2_server_t *srv;
  vnet_unlisten_args_t a = {};

  p = hash_get_mem (h2m->server_index_by_uri, uri);
  if (!p)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  srv = h2_server_get (p[0]);

  a.handle = srv->handle;
  a.app_index = h2m->app_index;
  if (vnet_unlisten (&a))
    return VNET_API_ERROR_INVALID_VALUE;

  hash_unset_mem (h2m->server_index_by_uri, srv->uri);
  {
    clib_bihash_kv_8_8_t kv = { .key = srv->handle };
    clib_bihash_add_del_8_8 (&h2m->server_by_handle, &kv, 0 /* is_del */);
  }
  vec_free (srv->uri);
  vec_free (srv->auth_secret);
  vec_free (srv->salamander_password);
  pool_put (h2m->servers, srv);
  h2_detach_if_unused ();
  return 0;
}

static clib_error_t *
h2_server_add_del_cli (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *uri = 0, *auth_secret = 0, *salamander = 0;
  u32 ckpair_index = ~0, table_id = 0, idle_timeout = 60;
  /* "del" command uses h2_server_del_cli as .function, so this is 0 for del */
  int is_add = cmd->function == h2_server_add_del_cli;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "missing arguments");
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "uri %s", &uri))
	;
      else if (unformat (line_input, "ckpair %u", &ckpair_index))
	;
      else if (unformat (line_input, "auth-secret %s", &auth_secret))
	;
      else if (unformat (line_input, "salamander %s", &salamander))
	;
      else if (unformat (line_input, "table-id %u", &table_id))
	;
      else if (unformat (line_input, "idle-timeout %u", &idle_timeout))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, line_input);
    }
  unformat_free (line_input);

  if (!uri)
    return clib_error_return (0, "uri is required");
  if (is_add)
    {
      if (ckpair_index == ~0)
	return clib_error_return (0, "ckpair is required");
      rv = h2_server_add (uri, auth_secret, salamander, ckpair_index, table_id,
			  idle_timeout);
    }
  else
    rv = h2_server_del (uri);
  vec_free (uri);
  vec_free (auth_secret);
  vec_free (salamander);
  if (rv)
    return clib_error_return (0, "operation failed: %d", rv);
  return 0;
}

VLIB_CLI_COMMAND (h2_server_add_cmd, static) = {
  .path = "hysteria2 server add",
  .short_help = "hysteria2 server add uri <https://addr:port> ckpair <id> "
		"auth-secret <secret> [salamander <password>] "
		"[table-id <id>] [idle-timeout <sec>]",
  .function = h2_server_add_del_cli,
};

static clib_error_t *
h2_server_del_cli (vlib_main_t *vm, unformat_input_t *input,
		   vlib_cli_command_t *cmd)
{
  return h2_server_add_del_cli (vm, input, cmd);
}

VLIB_CLI_COMMAND (h2_server_del_cmd, static) = {
  .path = "hysteria2 server del",
  .short_help = "hysteria2 server del uri <https://addr:port>",
  .function = h2_server_del_cli,
};

static clib_error_t *
h2_show_server_cli (vlib_main_t *vm, unformat_input_t *input,
		    vlib_cli_command_t *cmd)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  hysteria2_server_t *srv;

  pool_foreach (srv, h2m->servers)
    {
      vlib_cli_output (
	vm,
	"uri %v ckpair %u table-id %u idle-timeout %u auth-ok %llu auth-fail %llu salamander %s",
	srv->uri, srv->ckpair_index, srv->table_id, srv->idle_timeout,
	srv->auth_successes, srv->auth_failures,
	vec_len (srv->salamander_password) ? "on" : "off");
    }
  return 0;
}

VLIB_CLI_COMMAND (h2_show_server_cmd, static) = {
  .path = "show hysteria2 server",
  .short_help = "show hysteria2 server",
  .function = h2_show_server_cli,
};

static void
vl_api_hysteria2_server_add_del_t_handler (vl_api_hysteria2_server_add_del_t *mp)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  vl_api_hysteria2_server_add_del_reply_t *rmp;
  u8 *uri = 0, *auth_secret = 0, *salamander = 0;
  int rv;

  mp->uri[ARRAY_LEN (mp->uri) - 1] = 0;
  mp->auth_secret[ARRAY_LEN (mp->auth_secret) - 1] = 0;
  mp->salamander_password[ARRAY_LEN (mp->salamander_password) - 1] = 0;

  uri = format (0, "%s", mp->uri);
  auth_secret = format (0, "%s", mp->auth_secret);
  salamander = format (0, "%s", mp->salamander_password);

  if (mp->is_add)
    rv = h2_server_add (uri, auth_secret, salamander, ntohl (mp->ckpair_index),
			ntohl (mp->table_id), ntohl (mp->idle_timeout));
  else
    rv = h2_server_del (uri);

  vec_free (uri);
  vec_free (auth_secret);
  vec_free (salamander);
  REPLY_MACRO (VL_API_HYSTERIA2_SERVER_ADD_DEL_REPLY);
}

#include <hysteria2/hysteria2.api.c>

static clib_error_t *
h2_api_init (vlib_main_t *vm)
{
  hysteria2_main_t *h2m = &hysteria2_main;
  h2m->msg_id_base = setup_message_id_table ();
  return 0;
}

static clib_error_t *
h2_init (vlib_main_t *vm)
{
  hysteria2_main_t *h2m = &hysteria2_main;

  h2m->vlib_main = vm;
  h2m->app_index = APP_INVALID_INDEX;
  clib_rwlock_init (&h2m->lock);
  clib_bihash_init_8_8 (&h2m->server_by_handle, "h2 server by handle",
			 16, 1 << 20);
  clib_bihash_init_8_8 (&h2m->conn_by_quic_handle, "h2 conn by quic handle",
			 64, 1 << 20);
  clib_bihash_init_8_8 (&h2m->relay_by_conn_session,
			 "h2 relay by conn session", 256, 4 << 20);
  clib_bihash_init_16_8 (&h2m->frag_by_conn_key, "h2 frag by conn key",
			  256, 4 << 20);
  return 0;
}

VLIB_INIT_FUNCTION (h2_init);
VLIB_INIT_FUNCTION (h2_api_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Experimental Hysteria2 server scaffolding",
  .load_after = "quic_plugin.so",
};
