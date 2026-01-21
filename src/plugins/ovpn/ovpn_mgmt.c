/*
 * ovpn_mgmt.c - OpenVPN management interface implementation (UDP via VPP session layer)
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

#include <ovpn/ovpn_mgmt.h>
#include <ovpn/ovpn.h>
#include <ovpn/ovpn_peer.h>
#include <vnet/session/session.h>
#include <vnet/session/application.h>
#include <vnet/session/application_interface.h>
#include <vnet/ip/format.h>

ovpn_mgmt_main_t ovpn_mgmt_main;

/* Forward declarations */
static void ovpn_mgmt_send_to_client (ovpn_mgmt_t *mgmt,
				      ovpn_mgmt_client_t *client, const u8 *data,
				      u32 len);
static void ovpn_mgmt_process_command (ovpn_mgmt_t *mgmt,
				       ovpn_mgmt_client_t *client, u8 *cmd);

/* State names for display */
static const char *ovpn_mgmt_state_names[] = {
  [OVPN_MGMT_STATE_CONNECTING] = "CONNECTING",
  [OVPN_MGMT_STATE_WAIT] = "WAIT",
  [OVPN_MGMT_STATE_AUTH] = "AUTH",
  [OVPN_MGMT_STATE_GET_CONFIG] = "GET_CONFIG",
  [OVPN_MGMT_STATE_ASSIGN_IP] = "ASSIGN_IP",
  [OVPN_MGMT_STATE_ADD_ROUTES] = "ADD_ROUTES",
  [OVPN_MGMT_STATE_CONNECTED] = "CONNECTED",
  [OVPN_MGMT_STATE_RECONNECTING] = "RECONNECTING",
  [OVPN_MGMT_STATE_EXITING] = "EXITING",
  [OVPN_MGMT_STATE_RESOLVE] = "RESOLVE",
  [OVPN_MGMT_STATE_TCP_CONNECT] = "TCP_CONNECT",
};

u8 *
format_ovpn_mgmt_state (u8 *s, va_list *args)
{
  ovpn_mgmt_state_t state = va_arg (*args, int);
  if (state < ARRAY_LEN (ovpn_mgmt_state_names))
    s = format (s, "%s", ovpn_mgmt_state_names[state]);
  else
    s = format (s, "UNKNOWN(%d)", state);
  return s;
}

u8 *
format_ovpn_mgmt_log_flags (u8 *s, va_list *args)
{
  u8 flags = va_arg (*args, int);
  if (flags & OVPN_MGMT_LOG_FLAG_FATAL)
    vec_add1 (s, 'F');
  if (flags & OVPN_MGMT_LOG_FLAG_ERROR)
    vec_add1 (s, 'E');
  if (flags & OVPN_MGMT_LOG_FLAG_WARN)
    vec_add1 (s, 'W');
  if (flags & OVPN_MGMT_LOG_FLAG_NOTICE)
    vec_add1 (s, 'N');
  if (flags & OVPN_MGMT_LOG_FLAG_INFO)
    vec_add1 (s, 'I');
  if (flags & OVPN_MGMT_LOG_FLAG_DEBUG)
    vec_add1 (s, 'D');
  return s;
}

/*
 * Generate a hash key from IP address and port
 */
static u64
ovpn_mgmt_client_key (const ip_address_t *addr, u16 port)
{
  u64 key = 0;
  if (ip_addr_version (addr) == AF_IP4)
    {
      key = ((u64) addr->ip.ip4.as_u32 << 16) | port;
    }
  else
    {
      /* For IPv6, use a simple hash of the address */
      key = addr->ip.ip6.as_u64[0] ^ addr->ip.ip6.as_u64[1];
      key = (key << 16) | port;
    }
  return key;
}

/*
 * Find or create a client by remote address
 */
static ovpn_mgmt_client_t *
ovpn_mgmt_client_get_or_create (ovpn_mgmt_t *mgmt, const ip_address_t *addr,
				u16 port, f64 now)
{
  u64 key = ovpn_mgmt_client_key (addr, port);
  uword *p = hash_get (mgmt->client_by_key, key);

  if (p)
    {
      ovpn_mgmt_client_t *client = pool_elt_at_index (mgmt->clients, p[0]);
      client->last_activity_time = now;
      return client;
    }

  /* Check if we have too many clients */
  if (pool_elts (mgmt->clients) >= OVPN_MGMT_MAX_CLIENTS)
    {
      /* Remove oldest inactive client */
      f64 oldest_time = now;
      ovpn_mgmt_client_t *oldest = NULL;
      ovpn_mgmt_client_t *c;

      pool_foreach (c, mgmt->clients)
	{
	  if (c->last_activity_time < oldest_time)
	    {
	      oldest_time = c->last_activity_time;
	      oldest = c;
	    }
	}

      if (oldest)
	{
	  u64 old_key = ovpn_mgmt_client_key (&oldest->remote_addr,
					      oldest->remote_port);
	  hash_unset (mgmt->client_by_key, old_key);
	  pool_put (mgmt->clients, oldest);
	}
    }

  /* Create new client */
  ovpn_mgmt_client_t *client;
  pool_get_zero (mgmt->clients, client);
  clib_memcpy (&client->remote_addr, addr, sizeof (*addr));
  client->remote_port = port;
  client->instance_id = mgmt->instance_id;
  client->last_activity_time = now;
  client->authenticated = (mgmt->password == NULL);

  hash_set (mgmt->client_by_key, key, client - mgmt->clients);

  return client;
}

/*
 * Session callback: accept new UDP session
 */
static int
ovpn_mgmt_session_accept_callback (session_t *s)
{
  ovpn_mgmt_main_t *mm = &ovpn_mgmt_main;
  ovpn_mgmt_t *mgmt;

  /* Find the management context for this session */
  pool_foreach (mgmt, mm->contexts)
    {
      if (mgmt->udp_session_handle == session_handle (s))
	{
	  s->opaque = mgmt->instance_id;
	  return 0;
	}
    }

  /* Store instance ID in opaque for later use */
  s->opaque = ~0;
  return 0;
}

/*
 * Session callback: disconnect
 */
static void
ovpn_mgmt_session_disconnect_callback (session_t *s)
{
  /* UDP sessions don't really disconnect, but handle cleanup if needed */
}

/*
 * Session callback: reset
 */
static void
ovpn_mgmt_session_reset_callback (session_t *s)
{
  /* Handle session reset */
}

/*
 * Session callback: cleanup
 */
static void
ovpn_mgmt_session_cleanup_callback (session_t *s, session_cleanup_ntf_t ntf)
{
  /* Cleanup resources if needed */
}

/*
 * Session callback: connected (required but not used for UDP server)
 */
static int
ovpn_mgmt_session_connected_callback (u32 app_index, u32 api_context,
				      session_t *s, session_error_t err)
{
  /* Not used for UDP server - we only listen */
  return 0;
}

/*
 * Session callback: add segment (for shared memory allocation)
 */
static int
ovpn_mgmt_add_segment_callback (u32 client_index, u64 segment_handle)
{
  /* Accept new segments */
  return 0;
}

/*
 * Send UDP datagram response
 */
static void
ovpn_mgmt_send_to_client (ovpn_mgmt_t *mgmt, ovpn_mgmt_client_t *client,
			  const u8 *data, u32 len)
{
  session_t *s;
  svm_fifo_t *tx_fifo;
  session_dgram_hdr_t hdr;
  int rv;

  if (!mgmt->is_active || mgmt->udp_session_handle == SESSION_INVALID_HANDLE)
    return;

  s = session_get_from_handle (mgmt->udp_session_handle);
  if (!s)
    return;

  tx_fifo = s->tx_fifo;

  /* Check if we have enough space in TX fifo */
  u32 needed = sizeof (session_dgram_hdr_t) + len;
  if (svm_fifo_max_enqueue_prod (tx_fifo) < needed)
    return;

  /* Build datagram header */
  clib_memset (&hdr, 0, sizeof (hdr));
  hdr.data_length = len;
  hdr.data_offset = 0;

  /* Set remote address (destination for outgoing packet) */
  if (ip_addr_version (&client->remote_addr) == AF_IP4)
    {
      hdr.is_ip4 = 1;
      hdr.rmt_ip.ip4.as_u32 = client->remote_addr.ip.ip4.as_u32;
      hdr.lcl_ip.ip4.as_u32 = mgmt->bind_addr.ip.ip4.as_u32;
    }
  else
    {
      hdr.is_ip4 = 0;
      clib_memcpy (&hdr.rmt_ip.ip6, &client->remote_addr.ip.ip6,
		   sizeof (ip6_address_t));
      clib_memcpy (&hdr.lcl_ip.ip6, &mgmt->bind_addr.ip.ip6,
		   sizeof (ip6_address_t));
    }
  hdr.rmt_port = clib_host_to_net_u16 (client->remote_port);
  hdr.lcl_port = clib_host_to_net_u16 (mgmt->bind_port);

  /* Write header and data to TX fifo */
  rv = svm_fifo_enqueue (tx_fifo, sizeof (hdr), (u8 *) &hdr);
  if (rv != sizeof (hdr))
    return;

  rv = svm_fifo_enqueue (tx_fifo, len, data);
  if (rv != (int) len)
    return;

  /* Signal VPP to send the datagram */
  if (svm_fifo_set_event (tx_fifo))
    session_program_tx_io_evt (s->handle, SESSION_IO_EVT_TX);
}

/*
 * Send formatted response to client
 */
static void
ovpn_mgmt_send_response (ovpn_mgmt_t *mgmt, ovpn_mgmt_client_t *client,
			 const char *format, ...)
{
  va_list args;
  u8 *s = 0;

  va_start (args, format);
  s = va_format (s, format, &args);
  va_end (args);

  ovpn_mgmt_send_to_client (mgmt, client, s, vec_len (s));
  vec_free (s);
}

/*
 * Send notification to all connected clients
 */
void
ovpn_mgmt_notify (ovpn_mgmt_t *mgmt, ovpn_mgmt_notify_type_t type,
		  const char *format, ...)
{
  ovpn_mgmt_client_t *client;
  va_list args;
  u8 *msg = 0;

  if (!mgmt)
    return;

  va_start (args, format);
  msg = va_format (msg, format, &args);
  va_end (args);

  pool_foreach (client, mgmt->clients)
    {
      /* Check if client wants this notification type */
      int send = 0;
      switch (type)
	{
	case OVPN_MGMT_NOTIFY_BYTECOUNT:
	case OVPN_MGMT_NOTIFY_BYTECOUNT_CLI:
	  send = (client->notify.bytecount_interval > 0);
	  break;
	case OVPN_MGMT_NOTIFY_STATE:
	  send = client->notify.state_enabled;
	  break;
	case OVPN_MGMT_NOTIFY_LOG:
	  send = client->notify.log_enabled;
	  break;
	case OVPN_MGMT_NOTIFY_ECHO:
	  send = client->notify.echo_enabled;
	  break;
	case OVPN_MGMT_NOTIFY_HOLD:
	  send = client->notify.hold_enabled;
	  break;
	default:
	  send = 1; /* Always send FATAL, INFO, CLIENT */
	  break;
	}
      if (send && client->authenticated)
	ovpn_mgmt_send_to_client (mgmt, client, msg, vec_len (msg));
    }

  vec_free (msg);
}

/*
 * Send client event notification
 */
void
ovpn_mgmt_notify_client_event (ovpn_mgmt_t *mgmt,
			       ovpn_mgmt_client_event_t event, u32 peer_id,
			       const char *common_name,
			       const ip_address_t *real_addr, u16 real_port)
{
  const char *event_names[] = {
    [OVPN_MGMT_CLIENT_CONNECT] = "CONNECT",
    [OVPN_MGMT_CLIENT_DISCONNECT] = "DISCONNECT",
    [OVPN_MGMT_CLIENT_REAUTH] = "REAUTH",
    [OVPN_MGMT_CLIENT_ESTABLISHED] = "ESTABLISHED",
    [OVPN_MGMT_CLIENT_ADDRESS] = "ADDRESS",
    [OVPN_MGMT_CLIENT_CR_RESPONSE] = "CR_RESPONSE",
    [OVPN_MGMT_CLIENT_PF] = "PF",
  };

  u8 *addr_str = format (0, "%U", format_ip_address, real_addr);
  vec_add1 (addr_str, 0);

  ovpn_mgmt_notify (mgmt, OVPN_MGMT_NOTIFY_CLIENT,
		    ">CLIENT:%s,%u\r\n"
		    ">CLIENT:ENV,common_name=%s\r\n"
		    ">CLIENT:ENV,trusted_ip=%s\r\n"
		    ">CLIENT:ENV,trusted_port=%u\r\n"
		    ">CLIENT:ENV,END\r\n",
		    event < ARRAY_LEN (event_names) ? event_names[event]
						    : "UNKNOWN",
		    peer_id, common_name ? common_name : "", (char *) addr_str,
		    real_port);

  vec_free (addr_str);
}

/*
 * Send state change notification
 */
void
ovpn_mgmt_notify_state_change (ovpn_mgmt_t *mgmt, ovpn_mgmt_state_t state,
			       const char *description,
			       const ip_address_t *local_ip,
			       const ip_address_t *remote_ip)
{
  f64 now = vlib_time_now (ovpn_mgmt_main.vm);
  u8 *local_str = 0, *remote_str = 0;

  if (!mgmt)
    return;

  mgmt->state = state;

  /* Add to history */
  if (mgmt->state_history_size > 0)
    {
      u32 idx = mgmt->state_history_head;
      ovpn_mgmt_state_entry_t *entry = &mgmt->state_history[idx];

      vec_free (entry->description);
      entry->timestamp = now;
      entry->state = state;
      entry->description =
	(u8 *) format (0, "%s", description ? description : "");
      if (local_ip)
	clib_memcpy (&entry->local_ip, local_ip, sizeof (*local_ip));
      if (remote_ip)
	clib_memcpy (&entry->remote_ip, remote_ip, sizeof (*remote_ip));

      mgmt->state_history_head =
	(mgmt->state_history_head + 1) % mgmt->state_history_size;
      if (mgmt->state_history_count < mgmt->state_history_size)
	mgmt->state_history_count++;
    }

  /* Format addresses if provided */
  if (local_ip)
    {
      local_str = format (0, "%U", format_ip_address, local_ip);
      vec_add1 (local_str, 0);
    }
  if (remote_ip)
    {
      remote_str = format (0, "%U", format_ip_address, remote_ip);
      vec_add1 (remote_str, 0);
    }

  ovpn_mgmt_notify (mgmt, OVPN_MGMT_NOTIFY_STATE,
		    ">STATE:%.0f,%U,%s,%s,%s\r\n", now, format_ovpn_mgmt_state,
		    state, description ? description : "",
		    local_str ? (char *) local_str : "",
		    remote_str ? (char *) remote_str : "");

  vec_free (local_str);
  vec_free (remote_str);
}

/*
 * Log message
 */
void
ovpn_mgmt_log (ovpn_mgmt_t *mgmt, u8 flags, const char *format, ...)
{
  f64 now = vlib_time_now (ovpn_mgmt_main.vm);
  va_list args;
  u8 *msg = 0;

  if (!mgmt)
    return;

  va_start (args, format);
  msg = va_format (msg, format, &args);
  va_end (args);

  /* Add to history */
  if (mgmt->log_history_size > 0)
    {
      u32 idx = mgmt->log_history_head;
      ovpn_mgmt_log_entry_t *entry = &mgmt->log_history[idx];

      vec_free (entry->message);
      entry->timestamp = now;
      entry->flags = flags;
      entry->message = vec_dup (msg);

      mgmt->log_history_head =
	(mgmt->log_history_head + 1) % mgmt->log_history_size;
      if (mgmt->log_history_count < mgmt->log_history_size)
	mgmt->log_history_count++;
    }

  /* Send notification */
  ovpn_mgmt_notify (mgmt, OVPN_MGMT_NOTIFY_LOG, ">LOG:%.0f,%U,%v\r\n", now,
		    format_ovpn_mgmt_log_flags, (int) flags, msg);

  vec_free (msg);
}

/*
 * Echo message
 */
void
ovpn_mgmt_echo (ovpn_mgmt_t *mgmt, const u8 *message)
{
  f64 now = vlib_time_now (ovpn_mgmt_main.vm);

  if (!mgmt)
    return;

  /* Add to history */
  if (mgmt->echo_history_size > 0)
    {
      u32 idx = mgmt->echo_history_head;

      vec_free (mgmt->echo_history[idx]);
      mgmt->echo_history[idx] = vec_dup ((u8 *) message);
      mgmt->echo_timestamps[idx] = now;

      mgmt->echo_history_head =
	(mgmt->echo_history_head + 1) % mgmt->echo_history_size;
      if (mgmt->echo_history_count < mgmt->echo_history_size)
	mgmt->echo_history_count++;
    }

  ovpn_mgmt_notify (mgmt, OVPN_MGMT_NOTIFY_ECHO, ">ECHO:%.0f,%s\r\n", now,
		    message);
}

/*
 * Process bytecount notifications
 */
void
ovpn_mgmt_process_bytecount (ovpn_mgmt_t *mgmt, f64 now)
{
  ovpn_instance_t *inst;
  ovpn_mgmt_client_t *client;
  ovpn_peer_t *peer;

  if (!mgmt)
    return;

  inst = ovpn_instance_get (mgmt->instance_id);
  if (!inst)
    return;

  pool_foreach (client, mgmt->clients)
    {
      if (!client->authenticated || client->notify.bytecount_interval == 0)
	continue;

      f64 interval = (f64) client->notify.bytecount_interval;
      if (now - client->last_bytecount_time < interval)
	continue;

      client->last_bytecount_time = now;

      /* Calculate total bytes for this instance */
      u64 total_rx = 0, total_tx = 0;
      pool_foreach (peer, inst->multi_context.peer_db.peers)
	{
	  total_rx += peer->rx_bytes;
	  total_tx += peer->tx_bytes;
	}

      ovpn_mgmt_send_response (mgmt, client, ">BYTECOUNT:%lu,%lu\r\n", total_rx,
			       total_tx);

      /* Per-client bytecount */
      pool_foreach (peer, inst->multi_context.peer_db.peers)
	{
	  ovpn_mgmt_send_response (mgmt, client, ">BYTECOUNT_CLI:%u,%lu,%lu\r\n",
				   peer->peer_id, peer->rx_bytes, peer->tx_bytes);
	}
    }
}

/*
 * Set hold state
 */
void
ovpn_mgmt_set_hold (ovpn_mgmt_t *mgmt, u8 hold)
{
  if (!mgmt)
    return;
  mgmt->hold = hold;
  if (hold)
    ovpn_mgmt_notify (mgmt, OVPN_MGMT_NOTIFY_HOLD,
		      ">HOLD:Waiting for hold release\r\n");
}

/*
 * Release hold
 */
void
ovpn_mgmt_hold_release (ovpn_mgmt_t *mgmt)
{
  if (!mgmt)
    return;
  mgmt->hold = 0;
  ovpn_mgmt_notify (mgmt, OVPN_MGMT_NOTIFY_INFO, ">INFO:Hold released\r\n");
}

/*
 * Command handlers
 */

static void
cmd_help (ovpn_mgmt_t *mgmt, ovpn_mgmt_client_t *client, u8 **argv)
{
  ovpn_mgmt_send_response (
    mgmt, client,
    "Management Interface for OpenVPN VPP Plugin (UDP)\r\n"
    "Commands:\r\n"
    "  bytecount n            : Show bytes in/out, update every n secs (0=off)\r\n"
    "  echo [on|off] [N|all]  : Like log, but output echo msgs\r\n"
    "  help                   : Print this message\r\n"
    "  hold [on|off|release]  : Set/show hold flag, or release current hold\r\n"
    "  kill cn                : Kill client by common name\r\n"
    "  kill addr:port         : Kill client by address:port\r\n"
    "  log [on|off] [N|all]   : Turn on/off realtime log display\r\n"
    "  mute [n]               : Set log mute level to n, or show level\r\n"
    "  pid                    : Show process ID of server process\r\n"
    "  client-kill CID        : Kill client by CID (connection ID)\r\n"
    "  signal s               : Send signal s to daemon (SIGHUP,SIGTERM,etc)\r\n"
    "  state [on|off] [N|all] : Like log, but for state changes\r\n"
    "  status [n]             : Show current daemon status info (version n)\r\n"
    "  verb [n]               : Set log verbosity to n, or show if n absent\r\n"
    "  version                : Show current version number\r\n"
    "  password type pw       : Provide authentication password\r\n"
    "END\r\n");
}

static void
cmd_version (ovpn_mgmt_t *mgmt, ovpn_mgmt_client_t *client, u8 **argv)
{
  ovpn_mgmt_send_response (mgmt, client,
			   "OpenVPN Version: VPP OpenVPN Plugin 1.0 (UDP)\r\n"
			   "Management Version: 5\r\n"
			   "END\r\n");
}

static void
cmd_pid (ovpn_mgmt_t *mgmt, ovpn_mgmt_client_t *client, u8 **argv)
{
  ovpn_mgmt_send_response (mgmt, client, "SUCCESS: pid=%d\r\n", getpid ());
}

static void
cmd_status (ovpn_mgmt_t *mgmt, ovpn_mgmt_client_t *client, u8 **argv)
{
  ovpn_instance_t *inst = ovpn_instance_get (mgmt->instance_id);
  ovpn_peer_t *peer;
  f64 now = vlib_time_now (ovpn_mgmt_main.vm);
  int version = 1;

  if (vec_len (argv) > 1)
    version = atoi ((char *) argv[1]);

  if (!inst)
    {
      ovpn_mgmt_send_response (mgmt, client, "ERROR: instance not found\r\n");
      return;
    }

  if (version == 1)
    {
      ovpn_mgmt_send_response (mgmt, client,
			       "OpenVPN CLIENT LIST\r\n"
			       "Updated,%.0f\r\n"
			       "Common Name,Real Address,Bytes Received,Bytes "
			       "Sent,Connected Since\r\n",
			       now);
    }
  else if (version >= 2)
    {
      ovpn_mgmt_send_response (
	mgmt, client,
	"TITLE,OpenVPN VPP Plugin Client List\r\n"
	"TIME,%.0f,%.0f\r\n"
	"HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,"
	"Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,"
	"Connected Since (time_t),Username,Client ID,Peer ID,Data Channel "
	"Cipher\r\n",
	now, now);
    }

  pool_foreach (peer, inst->multi_context.peer_db.peers)
    {
      if (peer->state == OVPN_PEER_STATE_DEAD ||
	  peer->state == OVPN_PEER_STATE_INITIAL)
	continue;

      u8 *real_addr = format (0, "%U:%u", format_ip_address, &peer->remote_addr,
			      peer->remote_port);
      vec_add1 (real_addr, 0);

      u8 *virtual_addr = 0;
      if (peer->virtual_ip_set)
	{
	  virtual_addr = format (0, "%U", format_ip_address, &peer->virtual_ip);
	  vec_add1 (virtual_addr, 0);
	}

      if (version == 1)
	{
	  ovpn_mgmt_send_response (mgmt, client, "peer_%u,%s,%lu,%lu,%.0f\r\n",
				   peer->peer_id, real_addr, peer->rx_bytes,
				   peer->tx_bytes, peer->established_time);
	}
      else if (version >= 2)
	{
	  ovpn_mgmt_send_response (
	    mgmt, client,
	    "CLIENT_LIST,peer_%u,%s,%s,,%lu,%lu,%.0f,%.0f,,%u,%u,AES-256-GCM\r\n",
	    peer->peer_id, real_addr, virtual_addr ? (char *) virtual_addr : "",
	    peer->rx_bytes, peer->tx_bytes, peer->established_time,
	    peer->established_time, peer->peer_id, peer->peer_id);
	}

      vec_free (real_addr);
      vec_free (virtual_addr);
    }

  if (version == 1)
    {
      ovpn_mgmt_send_response (mgmt, client,
			       "ROUTING TABLE\r\n"
			       "Virtual Address,Common Name,Real Address,Last Ref\r\n"
			       "GLOBAL STATS\r\n"
			       "Max bcast/mcast queue length,0\r\n"
			       "END\r\n");
    }
  else
    {
      ovpn_mgmt_send_response (
	mgmt, client,
	"HEADER,ROUTING_TABLE,Virtual Address,Common Name,"
	"Real Address,Last Ref,Last Ref (time_t)\r\n"
	"GLOBAL_STATS,Max bcast/mcast queue length,0\r\n"
	"END\r\n");
    }
}

static void
cmd_state (ovpn_mgmt_t *mgmt, ovpn_mgmt_client_t *client, u8 **argv)
{
  if (vec_len (argv) == 1)
    {
      f64 now = vlib_time_now (ovpn_mgmt_main.vm);
      ovpn_mgmt_send_response (mgmt, client, "%.0f,%U,SUCCESS\r\n", now,
			       format_ovpn_mgmt_state, mgmt->state);
      ovpn_mgmt_send_response (mgmt, client, "END\r\n");
      return;
    }

  u8 *arg = argv[1];
  if (!strcmp ((char *) arg, "on"))
    {
      client->notify.state_enabled = 1;
      ovpn_mgmt_send_response (mgmt, client, "SUCCESS: state on\r\n");
    }
  else if (!strcmp ((char *) arg, "off"))
    {
      client->notify.state_enabled = 0;
      ovpn_mgmt_send_response (mgmt, client, "SUCCESS: state off\r\n");
    }
  else if (!strcmp ((char *) arg, "all"))
    {
      for (u32 i = 0; i < mgmt->state_history_count; i++)
	{
	  u32 idx = (mgmt->state_history_head - mgmt->state_history_count + i +
		     mgmt->state_history_size) %
		    mgmt->state_history_size;
	  ovpn_mgmt_state_entry_t *e = &mgmt->state_history[idx];
	  ovpn_mgmt_send_response (mgmt, client, "%.0f,%U,%v\r\n", e->timestamp,
				   format_ovpn_mgmt_state, e->state,
				   e->description);
	}
      ovpn_mgmt_send_response (mgmt, client, "END\r\n");
    }
  else
    {
      int n = atoi ((char *) arg);
      if (n < 0)
	n = 0;
      if (n > (int) mgmt->state_history_count)
	n = mgmt->state_history_count;

      for (u32 i = mgmt->state_history_count - n; i < mgmt->state_history_count;
	   i++)
	{
	  u32 idx = (mgmt->state_history_head - mgmt->state_history_count + i +
		     mgmt->state_history_size) %
		    mgmt->state_history_size;
	  ovpn_mgmt_state_entry_t *e = &mgmt->state_history[idx];
	  ovpn_mgmt_send_response (mgmt, client, "%.0f,%U,%v\r\n", e->timestamp,
				   format_ovpn_mgmt_state, e->state,
				   e->description);
	}
      ovpn_mgmt_send_response (mgmt, client, "END\r\n");
    }
}

static void
cmd_bytecount (ovpn_mgmt_t *mgmt, ovpn_mgmt_client_t *client, u8 **argv)
{
  if (vec_len (argv) < 2)
    {
      ovpn_mgmt_send_response (mgmt, client, "SUCCESS: bytecount interval=%u\r\n",
			       client->notify.bytecount_interval);
      return;
    }

  u32 interval = atoi ((char *) argv[1]);
  client->notify.bytecount_interval = interval;
  client->last_bytecount_time = vlib_time_now (ovpn_mgmt_main.vm);

  ovpn_mgmt_send_response (mgmt, client, "SUCCESS: bytecount interval changed\r\n");
}

static void
cmd_log (ovpn_mgmt_t *mgmt, ovpn_mgmt_client_t *client, u8 **argv)
{
  if (vec_len (argv) == 1)
    {
      ovpn_mgmt_send_response (mgmt, client, "SUCCESS: log %s\r\n",
			       client->notify.log_enabled ? "on" : "off");
      return;
    }

  u8 *arg = argv[1];
  if (!strcmp ((char *) arg, "on"))
    {
      client->notify.log_enabled = 1;
      ovpn_mgmt_send_response (mgmt, client, "SUCCESS: log on\r\n");
    }
  else if (!strcmp ((char *) arg, "off"))
    {
      client->notify.log_enabled = 0;
      ovpn_mgmt_send_response (mgmt, client, "SUCCESS: log off\r\n");
    }
  else if (!strcmp ((char *) arg, "all"))
    {
      for (u32 i = 0; i < mgmt->log_history_count; i++)
	{
	  u32 idx = (mgmt->log_history_head - mgmt->log_history_count + i +
		     mgmt->log_history_size) %
		    mgmt->log_history_size;
	  ovpn_mgmt_log_entry_t *e = &mgmt->log_history[idx];
	  ovpn_mgmt_send_response (mgmt, client, "%.0f,%U,%v\r\n", e->timestamp,
				   format_ovpn_mgmt_log_flags, (int) e->flags,
				   e->message);
	}
      ovpn_mgmt_send_response (mgmt, client, "END\r\n");
    }
  else
    {
      int n = atoi ((char *) arg);
      if (n < 0)
	n = 0;
      if (n > (int) mgmt->log_history_count)
	n = mgmt->log_history_count;

      for (u32 i = mgmt->log_history_count - n; i < mgmt->log_history_count; i++)
	{
	  u32 idx = (mgmt->log_history_head - mgmt->log_history_count + i +
		     mgmt->log_history_size) %
		    mgmt->log_history_size;
	  ovpn_mgmt_log_entry_t *e = &mgmt->log_history[idx];
	  ovpn_mgmt_send_response (mgmt, client, "%.0f,%U,%v\r\n", e->timestamp,
				   format_ovpn_mgmt_log_flags, (int) e->flags,
				   e->message);
	}
      ovpn_mgmt_send_response (mgmt, client, "END\r\n");
    }
}

static void
cmd_echo (ovpn_mgmt_t *mgmt, ovpn_mgmt_client_t *client, u8 **argv)
{
  if (vec_len (argv) == 1)
    {
      ovpn_mgmt_send_response (mgmt, client, "SUCCESS: echo %s\r\n",
			       client->notify.echo_enabled ? "on" : "off");
      return;
    }

  u8 *arg = argv[1];
  if (!strcmp ((char *) arg, "on"))
    {
      client->notify.echo_enabled = 1;
      ovpn_mgmt_send_response (mgmt, client, "SUCCESS: echo on\r\n");
    }
  else if (!strcmp ((char *) arg, "off"))
    {
      client->notify.echo_enabled = 0;
      ovpn_mgmt_send_response (mgmt, client, "SUCCESS: echo off\r\n");
    }
  else if (!strcmp ((char *) arg, "all"))
    {
      for (u32 i = 0; i < mgmt->echo_history_count; i++)
	{
	  u32 idx = (mgmt->echo_history_head - mgmt->echo_history_count + i +
		     mgmt->echo_history_size) %
		    mgmt->echo_history_size;
	  ovpn_mgmt_send_response (mgmt, client, "%.0f,%s\r\n",
				   mgmt->echo_timestamps[idx],
				   mgmt->echo_history[idx]);
	}
      ovpn_mgmt_send_response (mgmt, client, "END\r\n");
    }
}

static void
cmd_hold (ovpn_mgmt_t *mgmt, ovpn_mgmt_client_t *client, u8 **argv)
{
  if (vec_len (argv) == 1)
    {
      ovpn_mgmt_send_response (mgmt, client, "SUCCESS: hold=%s\r\n",
			       mgmt->hold ? "1" : "0");
      return;
    }

  u8 *arg = argv[1];
  if (!strcmp ((char *) arg, "on"))
    {
      ovpn_mgmt_set_hold (mgmt, 1);
      ovpn_mgmt_send_response (mgmt, client, "SUCCESS: hold on\r\n");
    }
  else if (!strcmp ((char *) arg, "off"))
    {
      ovpn_mgmt_set_hold (mgmt, 0);
      ovpn_mgmt_send_response (mgmt, client, "SUCCESS: hold off\r\n");
    }
  else if (!strcmp ((char *) arg, "release"))
    {
      ovpn_mgmt_hold_release (mgmt);
      ovpn_mgmt_send_response (mgmt, client, "SUCCESS: hold released\r\n");
    }
  else
    {
      ovpn_mgmt_send_response (mgmt, client, "ERROR: hold: bad argument\r\n");
    }
}

static void
cmd_verb (ovpn_mgmt_t *mgmt, ovpn_mgmt_client_t *client, u8 **argv)
{
  if (vec_len (argv) == 1)
    {
      ovpn_mgmt_send_response (mgmt, client, "SUCCESS: verb=%u\r\n",
			       client->notify.log_verbosity);
      return;
    }

  int v = atoi ((char *) argv[1]);
  if (v < 0)
    v = 0;
  if (v > 15)
    v = 15;

  client->notify.log_verbosity = v;
  ovpn_mgmt_send_response (mgmt, client, "SUCCESS: verb level changed\r\n");
}

static void
cmd_mute (ovpn_mgmt_t *mgmt, ovpn_mgmt_client_t *client, u8 **argv)
{
  ovpn_mgmt_send_response (mgmt, client, "SUCCESS: mute=0\r\n");
}

static void
cmd_kill (ovpn_mgmt_t *mgmt, ovpn_mgmt_client_t *client, u8 **argv)
{
  if (vec_len (argv) < 2)
    {
      ovpn_mgmt_send_response (mgmt, client, "ERROR: kill: requires argument\r\n");
      return;
    }

  ovpn_instance_t *inst = ovpn_instance_get (mgmt->instance_id);
  if (!inst)
    {
      ovpn_mgmt_send_response (mgmt, client, "ERROR: instance not found\r\n");
      return;
    }

  u8 *target = argv[1];
  ovpn_peer_t *peer = NULL;
  int found = 0;

  /* Try to parse as addr:port */
  u8 *colon = (u8 *) strrchr ((char *) target, ':');
  if (colon)
    {
      *colon = 0;
      u16 port = atoi ((char *) (colon + 1));
      ip_address_t addr;
      unformat_input_t input;

      unformat_init_string (&input, (char *) target, strlen ((char *) target));
      if (unformat (&input, "%U", unformat_ip_address, &addr))
	{
	  peer = ovpn_peer_lookup_by_remote (&inst->multi_context.peer_db, &addr,
					     port);
	  if (peer)
	    found = 1;
	}
      unformat_free (&input);
      *colon = ':';
    }

  /* Try as common name (peer_%u) */
  if (!found && strncmp ((char *) target, "peer_", 5) == 0)
    {
      u32 peer_id = atoi ((char *) target + 5);
      peer = ovpn_peer_get (&inst->multi_context.peer_db, peer_id);
      if (peer && peer->state != OVPN_PEER_STATE_DEAD)
	found = 1;
    }

  if (!found)
    {
      ovpn_mgmt_send_response (mgmt, client, "ERROR: common name '%s' not found\r\n",
			       target);
      return;
    }

  vlib_main_t *vm = ovpn_mgmt_main.vm;
  vlib_worker_thread_barrier_sync (vm);
  ovpn_peer_delete (&inst->multi_context.peer_db, peer->peer_id);
  vlib_worker_thread_barrier_release (vm);

  ovpn_mgmt_send_response (mgmt, client, "SUCCESS: client killed\r\n");
}

static void
cmd_client_kill (ovpn_mgmt_t *mgmt, ovpn_mgmt_client_t *client, u8 **argv)
{
  if (vec_len (argv) < 2)
    {
      ovpn_mgmt_send_response (mgmt, client,
			       "ERROR: client-kill: requires CID argument\r\n");
      return;
    }

  u32 cid = atoi ((char *) argv[1]);

  ovpn_instance_t *inst = ovpn_instance_get (mgmt->instance_id);
  if (!inst)
    {
      ovpn_mgmt_send_response (mgmt, client, "ERROR: instance not found\r\n");
      return;
    }

  ovpn_peer_t *peer = ovpn_peer_get (&inst->multi_context.peer_db, cid);
  if (!peer || peer->state == OVPN_PEER_STATE_DEAD)
    {
      ovpn_mgmt_send_response (mgmt, client, "ERROR: CID %u not found\r\n", cid);
      return;
    }

  vlib_main_t *vm = ovpn_mgmt_main.vm;
  vlib_worker_thread_barrier_sync (vm);
  ovpn_peer_delete (&inst->multi_context.peer_db, cid);
  vlib_worker_thread_barrier_release (vm);

  ovpn_mgmt_send_response (mgmt, client, "SUCCESS: client-kill command succeeded\r\n");
}

/*
 * client-auth <cid> <kid>
 * Approve pending authentication for client
 */
static void
cmd_client_auth (ovpn_mgmt_t *mgmt, ovpn_mgmt_client_t *client, u8 **argv)
{
  if (vec_len (argv) < 3)
    {
      ovpn_mgmt_send_response (
	mgmt, client, "ERROR: client-auth: requires CID and KID arguments\r\n");
      return;
    }

  u32 cid = atoi ((char *) argv[1]);
  u32 kid = atoi ((char *) argv[2]);

  int rv = ovpn_mgmt_client_auth (mgmt->instance_id, cid, kid);
  if (rv == 0)
    ovpn_mgmt_send_response (mgmt, client,
			     "SUCCESS: client-auth command succeeded\r\n");
  else if (rv == -1)
    ovpn_mgmt_send_response (mgmt, client, "ERROR: instance not found\r\n");
  else if (rv == -2)
    ovpn_mgmt_send_response (mgmt, client, "ERROR: CID %u not found\r\n", cid);
  else if (rv == -3)
    ovpn_mgmt_send_response (mgmt, client,
			     "ERROR: CID %u not pending auth\r\n", cid);
  else if (rv == -4)
    ovpn_mgmt_send_response (mgmt, client, "ERROR: KID mismatch\r\n");
  else
    ovpn_mgmt_send_response (mgmt, client, "ERROR: client-auth failed\r\n");
}

/*
 * client-deny <cid> <kid> [reason]
 * Deny pending authentication for client
 */
static void
cmd_client_deny (ovpn_mgmt_t *mgmt, ovpn_mgmt_client_t *client, u8 **argv)
{
  if (vec_len (argv) < 3)
    {
      ovpn_mgmt_send_response (
	mgmt, client, "ERROR: client-deny: requires CID and KID arguments\r\n");
      return;
    }

  u32 cid = atoi ((char *) argv[1]);
  u32 kid = atoi ((char *) argv[2]);
  const char *reason = vec_len (argv) > 3 ? (const char *) argv[3] : NULL;

  int rv = ovpn_mgmt_client_deny (mgmt->instance_id, cid, kid, reason);
  if (rv == 0)
    ovpn_mgmt_send_response (mgmt, client,
			     "SUCCESS: client-deny command succeeded\r\n");
  else if (rv == -1)
    ovpn_mgmt_send_response (mgmt, client, "ERROR: instance not found\r\n");
  else if (rv == -2)
    ovpn_mgmt_send_response (mgmt, client, "ERROR: CID %u not found\r\n", cid);
  else if (rv == -3)
    ovpn_mgmt_send_response (mgmt, client,
			     "ERROR: CID %u not pending auth\r\n", cid);
  else if (rv == -4)
    ovpn_mgmt_send_response (mgmt, client, "ERROR: KID mismatch\r\n");
  else
    ovpn_mgmt_send_response (mgmt, client, "ERROR: client-deny failed\r\n");
}

static void
cmd_signal (ovpn_mgmt_t *mgmt, ovpn_mgmt_client_t *client, u8 **argv)
{
  if (vec_len (argv) < 2)
    {
      ovpn_mgmt_send_response (mgmt, client, "ERROR: signal: requires argument\r\n");
      return;
    }

  u8 *sig = argv[1];

  if (!strcmp ((char *) sig, "SIGHUP"))
    {
      ovpn_mgmt_send_response (mgmt, client, "SUCCESS: signal SIGHUP thrown\r\n");
    }
  else if (!strcmp ((char *) sig, "SIGTERM"))
    {
      ovpn_mgmt_notify_state_change (mgmt, OVPN_MGMT_STATE_EXITING,
				     "SIGTERM received", NULL, NULL);
      ovpn_mgmt_send_response (mgmt, client, "SUCCESS: signal SIGTERM thrown\r\n");
    }
  else if (!strcmp ((char *) sig, "SIGUSR1"))
    {
      ovpn_mgmt_send_response (mgmt, client, "SUCCESS: signal SIGUSR1 thrown\r\n");
    }
  else if (!strcmp ((char *) sig, "SIGUSR2"))
    {
      ovpn_mgmt_send_response (mgmt, client, "SUCCESS: signal SIGUSR2 thrown\r\n");
    }
  else
    {
      ovpn_mgmt_send_response (mgmt, client, "ERROR: signal: unknown signal '%s'\r\n",
			       sig);
    }
}

static void
cmd_password (ovpn_mgmt_t *mgmt, ovpn_mgmt_client_t *client, u8 **argv)
{
  if (vec_len (argv) < 3)
    {
      ovpn_mgmt_send_response (mgmt, client,
			       "ERROR: password: requires type and value\r\n");
      return;
    }

  u8 *type = argv[1];
  u8 *value = argv[2];

  /* Remove quotes if present */
  if (type[0] == '"')
    {
      type++;
      u32 len = strlen ((char *) type);
      if (len > 0 && type[len - 1] == '"')
	type[len - 1] = 0;
    }

  if (!strcmp ((char *) type, "management"))
    {
      if (mgmt->password && strcmp ((char *) value, (char *) mgmt->password) == 0)
	{
	  client->authenticated = 1;
	  ovpn_mgmt_send_response (mgmt, client, "SUCCESS: password is correct\r\n");
	}
      else
	{
	  ovpn_mgmt_send_response (mgmt, client, "ERROR: password is incorrect\r\n");
	}
    }
  else
    {
      ovpn_mgmt_send_response (mgmt, client, "ERROR: unknown password type '%s'\r\n",
			       type);
    }
}

/* Command dispatch table */
typedef void (*ovpn_mgmt_cmd_fn_t) (ovpn_mgmt_t *mgmt, ovpn_mgmt_client_t *client,
				   u8 **argv);

typedef struct
{
  const char *name;
  ovpn_mgmt_cmd_fn_t fn;
  u8 needs_auth;
} ovpn_mgmt_cmd_t;

static ovpn_mgmt_cmd_t ovpn_mgmt_commands[] = {
  { "help", cmd_help, 1 },
  { "version", cmd_version, 1 },
  { "pid", cmd_pid, 1 },
  { "status", cmd_status, 1 },
  { "state", cmd_state, 1 },
  { "bytecount", cmd_bytecount, 1 },
  { "log", cmd_log, 1 },
  { "echo", cmd_echo, 1 },
  { "hold", cmd_hold, 1 },
  { "verb", cmd_verb, 1 },
  { "mute", cmd_mute, 1 },
  { "kill", cmd_kill, 1 },
  { "client-kill", cmd_client_kill, 1 },
  { "client-auth", cmd_client_auth, 1 },
  { "client-deny", cmd_client_deny, 1 },
  { "signal", cmd_signal, 1 },
  { "password", cmd_password, 0 },
  { NULL, NULL, 0 },
};

/*
 * Parse command line into argv
 */
static u8 **
ovpn_mgmt_parse_command (u8 *cmd)
{
  u8 **argv = 0;
  u8 *arg = 0;
  int in_quotes = 0;
  int escaped = 0;

  for (u8 *p = cmd; *p; p++)
    {
      if (escaped)
	{
	  vec_add1 (arg, *p);
	  escaped = 0;
	  continue;
	}

      if (*p == '\\' && !in_quotes)
	{
	  escaped = 1;
	  continue;
	}

      if (*p == '"')
	{
	  in_quotes = !in_quotes;
	  continue;
	}

      if ((*p == ' ' || *p == '\t') && !in_quotes)
	{
	  if (vec_len (arg) > 0)
	    {
	      vec_add1 (arg, 0);
	      vec_add1 (argv, arg);
	      arg = 0;
	    }
	  continue;
	}

      vec_add1 (arg, *p);
    }

  if (vec_len (arg) > 0)
    {
      vec_add1 (arg, 0);
      vec_add1 (argv, arg);
    }

  return argv;
}

/*
 * Free parsed argv
 */
static void
ovpn_mgmt_free_argv (u8 **argv)
{
  u8 **p;
  vec_foreach (p, argv)
    vec_free (*p);
  vec_free (argv);
}

/*
 * Process a single command
 */
static void
ovpn_mgmt_process_command (ovpn_mgmt_t *mgmt, ovpn_mgmt_client_t *client, u8 *cmd)
{
  u8 **argv = ovpn_mgmt_parse_command (cmd);

  if (vec_len (argv) == 0)
    {
      ovpn_mgmt_free_argv (argv);
      return;
    }

  /* Find command handler */
  ovpn_mgmt_cmd_t *c;
  for (c = ovpn_mgmt_commands; c->name; c++)
    {
      if (!strcmp ((char *) argv[0], c->name))
	{
	  /* Check authentication */
	  if (c->needs_auth && mgmt->password && !client->authenticated)
	    {
	      ovpn_mgmt_send_response (mgmt, client,
				       "ERROR: authentication required\r\n");
	    }
	  else
	    {
	      c->fn (mgmt, client, argv);
	    }
	  ovpn_mgmt_free_argv (argv);
	  return;
	}
    }

  ovpn_mgmt_send_response (mgmt, client, "ERROR: unknown command '%s'\r\n",
			   argv[0]);
  ovpn_mgmt_free_argv (argv);
}

/*
 * Session callback: RX data available
 */
static int
ovpn_mgmt_session_rx_callback (session_t *s)
{
  ovpn_mgmt_main_t *mm = &ovpn_mgmt_main;
  svm_fifo_t *rx_fifo = s->rx_fifo;
  session_dgram_pre_hdr_t ph;
  session_dgram_hdr_t hdr;
  u8 *data = 0;
  ovpn_mgmt_t *mgmt = NULL;
  f64 now = vlib_time_now (mm->vm);

  /* Process all available datagrams */
  while (svm_fifo_max_dequeue_cons (rx_fifo) > sizeof (session_dgram_hdr_t))
    {
      /* Peek at header to get data length */
      svm_fifo_peek (rx_fifo, 0, sizeof (ph), (u8 *) &ph);

      if (svm_fifo_max_dequeue_cons (rx_fifo) <
	  sizeof (session_dgram_hdr_t) + ph.data_length)
	break;

      /* Read full header */
      svm_fifo_peek (rx_fifo, 0, sizeof (hdr), (u8 *) &hdr);

      /* Read data */
      vec_validate (data, hdr.data_length - 1);
      svm_fifo_peek (rx_fifo, sizeof (hdr), hdr.data_length, data);

      /* Consume from fifo */
      svm_fifo_dequeue_drop (rx_fifo, sizeof (hdr) + hdr.data_length);

      /* Find the management context by matching local port */
      u16 lcl_port = clib_net_to_host_u16 (hdr.lcl_port);
      pool_foreach (mgmt, mm->contexts)
	{
	  if (mgmt->bind_port == lcl_port)
	    {
	      /* Update session handle from actual session with FIFOs */
	      mgmt->udp_session_handle = session_handle (s);
	      break;
	    }
	}

      if (!mgmt || !mgmt->is_active)
	{
	  vec_reset_length (data);
	  continue;
	}

      /* Get or create client by remote address */
      ip_address_t rmt_addr;
      if (hdr.is_ip4)
	{
	  ip_addr_version (&rmt_addr) = AF_IP4;
	  rmt_addr.ip.ip4.as_u32 = hdr.rmt_ip.ip4.as_u32;
	}
      else
	{
	  ip_addr_version (&rmt_addr) = AF_IP6;
	  clib_memcpy (&rmt_addr.ip.ip6, &hdr.rmt_ip.ip6, sizeof (ip6_address_t));
	}
      u16 rmt_port = clib_net_to_host_u16 (hdr.rmt_port);

      ovpn_mgmt_client_t *client =
	ovpn_mgmt_client_get_or_create (mgmt, &rmt_addr, rmt_port, now);
      if (!client)
	{
	  vec_reset_length (data);
	  continue;
	}

      /* Process each line in the datagram */
      u8 *line_start = data;
      for (u32 i = 0; i < vec_len (data); i++)
	{
	  if (data[i] == '\n')
	    {
	      u32 line_end = i;
	      if (line_end > 0 && data[line_end - 1] == '\r')
		line_end--;

	      u8 *cmd = 0;
	      u32 line_len = line_end - (line_start - data);
	      vec_add (cmd, line_start, line_len);
	      vec_add1 (cmd, 0);

	      ovpn_mgmt_process_command (mgmt, client, cmd);
	      vec_free (cmd);

	      line_start = data + i + 1;
	    }
	}

      /* If no newline found, treat entire datagram as one command */
      if (line_start == data && vec_len (data) > 0)
	{
	  vec_add1 (data, 0);
	  ovpn_mgmt_process_command (mgmt, client, data);
	}

      vec_reset_length (data);
    }

  vec_free (data);
  return 0;
}

/*
 * Session callbacks for management UDP server
 */
static session_cb_vft_t ovpn_mgmt_session_cb_vft = {
  .session_accept_callback = ovpn_mgmt_session_accept_callback,
  .session_disconnect_callback = ovpn_mgmt_session_disconnect_callback,
  .session_connected_callback = ovpn_mgmt_session_connected_callback,
  .session_reset_callback = ovpn_mgmt_session_reset_callback,
  .session_cleanup_callback = ovpn_mgmt_session_cleanup_callback,
  .add_segment_callback = ovpn_mgmt_add_segment_callback,
  .builtin_app_rx_callback = ovpn_mgmt_session_rx_callback,
};

/*
 * Attach application to session layer
 */
static int
ovpn_mgmt_app_attach (void)
{
  ovpn_mgmt_main_t *mm = &ovpn_mgmt_main;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];

  if (mm->app_attached)
    return 0;

  /* Enable session layer first */
  session_enable_disable_args_t session_args = {
    .is_en = 1,
    .rt_engine_type = RT_BACKEND_ENGINE_RULE_TABLE
  };
  vnet_session_enable_disable (mm->vm, &session_args);

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->api_client_index = APP_INVALID_INDEX;
  a->name = format (0, "ovpn-mgmt");
  a->session_cb_vft = &ovpn_mgmt_session_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = 64 << 20;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = 64 << 20;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = 64 << 10;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = 64 << 10;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;

  if (vnet_application_attach (a))
    {
      vec_free (a->name);
      return -1;
    }

  mm->app_index = a->app_index;
  mm->app_attached = 1;
  vec_free (a->name);

  return 0;
}

/*
 * Initialize management subsystem
 */
void
ovpn_mgmt_init (vlib_main_t *vm)
{
  ovpn_mgmt_main_t *mm = &ovpn_mgmt_main;

  clib_memset (mm, 0, sizeof (*mm));
  mm->vm = vm;
  mm->context_by_instance_id = hash_create (0, sizeof (uword));
}

/*
 * Get management context for an instance
 */
ovpn_mgmt_t *
ovpn_mgmt_get_by_instance (u32 instance_id)
{
  ovpn_mgmt_main_t *mm = &ovpn_mgmt_main;
  uword *p = hash_get (mm->context_by_instance_id, instance_id);
  if (!p)
    return NULL;
  return pool_elt_at_index (mm->contexts, p[0]);
}

/*
 * Enable management interface (UDP)
 */
int
ovpn_mgmt_enable (vlib_main_t *vm, u32 instance_id, const ip_address_t *bind_addr,
		  u16 bind_port, const u8 *password)
{
  ovpn_mgmt_main_t *mm = &ovpn_mgmt_main;
  vnet_listen_args_t _a, *a = &_a;
  int rv;

  /* Check if already enabled */
  if (ovpn_mgmt_get_by_instance (instance_id))
    return -1;

  /* Check if instance exists */
  ovpn_instance_t *inst = ovpn_instance_get (instance_id);
  if (!inst)
    return -2;

  /* Attach app if not already done */
  if (ovpn_mgmt_app_attach () < 0)
    return -3;

  /* Create management context */
  ovpn_mgmt_t *mgmt;
  pool_get_zero (mm->contexts, mgmt);
  mgmt->instance_id = instance_id;
  mgmt->bind_port = bind_port;
  mgmt->app_index = mm->app_index;
  mgmt->udp_session_handle = SESSION_INVALID_HANDLE;

  if (bind_addr)
    clib_memcpy (&mgmt->bind_addr, bind_addr, sizeof (*bind_addr));
  else
    {
      /* Default to 0.0.0.0 (any) */
      ip_addr_version (&mgmt->bind_addr) = AF_IP4;
      mgmt->bind_addr.ip.ip4.as_u32 = 0;
    }

  if (password)
    mgmt->password = vec_dup ((u8 *) password);

  mgmt->client_by_key = hash_create (0, sizeof (uword));

  /* Initialize history buffers */
  mgmt->log_history_size = 256;
  vec_validate (mgmt->log_history, mgmt->log_history_size - 1);

  mgmt->state_history_size = 64;
  vec_validate (mgmt->state_history, mgmt->state_history_size - 1);

  mgmt->echo_history_size = 64;
  vec_validate (mgmt->echo_history, mgmt->echo_history_size - 1);
  vec_validate (mgmt->echo_timestamps, mgmt->echo_history_size - 1);

  /* Setup listen args */
  clib_memset (a, 0, sizeof (*a));
  a->app_index = mm->app_index;

  session_endpoint_cfg_t *sep = &a->sep_ext;
  clib_memset (sep, 0, sizeof (*sep));

  /*
   * Always bind to 0.0.0.0 (any address) for UDP management interface.
   * The session layer requires the IP to be assigned to an interface,
   * but during startup the tap interface may not exist yet. Using 0.0.0.0
   * allows the session layer to accept packets on any VPP interface.
   */
  sep->is_ip4 = 1;
  sep->ip.ip4.as_u32 = 0; /* 0.0.0.0 - listen on any address */
  sep->port = clib_host_to_net_u16 (bind_port);
  sep->transport_proto = TRANSPORT_PROTO_UDP;

  rv = vnet_listen (a);
  if (rv)
    {
      hash_free (mgmt->client_by_key);
      vec_free (mgmt->log_history);
      vec_free (mgmt->state_history);
      vec_free (mgmt->echo_history);
      vec_free (mgmt->echo_timestamps);
      vec_free (mgmt->password);
      pool_put (mm->contexts, mgmt);
      return -4;
    }

  mgmt->udp_session_handle = a->handle;

  /* Add to lookup hash */
  hash_set (mm->context_by_instance_id, instance_id, mgmt - mm->contexts);

  mgmt->is_active = 1;
  mgmt->state = OVPN_MGMT_STATE_CONNECTED;

  return 0;
}

/*
 * Disable management interface
 */
int
ovpn_mgmt_disable (vlib_main_t *vm, u32 instance_id)
{
  ovpn_mgmt_main_t *mm = &ovpn_mgmt_main;
  ovpn_mgmt_t *mgmt = ovpn_mgmt_get_by_instance (instance_id);

  if (!mgmt)
    return -1;

  mgmt->is_active = 0;

  if (mgmt->type == OVPN_MGMT_TYPE_UDP)
    {
      /* Unlisten UDP */
      if (mgmt->udp_session_handle != SESSION_INVALID_HANDLE)
	{
	  vnet_unlisten_args_t _a, *a = &_a;
	  clib_memset (a, 0, sizeof (*a));
	  a->handle = mgmt->udp_session_handle;
	  a->app_index = mgmt->app_index;
	  vnet_unlisten (a);
	  mgmt->udp_session_handle = SESSION_INVALID_HANDLE;
	}

      /* Free UDP clients */
      pool_free (mgmt->clients);
      hash_free (mgmt->client_by_key);
    }
  else if (mgmt->type == OVPN_MGMT_TYPE_UNIX)
    {
      /* Close all Unix socket clients */
      ovpn_mgmt_unix_client_t *uc;
      pool_foreach (uc, mgmt->unix_clients)
	{
	  if (uc->clib_file_index != ~0)
	    clib_file_del_by_index (&file_main, uc->clib_file_index);
	  if (uc->socket)
	    {
	      clib_socket_close (uc->socket);
	      clib_mem_free (uc->socket);
	    }
	  vec_free (uc->rx_buffer);
	}
      pool_free (mgmt->unix_clients);

      /* Close listener socket */
      if (mgmt->listen_file_index != ~0)
	clib_file_del_by_index (&file_main, mgmt->listen_file_index);

      if (mgmt->listen_socket)
	{
	  clib_socket_close (mgmt->listen_socket);
	  /* Remove socket file */
	  if (mgmt->socket_path)
	    unlink ((char *) mgmt->socket_path);
	  clib_mem_free (mgmt->listen_socket);
	}
      vec_free (mgmt->socket_path);
    }

  /* Free history buffers */
  for (u32 i = 0; i < vec_len (mgmt->log_history); i++)
    vec_free (mgmt->log_history[i].message);
  vec_free (mgmt->log_history);

  for (u32 i = 0; i < vec_len (mgmt->state_history); i++)
    vec_free (mgmt->state_history[i].description);
  vec_free (mgmt->state_history);

  for (u32 i = 0; i < vec_len (mgmt->echo_history); i++)
    vec_free (mgmt->echo_history[i]);
  vec_free (mgmt->echo_history);
  vec_free (mgmt->echo_timestamps);

  vec_free (mgmt->password);

  /* Remove from hash and pool */
  hash_unset (mm->context_by_instance_id, instance_id);
  pool_put (mm->contexts, mgmt);

  return 0;
}

/*
 * CLI command: show ovpn management
 */
static clib_error_t *
show_ovpn_mgmt_command_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  ovpn_mgmt_main_t *mm = &ovpn_mgmt_main;
  ovpn_mgmt_t *mgmt;

  pool_foreach (mgmt, mm->contexts)
    {
      vlib_cli_output (vm, "Instance %u:", mgmt->instance_id);
      if (mgmt->type == OVPN_MGMT_TYPE_UDP)
	{
	  vlib_cli_output (vm, "  Type: UDP (VPP session layer)");
	  vlib_cli_output (vm, "  Address: %U:%u", format_ip_address,
			   &mgmt->bind_addr, mgmt->bind_port);
	  vlib_cli_output (vm, "  Active clients: %u",
			   pool_elts (mgmt->clients));
	}
      else if (mgmt->type == OVPN_MGMT_TYPE_UNIX)
	{
	  vlib_cli_output (vm, "  Type: Unix socket");
	  vlib_cli_output (vm, "  Socket path: %s", mgmt->socket_path);
	  vlib_cli_output (vm, "  Active clients: %u",
			   pool_elts (mgmt->unix_clients));
	}
      vlib_cli_output (vm, "  Password required: %s",
		       mgmt->password ? "yes" : "no");
      vlib_cli_output (vm, "  Hold: %s", mgmt->hold ? "yes" : "no");
      vlib_cli_output (vm, "  State: %U", format_ovpn_mgmt_state, mgmt->state);
    }

  if (pool_elts (mm->contexts) == 0)
    vlib_cli_output (vm, "No management interfaces configured");

  return 0;
}

VLIB_CLI_COMMAND (show_ovpn_mgmt_command, static) = {
  .path = "show ovpn management",
  .short_help = "show ovpn management",
  .function = show_ovpn_mgmt_command_fn,
};

/*
 * ============================================================================
 * Unix Socket Management Interface Implementation
 * ============================================================================
 */

/* Forward declarations */
static void ovpn_mgmt_unix_send_to_client (ovpn_mgmt_t *mgmt,
					   ovpn_mgmt_unix_client_t *client,
					   const u8 *data, u32 len);
static void ovpn_mgmt_unix_process_command (ovpn_mgmt_t *mgmt,
					    ovpn_mgmt_unix_client_t *client,
					    u8 *cmd);

/*
 * Send data to a Unix socket client
 */
static void
ovpn_mgmt_unix_send_to_client (ovpn_mgmt_t *mgmt,
			       ovpn_mgmt_unix_client_t *client, const u8 *data,
			       u32 len)
{
  (void) mgmt; /* Reserved for future use */

  if (!client || !client->socket || !data || len == 0)
    return;

  /* Add data to TX buffer and write */
  vec_add (client->socket->tx_buffer, data, len);
  clib_socket_tx (client->socket);
}

/*
 * Send formatted response to Unix socket client
 */
static void
ovpn_mgmt_unix_send_response (ovpn_mgmt_t *mgmt,
			      ovpn_mgmt_unix_client_t *client,
			      const char *format, ...)
{
  va_list args;
  u8 *s = 0;

  va_start (args, format);
  s = va_format (s, format, &args);
  va_end (args);

  ovpn_mgmt_unix_send_to_client (mgmt, client, s, vec_len (s));
  vec_free (s);
}

/*
 * Process command from Unix socket client
 * Reuses the same command processing logic as UDP mode
 */
static void
ovpn_mgmt_unix_process_command (ovpn_mgmt_t *mgmt,
				ovpn_mgmt_unix_client_t *client, u8 *cmd)
{
  /*
   * Create a temporary UDP-style client struct to reuse command handlers.
   * This is a bit of a hack but avoids duplicating all command handlers.
   */
  ovpn_mgmt_client_t temp_client;
  clib_memset (&temp_client, 0, sizeof (temp_client));
  temp_client.instance_id = mgmt->instance_id;
  temp_client.notify = client->notify;
  temp_client.last_activity_time = client->last_activity_time;
  temp_client.last_bytecount_time = client->last_bytecount_time;
  temp_client.authenticated = client->authenticated;

  /* We need to intercept the send function for Unix socket mode */
  /* For now, implement a simple command dispatcher inline */

  u8 **argv = 0;
  u8 *arg = 0;
  int in_quotes = 0;

  /* Parse command into argv */
  for (u8 *p = cmd; *p; p++)
    {
      if (*p == '"')
	{
	  in_quotes = !in_quotes;
	  continue;
	}
      if ((*p == ' ' || *p == '\t') && !in_quotes)
	{
	  if (vec_len (arg) > 0)
	    {
	      vec_add1 (arg, 0);
	      vec_add1 (argv, arg);
	      arg = 0;
	    }
	  continue;
	}
      vec_add1 (arg, *p);
    }
  if (vec_len (arg) > 0)
    {
      vec_add1 (arg, 0);
      vec_add1 (argv, arg);
    }

  if (vec_len (argv) == 0)
    goto cleanup;

  /* Check authentication if required */
  if (mgmt->password && !client->authenticated)
    {
      if (strcmp ((char *) argv[0], "password") != 0)
	{
	  ovpn_mgmt_unix_send_response (mgmt, client,
					"ERROR: authentication required\r\n");
	  goto cleanup;
	}
    }

  /* Simple command dispatch */
  if (!strcmp ((char *) argv[0], "help"))
    {
      ovpn_mgmt_unix_send_response (
	mgmt, client,
	"Management Interface for OpenVPN VPP Plugin (Unix socket)\r\n"
	"Commands:\r\n"
	"  bytecount n            : Show bytes in/out, update every n secs\r\n"
	"  echo [on|off]          : Turn on/off echo messages\r\n"
	"  help                   : Print this message\r\n"
	"  hold [on|off|release]  : Set/show hold flag\r\n"
	"  kill cn                : Kill client by common name\r\n"
	"  log [on|off]           : Turn on/off realtime log display\r\n"
	"  pid                    : Show process ID\r\n"
	"  state [on|off]         : Turn on/off state changes\r\n"
	"  status [n]             : Show current daemon status\r\n"
	"  version                : Show current version\r\n"
	"  password type pw       : Provide authentication password\r\n"
	"  quit                   : Close management session\r\n"
	"END\r\n");
    }
  else if (!strcmp ((char *) argv[0], "version"))
    {
      ovpn_mgmt_unix_send_response (
	mgmt, client,
	"OpenVPN Version: VPP OpenVPN Plugin 1.0 (Unix socket)\r\n"
	"Management Version: 5\r\n"
	"END\r\n");
    }
  else if (!strcmp ((char *) argv[0], "pid"))
    {
      ovpn_mgmt_unix_send_response (mgmt, client, "SUCCESS: pid=%d\r\n",
				    getpid ());
    }
  else if (!strcmp ((char *) argv[0], "state"))
    {
      if (vec_len (argv) == 1)
	{
	  f64 now = vlib_time_now (ovpn_mgmt_main.vm);
	  ovpn_mgmt_unix_send_response (mgmt, client, "%.0f,%U,SUCCESS\r\n",
					now, format_ovpn_mgmt_state,
					mgmt->state);
	  ovpn_mgmt_unix_send_response (mgmt, client, "END\r\n");
	}
      else if (!strcmp ((char *) argv[1], "on"))
	{
	  client->notify.state_enabled = 1;
	  ovpn_mgmt_unix_send_response (mgmt, client, "SUCCESS: state on\r\n");
	}
      else if (!strcmp ((char *) argv[1], "off"))
	{
	  client->notify.state_enabled = 0;
	  ovpn_mgmt_unix_send_response (mgmt, client, "SUCCESS: state off\r\n");
	}
    }
  else if (!strcmp ((char *) argv[0], "hold"))
    {
      if (vec_len (argv) == 1)
	{
	  ovpn_mgmt_unix_send_response (mgmt, client, "SUCCESS: hold=%s\r\n",
					mgmt->hold ? "1" : "0");
	}
      else if (!strcmp ((char *) argv[1], "on"))
	{
	  mgmt->hold = 1;
	  ovpn_mgmt_unix_send_response (mgmt, client, "SUCCESS: hold on\r\n");
	}
      else if (!strcmp ((char *) argv[1], "off"))
	{
	  mgmt->hold = 0;
	  ovpn_mgmt_unix_send_response (mgmt, client, "SUCCESS: hold off\r\n");
	}
      else if (!strcmp ((char *) argv[1], "release"))
	{
	  mgmt->hold = 0;
	  ovpn_mgmt_unix_send_response (mgmt, client,
					"SUCCESS: hold released\r\n");
	}
    }
  else if (!strcmp ((char *) argv[0], "log"))
    {
      if (vec_len (argv) == 1)
	{
	  ovpn_mgmt_unix_send_response (mgmt, client, "SUCCESS: log %s\r\n",
					client->notify.log_enabled ? "on"
								   : "off");
	}
      else if (!strcmp ((char *) argv[1], "on"))
	{
	  client->notify.log_enabled = 1;
	  ovpn_mgmt_unix_send_response (mgmt, client, "SUCCESS: log on\r\n");
	}
      else if (!strcmp ((char *) argv[1], "off"))
	{
	  client->notify.log_enabled = 0;
	  ovpn_mgmt_unix_send_response (mgmt, client, "SUCCESS: log off\r\n");
	}
    }
  else if (!strcmp ((char *) argv[0], "bytecount"))
    {
      if (vec_len (argv) < 2)
	{
	  ovpn_mgmt_unix_send_response (mgmt, client,
					"SUCCESS: bytecount interval=%u\r\n",
					client->notify.bytecount_interval);
	}
      else
	{
	  client->notify.bytecount_interval = atoi ((char *) argv[1]);
	  client->last_bytecount_time = vlib_time_now (ovpn_mgmt_main.vm);
	  ovpn_mgmt_unix_send_response (
	    mgmt, client, "SUCCESS: bytecount interval changed\r\n");
	}
    }
  else if (!strcmp ((char *) argv[0], "password"))
    {
      if (vec_len (argv) >= 3 && !strcmp ((char *) argv[1], "management"))
	{
	  if (mgmt->password &&
	      strcmp ((char *) argv[2], (char *) mgmt->password) == 0)
	    {
	      client->authenticated = 1;
	      ovpn_mgmt_unix_send_response (mgmt, client,
					    "SUCCESS: password is correct\r\n");
	    }
	  else
	    {
	      ovpn_mgmt_unix_send_response (
		mgmt, client, "ERROR: password is incorrect\r\n");
	    }
	}
      else
	{
	  ovpn_mgmt_unix_send_response (
	    mgmt, client, "ERROR: password: requires type and value\r\n");
	}
    }
  else if (!strcmp ((char *) argv[0], "status"))
    {
      ovpn_instance_t *inst = ovpn_instance_get (mgmt->instance_id);
      f64 now = vlib_time_now (ovpn_mgmt_main.vm);

      if (!inst)
	{
	  ovpn_mgmt_unix_send_response (mgmt, client,
					"ERROR: instance not found\r\n");
	}
      else
	{
	  ovpn_mgmt_unix_send_response (
	    mgmt, client,
	    "OpenVPN CLIENT LIST\r\nUpdated,%.0f\r\n"
	    "Common Name,Real Address,Bytes Received,Bytes Sent,Connected "
	    "Since\r\n",
	    now);

	  ovpn_peer_t *peer;
	  pool_foreach (peer, inst->multi_context.peer_db.peers)
	    {
	      if (peer->state == OVPN_PEER_STATE_DEAD ||
		  peer->state == OVPN_PEER_STATE_INITIAL)
		continue;
	      ovpn_mgmt_unix_send_response (
		mgmt, client, "peer_%u,%U:%u,%lu,%lu,%.0f\r\n", peer->peer_id,
		format_ip_address, &peer->remote_addr, peer->remote_port,
		peer->rx_bytes, peer->tx_bytes, peer->established_time);
	    }
	  ovpn_mgmt_unix_send_response (mgmt, client, "END\r\n");
	}
    }
  else if (!strcmp ((char *) argv[0], "quit") ||
	   !strcmp ((char *) argv[0], "exit"))
    {
      /* Mark for close - will be handled after this function returns */
      ovpn_mgmt_unix_send_response (mgmt, client, "SUCCESS: closing\r\n");
      client->socket->rx_end_of_file = 1;
    }
  else
    {
      ovpn_mgmt_unix_send_response (mgmt, client,
				    "ERROR: unknown command '%s'\r\n",
				    argv[0]);
    }

cleanup:
  /* Free argv */
  {
    u8 **p;
    vec_foreach (p, argv)
      vec_free (*p);
    vec_free (argv);
  }
}

/*
 * Unix socket client read callback
 * Called by VPP file event system when data is available
 */
static clib_error_t *
ovpn_mgmt_unix_client_read (clib_file_t *uf)
{
  ovpn_mgmt_main_t *mm = &ovpn_mgmt_main;
  u32 client_index = uf->private_data & 0xFFFF;
  u32 mgmt_index = uf->private_data >> 16;
  ovpn_mgmt_t *mgmt;
  ovpn_mgmt_unix_client_t *client;
  clib_error_t *err;
  f64 now = vlib_time_now (mm->vm);

  if (pool_is_free_index (mm->contexts, mgmt_index))
    return clib_error_return (0, "management context not found");

  mgmt = pool_elt_at_index (mm->contexts, mgmt_index);

  if (pool_is_free_index (mgmt->unix_clients, client_index))
    return clib_error_return (0, "unix client not found");

  client = pool_elt_at_index (mgmt->unix_clients, client_index);
  client->last_activity_time = now;

  /* Read from socket */
  err = clib_socket_rx (client->socket, 4096);
  if (err)
    {
      clib_error_free (err);
      goto close_client;
    }

  /* Check for EOF */
  if (clib_socket_rx_end_of_file (client->socket))
    goto close_client;

  /* Append to receive buffer */
  vec_append (client->rx_buffer, client->socket->rx_buffer);
  vec_reset_length (client->socket->rx_buffer);

  /* Process complete lines */
  u8 *line_start = client->rx_buffer;
  for (u32 i = 0; i < vec_len (client->rx_buffer); i++)
    {
      if (client->rx_buffer[i] == '\n')
	{
	  u32 line_end = i;
	  if (line_end > 0 && client->rx_buffer[line_end - 1] == '\r')
	    line_end--;

	  u8 *cmd = 0;
	  u32 line_len = line_end - (line_start - client->rx_buffer);
	  vec_add (cmd, line_start, line_len);
	  vec_add1 (cmd, 0);

	  ovpn_mgmt_unix_process_command (mgmt, client, cmd);
	  vec_free (cmd);

	  line_start = client->rx_buffer + i + 1;
	}
    }

  /* Remove processed data from buffer */
  if (line_start != client->rx_buffer)
    {
      u32 remaining = vec_end (client->rx_buffer) - line_start;
      if (remaining > 0)
	memmove (client->rx_buffer, line_start, remaining);
      vec_set_len (client->rx_buffer, remaining);
    }

  /* Check if we should close (quit command) */
  if (client->socket->rx_end_of_file)
    goto close_client;

  return 0;

close_client:
  /* Close and free client */
  clib_file_del (&file_main, uf);

  if (client->socket)
    {
      clib_socket_close (client->socket);
      clib_mem_free (client->socket);
    }
  vec_free (client->rx_buffer);

  pool_put (mgmt->unix_clients, client);

  return 0;
}

/*
 * Unix socket client error callback
 */
static clib_error_t *
ovpn_mgmt_unix_client_error (clib_file_t *uf)
{
  /* Treat errors as close */
  return ovpn_mgmt_unix_client_read (uf);
}

/*
 * Unix socket listener accept callback
 * Called when a new client connects to the Unix socket
 */
static clib_error_t *
ovpn_mgmt_unix_accept (clib_file_t *uf)
{
  ovpn_mgmt_main_t *mm = &ovpn_mgmt_main;
  u32 mgmt_index = uf->private_data;
  ovpn_mgmt_t *mgmt;
  ovpn_mgmt_unix_client_t *client;
  clib_socket_t *new_sock;
  clib_error_t *err;
  clib_file_t template = { 0 };
  f64 now = vlib_time_now (mm->vm);

  if (pool_is_free_index (mm->contexts, mgmt_index))
    return clib_error_return (0, "management context not found");

  mgmt = pool_elt_at_index (mm->contexts, mgmt_index);

  /* Accept new connection */
  new_sock = clib_mem_alloc (sizeof (clib_socket_t));
  clib_memset (new_sock, 0, sizeof (*new_sock));

  err = clib_socket_accept (mgmt->listen_socket, new_sock);
  if (err)
    {
      clib_mem_free (new_sock);
      return err;
    }

  /* Create client entry */
  pool_get_zero (mgmt->unix_clients, client);
  client->socket = new_sock;
  client->last_activity_time = now;
  client->authenticated = (mgmt->password == NULL);

  /* Register with file event system */
  template.read_function = ovpn_mgmt_unix_client_read;
  template.error_function = ovpn_mgmt_unix_client_error;
  template.file_descriptor = new_sock->fd;
  template.private_data = (mgmt_index << 16) | (client - mgmt->unix_clients);
  template.description =
    format (0, "ovpn-mgmt-unix-client-%u", client - mgmt->unix_clients);

  client->clib_file_index = clib_file_add (&file_main, &template);
  client->mgmt_index = mgmt_index;

  /* Send welcome banner if no password required */
  if (client->authenticated)
    {
      ovpn_mgmt_unix_send_response (mgmt, client,
				    ">INFO:OpenVPN Management Interface "
				    "Version 5 -- type 'help' for more info\r\n");
    }
  else
    {
      ovpn_mgmt_unix_send_response (
	mgmt, client, "ENTER PASSWORD:"); /* No newline - password on same line */
    }

  return 0;
}

/*
 * Enable Unix socket management interface
 */
int
ovpn_mgmt_enable_unix (vlib_main_t *vm, u32 instance_id,
		       const char *socket_path, const u8 *password)
{
  ovpn_mgmt_main_t *mm = &ovpn_mgmt_main;
  clib_socket_t *sock;
  clib_error_t *err;
  clib_file_t template = { 0 };

  /* Check if already enabled */
  if (ovpn_mgmt_get_by_instance (instance_id))
    return -1;

  /* Check if instance exists */
  ovpn_instance_t *inst = ovpn_instance_get (instance_id);
  if (!inst)
    return -2;

  /* Remove existing socket file if it exists */
  unlink (socket_path);

  /* Create listener socket */
  sock = clib_mem_alloc (sizeof (clib_socket_t));
  clib_memset (sock, 0, sizeof (*sock));

  sock->config = (char *) format (0, "%s%c", socket_path, 0);
  sock->flags = CLIB_SOCKET_F_IS_SERVER | CLIB_SOCKET_F_ALLOW_GROUP_WRITE;

  err = clib_socket_init (sock);
  if (err)
    {
      clib_error_report (err);
      clib_mem_free (sock);
      return -3;
    }

  /* Create management context */
  ovpn_mgmt_t *mgmt;
  pool_get_zero (mm->contexts, mgmt);
  mgmt->instance_id = instance_id;
  mgmt->type = OVPN_MGMT_TYPE_UNIX;
  mgmt->socket_path = vec_dup ((u8 *) socket_path);
  mgmt->listen_socket = sock;
  mgmt->udp_session_handle = SESSION_INVALID_HANDLE;

  if (password)
    mgmt->password = vec_dup ((u8 *) password);

  /* Initialize history buffers */
  mgmt->log_history_size = 256;
  vec_validate (mgmt->log_history, mgmt->log_history_size - 1);

  mgmt->state_history_size = 64;
  vec_validate (mgmt->state_history, mgmt->state_history_size - 1);

  mgmt->echo_history_size = 64;
  vec_validate (mgmt->echo_history, mgmt->echo_history_size - 1);
  vec_validate (mgmt->echo_timestamps, mgmt->echo_history_size - 1);

  /* Register listener with file event system */
  template.read_function = ovpn_mgmt_unix_accept;
  template.file_descriptor = sock->fd;
  template.private_data = mgmt - mm->contexts;
  template.description = format (0, "ovpn-mgmt-unix-listener-%s", socket_path);

  mgmt->listen_file_index = clib_file_add (&file_main, &template);

  /* Add to lookup hash */
  hash_set (mm->context_by_instance_id, instance_id, mgmt - mm->contexts);

  mgmt->is_active = 1;
  mgmt->state = OVPN_MGMT_STATE_CONNECTED;

  return 0;
}

/*
 * Send client auth request to management interface (management-client-auth)
 *
 * This sends a >CLIENT:CONNECT notification with extended environment
 * variables including username. The management client should respond
 * with client-auth or client-deny.
 */
void
ovpn_mgmt_send_client_auth_request (ovpn_mgmt_t *mgmt, u32 peer_id, u32 key_id,
				    const char *common_name,
				    const char *username,
				    const ip_address_t *remote_addr,
				    u16 remote_port)
{
  if (!mgmt || !mgmt->is_active)
    return;

  u8 *addr_str = format (0, "%U", format_ip_address, remote_addr);
  vec_add1 (addr_str, 0);

  /*
   * Send CLIENT:CONNECT notification with environment variables.
   * Format matches OpenVPN's management protocol for compatibility.
   * Note: We do NOT send the password - only username for auth decision.
   */
  ovpn_mgmt_notify (mgmt, OVPN_MGMT_NOTIFY_CLIENT,
		    ">CLIENT:CONNECT,%u,%u\r\n"
		    ">CLIENT:ENV,common_name=%s\r\n"
		    ">CLIENT:ENV,username=%s\r\n"
		    ">CLIENT:ENV,trusted_ip=%s\r\n"
		    ">CLIENT:ENV,trusted_port=%u\r\n"
		    ">CLIENT:ENV,END\r\n",
		    peer_id, key_id, common_name ? common_name : "",
		    username ? username : "", (char *) addr_str, remote_port);

  vec_free (addr_str);
}

/*
 * Process client-auth command from management
 *
 * This is called when management client sends "client-auth <cid> <kid>"
 * to approve a pending authentication. Continues the handshake and
 * establishes the connection.
 */
int
ovpn_mgmt_client_auth (u32 instance_id, u32 peer_id, u32 key_id)
{
  ovpn_instance_t *inst = ovpn_instance_get (instance_id);
  if (!inst || !inst->is_active)
    return -1; /* Instance not found */

  ovpn_peer_t *peer = ovpn_peer_get (&inst->multi_context.peer_db, peer_id);
  if (!peer)
    return -2; /* Peer not found */

  if (peer->state != OVPN_PEER_STATE_PENDING_AUTH)
    return -3; /* Not pending auth */

  if (peer->pending_auth_key_id != key_id)
    return -4; /* Key ID mismatch */

  /*
   * Auth approved - transfer username and clear pending auth data.
   * The handshake continuation will be triggered by signaling an event.
   */
  vec_free (peer->username);
  peer->username = peer->pending_auth_username;
  peer->pending_auth_username = NULL;

  /* Securely clear password */
  if (peer->pending_auth_password)
    {
      ovpn_secure_zero_memory (peer->pending_auth_password,
			       vec_len (peer->pending_auth_password));
      vec_free (peer->pending_auth_password);
    }

  /*
   * Signal the handshake to continue.
   * The handshake processing will check the state and continue
   * with cipher negotiation and key derivation.
   */
  vlib_main_t *vm = ovpn_mgmt_main.vm;
  vlib_process_signal_event_mt (vm, ovpn_periodic_node.index,
				OVPN_PROCESS_EVENT_CLIENT_AUTH,
				OVPN_ADDR_UPDATE_DATA (instance_id, peer_id));

  return 0;
}

/*
 * Process client-deny command from management
 *
 * This is called when management client sends "client-deny <cid> <kid> [reason]"
 * to reject a pending authentication. Disconnects the client.
 */
int
ovpn_mgmt_client_deny (u32 instance_id, u32 peer_id, u32 key_id,
		       const char *reason)
{
  (void) reason; /* Reserved for future use */

  ovpn_instance_t *inst = ovpn_instance_get (instance_id);
  if (!inst || !inst->is_active)
    return -1; /* Instance not found */

  ovpn_peer_t *peer = ovpn_peer_get (&inst->multi_context.peer_db, peer_id);
  if (!peer)
    return -2; /* Peer not found */

  if (peer->state != OVPN_PEER_STATE_PENDING_AUTH)
    return -3; /* Not pending auth */

  if (peer->pending_auth_key_id != key_id)
    return -4; /* Key ID mismatch */

  /* Securely clear pending auth data */
  if (peer->pending_auth_username)
    vec_free (peer->pending_auth_username);

  if (peer->pending_auth_password)
    {
      ovpn_secure_zero_memory (peer->pending_auth_password,
			       vec_len (peer->pending_auth_password));
      vec_free (peer->pending_auth_password);
    }

  /* Delete the peer with barrier sync */
  vlib_main_t *vm = ovpn_mgmt_main.vm;
  vlib_worker_thread_barrier_sync (vm);
  ovpn_peer_delete (&inst->multi_context.peer_db, peer_id);
  vlib_worker_thread_barrier_release (vm);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
