/*
 * ovpn_api.c - OpenVPN Binary API implementation
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

#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/format_fns.h>
#include <vnet/ip/ip_types_api.h>
#include <vlibapi/api.h>

#include <ovpn/ovpn.api_enum.h>
#include <ovpn/ovpn.api_types.h>

#include <ovpn/ovpn.h>
#include <ovpn/ovpn_if.h>
#include <ovpn/ovpn_mgmt.h>

#define REPLY_MSG_ID_BASE omp->msg_id_base
#include <vlibapi/api_helper_macros.h>

/*
 * Peer event registration structure
 */
typedef struct ovpn_peer_event_registration_t_
{
  u32 client_index;
  u32 client_pid;
  u32 instance_id; /* ~0 for all instances */
} ovpn_peer_event_registration_t;

typedef struct
{
  u16 msg_id_base;

  /* Pool of peer event registrations */
  ovpn_peer_event_registration_t *peer_event_registrations;

  /* Hash: client_index -> pool index in peer_event_registrations */
  uword *peer_event_registration_by_client;

} ovpn_api_main_t;

static ovpn_api_main_t ovpn_api_main;

/*
 * Handler for ovpn_interface_create
 */
static void
vl_api_ovpn_interface_create_t_handler (vl_api_ovpn_interface_create_t *mp)
{
  vl_api_ovpn_interface_create_reply_t *rmp;
  ovpn_api_main_t *omp = &ovpn_api_main;
  ovpn_main_t *om = &ovpn_main;
  ip_address_t local_addr;
  ovpn_options_t options;
  u32 instance_id = ~0;
  u32 sw_if_index = ~0;
  int rv = 0;

  /* Initialize options */
  ovpn_options_init (&options);

  /* Decode local address */
  ip_address_decode2 (&mp->local_addr, &local_addr);

  /* Set device name if provided */
  if (mp->dev_name[0] != 0)
    {
      /* mp->dev_name is a fixed-size array, use format to create a vec */
      options.dev_name = (char *) format (0, "%s", mp->dev_name);
    }

  /* Set TUN/TAP mode (default is TUN) */
  options.is_tun = mp->is_tun;

  /* Network options */
  options.mtu = clib_net_to_host_u16 (mp->mtu);
  options.mssfix = clib_net_to_host_u16 (mp->mssfix);
  options.fragment_size = clib_net_to_host_u16 (mp->fragment_size);

  /* Timing options */
  options.keepalive_ping = clib_net_to_host_u32 (mp->keepalive_ping);
  options.keepalive_timeout = clib_net_to_host_u32 (mp->keepalive_timeout);
  options.renegotiate_seconds = clib_net_to_host_u32 (mp->renegotiate_seconds);
  options.handshake_window = clib_net_to_host_u32 (mp->handshake_window);

  /* Replay protection */
  options.replay_window = clib_net_to_host_u32 (mp->replay_window);
  options.replay_time = clib_net_to_host_u32 (mp->replay_time);
  options.replay_protection = (options.replay_window > 0) ? 1 : 0;

  /* Client pool */
  options.max_clients = clib_net_to_host_u32 (mp->max_clients);
  ip_address_decode2 (&mp->pool_start, &options.pool_start);
  ip_address_decode2 (&mp->pool_end, &options.pool_end);
  options.client_to_client = mp->client_to_client;

  /* Cipher options */
  if (mp->cipher_name[0] != 0)
    options.cipher_name = (u8 *) format (0, "%s%c", mp->cipher_name, 0);

  if (mp->data_ciphers[0] != 0)
    ovpn_options_set_data_ciphers (&options, (char *) mp->data_ciphers);

  /* Handle crypto mode */
  switch (mp->crypto_mode)
    {
    case OVPN_CRYPTO_MODE_STATIC_KEY:
      {
	/* Allocate and copy static key */
	options.static_key = clib_mem_alloc (OVPN_STATIC_KEY_SIZE);
	clib_memcpy (options.static_key, mp->static_key, OVPN_STATIC_KEY_SIZE);
	options.static_key_direction = mp->static_key_direction;
	options.static_key_mode = 1;
      }
      break;

    case OVPN_CRYPTO_MODE_TLS:
    case OVPN_CRYPTO_MODE_TLS_AUTH:
    case OVPN_CRYPTO_MODE_TLS_CRYPT:
      {
	/* Parse variable-length certificates and keys */
	u8 *ptr = mp->certs_and_keys;
	u32 ca_len = clib_net_to_host_u32 (mp->ca_cert_len);
	u32 cert_len = clib_net_to_host_u32 (mp->server_cert_len);
	u32 key_len = clib_net_to_host_u32 (mp->server_key_len);
	u32 dh_len = clib_net_to_host_u32 (mp->dh_params_len);
	u32 tls_auth_len = clib_net_to_host_u32 (mp->tls_auth_key_len);
	u32 tls_crypt_len = clib_net_to_host_u32 (mp->tls_crypt_key_len);
	u32 tls_crypt_v2_len = clib_net_to_host_u32 (mp->tls_crypt_v2_key_len);
	u32 crl_len = clib_net_to_host_u32 (mp->crl_len);

	if (ca_len > 0)
	  {
	    vec_validate (options.ca_cert, ca_len - 1);
	    clib_memcpy (options.ca_cert, ptr, ca_len);
	    ptr += ca_len;
	  }

	if (cert_len > 0)
	  {
	    vec_validate (options.server_cert, cert_len - 1);
	    clib_memcpy (options.server_cert, ptr, cert_len);
	    ptr += cert_len;
	  }

	if (key_len > 0)
	  {
	    vec_validate (options.server_key, key_len - 1);
	    clib_memcpy (options.server_key, ptr, key_len);
	    ptr += key_len;
	  }

	if (dh_len > 0)
	  {
	    vec_validate (options.dh_params, dh_len - 1);
	    clib_memcpy (options.dh_params, ptr, dh_len);
	    ptr += dh_len;
	  }

	if (mp->crypto_mode == OVPN_CRYPTO_MODE_TLS_AUTH && tls_auth_len > 0)
	  {
	    vec_validate (options.tls_auth_key, tls_auth_len - 1);
	    clib_memcpy (options.tls_auth_key, ptr, tls_auth_len);
	    ptr += tls_auth_len;
	  }

	if (mp->crypto_mode == OVPN_CRYPTO_MODE_TLS_CRYPT && tls_crypt_len > 0)
	  {
	    vec_validate (options.tls_crypt_key, tls_crypt_len - 1);
	    clib_memcpy (options.tls_crypt_key, ptr, tls_crypt_len);
	    ptr += tls_crypt_len;
	  }

	if (tls_crypt_v2_len > 0)
	  {
	    vec_validate (options.tls_crypt_v2_key, tls_crypt_v2_len - 1);
	    clib_memcpy (options.tls_crypt_v2_key, ptr, tls_crypt_v2_len);
	    ptr += tls_crypt_v2_len;
	  }

	if (crl_len > 0)
	  {
	    vec_validate (options.crl_file, crl_len - 1);
	    clib_memcpy (options.crl_file, ptr, crl_len);
	    ptr += crl_len;
	  }
      }
      break;

    default:
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto done;
    }

  /* Create the instance */
  rv = ovpn_instance_create (
    om->vm, &local_addr, clib_net_to_host_u16 (mp->local_port),
    clib_net_to_host_u32 (mp->table_id), &options, &instance_id, &sw_if_index);

done:
  /* Free options memory on failure */
  if (rv != 0)
    {
      vec_free (options.dev_name);
      vec_free (options.ca_cert);
      vec_free (options.server_cert);
      vec_free (options.server_key);
      vec_free (options.dh_params);
      vec_free (options.tls_auth_key);
      vec_free (options.tls_crypt_key);
      vec_free (options.tls_crypt_v2_key);
      vec_free (options.crl_file);
      vec_free (options.cipher_name);
      ovpn_options_free_dynamic (&options);
      if (options.static_key)
	clib_mem_free (options.static_key);
    }

  REPLY_MACRO2 (VL_API_OVPN_INTERFACE_CREATE_REPLY, ({
		  rmp->sw_if_index = clib_host_to_net_u32 (sw_if_index);
		  rmp->instance_id = clib_host_to_net_u32 (instance_id);
		}));
}

/*
 * Handler for ovpn_interface_delete
 */
static void
vl_api_ovpn_interface_delete_t_handler (vl_api_ovpn_interface_delete_t *mp)
{
  vl_api_ovpn_interface_delete_reply_t *rmp;
  ovpn_api_main_t *omp = &ovpn_api_main;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  rv = ovpn_instance_delete (vlib_get_main (),
			     clib_net_to_host_u32 (mp->sw_if_index));

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_OVPN_INTERFACE_DELETE_REPLY);
}

/*
 * Walk context for interface dump
 */
typedef struct ovpn_interface_dump_ctx_t_
{
  vl_api_registration_t *reg;
  u32 context;
} ovpn_interface_dump_ctx_t;

/*
 * Send interface details
 */
static void
ovpn_send_interface_details (ovpn_instance_t *instance,
			     ovpn_interface_dump_ctx_t *ctx)
{
  vl_api_ovpn_interface_details_t *rmp;
  ovpn_api_main_t *omp = &ovpn_api_main;

  rmp = vl_msg_api_alloc_zero (sizeof (*rmp));
  rmp->_vl_msg_id =
    clib_host_to_net_u16 (VL_API_OVPN_INTERFACE_DETAILS + omp->msg_id_base);
  rmp->context = ctx->context;

  /* Fill interface details */
  rmp->interface.sw_if_index = clib_host_to_net_u32 (instance->sw_if_index);
  rmp->interface.instance_id = clib_host_to_net_u32 (instance->instance_id);
  ip_address_encode2 (&instance->local_addr, &rmp->interface.local_addr);
  rmp->interface.local_port = clib_host_to_net_u16 (instance->local_port);
  rmp->interface.table_id = clib_host_to_net_u32 (instance->fib_table_id);

  /* Determine crypto mode */
  if (instance->options.static_key_mode)
    rmp->interface.crypto_mode = OVPN_CRYPTO_MODE_STATIC_KEY;
  else if (instance->tls_crypt.enabled)
    rmp->interface.crypto_mode = OVPN_CRYPTO_MODE_TLS_CRYPT;
  else if (instance->tls_auth.enabled)
    rmp->interface.crypto_mode = OVPN_CRYPTO_MODE_TLS_AUTH;
  else
    rmp->interface.crypto_mode = OVPN_CRYPTO_MODE_TLS;

  /* Copy device name */
  if (instance->options.dev_name)
    {
      strncpy ((char *) rmp->interface.dev_name, instance->options.dev_name,
	       sizeof (rmp->interface.dev_name) - 1);
    }

  /* TUN/TAP mode */
  rmp->interface.is_tun = instance->options.is_tun;

  /* Network options */
  rmp->interface.mtu = clib_host_to_net_u16 (instance->options.mtu);
  rmp->interface.mssfix = clib_host_to_net_u16 (instance->options.mssfix);
  rmp->interface.fragment_size =
    clib_host_to_net_u16 (instance->options.fragment_size);

  /* Timing options */
  rmp->interface.keepalive_ping =
    clib_host_to_net_u32 (instance->options.keepalive_ping);
  rmp->interface.keepalive_timeout =
    clib_host_to_net_u32 (instance->options.keepalive_timeout);
  rmp->interface.renegotiate_seconds =
    clib_host_to_net_u32 (instance->options.renegotiate_seconds);

  /* Client options */
  rmp->interface.max_clients =
    clib_host_to_net_u32 (instance->options.max_clients);
  ip_address_encode2 (&instance->options.pool_start,
		      &rmp->interface.pool_start);
  ip_address_encode2 (&instance->options.pool_end, &rmp->interface.pool_end);
  rmp->interface.client_to_client = instance->options.client_to_client;

  /* Cipher name */
  if (instance->options.cipher_name)
    {
      strncpy ((char *) rmp->interface.cipher_name,
	       (char *) instance->options.cipher_name,
	       sizeof (rmp->interface.cipher_name) - 1);
    }

  /* Count peers */
  rmp->num_peers =
    clib_host_to_net_u32 (pool_elts (instance->multi_context.peer_db.peers));

  vl_api_send_msg (ctx->reg, (u8 *) rmp);
}

/*
 * Handler for ovpn_interface_dump
 */
static void
vl_api_ovpn_interface_dump_t_handler (vl_api_ovpn_interface_dump_t *mp)
{
  vl_api_registration_t *reg;
  ovpn_main_t *om = &ovpn_main;
  ovpn_instance_t *instance;
  u32 sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (reg == NULL)
    return;

  ovpn_interface_dump_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);

  if (sw_if_index == ~0)
    {
      /* Dump all instances */
      pool_foreach (instance, om->instances)
	{
	  if (instance->is_active)
	    ovpn_send_interface_details (instance, &ctx);
	}
    }
  else
    {
      /* Dump specific instance */
      instance = ovpn_instance_get_by_sw_if_index (sw_if_index);
      if (instance && instance->is_active)
	ovpn_send_interface_details (instance, &ctx);
    }
}

/*
 * Walk context for peer dump
 */
typedef struct ovpn_peer_dump_ctx_t_
{
  vl_api_registration_t *reg;
  u32 context;
  u32 instance_id;
} ovpn_peer_dump_ctx_t;

/*
 * Send peer details
 */
static void
ovpn_send_peer_details (ovpn_peer_t *peer, u32 instance_id,
			ovpn_peer_dump_ctx_t *ctx)
{
  vl_api_ovpn_peers_details_t *rmp;
  ovpn_api_main_t *omp = &ovpn_api_main;

  rmp = vl_msg_api_alloc_zero (sizeof (*rmp));
  rmp->_vl_msg_id =
    clib_host_to_net_u16 (VL_API_OVPN_PEERS_DETAILS + omp->msg_id_base);
  rmp->context = ctx->context;

  /* Fill peer details */
  rmp->peer.peer_id = clib_host_to_net_u32 (peer->peer_id);
  rmp->peer.instance_id = clib_host_to_net_u32 (instance_id);
  rmp->peer.sw_if_index = clib_host_to_net_u32 (peer->sw_if_index);
  ip_address_encode2 (&peer->remote_addr, &rmp->peer.remote_addr);
  rmp->peer.remote_port = clib_host_to_net_u16 (peer->remote_port);

  if (peer->virtual_ip_set)
    ip_address_encode2 (&peer->virtual_ip, &rmp->peer.virtual_ip);

  rmp->peer.state = (vl_api_ovpn_api_peer_state_t) peer->state;
  rmp->peer.rx_bytes = clib_host_to_net_u64 (peer->rx_bytes);
  rmp->peer.tx_bytes = clib_host_to_net_u64 (peer->tx_bytes);
  rmp->peer.rx_packets = clib_host_to_net_u64 (peer->rx_packets);
  rmp->peer.tx_packets = clib_host_to_net_u64 (peer->tx_packets);
  rmp->peer.established_time = peer->established_time;
  rmp->peer.last_rx_time = peer->last_rx_time;

  vl_api_send_msg (ctx->reg, (u8 *) rmp);
}

/*
 * Handler for ovpn_peers_dump
 */
static void
vl_api_ovpn_peers_dump_t_handler (vl_api_ovpn_peers_dump_t *mp)
{
  vl_api_registration_t *reg;
  ovpn_main_t *om = &ovpn_main;
  ovpn_instance_t *instance;
  ovpn_peer_t *peer;
  u32 sw_if_index;
  u32 peer_id;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (reg == NULL)
    return;

  ovpn_peer_dump_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  peer_id = clib_net_to_host_u32 (mp->peer_id);

  if (sw_if_index == ~0)
    {
      /* Dump peers from all instances */
      pool_foreach (instance, om->instances)
	{
	  if (!instance->is_active)
	    continue;

	  ctx.instance_id = instance->instance_id;

	  if (peer_id == ~0)
	    {
	      /* All peers in this instance */
	      pool_foreach (peer, instance->multi_context.peer_db.peers)
		{
		  if (peer->state != OVPN_PEER_STATE_DEAD)
		    ovpn_send_peer_details (peer, instance->instance_id, &ctx);
		}
	    }
	  else
	    {
	      /* Specific peer */
	      peer = ovpn_peer_get (&instance->multi_context.peer_db, peer_id);
	      if (peer && peer->state != OVPN_PEER_STATE_DEAD)
		ovpn_send_peer_details (peer, instance->instance_id, &ctx);
	    }
	}
    }
  else
    {
      /* Dump peers from specific instance */
      instance = ovpn_instance_get_by_sw_if_index (sw_if_index);
      if (instance && instance->is_active)
	{
	  ctx.instance_id = instance->instance_id;

	  if (peer_id == ~0)
	    {
	      /* All peers */
	      pool_foreach (peer, instance->multi_context.peer_db.peers)
		{
		  if (peer->state != OVPN_PEER_STATE_DEAD)
		    ovpn_send_peer_details (peer, instance->instance_id, &ctx);
		}
	    }
	  else
	    {
	      /* Specific peer */
	      peer = ovpn_peer_get (&instance->multi_context.peer_db, peer_id);
	      if (peer && peer->state != OVPN_PEER_STATE_DEAD)
		ovpn_send_peer_details (peer, instance->instance_id, &ctx);
	    }
	}
    }
}

/*
 * Handler for ovpn_peer_remove
 */
static void
vl_api_ovpn_peer_remove_t_handler (vl_api_ovpn_peer_remove_t *mp)
{
  vl_api_ovpn_peer_remove_reply_t *rmp;
  ovpn_api_main_t *omp = &ovpn_api_main;
  ovpn_main_t *om = &ovpn_main;
  ovpn_instance_t *instance;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  u32 sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  u32 peer_id = clib_net_to_host_u32 (mp->peer_id);

  instance = ovpn_instance_get_by_sw_if_index (sw_if_index);
  if (!instance || !instance->is_active)
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto done;
    }

  /* Use worker barrier for safe peer deletion */
  vlib_worker_thread_barrier_sync (om->vm);
  ovpn_peer_delete (&instance->multi_context.peer_db, peer_id);
  vlib_worker_thread_barrier_release (om->vm);

done:
  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_OVPN_PEER_REMOVE_REPLY);
}

/*
 * Handler for ovpn_mgmt_enable_tcp
 */
static void
vl_api_ovpn_mgmt_enable_tcp_t_handler (vl_api_ovpn_mgmt_enable_tcp_t *mp)
{
  vl_api_ovpn_mgmt_enable_tcp_reply_t *rmp;
  ovpn_api_main_t *omp = &ovpn_api_main;
  ip_address_t bind_addr;
  u8 *password = NULL;
  int rv = 0;

  u32 instance_id = clib_net_to_host_u32 (mp->instance_id);
  u16 bind_port = clib_net_to_host_u16 (mp->bind_port);

  ip_address_decode2 (&mp->bind_addr, &bind_addr);

  /* Extract password if provided */
  if (mp->password[0] != 0)
    password = (u8 *) mp->password;

  rv = ovpn_mgmt_enable_tcp (vlib_get_main (), instance_id, &bind_addr,
			     bind_port, password);

  REPLY_MACRO (VL_API_OVPN_MGMT_ENABLE_TCP_REPLY);
}

/*
 * Handler for ovpn_mgmt_enable_unix
 * Enables Unix socket management interface for an OpenVPN instance.
 */
static void
vl_api_ovpn_mgmt_enable_unix_t_handler (vl_api_ovpn_mgmt_enable_unix_t *mp)
{
  vl_api_ovpn_mgmt_enable_unix_reply_t *rmp;
  ovpn_api_main_t *omp = &ovpn_api_main;
  int rv;

  u32 instance_id = clib_net_to_host_u32 (mp->instance_id);
  u8 *password = NULL;

  if (mp->password[0] != 0)
    password = (u8 *) mp->password;

  rv = ovpn_mgmt_enable_unix (vlib_get_main (), instance_id,
			      (const char *) mp->socket_path, password);

  REPLY_MACRO (VL_API_OVPN_MGMT_ENABLE_UNIX_REPLY);
}

/*
 * Handler for ovpn_mgmt_disable
 */
static void
vl_api_ovpn_mgmt_disable_t_handler (vl_api_ovpn_mgmt_disable_t *mp)
{
  vl_api_ovpn_mgmt_disable_reply_t *rmp;
  ovpn_api_main_t *omp = &ovpn_api_main;
  int rv = 0;

  u32 instance_id = clib_net_to_host_u32 (mp->instance_id);

  rv = ovpn_mgmt_disable (vlib_get_main (), instance_id);

  REPLY_MACRO (VL_API_OVPN_MGMT_DISABLE_REPLY);
}

/*
 * Walk context for management dump
 */
typedef struct ovpn_mgmt_dump_ctx_t_
{
  vl_api_registration_t *reg;
  u32 context;
} ovpn_mgmt_dump_ctx_t;

/*
 * Send management details
 */
static void
ovpn_send_mgmt_details (ovpn_mgmt_t *mgmt, ovpn_mgmt_dump_ctx_t *ctx)
{
  vl_api_ovpn_mgmt_details_t *rmp;
  ovpn_api_main_t *omp = &ovpn_api_main;

  rmp = vl_msg_api_alloc_zero (sizeof (*rmp));
  rmp->_vl_msg_id =
    clib_host_to_net_u16 (VL_API_OVPN_MGMT_DETAILS + omp->msg_id_base);
  rmp->context = ctx->context;

  rmp->status.instance_id = clib_host_to_net_u32 (mgmt->instance_id);
  ip_address_encode2 (&mgmt->bind_addr, &rmp->status.bind_addr);
  rmp->status.bind_port = clib_host_to_net_u16 (mgmt->bind_port);
  rmp->status.num_clients = clib_host_to_net_u32 (pool_elts (mgmt->clients));
  rmp->status.password_required = (mgmt->password != NULL);
  rmp->status.hold = mgmt->hold;

  vl_api_send_msg (ctx->reg, (u8 *) rmp);
}

/*
 * Handler for ovpn_mgmt_dump
 */
static void
vl_api_ovpn_mgmt_dump_t_handler (vl_api_ovpn_mgmt_dump_t *mp)
{
  vl_api_registration_t *reg;
  ovpn_mgmt_main_t *mm = &ovpn_mgmt_main;
  ovpn_mgmt_t *mgmt;
  u32 instance_id;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (reg == NULL)
    return;

  ovpn_mgmt_dump_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };

  instance_id = clib_net_to_host_u32 (mp->instance_id);

  if (instance_id == ~0)
    {
      /* Dump all management interfaces */
      pool_foreach (mgmt, mm->contexts)
	{
	  if (mgmt->is_active)
	    ovpn_send_mgmt_details (mgmt, &ctx);
	}
    }
  else
    {
      /* Dump specific instance */
      mgmt = ovpn_mgmt_get_by_instance (instance_id);
      if (mgmt && mgmt->is_active)
	ovpn_send_mgmt_details (mgmt, &ctx);
    }
}

/*
 * Handler for want_ovpn_peer_events
 */
static void
vl_api_want_ovpn_peer_events_t_handler (vl_api_want_ovpn_peer_events_t *mp)
{
  vl_api_want_ovpn_peer_events_reply_t *rmp;
  ovpn_api_main_t *omp = &ovpn_api_main;
  ovpn_peer_event_registration_t *reg;
  uword *p;
  int rv = 0;

  u32 client_index = mp->client_index;
  u32 pid = clib_net_to_host_u32 (mp->pid);
  u32 instance_id = clib_net_to_host_u32 (mp->instance_id);

  p = hash_get (omp->peer_event_registration_by_client, client_index);

  if (mp->enable_disable)
    {
      /* Register for events */
      if (p)
	{
	  /* Already registered, update instance filter */
	  reg = pool_elt_at_index (omp->peer_event_registrations, p[0]);
	  reg->instance_id = instance_id;
	  reg->client_pid = pid;
	}
      else
	{
	  /* New registration */
	  pool_get (omp->peer_event_registrations, reg);
	  clib_memset (reg, 0, sizeof (*reg));
	  reg->client_index = client_index;
	  reg->client_pid = pid;
	  reg->instance_id = instance_id;
	  hash_set (omp->peer_event_registration_by_client, client_index,
		    reg - omp->peer_event_registrations);
	}
    }
  else
    {
      /* Unregister */
      if (p)
	{
	  reg = pool_elt_at_index (omp->peer_event_registrations, p[0]);
	  hash_unset (omp->peer_event_registration_by_client, client_index);
	  pool_put (omp->peer_event_registrations, reg);
	}
      /* else: not registered, ignore */
    }

  REPLY_MACRO (VL_API_WANT_OVPN_PEER_EVENTS_REPLY);
}

/*
 * Send peer event notification to all registered clients
 */
void
ovpn_api_send_peer_event (u32 instance_id, ovpn_peer_t *peer, u8 event_type)
{
  ovpn_api_main_t *omp = &ovpn_api_main;
  ovpn_peer_event_registration_t *reg;
  vl_api_registration_t *vl_reg;
  vl_api_ovpn_peer_event_t *mp;

  pool_foreach (reg, omp->peer_event_registrations)
    {
      /* Check instance filter */
      if (reg->instance_id != ~0 && reg->instance_id != instance_id)
	continue;

      vl_reg = vl_api_client_index_to_registration (reg->client_index);
      if (!vl_reg)
	continue;

      mp = vl_msg_api_alloc (sizeof (*mp));
      clib_memset (mp, 0, sizeof (*mp));
      mp->_vl_msg_id =
	clib_host_to_net_u16 (VL_API_OVPN_PEER_EVENT + omp->msg_id_base);

      mp->client_index = reg->client_index;
      mp->pid = clib_host_to_net_u32 (reg->client_pid);
      mp->event_type = event_type;
      mp->instance_id = clib_host_to_net_u32 (instance_id);
      mp->peer_id = clib_host_to_net_u32 (peer->peer_id);

      ip_address_encode2 (&peer->remote_addr, &mp->remote_addr);
      mp->remote_port = clib_host_to_net_u16 (peer->remote_port);

      if (peer->virtual_ip_set)
	ip_address_encode2 (&peer->virtual_ip, &mp->virtual_addr);

      /* Copy common name if available */
      if (peer->tls_ctx && peer->tls_ctx->client_common_name)
	{
	  strncpy ((char *) mp->common_name, peer->tls_ctx->client_common_name,
		   sizeof (mp->common_name) - 1);
	}

      mp->bytes_received = clib_host_to_net_u64 (peer->rx_bytes);
      mp->bytes_sent = clib_host_to_net_u64 (peer->tx_bytes);

      vl_api_send_msg (vl_reg, (u8 *) mp);
    }
}

/* Setup API message handlers */
#include <ovpn/ovpn.api.c>

static clib_error_t *
ovpn_api_hookup (vlib_main_t *vm)
{
  ovpn_api_main_t *omp = &ovpn_api_main;
  omp->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (ovpn_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
