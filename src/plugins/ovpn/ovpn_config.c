/*
 * ovpn_config.c - OpenVPN configuration file parser
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

#include <ovpn/ovpn_config.h>
#include <ovpn/ovpn.h>
#include <vppinfra/unix.h>
#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#include <sys/stat.h>
#include <libgen.h>

/*
 * Initialize configuration to default values
 */
void
ovpn_config_init (ovpn_parsed_config_t *config)
{
  clib_memset (config, 0, sizeof (*config));

  /* Network defaults */
  config->local_port = 1194;
  config->table_id = 0;

  /* Option defaults */
  config->options.mtu = 1500;
  config->options.is_tun = 1;
  config->options.proto = IP_PROTOCOL_UDP;
  config->options.sw_if_index = ~0;

  /* Timing defaults */
  config->options.keepalive_ping = 10;
  config->options.keepalive_timeout = 120;
  config->options.handshake_window = 60;
  config->options.renegotiate_seconds = 3600;
  config->options.transition_window = 3600;
  config->options.tls_timeout = 2;

  /* Replay protection defaults */
  config->options.replay_protection = 1;
  config->options.replay_window = 64;
  config->options.replay_time = 15;

  /* Client defaults */
  config->options.max_clients = 1024;
}

/*
 * Free parsed configuration
 */
void
ovpn_config_free (ovpn_parsed_config_t *config)
{
  vec_free (config->instance_name);
  vec_free (config->options.dev_name);
  vec_free (config->options.ca_cert);
  vec_free (config->options.server_cert);
  vec_free (config->options.server_key);
  vec_free (config->options.dh_params);
  vec_free (config->options.cipher_name);
  vec_free (config->options.auth_name);
  vec_free (config->options.tls_crypt_key);
  vec_free (config->options.tls_crypt_v2_key);
  vec_free (config->options.tls_auth_key);
  vec_free (config->options.crl_file);

  if (config->options.static_key)
    clib_mem_free (config->options.static_key);

  /* Free dynamic options (push, dhcp, ciphers, routes) */
  ovpn_options_free_dynamic (&config->options);

  vec_free (config->ca_file);
  vec_free (config->cert_file);
  vec_free (config->key_file);
  vec_free (config->dh_file);
  vec_free (config->tls_crypt_file);
  vec_free (config->tls_crypt_v2_file);
  vec_free (config->tls_auth_file);
  vec_free (config->secret_file);
  vec_free (config->crl_file);

  clib_memset (config, 0, sizeof (*config));
}

/*
 * Helper: resolve relative path to absolute
 */
static char *
resolve_path (const char *path, const char *base_dir)
{
  char *result;

  if (!path)
    return NULL;

  /* If path is absolute, use it directly */
  if (path[0] == '/')
    {
      result = (char *) vec_dup ((u8 *) path);
      vec_add1 (result, 0);
      return result;
    }

  /* If we have a base directory, combine them */
  if (base_dir)
    {
      result = (char *) format (0, "%s/%s%c", base_dir, path, 0);
      return result;
    }

  /* Otherwise, assume current directory */
  result = (char *) vec_dup ((u8 *) path);
  vec_add1 (result, 0);
  return result;
}

/*
 * Helper: read file contents
 */
static clib_error_t *
read_file_contents (const char *file_path, u8 **result)
{
  clib_error_t *error;

  if (!file_path)
    return clib_error_return (0, "file path is NULL");

  error = clib_file_contents ((char *) file_path, result);
  if (error)
    return clib_error_return (0, "failed to read file '%s': %U", file_path,
			      format_clib_error, error);

  return 0;
}

/*
 * Helper: skip whitespace and comments
 */
static u8 *
skip_whitespace_and_comments (u8 *p, u8 *end)
{
  while (p < end)
    {
      /* Skip whitespace */
      while (p < end && (*p == ' ' || *p == '\t'))
	p++;

      /* Check for comment */
      if (p < end && (*p == '#' || *p == ';'))
	{
	  /* Skip to end of line */
	  while (p < end && *p != '\n')
	    p++;
	  if (p < end)
	    p++; /* Skip newline */
	  continue;
	}

      break;
    }
  return p;
}

/*
 * Helper: parse a single line/option
 */
static clib_error_t *
parse_option (u8 *line_start, u8 *line_end, const char *base_dir,
	      ovpn_parsed_config_t *config)
{
  unformat_input_t input;
  u8 *line;
  u32 u32_val;
  u8 *str_val = NULL;
  u8 *str_val2 = NULL;
  ip4_address_t ip4_addr, ip4_mask;
  ip6_address_t ip6_addr;

  /* Create null-terminated copy of the line */
  line = vec_new (u8, line_end - line_start + 1);
  clib_memcpy (line, line_start, line_end - line_start);
  line[line_end - line_start] = 0;

  unformat_init_string (&input, (char *) line, vec_len (line) - 1);

  /* Parse options */
  if (unformat (&input, "local %U", unformat_ip4_address, &ip4_addr))
    {
      ip_address_set (&config->local_addr, &ip4_addr, AF_IP4);
    }
  else if (unformat (&input, "port %u", &u32_val))
    {
      config->local_port = (u16) u32_val;
    }
  else if (unformat (&input, "lport %u", &u32_val))
    {
      config->local_port = (u16) u32_val;
    }
  else if (unformat (&input, "dev %s", &str_val))
    {
      vec_free (config->options.dev_name);
      config->options.dev_name = (char *) str_val;
      str_val = NULL;
    }
  else if (unformat (&input, "dev-type tun"))
    {
      config->options.is_tun = 1;
    }
  else if (unformat (&input, "dev-type tap"))
    {
      config->options.is_tun = 0;
    }
  else if (unformat (&input, "proto udp6"))
    {
      config->options.proto = IP_PROTOCOL_UDP;
    }
  else if (unformat (&input, "proto udp4"))
    {
      config->options.proto = IP_PROTOCOL_UDP;
    }
  else if (unformat (&input, "proto udp"))
    {
      config->options.proto = IP_PROTOCOL_UDP;
    }
  else if (unformat (&input, "server %U %U", unformat_ip4_address, &ip4_addr,
		     unformat_ip4_address, &ip4_mask))
    {
      config->server_network = ip4_addr;
      config->server_netmask = ip4_mask;
      config->server_mode = 1;
    }
  else if (unformat (&input, "ifconfig-pool %U %U", unformat_ip4_address,
		     &config->options.pool_start.ip.ip4, unformat_ip4_address,
		     &config->options.pool_end.ip.ip4))
    {
      config->options.pool_start.version = AF_IP4;
      config->options.pool_end.version = AF_IP4;
    }
  else if (unformat (&input, "max-clients %u", &u32_val))
    {
      config->options.max_clients = u32_val;
    }
  else if (unformat (&input, "ca %s", &str_val))
    {
      vec_free (config->ca_file);
      config->ca_file = resolve_path ((char *) str_val, base_dir);
      vec_free (str_val);
    }
  else if (unformat (&input, "crl-verify %s", &str_val))
    {
      vec_free (config->crl_file);
      config->crl_file = resolve_path ((char *) str_val, base_dir);
      vec_free (str_val);
    }
  else if (unformat (&input, "cert %s", &str_val))
    {
      vec_free (config->cert_file);
      config->cert_file = resolve_path ((char *) str_val, base_dir);
      vec_free (str_val);
    }
  else if (unformat (&input, "key %s", &str_val))
    {
      vec_free (config->key_file);
      config->key_file = resolve_path ((char *) str_val, base_dir);
      vec_free (str_val);
    }
  else if (unformat (&input, "dh %s", &str_val))
    {
      vec_free (config->dh_file);
      config->dh_file = resolve_path ((char *) str_val, base_dir);
      vec_free (str_val);
    }
  else if (unformat (&input, "tls-crypt-v2 %s", &str_val))
    {
      vec_free (config->tls_crypt_v2_file);
      config->tls_crypt_v2_file = resolve_path ((char *) str_val, base_dir);
      vec_free (str_val);
    }
  else if (unformat (&input, "tls-crypt %s", &str_val))
    {
      vec_free (config->tls_crypt_file);
      config->tls_crypt_file = resolve_path ((char *) str_val, base_dir);
      vec_free (str_val);
    }
  else if (unformat (&input, "tls-auth %s %u", &str_val, &u32_val))
    {
      vec_free (config->tls_auth_file);
      config->tls_auth_file = resolve_path ((char *) str_val, base_dir);
      config->tls_auth_direction = (u8) u32_val;
      vec_free (str_val);
    }
  else if (unformat (&input, "tls-auth %s", &str_val))
    {
      vec_free (config->tls_auth_file);
      config->tls_auth_file = resolve_path ((char *) str_val, base_dir);
      config->tls_auth_direction = 0;
      vec_free (str_val);
    }
  else if (unformat (&input, "secret %s %u", &str_val, &u32_val))
    {
      vec_free (config->secret_file);
      config->secret_file = resolve_path ((char *) str_val, base_dir);
      config->secret_direction = (u8) u32_val;
      config->options.static_key_mode = 1;
      vec_free (str_val);
    }
  else if (unformat (&input, "secret %s", &str_val))
    {
      vec_free (config->secret_file);
      config->secret_file = resolve_path ((char *) str_val, base_dir);
      config->secret_direction = 0;
      config->options.static_key_mode = 1;
      vec_free (str_val);
    }
  else if (unformat (&input, "cipher %s", &str_val))
    {
      vec_free (config->options.cipher_name);
      config->options.cipher_name = str_val;
      str_val = NULL;
    }
  else if (unformat (&input, "auth %s", &str_val))
    {
      vec_free (config->options.auth_name);
      config->options.auth_name = str_val;
      str_val = NULL;
    }
  else if (unformat (&input, "keepalive %u %u",
		     &config->options.keepalive_ping,
		     &config->options.keepalive_timeout))
    {
      /* Already parsed */
    }
  else if (unformat (&input, "ping %u", &u32_val))
    {
      config->options.keepalive_ping = u32_val;
    }
  else if (unformat (&input, "ping-exit %u", &u32_val))
    {
      config->options.keepalive_timeout = u32_val;
    }
  else if (unformat (&input, "ping-restart %u", &u32_val))
    {
      config->options.keepalive_timeout = u32_val;
    }
  else if (unformat (&input, "tun-mtu %u", &u32_val))
    {
      config->options.mtu = (u16) u32_val;
    }
  else if (unformat (&input, "link-mtu %u", &u32_val))
    {
      /* We use tun-mtu primarily, but accept link-mtu */
    }
  else if (unformat (&input, "mssfix %u", &u32_val))
    {
      /* MSS clamping to avoid tunnel fragmentation */
      config->options.mssfix = (u16) u32_val;
    }
  else if (unformat (&input, "mssfix"))
    {
      /* Default mssfix value (1450 is typical for OpenVPN) */
      config->options.mssfix = 1450;
    }
  else if (unformat (&input, "fragment %u", &u32_val))
    {
      /* OpenVPN fragmentation - fragment packets larger than this */
      config->options.fragment_size = (u16) u32_val;
    }
  else if (unformat (&input, "reneg-sec %u", &u32_val))
    {
      config->options.renegotiate_seconds = u32_val;
    }
  else if (unformat (&input, "reneg-bytes %lu",
		     &config->options.renegotiate_bytes))
    {
      /* Already parsed */
    }
  else if (unformat (&input, "reneg-pkts %lu",
		     &config->options.renegotiate_packets))
    {
      /* Already parsed */
    }
  else if (unformat (&input, "hand-window %u", &u32_val))
    {
      config->options.handshake_window = u32_val;
    }
  else if (unformat (&input, "tran-window %u", &u32_val))
    {
      config->options.transition_window = u32_val;
    }
  else if (unformat (&input, "tls-timeout %u", &u32_val))
    {
      config->options.tls_timeout = u32_val;
    }
  else if (unformat (&input, "replay-window %u %u",
		     &config->options.replay_window,
		     &config->options.replay_time))
    {
      config->options.replay_protection = 1;
    }
  else if (unformat (&input, "replay-window %u", &u32_val))
    {
      config->options.replay_window = u32_val;
      config->options.replay_protection = 1;
    }
  else if (unformat (&input, "no-replay"))
    {
      config->options.replay_protection = 0;
    }
  else if (unformat (&input, "table-id %u", &u32_val))
    {
      config->table_id = u32_val;
    }
  /* Ignore these common options that don't affect VPP */
  else if (unformat (&input, "topology %s", &str_val))
    {
      vec_free (str_val);
    }
  else if (unformat (&input, "persist-key"))
    {
    }
  else if (unformat (&input, "persist-tun"))
    {
    }
  else if (unformat (&input, "verb %u", &u32_val))
    {
    }
  else if (unformat (&input, "mute %u", &u32_val))
    {
    }
  else if (unformat (&input, "status %s", &str_val))
    {
      vec_free (str_val);
    }
  else if (unformat (&input, "log %s", &str_val))
    {
      vec_free (str_val);
    }
  else if (unformat (&input, "log-append %s", &str_val))
    {
      vec_free (str_val);
    }
  else if (unformat (&input, "user %s", &str_val))
    {
      vec_free (str_val);
    }
  else if (unformat (&input, "group %s", &str_val))
    {
      vec_free (str_val);
    }
  else if (unformat (&input, "daemon"))
    {
    }
  else if (unformat (&input, "client-to-client"))
    {
      config->options.client_to_client = 1;
    }
  else if (unformat (&input, "duplicate-cn"))
    {
      config->options.duplicate_cn = 1;
    }
  else if (unformat (&input, "float"))
    {
      config->options.float_enabled = 1;
    }
  /*
   * Management interface options (UDP only via VPP session layer)
   */
  else if (unformat (&input, "management %U %u %s", unformat_ip_address,
		     &config->options.management_ip,
		     &config->options.management_port, &str_val))
    {
      /* management IP port [pw-file] */
      config->options.management_enabled = 1;
      /* Read password from file */
      if (str_val)
	{
	  u8 *pw = 0;
	  clib_error_t *err = read_file_contents ((char *) str_val, &pw);
	  if (!err && pw)
	    {
	      /* Remove trailing newline */
	      while (vec_len (pw) > 0 &&
		     (pw[vec_len (pw) - 1] == '\n' ||
		      pw[vec_len (pw) - 1] == '\r'))
		vec_dec_len (pw, 1);
	      vec_add1 (pw, 0);
	      config->options.management_password = pw;
	    }
	  else if (err)
	    clib_error_free (err);
	  vec_free (str_val);
	}
    }
  else if (unformat (&input, "management %U %u", unformat_ip_address,
		     &config->options.management_ip,
		     &config->options.management_port))
    {
      /* management IP port */
      config->options.management_enabled = 1;
    }
  else if (unformat (&input, "management-hold"))
    {
      config->options.management_hold = 1;
    }
  else if (unformat (&input, "management-log-cache %u", &u32_val))
    {
      config->options.management_log_cache = u32_val;
    }
  else if (unformat (&input, "management-client"))
    {
      config->options.management_client = 1;
    }
  else if (unformat (&input, "management-up-down"))
    {
      config->options.management_up_down = 1;
    }
  else if (unformat (&input, "management-query-passwords"))
    {
      config->options.management_query_passwords = 1;
    }
  else if (unformat (&input, "management-query-remote"))
    {
      /* Ignored - not applicable to VPP server mode */
    }
  else if (unformat (&input, "management-query-proxy"))
    {
      /* Ignored - not applicable to VPP server mode */
    }
  else if (unformat (&input, "management-forget-disconnect"))
    {
      /* Ignored - not applicable to VPP */
    }
  else if (unformat (&input, "management-signal"))
    {
      /* Ignored - not applicable to VPP */
    }
  else if (unformat (&input, "duplicate-cn"))
    {
    }
  else if (unformat (&input, "comp-lzo"))
    {
      /* Compression not supported */
    }
  else if (unformat (&input, "compress"))
    {
      /* Compression not supported */
    }
  else if (unformat (&input, "push"))
    {
      /*
       * Push directive: push "option value"
       * The rest of the line (after "push ") is the option to push
       */
      u8 *rest = 0;
      if (unformat (&input, " \"%v\"", &rest) ||
	  unformat (&input, " %v", &rest))
	{
	  /* Remove any trailing whitespace/newline */
	  while (vec_len (rest) > 0 && (rest[vec_len (rest) - 1] == ' ' ||
					rest[vec_len (rest) - 1] == '\t' ||
					rest[vec_len (rest) - 1] == '\n' ||
					rest[vec_len (rest) - 1] == '\r' ||
					rest[vec_len (rest) - 1] == '"'))
	    {
	      vec_dec_len (rest, 1);
	    }
	  vec_add1 (rest, 0);
	  ovpn_options_add_push (&config->options, (char *) rest);
	  vec_free (rest);
	}
    }
  else if (unformat (&input, "dhcp-option DNS %U", unformat_ip4_address,
		     &ip4_addr))
    {
      ip_address_t dns_ip;
      ip_address_set (&dns_ip, &ip4_addr, AF_IP4);
      ovpn_options_add_dns (&config->options, &dns_ip);
    }
  else if (unformat (&input, "dhcp-option DNS6 %U", unformat_ip6_address,
		     &ip6_addr))
    {
      ip_address_t dns_ip;
      ip_address_set (&dns_ip, &ip6_addr, AF_IP6);
      ovpn_options_add_dns (&config->options, &dns_ip);
    }
  else if (unformat (&input, "dhcp-option WINS %U", unformat_ip4_address,
		     &ip4_addr))
    {
      ip_address_t wins_ip;
      ip_address_set (&wins_ip, &ip4_addr, AF_IP4);
      ovpn_options_add_dhcp_option (&config->options, OVPN_DHCP_OPTION_WINS,
				    &wins_ip);
    }
  else if (unformat (&input, "dhcp-option DOMAIN %s", &str_val))
    {
      ovpn_options_set_domain (&config->options, (char *) str_val);
      vec_free (str_val);
    }
  else if (unformat (&input, "dhcp-option DOMAIN-SEARCH %s", &str_val))
    {
      ovpn_options_add_dhcp_option (&config->options,
				    OVPN_DHCP_OPTION_DOMAIN_SEARCH, str_val);
      vec_free (str_val);
    }
  else if (unformat (&input, "dhcp-option NTP %U", unformat_ip4_address,
		     &ip4_addr))
    {
      ip_address_t ntp_ip;
      ip_address_set (&ntp_ip, &ip4_addr, AF_IP4);
      ovpn_options_add_dhcp_option (&config->options, OVPN_DHCP_OPTION_NTP,
				    &ntp_ip);
    }
  else if (unformat (&input, "dhcp-option DISABLE-NBT"))
    {
      u8 dummy = 0;
      ovpn_options_add_dhcp_option (&config->options,
				    OVPN_DHCP_OPTION_DISABLE_NBT, &dummy);
    }
  else if (unformat (&input, "route %U %U", unformat_ip4_address, &ip4_addr,
		     unformat_ip4_address, &ip4_mask))
    {
      /* Parse route to push to clients */
      fib_prefix_t route;
      clib_memset (&route, 0, sizeof (route));
      route.fp_proto = FIB_PROTOCOL_IP4;
      route.fp_addr.ip4 = ip4_addr;
      route.fp_len = ip4_mask_to_preflen (&ip4_mask);
      ovpn_options_add_push_route (&config->options, &route);
    }
  else if (unformat (&input, "redirect-gateway"))
    {
      config->options.redirect_gateway = 1;
      /* Parse optional flags */
      if (unformat (&input, "def1"))
	config->options.redirect_gateway_flags |= 0x01;
      if (unformat (&input, "local"))
	config->options.redirect_gateway_flags |= 0x02;
      if (unformat (&input, "autolocal"))
	config->options.redirect_gateway_flags |= 0x04;
      if (unformat (&input, "bypass-dhcp"))
	config->options.redirect_gateway_flags |= 0x08;
      if (unformat (&input, "bypass-dns"))
	config->options.redirect_gateway_flags |= 0x10;
    }
  else if (unformat (&input, "client-to-client"))
    {
      config->options.client_to_client = 1;
    }
  else if (unformat (&input, "duplicate-cn"))
    {
      config->options.duplicate_cn = 1;
    }
  else if (unformat (&input, "float"))
    {
      config->options.float_enabled = 1;
    }
  /* Username/Password authentication via static file or management interface */
  else if (unformat (&input, "auth-user-pass-verify %s via-file", &str_val) ||
	   unformat (&input, "auth-user-pass-verify %s", &str_val))
    {
      /* Deprecated: script-based auth removed, use management-client-auth */
      vec_free (str_val);
      clib_warning ("ovpn: auth-user-pass-verify script is deprecated, "
		    "use management-client-auth instead");
    }
  else if (unformat (&input, "management-client-auth"))
    {
      config->options.management_client_auth = 1;
      config->options.auth_user_pass_required = 1;
    }
  else if (unformat (&input, "auth-user-pass-file %s", &str_val))
    {
      /* VPP-specific: static password file (username:password per line) */
      vec_free (config->options.auth_user_pass_file);
      config->options.auth_user_pass_file = str_val;
      config->options.auth_user_pass_required = 1;
      str_val = NULL;
    }
  else if (unformat (&input, "auth-user-pass-optional"))
    {
      config->options.auth_user_pass_optional = 1;
    }
  else if (unformat (&input, "client-config-dir %s", &str_val))
    {
      vec_free (str_val);
    }
  else if (unformat (&input, "ccd-exclusive"))
    {
      config->options.ccd_exclusive = 1;
    }
  else if (unformat (&input, "ifconfig-pool-persist %s %u", &str_val,
		     &config->options.ifconfig_pool_persist_seconds))
    {
      vec_free (config->options.ifconfig_pool_persist_file);
      config->options.ifconfig_pool_persist_file = str_val;
      str_val = NULL;
    }
  else if (unformat (&input, "ifconfig-pool-persist %s", &str_val))
    {
      vec_free (config->options.ifconfig_pool_persist_file);
      config->options.ifconfig_pool_persist_file = str_val;
      config->options.ifconfig_pool_persist_seconds = 0; /* Save on change */
      str_val = NULL;
    }
  else if (unformat (&input, "explicit-exit-notify"))
    {
    }
  /* Check data-ciphers-fallback BEFORE data-ciphers to avoid prefix matching */
  else if (unformat (&input, "data-ciphers-fallback %s", &str_val))
    {
      vec_free (config->options.data_ciphers_fallback);
      config->options.data_ciphers_fallback = str_val;
      str_val = NULL;
    }
  else if (unformat (&input, "data-ciphers %s", &str_val))
    {
      /* Parse data-ciphers list (colon or comma separated) */
      ovpn_options_set_data_ciphers (&config->options, (char *) str_val);

      /* Also set cipher_name to first cipher for backwards compatibility */
      if (!config->options.cipher_name && config->options.n_data_ciphers > 0)
	{
	  config->options.cipher_name =
	    (u8 *) format (0, "%s%c", config->options.data_ciphers[0], 0);
	}
      vec_free (str_val);
    }
  else if (unformat (&input, "ncp-ciphers %s", &str_val))
    {
      /* ncp-ciphers is deprecated alias for data-ciphers */
      ovpn_options_set_data_ciphers (&config->options, (char *) str_val);
      vec_free (str_val);
    }
  else if (unformat (&input, "tls-version-min %s", &str_val))
    {
      vec_free (str_val);
    }
  else if (unformat (&input, "tls-cipher %s", &str_val))
    {
      vec_free (str_val);
    }
  else if (unformat (&input, "remote-cert-tls %s", &str_val))
    {
      vec_free (str_val);
    }
  else if (unformat (&input, "verify-x509-name %s %s", &str_val, &str_val2))
    {
      /* verify-x509-name name type */
      config->options.verify_x509_name = str_val;
      if (!strcmp ((char *) str_val2, "name-prefix"))
	config->options.verify_x509_type = OVPN_X509_VERIFY_NAME_PREFIX;
      else if (!strcmp ((char *) str_val2, "subject"))
	config->options.verify_x509_type = OVPN_X509_VERIFY_SUBJECT;
      else
	config->options.verify_x509_type = OVPN_X509_VERIFY_NAME;
      vec_free (str_val2);
      str_val = NULL; /* Don't free, stored in options */
    }
  else if (unformat (&input, "verify-x509-name %s", &str_val))
    {
      /* verify-x509-name name (default type=name) */
      config->options.verify_x509_name = str_val;
      config->options.verify_x509_type = OVPN_X509_VERIFY_NAME;
      str_val = NULL; /* Don't free, stored in options */
    }
  /* Skip empty lines */
  else if (unformat (&input, ""))
    {
    }
  else
    {
      /* Unknown option - log but don't fail */
      clib_warning ("ovpn config: ignoring unknown option: %s", line);
    }

  vec_free (str_val);
  vec_free (line);
  unformat_free (&input);

  return 0;
}

/*
 * Parse OpenVPN configuration from buffer
 */
clib_error_t *
ovpn_config_parse_buffer (const u8 *config_data, u32 config_len,
			  const char *base_dir, ovpn_parsed_config_t *config)
{
  clib_error_t *error = NULL;
  u8 *p, *end, *line_start;

  if (!config_data || config_len == 0)
    return clib_error_return (0, "empty configuration");

  ovpn_config_init (config);

  p = (u8 *) config_data;
  end = p + config_len;

  while (p < end)
    {
      /* Skip whitespace and comments */
      p = skip_whitespace_and_comments (p, end);
      if (p >= end)
	break;

      /* Find start of option */
      line_start = p;

      /* Find end of line */
      while (p < end && *p != '\n' && *p != '\r')
	p++;

      /* Skip trailing whitespace */
      u8 *line_end = p;
      while (line_end > line_start &&
	     (*(line_end - 1) == ' ' || *(line_end - 1) == '\t'))
	line_end--;

      /* Parse the option if line is not empty */
      if (line_end > line_start)
	{
	  error = parse_option (line_start, line_end, base_dir, config);
	  if (error)
	    goto done;
	}

      /* Skip newline */
      if (p < end && (*p == '\n' || *p == '\r'))
	{
	  p++;
	  /* Handle \r\n */
	  if (p < end && p[-1] == '\r' && *p == '\n')
	    p++;
	}
    }

  /* Setup server mode IP pool if server directive was used */
  clib_warning ("ovpn config: server_mode=%d", config->server_mode);
  if (config->server_mode)
    {
      /* OpenVPN server mode: server 10.8.0.0 255.255.255.0
       * Server gets .1, clients get .2 onwards
       */
      u32 network = clib_net_to_host_u32 (config->server_network.as_u32);
      u32 mask = clib_net_to_host_u32 (config->server_netmask.as_u32);
      u32 host_bits = ~mask;

      /* Server address is network + 1 */
      ip4_address_t server_ip;
      server_ip.as_u32 = clib_host_to_net_u32 (network + 1);

      /* Set local address if not already set */
      if (ip_address_is_zero (&config->local_addr))
	{
	  ip_address_set (&config->local_addr, &server_ip, AF_IP4);
	}

      /* Setup pool from .2 to .254 (or end of subnet) */
      if (config->options.pool_start.version == 0)
	{
	  config->options.pool_start.version = AF_IP4;
	  config->options.pool_start.ip.ip4.as_u32 =
	    clib_host_to_net_u32 (network + 2);

	  config->options.pool_end.version = AF_IP4;
	  u32 pool_end = (network | host_bits) - 1;
	  if (pool_end > network + 253)
	    pool_end = network + 253;
	  config->options.pool_end.ip.ip4.as_u32 =
	    clib_host_to_net_u32 (pool_end);

	  clib_warning (
	    "ovpn config: server mode pool setup: start.version=%d, "
	    "start=0x%x, end=0x%x",
	    config->options.pool_start.version,
	    clib_net_to_host_u32 (config->options.pool_start.ip.ip4.as_u32),
	    clib_net_to_host_u32 (config->options.pool_end.ip.ip4.as_u32));
	}
    }

  config->is_valid = 1;

done:
  if (error)
    {
      ovpn_config_free (config);
    }
  return error;
}

/*
 * Parse OpenVPN configuration file
 */
clib_error_t *
ovpn_config_parse_file (const char *file_path, ovpn_parsed_config_t *config)
{
  clib_error_t *error = NULL;
  u8 *config_data = NULL;
  char *base_dir = NULL;
  char *path_copy = NULL;

  if (!file_path)
    return clib_error_return (0, "file path is NULL");

  /* Read file contents */
  error = read_file_contents (file_path, &config_data);
  if (error)
    return error;

  /* Get base directory for relative paths */
  path_copy = (char *) format (0, "%s%c", file_path, 0);
  base_dir = dirname (path_copy);

  /* Parse the configuration */
  error = ovpn_config_parse_buffer (config_data, vec_len (config_data),
				    base_dir, config);

  vec_free (config_data);
  vec_free (path_copy);

  return error;
}

/*
 * Load certificate/key files referenced in configuration
 */
clib_error_t *
ovpn_config_load_files (ovpn_parsed_config_t *config)
{
  clib_error_t *error = NULL;

  /* Load CA certificate */
  if (config->ca_file)
    {
      error = read_file_contents (config->ca_file, &config->options.ca_cert);
      if (error)
	return clib_error_return (0, "failed to load CA cert '%s': %U",
				  config->ca_file, format_clib_error, error);
    }

  /* Load CRL file if specified */
  if (config->crl_file)
    {
      error = read_file_contents (config->crl_file, &config->options.crl_file);
      if (error)
	return clib_error_return (0, "failed to load CRL '%s': %U",
				  config->crl_file, format_clib_error, error);
    }

  /* Load server certificate */
  if (config->cert_file)
    {
      error =
	read_file_contents (config->cert_file, &config->options.server_cert);
      if (error)
	return clib_error_return (0, "failed to load server cert '%s': %U",
				  config->cert_file, format_clib_error, error);
    }

  /* Load server private key */
  if (config->key_file)
    {
      error =
	read_file_contents (config->key_file, &config->options.server_key);
      if (error)
	return clib_error_return (0, "failed to load server key '%s': %U",
				  config->key_file, format_clib_error, error);
    }

  /* Load DH parameters */
  if (config->dh_file)
    {
      error = read_file_contents (config->dh_file, &config->options.dh_params);
      if (error)
	return clib_error_return (0, "failed to load DH params '%s': %U",
				  config->dh_file, format_clib_error, error);
    }

  /* Load TLS-Crypt key */
  if (config->tls_crypt_file)
    {
      error = read_file_contents (config->tls_crypt_file,
				  &config->options.tls_crypt_key);
      if (error)
	return clib_error_return (0, "failed to load TLS-Crypt key '%s': %U",
				  config->tls_crypt_file, format_clib_error,
				  error);
    }

  /* Load TLS-Crypt-V2 key */
  if (config->tls_crypt_v2_file)
    {
      error = read_file_contents (config->tls_crypt_v2_file,
				  &config->options.tls_crypt_v2_key);
      if (error)
	return clib_error_return (
	  0, "failed to load TLS-Crypt-V2 key '%s': %U",
	  config->tls_crypt_v2_file, format_clib_error, error);
    }

  /* Load TLS-Auth key */
  if (config->tls_auth_file)
    {
      error = read_file_contents (config->tls_auth_file,
				  &config->options.tls_auth_key);
      if (error)
	return clib_error_return (0, "failed to load TLS-Auth key '%s': %U",
				  config->tls_auth_file, format_clib_error,
				  error);
    }

  /* Load static key */
  if (config->secret_file)
    {
      u8 *key_data = NULL;
      error = read_file_contents (config->secret_file, &key_data);
      if (error)
	return clib_error_return (0, "failed to load static key '%s': %U",
				  config->secret_file, format_clib_error,
				  error);

      /* Allocate and parse static key */
      config->options.static_key = clib_mem_alloc (OVPN_STATIC_KEY_SIZE);
      if (!config->options.static_key)
	{
	  vec_free (key_data);
	  return clib_error_return (0, "failed to allocate static key");
	}

      int rv = ovpn_parse_static_key (key_data, vec_len (key_data),
				      config->options.static_key);
      vec_free (key_data);

      if (rv < 0)
	{
	  clib_mem_free (config->options.static_key);
	  config->options.static_key = NULL;
	  return clib_error_return (0, "failed to parse static key: %d", rv);
	}

      config->options.static_key_direction = config->secret_direction;
    }

  return 0;
}

/*
 * Create OpenVPN instance from parsed configuration
 */
int
ovpn_config_create_instance (vlib_main_t *vm, ovpn_parsed_config_t *config,
			     u32 *instance_id_out, u32 *sw_if_index_out)
{
  if (!config->is_valid)
    return VNET_API_ERROR_INVALID_VALUE;

  /* Validate required fields */
  if (ip_address_is_zero (&config->local_addr))
    {
      clib_warning ("ovpn config: local address required");
      return VNET_API_ERROR_INVALID_VALUE;
    }

  /* Create the instance */
  return ovpn_instance_create (vm, &config->local_addr, config->local_port,
			       config->table_id, &config->options,
			       instance_id_out, sw_if_index_out);
}

/*
 * Helper: Create instance from config and handle cleanup
 */
static int
ovpn_config_create_and_cleanup (vlib_main_t *vm, ovpn_parsed_config_t *config,
				const char *source_name)
{
  clib_error_t *error = NULL;
  u32 instance_id = ~0;
  u32 sw_if_index = ~0;
  int rv;
  const char *display_name;

  /* Determine display name for logging */
  if (config->instance_name)
    display_name = config->instance_name;
  else if (source_name)
    display_name = source_name;
  else
    display_name = "unnamed";

  /* Load referenced files */
  error = ovpn_config_load_files (config);
  if (error)
    {
      clib_warning ("ovpn [%s]: failed to load files: %U", display_name,
		    format_clib_error, error);
      clib_error_free (error);
      ovpn_config_free (config);
      return -1;
    }

  /* Create the instance */
  rv = ovpn_config_create_instance (vm, config, &instance_id, &sw_if_index);
  if (rv != 0)
    {
      clib_warning ("ovpn [%s]: failed to create instance: %d", display_name,
		    rv);
      ovpn_config_free (config);
      return rv;
    }

  clib_warning ("ovpn [%s]: created instance %u (interface %s)", display_name,
		instance_id,
		config->options.dev_name ? config->options.dev_name : "ovpnX");

  /* Free config file paths (options were transferred to instance) */
  vec_free (config->instance_name);
  vec_free (config->ca_file);
  vec_free (config->cert_file);
  vec_free (config->key_file);
  vec_free (config->dh_file);
  vec_free (config->tls_crypt_file);
  vec_free (config->tls_crypt_v2_file);
  vec_free (config->tls_auth_file);
  vec_free (config->secret_file);
  vec_free (config->crl_file);

  return 0;
}

/*
 * Parse inline instance configuration from startup.conf
 */
static clib_error_t *
ovpn_parse_inline_instance (vlib_main_t *vm, const char *instance_name,
			    unformat_input_t *input)
{
  clib_error_t *error = NULL;
  ovpn_parsed_config_t config;
  u8 *str_val = NULL;
  u32 u32_val;
  ip4_address_t ip4_addr, ip4_mask;
  u8 *config_file = NULL;

  ovpn_config_init (&config);

  /* Set instance name if provided */
  if (instance_name)
    {
      config.instance_name = (char *) format (0, "%s%c", instance_name, 0);
    }

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      /* Instance name can also be set inside the block */
      if (unformat (input, "name %s", &str_val))
	{
	  vec_free (config.instance_name);
	  config.instance_name = (char *) str_val;
	  str_val = NULL;
	}
      /* Allow loading from config file within instance block */
      else if (unformat (input, "config %s", &config_file))
	{
	  /* Parse external config file first */
	  error = ovpn_config_parse_file ((char *) config_file, &config);
	  if (error)
	    {
	      vec_free (config_file);
	      return error;
	    }
	  vec_free (config_file);
	}
      /* Network options */
      else if (unformat (input, "local %U", unformat_ip4_address, &ip4_addr))
	{
	  ip_address_set (&config.local_addr, &ip4_addr, AF_IP4);
	}
      else if (unformat (input, "port %u", &u32_val))
	{
	  config.local_port = (u16) u32_val;
	}
      /* dev-type must be checked before "dev %s" to avoid partial match */
      else if (unformat (input, "dev-type tun"))
	{
	  config.options.is_tun = 1;
	}
      else if (unformat (input, "dev-type tap"))
	{
	  config.options.is_tun = 0;
	}
      else if (unformat (input, "dev %s", &str_val))
	{
	  vec_free (config.options.dev_name);
	  config.options.dev_name = (char *) str_val;
	  str_val = NULL;
	}
      /* Server mode */
      else if (unformat (input, "server %U %U", unformat_ip4_address,
			 &ip4_addr, unformat_ip4_address, &ip4_mask))
	{
	  config.server_network = ip4_addr;
	  config.server_netmask = ip4_mask;
	  config.server_mode = 1;
	}
      else if (unformat (input, "ifconfig-pool %U %U", unformat_ip4_address,
			 &config.options.pool_start.ip.ip4,
			 unformat_ip4_address,
			 &config.options.pool_end.ip.ip4))
	{
	  config.options.pool_start.version = AF_IP4;
	  config.options.pool_end.version = AF_IP4;
	}
      /* TLS/Key files */
      else if (unformat (input, "ca %s", &str_val))
	{
	  vec_free (config.ca_file);
	  config.ca_file = (char *) str_val;
	  str_val = NULL;
	}
      else if (unformat (input, "crl-verify %s", &str_val))
	{
	  vec_free (config.crl_file);
	  config.crl_file = (char *) str_val;
	  str_val = NULL;
	}
      else if (unformat (input, "cert %s", &str_val))
	{
	  vec_free (config.cert_file);
	  config.cert_file = (char *) str_val;
	  str_val = NULL;
	}
      else if (unformat (input, "key %s", &str_val))
	{
	  vec_free (config.key_file);
	  config.key_file = (char *) str_val;
	  str_val = NULL;
	}
      else if (unformat (input, "tls-crypt-v2 %s", &str_val))
	{
	  vec_free (config.tls_crypt_v2_file);
	  config.tls_crypt_v2_file = (char *) str_val;
	  str_val = NULL;
	}
      else if (unformat (input, "tls-crypt %s", &str_val))
	{
	  vec_free (config.tls_crypt_file);
	  config.tls_crypt_file = (char *) str_val;
	  str_val = NULL;
	}
      else if (unformat (input, "tls-auth %s %u", &str_val, &u32_val))
	{
	  vec_free (config.tls_auth_file);
	  config.tls_auth_file = (char *) str_val;
	  config.tls_auth_direction = (u8) u32_val;
	  str_val = NULL;
	}
      else if (unformat (input, "tls-auth %s", &str_val))
	{
	  vec_free (config.tls_auth_file);
	  config.tls_auth_file = (char *) str_val;
	  config.tls_auth_direction = 0;
	  str_val = NULL;
	}
      else if (unformat (input, "secret %s %u", &str_val, &u32_val))
	{
	  vec_free (config.secret_file);
	  config.secret_file = (char *) str_val;
	  config.secret_direction = (u8) u32_val;
	  config.options.static_key_mode = 1;
	  str_val = NULL;
	}
      else if (unformat (input, "secret %s", &str_val))
	{
	  vec_free (config.secret_file);
	  config.secret_file = (char *) str_val;
	  config.secret_direction = 0;
	  config.options.static_key_mode = 1;
	  str_val = NULL;
	}
      /* Cipher */
      else if (unformat (input, "cipher %s", &str_val))
	{
	  vec_free (config.options.cipher_name);
	  config.options.cipher_name = str_val;
	  str_val = NULL;
	}
      /* Timers */
      else if (unformat (input, "keepalive %u %u",
			 &config.options.keepalive_ping,
			 &config.options.keepalive_timeout))
	{
	}
      else if (unformat (input, "tun-mtu %u", &u32_val))
	{
	  config.options.mtu = (u16) u32_val;
	}
      else if (unformat (input, "mssfix %u", &u32_val))
	{
	  config.options.mssfix = (u16) u32_val;
	}
      else if (unformat (input, "mssfix"))
	{
	  config.options.mssfix = 1450;
	}
      else if (unformat (input, "fragment %u", &u32_val))
	{
	  config.options.fragment_size = (u16) u32_val;
	}
      else if (unformat (input, "reneg-sec %u", &u32_val))
	{
	  config.options.renegotiate_seconds = u32_val;
	}
      /* VPP specific */
      else if (unformat (input, "table-id %u", &u32_val))
	{
	  config.table_id = u32_val;
	}
      else if (unformat (input, "max-clients %u", &u32_val))
	{
	  config.options.max_clients = u32_val;
	}
      /* Push options - handle quoted strings */
      else if (unformat (input, "push"))
	{
	  /*
	   * Try to parse: push "option value" or push option
	   * VPP's unformat doesn't handle quotes well, so we use %v
	   */
	  if (unformat (input, " \"%v\"", &str_val) ||
	      unformat (input, " %s", &str_val))
	    {
	      /* Null-terminate the vector */
	      vec_add1 (str_val, 0);
	      ovpn_options_add_push (&config.options, (char *) str_val);
	      vec_free (str_val);
	    }
	}
      /* DHCP options */
      else if (unformat (input, "dhcp-option DNS %U", unformat_ip4_address,
			 &ip4_addr))
	{
	  ip_address_t dns_ip;
	  ip_address_set (&dns_ip, &ip4_addr, AF_IP4);
	  ovpn_options_add_dns (&config.options, &dns_ip);
	}
      else if (unformat (input, "dhcp-option DOMAIN %s", &str_val))
	{
	  ovpn_options_set_domain (&config.options, (char *) str_val);
	  vec_free (str_val);
	}
      else if (unformat (input, "dhcp-option WINS %U", unformat_ip4_address,
			 &ip4_addr))
	{
	  ip_address_t wins_ip;
	  ip_address_set (&wins_ip, &ip4_addr, AF_IP4);
	  ovpn_options_add_dhcp_option (&config.options, OVPN_DHCP_OPTION_WINS,
					&wins_ip);
	}
      /* Route options */
      else if (unformat (input, "route %U %U", unformat_ip4_address, &ip4_addr,
			 unformat_ip4_address, &ip4_mask))
	{
	  fib_prefix_t route;
	  clib_memset (&route, 0, sizeof (route));
	  route.fp_proto = FIB_PROTOCOL_IP4;
	  route.fp_addr.ip4 = ip4_addr;
	  route.fp_len = ip4_mask_to_preflen (&ip4_mask);
	  ovpn_options_add_push_route (&config.options, &route);
	}
      else if (unformat (input, "redirect-gateway"))
	{
	  config.options.redirect_gateway = 1;
	}
      /* Data ciphers - check data-ciphers-fallback BEFORE data-ciphers
       * to avoid prefix matching issue where "data-ciphers" matches
       * the beginning of "data-ciphers-fallback" */
      else if (unformat (input, "data-ciphers-fallback %s", &str_val))
	{
	  vec_free (config.options.data_ciphers_fallback);
	  config.options.data_ciphers_fallback = str_val;
	  str_val = NULL;
	}
      else if (unformat (input, "data-ciphers %s", &str_val))
	{
	  ovpn_options_set_data_ciphers (&config.options, (char *) str_val);
	  if (!config.options.cipher_name && config.options.n_data_ciphers > 0)
	    {
	      config.options.cipher_name =
		(u8 *) format (0, "%s%c", config.options.data_ciphers[0], 0);
	    }
	  vec_free (str_val);
	}
      /* Client-to-client */
      else if (unformat (input, "client-to-client"))
	{
	  config.options.client_to_client = 1;
	}
      /* Duplicate CN */
      else if (unformat (input, "duplicate-cn"))
	{
	  config.options.duplicate_cn = 1;
	}
      /* Float */
      else if (unformat (input, "float"))
	{
	  config.options.float_enabled = 1;
	}
      /* Management interface (UDP via VPP session layer) */
      else if (unformat (input, "management %U %u", unformat_ip4_address,
			 &ip4_addr, &u32_val))
	{
	  ip_address_set (&config.options.management_ip, &ip4_addr, AF_IP4);
	  config.options.management_port = (u16) u32_val;
	  config.options.management_enabled = 1;
	}
      /* Username/Password authentication */
      else if (unformat (input, "auth-user-pass-verify %s", &str_val))
	{
	  /* Deprecated: script-based auth removed */
	  vec_free (str_val);
	  clib_warning ("ovpn: auth-user-pass-verify script is deprecated, "
			"use management-client-auth instead");
	}
      else if (unformat (input, "management-client-auth"))
	{
	  config.options.management_client_auth = 1;
	  config.options.auth_user_pass_required = 1;
	}
      else if (unformat (input, "auth-user-pass-file %s", &str_val))
	{
	  vec_free (config.options.auth_user_pass_file);
	  config.options.auth_user_pass_file = str_val;
	  config.options.auth_user_pass_required = 1;
	  str_val = NULL;
	}
      else if (unformat (input, "auth-user-pass-optional"))
	{
	  config.options.auth_user_pass_optional = 1;
	}
      else
	{
	  error = clib_error_return (0, "unknown instance option '%U'",
				     format_unformat_error, input);
	  ovpn_config_free (&config);
	  return error;
	}
    }

  /* Setup server mode IP pool if server directive was used */
  if (config.server_mode)
    {
      u32 network = clib_net_to_host_u32 (config.server_network.as_u32);
      u32 mask = clib_net_to_host_u32 (config.server_netmask.as_u32);
      u32 host_bits = ~mask;

      /* Server address is network + 1 */
      ip4_address_t server_ip;
      server_ip.as_u32 = clib_host_to_net_u32 (network + 1);

      /* Set local address if not already set */
      if (ip_address_is_zero (&config.local_addr))
	{
	  ip_address_set (&config.local_addr, &server_ip, AF_IP4);
	}

      /* Setup pool from .2 to .254 (or end of subnet) */
      if (config.options.pool_start.version == 0)
	{
	  config.options.pool_start.version = AF_IP4;
	  config.options.pool_start.ip.ip4.as_u32 =
	    clib_host_to_net_u32 (network + 2);

	  config.options.pool_end.version = AF_IP4;
	  u32 pool_end = (network | host_bits) - 1;
	  if (pool_end > network + 253)
	    pool_end = network + 253;
	  config.options.pool_end.ip.ip4.as_u32 =
	    clib_host_to_net_u32 (pool_end);

	  clib_warning (
	    "ovpn inline config: server mode pool setup: start.version=%d",
	    config.options.pool_start.version);
	}
    }

  config.is_valid = 1;

  /* Create the instance */
  int rv = ovpn_config_create_and_cleanup (vm, &config, NULL);
  if (rv != 0)
    {
      return clib_error_return (0, "failed to create instance: %d", rv);
    }

  return 0;
}

/*
 * VPP startup configuration handler for "openvpn" section
 *
 * Example startup.conf:
 *
 * Method 1: Reference external config files
 *   openvpn {
 *     config /etc/openvpn/server1.conf
 *     config /etc/openvpn/server2.conf
 *   }
 *
 * Method 2: Named inline instance configuration
 *   openvpn {
 *     instance myserver1 {
 *       local 10.10.2.2
 *       port 1194
 *       dev ovpn0
 *       secret /etc/openvpn/static.key
 *       table-id 0
 *     }
 *     instance myserver2 {
 *       local 10.10.3.2
 *       port 1195
 *       dev ovpn1
 *       ca /etc/openvpn/ca.crt
 *       cert /etc/openvpn/server.crt
 *       key /etc/openvpn/server.key
 *       tls-crypt /etc/openvpn/tc.key
 *     }
 *   }
 *
 * Method 3: Instance with name inside the block
 *   openvpn {
 *     instance {
 *       name myserver3
 *       config /etc/openvpn/base.conf
 *       port 1196
 *       dev ovpn2
 *     }
 *   }
 */
static clib_error_t *
ovpn_startup_config (vlib_main_t *vm, unformat_input_t *input)
{
  clib_error_t *error = NULL;
  u8 *config_file = NULL;
  u8 *instance_name = NULL;
  unformat_input_t sub_input;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      /* Method 1: Reference config file directly */
      if (unformat (input, "config %s", &config_file))
	{
	  ovpn_parsed_config_t config;

	  /* Parse the configuration file */
	  error = ovpn_config_parse_file ((char *) config_file, &config);
	  if (error)
	    {
	      clib_warning ("ovpn: failed to parse config file '%s': %U",
			    config_file, format_clib_error, error);
	      clib_error_free (error);
	      vec_free (config_file);
	      continue;
	    }

	  /* Create the instance */
	  ovpn_config_create_and_cleanup (vm, &config, (char *) config_file);
	  vec_free (config_file);
	}
      /* Method 2: Named instance block - "instance <name> { ... }" */
      else if (unformat (input, "instance %s %U", &instance_name,
			 unformat_vlib_cli_sub_input, &sub_input))
	{
	  error = ovpn_parse_inline_instance (vm, (char *) instance_name,
					      &sub_input);
	  vec_free (instance_name);
	  unformat_free (&sub_input);
	  if (error)
	    {
	      clib_warning ("ovpn: failed to parse inline instance: %U",
			    format_clib_error, error);
	      clib_error_free (error);
	      /* Continue parsing other instances */
	    }
	}
      /* Method 3: Anonymous instance block - "instance { ... }" */
      else if (unformat (input, "instance %U", unformat_vlib_cli_sub_input,
			 &sub_input))
	{
	  error = ovpn_parse_inline_instance (vm, NULL, &sub_input);
	  unformat_free (&sub_input);
	  if (error)
	    {
	      clib_warning ("ovpn: failed to parse inline instance: %U",
			    format_clib_error, error);
	      clib_error_free (error);
	      /* Continue parsing other instances */
	    }
	}
      else
	{
	  return clib_error_return (0, "unknown input '%U'",
				    format_unformat_error, input);
	}
    }

  return 0;
}

VLIB_CONFIG_FUNCTION (ovpn_startup_config, "openvpn");

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
