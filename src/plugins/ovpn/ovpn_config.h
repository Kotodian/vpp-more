/*
 * ovpn_config.h - OpenVPN configuration file parser header
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
#ifndef __included_ovpn_config_h__
#define __included_ovpn_config_h__

#include <vlib/vlib.h>
#include <ovpn/ovpn_options.h>

/*
 * OpenVPN configuration file parser
 *
 * Parses standard OpenVPN .ovpn/.conf files and populates ovpn_options_t.
 *
 * Supported options:
 *   - local <ip>           : Local IP address to bind
 *   - port <n>             : UDP port (default 1194)
 *   - dev <name>           : Device name (e.g., tun0)
 *   - dev-type <tun|tap>   : Device type
 *   - proto <udp|udp4|udp6>: Protocol
 *   - server <ip> <mask>   : Server mode with IP pool
 *   - ifconfig-pool <start> <end> : IP address pool
 *   - ca <file>            : CA certificate file
 *   - cert <file>          : Server certificate file
 *   - key <file>           : Server private key file
 *   - dh <file>            : DH parameters file
 *   - tls-crypt <file>     : TLS-Crypt key file
 *   - tls-crypt-v2 <file>  : TLS-Crypt-V2 server key file
 *   - tls-auth <file> [dir]: TLS-Auth key file
 *   - secret <file> [dir]  : Static key file (for static key mode)
 *   - cipher <name>        : Data channel cipher
 *   - auth <name>          : HMAC algorithm
 *   - keepalive <ping> <timeout> : Keepalive settings
 *   - max-clients <n>      : Maximum number of clients
 *   - tun-mtu <n>          : Tunnel MTU
 *   - reneg-sec <n>        : Renegotiate key after n seconds
 *   - hand-window <n>      : Handshake window
 *   - tran-window <n>      : Transition window
 *   - tls-timeout <n>      : TLS retransmit timeout
 *   - replay-window <n> [t]: Replay window size and time
 *   - table-id <n>         : VPP FIB table ID
 */

/*
 * Parsed configuration structure
 * This extends ovpn_options_t with additional parsed fields
 */
typedef struct ovpn_parsed_config_t_
{
  /* Instance name (for identification) */
  char *instance_name;

  /* Parsed options */
  ovpn_options_t options;

  /* Parsed network binding (not in ovpn_options_t) */
  ip_address_t local_addr;
  u16 local_port;
  u32 table_id;

  /* Parsed but not yet loaded file contents */
  char *ca_file;
  char *cert_file;
  char *key_file;
  char *dh_file;
  char *tls_crypt_file;
  char *tls_crypt_v2_file;
  char *tls_auth_file;
  char *secret_file;
  char *crl_file; /* CRL file path for crl-verify */
  u8 tls_auth_direction;
  u8 secret_direction;

  /* Server mode network */
  ip4_address_t server_network;
  ip4_address_t server_netmask;
  u8 server_mode;

  /* Valid flag */
  u8 is_valid;

} ovpn_parsed_config_t;

/**
 * Parse an OpenVPN configuration file
 *
 * @param file_path Path to the .ovpn or .conf file
 * @param config Output: parsed configuration
 * @return 0 on success, error code on failure
 */
clib_error_t *ovpn_config_parse_file (const char *file_path,
				      ovpn_parsed_config_t *config);

/**
 * Parse OpenVPN configuration from a buffer
 *
 * @param config_data Configuration file contents
 * @param config_len Length of config_data
 * @param base_dir Base directory for relative file paths (can be NULL)
 * @param config Output: parsed configuration
 * @return 0 on success, error code on failure
 */
clib_error_t *ovpn_config_parse_buffer (const u8 *config_data, u32 config_len,
					const char *base_dir,
					ovpn_parsed_config_t *config);

/**
 * Load certificate/key files referenced in the configuration
 *
 * After parsing, call this to load the actual file contents
 * into the options structure.
 *
 * @param config Parsed configuration with file paths
 * @return 0 on success, error code on failure
 */
clib_error_t *ovpn_config_load_files (ovpn_parsed_config_t *config);

/**
 * Free a parsed configuration
 *
 * @param config Configuration to free
 */
void ovpn_config_free (ovpn_parsed_config_t *config);

/**
 * Initialize a parsed configuration to default values
 *
 * @param config Configuration to initialize
 */
void ovpn_config_init (ovpn_parsed_config_t *config);

/**
 * Create an OpenVPN instance from parsed configuration
 *
 * @param vm VPP main structure
 * @param config Parsed and loaded configuration
 * @param instance_id_out Output: created instance ID
 * @param sw_if_index_out Output: created interface index
 * @return 0 on success, error code on failure
 */
int ovpn_config_create_instance (vlib_main_t *vm, ovpn_parsed_config_t *config,
				 u32 *instance_id_out, u32 *sw_if_index_out);

#endif /* __included_ovpn_config_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
