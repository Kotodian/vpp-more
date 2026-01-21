/*
 * options.h - ovpn options header file
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
#ifndef __included_ovpn_options_h__
#define __included_ovpn_options_h__

#include <vnet/ip/ip_types.h>
#include <vnet/fib/fib_types.h>
#include <vlib/vlib.h>

#define OVPN_DEFAULT_SEQ_BACKTRACK  64
#define OVPN_DEFAULT_TIME_BACKTRACK 15

/* Maximum number of push options */
#define OVPN_MAX_PUSH_OPTIONS 64

/* Maximum number of data ciphers */
#define OVPN_MAX_DATA_CIPHERS 16

/* Maximum number of DNS servers */
#define OVPN_MAX_DNS_SERVERS 4

/*
 * DHCP option types for dhcp-option directive
 */
typedef enum ovpn_dhcp_option_type_t_
{
  OVPN_DHCP_OPTION_DNS = 0,
  OVPN_DHCP_OPTION_WINS,
  OVPN_DHCP_OPTION_DOMAIN,
  OVPN_DHCP_OPTION_DOMAIN_SEARCH,
  OVPN_DHCP_OPTION_NTP,
  OVPN_DHCP_OPTION_NBDD,
  OVPN_DHCP_OPTION_NBT,
  OVPN_DHCP_OPTION_DISABLE_NBT,
} ovpn_dhcp_option_type_t;

/*
 * Single DHCP option entry
 */
typedef struct ovpn_dhcp_option_t_
{
  ovpn_dhcp_option_type_t type;
  union
  {
    ip_address_t ip; /* For DNS, WINS, NTP, NBDD */
    u8 *string;	     /* For DOMAIN, DOMAIN_SEARCH */
    u8 nbt_type;     /* For NBT (1=b-node, 2=p-node, 4=m-node, 8=h-node) */
  };
} ovpn_dhcp_option_t;

typedef struct ovpn_options_t_
{

  /* Network */
  u16 listen_port;
  /* Only support UDP */
  u32 proto;

  /* Tunnel device related*/
  char *dev_name;
  u32 sw_if_index; /* Software interface index */
  fib_prefix_t server_addr;
  u16 mtu;
  u8 is_tun;

  /* TLS */
  u8 *ca_cert;
  u8 *server_cert;
  u8 *server_key;
  u8 *dh_params;
  u8 *cipher_name;
  u8 *auth_name;

  /*
   * Certificate name verification (--verify-x509-name)
   * verify_x509_name: the name/pattern to match
   * verify_x509_type: 0=name (exact CN), 1=name-prefix, 2=subject
   */
  u8 *verify_x509_name;
  u8 verify_x509_type;
#define OVPN_X509_VERIFY_NAME	     0 /* Exact CN match */
#define OVPN_X509_VERIFY_NAME_PREFIX 1 /* CN prefix match */
#define OVPN_X509_VERIFY_SUBJECT     2 /* Full subject DN match */

  /* Replay */
  u8 replay_protection;
  u32 replay_window;
  u32 replay_time;

  /* Negotiation */
  u32 renegotiate_seconds; /* Renegotiate data channel key after n seconds */
  u64
    renegotiate_bytes; /* Renegotiate after n bytes transferred (0=disabled) */
  u64 renegotiate_packets; /* Renegotiate after n packets (0=disabled) */
  u32 handshake_window;	   /* TLS handshake must complete within n seconds */
  u32 transition_window; /* Old key allowed to live n seconds after new key */
  u32 tls_timeout;	 /* Control channel packet retransmit timeout */

  /* Client*/
  ip_address_t pool_start;
  ip_address_t pool_end;
  u32 max_clients;

  /*
   * IP Pool Persistence (--ifconfig-pool-persist)
   * Saves IP assignments to file so clients get same IP across restarts.
   * File format: common_name,ip_address (one per line)
   */
  u8 *ifconfig_pool_persist_file; /* Path to persist file */
  u32 ifconfig_pool_persist_seconds; /* Save interval (0 = on change, default) */

  /* Keepalive */
  u32 keepalive_ping;
  u32 keepalive_timeout;

  /* Optional*/
  u8 *tls_crypt_key;
  u8 *tls_crypt_v2_key; /* TLS-Crypt-V2 server key */
  u8 *tls_auth_key;

  /* Static key mode (--secret) */
  u8 *static_key;	   /* Raw static key data (256 bytes) */
  u8 static_key_direction; /* 0 = normal, 1 = inverse */
  u8 static_key_mode;	   /* 1 if using static key mode */

  /*
   * Push options (--push "option")
   * Array of strings to push to clients during connection
   */
  u8 **push_options; /* vec of vec strings */
  u32 n_push_options;

  /*
   * DHCP options (--dhcp-option)
   * These are pushed to clients for network configuration
   */
  ovpn_dhcp_option_t *dhcp_options; /* vec of dhcp options */
  u32 n_dhcp_options;

  /*
   * Data channel cipher negotiation (--data-ciphers)
   * List of acceptable ciphers in order of preference
   * OpenVPN 2.5+ uses NCP (Negotiable Crypto Parameters)
   */
  u8 **data_ciphers; /* vec of cipher name strings */
  u32 n_data_ciphers;
  u8 *data_ciphers_fallback; /* Fallback cipher if negotiation fails */

  /*
   * Route push options
   */
  fib_prefix_t *push_routes; /* vec of routes to push */
  u32 n_push_routes;
  u8 redirect_gateway;	     /* Push redirect-gateway to clients */
  u8 redirect_gateway_flags; /* def1, local, autolocal, bypass-dhcp, bypass-dns
			      */

  /*
   * Client-to-client routing
   */
  u8 client_to_client; /* Allow clients to reach each other */

  /*
   * Duplicate common name (--duplicate-cn)
   * Allow multiple clients to connect with the same certificate CN.
   * If disabled (default), a new connection with the same CN disconnects
   * the existing client.
   */
  u8 duplicate_cn;

  /*
   * Float (--float)
   * Allow client's real IP address to change during the session.
   * Required when clients are behind NAT that may rebind.
   * If disabled, packets from unexpected addresses are dropped.
   */
  u8 float_enabled;

  /*
   * Client config directory (--client-config-dir)
   * Directory containing per-client configuration files.
   * Files are named after the client's Common Name (CN).
   */
  u8 *client_config_dir;

  /*
   * CCD exclusive (--ccd-exclusive)
   * When enabled, only allow clients that have a CCD file.
   * Clients without a matching file in client-config-dir are rejected.
   */
  u8 ccd_exclusive;

  /*
   * Management interface (--management)
   * Enables external control via UDP using VPP session layer
   */
  u8 management_enabled;      /* 1 if management is configured */
  ip_address_t management_ip; /* IP to bind (default 0.0.0.0) */
  u16 management_port;	      /* UDP port (default 7505) */
  u8 *management_password;    /* Management password (optional) */
  u8 management_hold;	      /* Start in hold state (--management-hold) */
  u32 management_log_cache;   /* Number of log lines to cache (--management-log-cache) */
  u8 management_client;	      /* Act as management client (--management-client) */
  u8 management_up_down;      /* Report up/down events (--management-up-down) */
  u8 management_query_passwords; /* Query passwords via management
				    (--management-query-passwords) */

  /*
   * Data channel protocol options
   */
  u8 use_data_v2; /* Enable DATA_V2 format support (default 0) */
  u8 data_channel_keydir; /* Key direction for data channel:
			     0=NORMAL (client encrypts key2[0]),
			     1=INVERSE (client encrypts key2[1]),
			     255=auto (from client options, default 0) */

  /*
   * MSS fix - clamp TCP MSS to avoid fragmentation
   * mssfix <max_mss> - Clamp TCP MSS to max_mss value
   * Default: 0 (disabled), typical value: 1450
   */
  u16 mssfix;

  /*
   * OpenVPN Fragmentation (--fragment <max>)
   * Fragment UDP packets larger than max bytes.
   * Default: 0 (disabled), typical value: 1300
   *
   * When enabled, large packets are split into fragments before encryption.
   * Each fragment has a 4-byte header containing:
   *   - Fragment type (2 bits): WHOLE, NOT_LAST, LAST, TEST
   *   - Sequence ID (8 bits): Groups fragments of same packet
   *   - Fragment ID (5 bits): Orders fragments (0-31)
   *   - Fragment size (14 bits): Max size (only in last fragment)
   */
  u16 fragment_size;

  /*
   * Username/Password Authentication
   * Enables client authentication via username and password.
   * Use auth-user-pass-file for static file or management-client-auth
   * for async authentication via management interface.
   */
  u8 auth_user_pass_required;	/* 1 if username/password auth is required */
  u8 *auth_user_pass_file;	/* Static file with username:password pairs */
  u8 auth_user_pass_optional;	/* Allow clients without credentials */
  u8 management_client_auth;	/* Use management interface for auth */

  /*
   * Certificate Revocation List (--crl-verify)
   * CRL file to check client certificates against
   */
  u8 *crl_file; /* Path to CRL file (PEM or DER format) */

} ovpn_options_t;

/* Static key size: 256 bytes (2048 bits) */
#define OVPN_STATIC_KEY_SIZE 256

/*
 * Parse OpenVPN static key file format.
 *
 * OpenVPN static.key format:
 * -----BEGIN OpenVPN Static key V1-----
 * <16 lines of 32 hex characters each = 256 bytes>
 * -----END OpenVPN Static key V1-----
 *
 * @param key_data Raw file contents
 * @param key_len Length of key_data
 * @param key_out Output buffer (must be at least OVPN_STATIC_KEY_SIZE bytes)
 * @return 0 on success, <0 on error
 */
int ovpn_parse_static_key (const u8 *key_data, u32 key_len, u8 *key_out);

bool string_defined_equal (const char *s1, const char *s2);
void ovpn_options_init (ovpn_options_t *opts);

u8 ovpn_options_cmp_equal_safe (char *actual, const char *expected,
				size_t actual_n);

/*
 * Compare two strings, returning 1 if they are equal, 0 otherwise.
 */
u8 ovpn_options_cmp_equal (char *actual, const char *expected);

/**
 * Given an OpenVPN options string, extract the value of an option.
 *
 * @param options_string Zero-terminated, comma-separated options string
 * @param opt_name The name of the option to extract
 * @return The value of the option, or NULL if the option is not found, You
 * should free the returned string using clib_mem_free().
 */
char *ovpn_options_string_extract_option (const char *options_string,
					  const char *opt_name);

/**
 * Build the server's options string to send to the client in Key Method 2.
 *
 * The options string contains the negotiated cipher, virtual IP assignment,
 * and other settings that the client needs to know about.
 *
 * @param buf Buffer to write options string into
 * @param buf_len Length of buffer
 * @param cipher_name Name of negotiated cipher (e.g., "AES-256-GCM")
 * @param use_tls_ekm Whether to use TLS-EKM for key derivation
 * @param peer_id Peer ID for this connection
 * @param virtual_ip Virtual IP address to assign to client (can be NULL)
 * @param virtual_netmask Netmask for the virtual IP (can be NULL)
 * @return Length of options string written (including null terminator),
 *         or < 0 on error
 */
int ovpn_options_string_build_server (char *buf, u32 buf_len,
				      const char *cipher_name, u8 use_tls_ekm,
				      u32 peer_id,
				      const ip_address_t *virtual_ip,
				      const ip_address_t *virtual_netmask);

/**
 * Get cipher name string from cipher algorithm enum
 */
const char *ovpn_cipher_alg_to_name (u8 cipher_alg);

/**
 * Parse client's ifconfig option from options string
 *
 * Clients can specify their desired virtual IP using:
 *   "ifconfig <ip> <netmask>" (IPv4)
 *   "ifconfig-ipv6 <ip>/<prefix> <remote>" (IPv6)
 *
 * @param options_string Client's options string from Key Method 2
 * @param virtual_ip Output: parsed virtual IP address
 * @return 0 on success (IP extracted), <0 if not found or invalid
 */
int ovpn_options_parse_client_ifconfig (const char *options_string,
					ip_address_t *virtual_ip);

/**
 * Check if an IP address is within the configured pool range
 *
 * @param ip IP address to check
 * @param pool_start Start of IP pool
 * @param pool_end End of IP pool
 * @return 1 if IP is within range, 0 otherwise
 */
int ovpn_options_ip_in_pool (const ip_address_t *ip,
			     const ip_address_t *pool_start,
			     const ip_address_t *pool_end);

/**
 * Add a push option
 *
 * @param opts Options structure
 * @param option Option string to push (will be copied)
 * @return 0 on success, <0 on error
 */
int ovpn_options_add_push (ovpn_options_t *opts, const char *option);

/**
 * Add a DHCP option
 *
 * @param opts Options structure
 * @param type DHCP option type
 * @param value Value (IP address or string depending on type)
 * @return 0 on success, <0 on error
 */
int ovpn_options_add_dhcp_option (ovpn_options_t *opts,
				  ovpn_dhcp_option_type_t type,
				  const void *value);

/**
 * Add a DNS server (convenience wrapper for dhcp-option DNS)
 *
 * @param opts Options structure
 * @param dns_ip DNS server IP address
 * @return 0 on success, <0 on error
 */
int ovpn_options_add_dns (ovpn_options_t *opts, const ip_address_t *dns_ip);

/**
 * Set the domain name (convenience wrapper for dhcp-option DOMAIN)
 *
 * @param opts Options structure
 * @param domain Domain name string
 * @return 0 on success, <0 on error
 */
int ovpn_options_set_domain (ovpn_options_t *opts, const char *domain);

/**
 * Add a data cipher to the negotiation list
 *
 * @param opts Options structure
 * @param cipher_name Cipher name (e.g., "AES-256-GCM")
 * @return 0 on success, <0 on error
 */
int ovpn_options_add_data_cipher (ovpn_options_t *opts,
				  const char *cipher_name);

/**
 * Set data ciphers from a colon-separated string
 *
 * @param opts Options structure
 * @param cipher_list Colon-separated list of ciphers (e.g.,
 * "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305")
 * @return 0 on success, <0 on error
 */
int ovpn_options_set_data_ciphers (ovpn_options_t *opts,
				   const char *cipher_list);

/**
 * Add a route to push to clients
 *
 * @param opts Options structure
 * @param prefix Route prefix to push
 * @return 0 on success, <0 on error
 */
int ovpn_options_add_push_route (ovpn_options_t *opts,
				 const fib_prefix_t *prefix);

/**
 * Build push options string for sending to client
 *
 * @param opts Options structure
 * @param buf Output buffer
 * @param buf_len Buffer length
 * @return Length written, or <0 on error
 */
int ovpn_options_build_push_reply (const ovpn_options_t *opts, char *buf,
				   u32 buf_len);

/* Forward declaration for per-client push options */
struct ovpn_peer_push_options_t_;

/**
 * Build push options string with per-client overrides
 *
 * This function builds the push options considering:
 * - push-reset: If set, skip all global push options
 * - push-remove: Filter out matching global options
 * - Per-client push options are appended
 *
 * @param opts Global options structure
 * @param client_opts Per-client push options (can be NULL)
 * @param buf Output buffer
 * @param buf_len Buffer length
 * @return Length written, or <0 on error
 */
int ovpn_options_build_push_reply_for_peer (
  const ovpn_options_t *opts, const struct ovpn_peer_push_options_t_ *client_opts,
  char *buf, u32 buf_len);

/**
 * Free all dynamically allocated options (push, dhcp, ciphers, routes)
 *
 * @param opts Options structure
 */
void ovpn_options_free_dynamic (ovpn_options_t *opts);

/**
 * Negotiate cipher from client's IV_CIPHERS list
 *
 * @param opts Server options with data_ciphers list
 * @param client_ciphers Client's cipher list (colon-separated)
 * @return Negotiated cipher name (static string), or NULL if no match
 */
const char *ovpn_options_negotiate_cipher (const ovpn_options_t *opts,
					   const char *client_ciphers);

#endif /* __included_ovpn_options_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
