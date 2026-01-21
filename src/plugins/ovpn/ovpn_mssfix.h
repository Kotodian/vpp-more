/*
 * ovpn_mssfix.h - TCP MSS clamping for OpenVPN tunnel
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
#ifndef __included_ovpn_mssfix_h__
#define __included_ovpn_mssfix_h__

#include <vlib/vlib.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/ip/ip_packet.h>

/*
 * TCP MSS clamping for VPN tunnels.
 *
 * When packets traverse a VPN tunnel, the effective MTU is reduced due to
 * the overhead of encapsulation (UDP header, OpenVPN header, encryption).
 * If TCP MSS is not adjusted, large TCP segments may cause IP fragmentation
 * or be dropped by routers with "don't fragment" set.
 *
 * mssfix clamps the MSS in TCP SYN packets to prevent this problem.
 * The typical value for OpenVPN is MTU - 40 (IP+TCP headers) - tunnel overhead.
 */

/*
 * Clamp TCP MSS in SYN packets to the specified maximum value.
 *
 * Based on VPP's mss_clamp plugin implementation.
 *
 * @param tcp0 TCP header pointer
 * @param max_mss Maximum MSS value to allow
 * @return 1 if MSS was clamped, 0 otherwise
 */
always_inline u32
ovpn_mssfix_clamp (tcp_header_t *tcp0, u16 max_mss)
{
  ip_csum_t sum0;

  /* Only process SYN packets */
  if (PREDICT_FALSE (tcp_syn (tcp0)))
    {
      u8 opt_len, opts_len, kind;
      const u8 *data;
      u16 mss0, new_mss0;

      /* Calculate TCP options length */
      opts_len = (tcp_doff (tcp0) << 2) - sizeof (tcp_header_t);
      data = (const u8 *) (tcp0 + 1);

      /* Iterate through TCP options */
      for (; opts_len > 0; opts_len -= opt_len, data += opt_len)
	{
	  kind = data[0];

	  /* End of options list */
	  if (kind == TCP_OPTION_EOL)
	    break;

	  /* No-operation option (padding) */
	  if (kind == TCP_OPTION_NOOP)
	    {
	      opt_len = 1;
	      continue;
	    }

	  /* All other options have a length field */
	  if (opts_len < 2)
	    return 0; /* Broken options */

	  opt_len = data[1];

	  /* Validate option length */
	  if (opt_len < 2 || opt_len > opts_len)
	    return 0; /* Invalid option length */

	  /* Check for MSS option (kind = 2, length = 4) */
	  if (kind == TCP_OPTION_MSS)
	    {
	      if (opt_len != 4)
		return 0; /* Invalid MSS option length */

	      /* MSS value is at offset 2, in network byte order */
	      mss0 = *(u16 *) (data + 2);

	      /* Clamp if current MSS exceeds maximum */
	      if (clib_net_to_host_u16 (mss0) > max_mss)
		{
		  new_mss0 = clib_host_to_net_u16 (max_mss);

		  /* Update MSS value (cast away const for modification) */
		  *((u16 *) (data + 2)) = new_mss0;

		  /* Update TCP checksum incrementally */
		  sum0 = tcp0->checksum;
		  sum0 =
		    ip_csum_update (sum0, mss0, new_mss0, tcp_header_t, checksum);
		  tcp0->checksum = ip_csum_fold (sum0);

		  return 1;
		}
	    }
	}
    }

  return 0;
}

/*
 * Apply MSS clamping to an IPv4 packet.
 *
 * @param ip4 IPv4 header pointer
 * @param max_mss Maximum MSS value
 * @return 1 if MSS was clamped, 0 otherwise
 */
always_inline u32
ovpn_mssfix_ip4 (ip4_header_t *ip4, u16 max_mss)
{
  /* Only process TCP packets */
  if (ip4->protocol != IP_PROTOCOL_TCP)
    return 0;

  /* Check for IP options (IHL > 5) */
  u32 ip_hdr_len = ip4_header_bytes (ip4);

  /* Get TCP header */
  tcp_header_t *tcp = (tcp_header_t *) ((u8 *) ip4 + ip_hdr_len);

  return ovpn_mssfix_clamp (tcp, max_mss);
}

/*
 * Apply MSS clamping to an IPv6 packet.
 *
 * @param vm vlib_main_t pointer (needed for extension header parsing)
 * @param b0 Buffer pointer (needed for extension header parsing)
 * @param ip6 IPv6 header pointer
 * @param max_mss Maximum MSS value
 * @return 1 if MSS was clamped, 0 otherwise
 */
always_inline u32
ovpn_mssfix_ip6 (vlib_main_t *vm, vlib_buffer_t *b0, ip6_header_t *ip6,
		 u16 max_mss)
{
  /* Find TCP header, handling extension headers */
  tcp_header_t *tcp = ip6_ext_header_find (vm, b0, ip6, IP_PROTOCOL_TCP, NULL);

  if (!tcp)
    return 0;

  return ovpn_mssfix_clamp (tcp, max_mss);
}

/*
 * Apply MSS clamping to a decrypted tunnel packet.
 * Determines IP version from the packet itself.
 *
 * @param vm vlib_main_t pointer
 * @param b0 Buffer pointer (data should point to inner IP header)
 * @param max_mss Maximum MSS value
 * @return 1 if MSS was clamped, 0 otherwise
 */
always_inline u32
ovpn_mssfix_inner_packet (vlib_main_t *vm, vlib_buffer_t *b0, u16 max_mss)
{
  u8 *data = vlib_buffer_get_current (b0);

  if (b0->current_length < 1)
    return 0;

  /* Determine IP version from first nibble */
  u8 version = (data[0] >> 4) & 0x0f;

  if (version == 4)
    {
      if (b0->current_length < sizeof (ip4_header_t))
	return 0;
      return ovpn_mssfix_ip4 ((ip4_header_t *) data, max_mss);
    }
  else if (version == 6)
    {
      if (b0->current_length < sizeof (ip6_header_t))
	return 0;
      return ovpn_mssfix_ip6 (vm, b0, (ip6_header_t *) data, max_mss);
    }

  return 0;
}

/*
 * Apply MSS clamping to a decrypted tunnel packet (TAP mode).
 * Parses Ethernet header and handles VLAN tags.
 *
 * @param vm vlib_main_t pointer
 * @param b0 Buffer pointer (data should point to Ethernet frame)
 * @param max_mss Maximum MSS value
 * @return 1 if MSS was clamped, 0 otherwise
 */
always_inline u32
ovpn_mssfix_inner_packet_tap (vlib_main_t *vm, vlib_buffer_t *b0, u16 max_mss)
{
  /* Ethernet header: 6 bytes dst MAC + 6 bytes src MAC + 2 bytes EtherType */
  const u32 eth_hdr_len = 14;
  const u32 vlan_tag_len = 4;
  u8 *data = vlib_buffer_get_current (b0);

  if (b0->current_length < eth_hdr_len)
    return 0;

  /* Get EtherType (bytes 12-13, network byte order) */
  u16 ethertype = clib_net_to_host_u16 (*(u16 *) (data + 12));
  u32 l3_offset = eth_hdr_len;

  /* Handle 802.1Q VLAN tag */
  if (ethertype == 0x8100)
    {
      if (b0->current_length < eth_hdr_len + vlan_tag_len)
	return 0;
      /* Skip VLAN tag (4 bytes: 2 TCI + 2 inner EtherType) */
      ethertype = clib_net_to_host_u16 (*(u16 *) (data + 16));
      l3_offset = eth_hdr_len + vlan_tag_len;
    }
  /* Handle 802.1ad QinQ (double VLAN) */
  else if (ethertype == 0x88a8)
    {
      if (b0->current_length < eth_hdr_len + 2 * vlan_tag_len)
	return 0;
      /* Check inner VLAN tag */
      u16 inner_type = clib_net_to_host_u16 (*(u16 *) (data + 16));
      if (inner_type == 0x8100)
	{
	  ethertype = clib_net_to_host_u16 (*(u16 *) (data + 20));
	  l3_offset = eth_hdr_len + 2 * vlan_tag_len;
	}
      else
	{
	  ethertype = inner_type;
	  l3_offset = eth_hdr_len + vlan_tag_len;
	}
    }

  u8 *ip_data = data + l3_offset;
  u32 ip_len = b0->current_length - l3_offset;

  /* Process based on EtherType */
  if (ethertype == 0x0800) /* IPv4 */
    {
      if (ip_len < sizeof (ip4_header_t))
	return 0;
      return ovpn_mssfix_ip4 ((ip4_header_t *) ip_data, max_mss);
    }
  else if (ethertype == 0x86DD) /* IPv6 */
    {
      if (ip_len < sizeof (ip6_header_t))
	return 0;
      /* For IPv6, we need to temporarily adjust buffer current pointer */
      vlib_buffer_advance (b0, l3_offset);
      u32 result = ovpn_mssfix_ip6 (vm, b0, (ip6_header_t *) ip_data, max_mss);
      vlib_buffer_advance (b0, -(i32) l3_offset);
      return result;
    }

  /* Not an IP packet (e.g., ARP, other protocols) */
  return 0;
}

/*
 * Apply MSS clamping to a decrypted tunnel packet.
 * Handles both TUN (L3) and TAP (L2) modes.
 *
 * @param vm vlib_main_t pointer
 * @param b0 Buffer pointer
 * @param max_mss Maximum MSS value
 * @param is_tun true for TUN mode, false for TAP mode
 * @return 1 if MSS was clamped, 0 otherwise
 */
always_inline u32
ovpn_mssfix_packet (vlib_main_t *vm, vlib_buffer_t *b0, u16 max_mss,
		    u8 is_tun)
{
  if (is_tun)
    return ovpn_mssfix_inner_packet (vm, b0, max_mss);
  else
    return ovpn_mssfix_inner_packet_tap (vm, b0, max_mss);
}

#endif /* __included_ovpn_mssfix_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
