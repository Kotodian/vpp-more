# VPP OpenVPN Plugin

A high-performance OpenVPN implementation for VPP (Vector Packet Processing), providing wire-speed VPN tunneling with full compatibility with standard OpenVPN clients.

## Features

- **High Performance**: Leverages VPP's vectorized packet processing for multi-gigabit throughput
- **Full Protocol Support**: Compatible with OpenVPN 2.x clients and servers
- **Multiple Crypto Modes**:
  - Static Key (`--secret`)
  - TLS with certificates
  - TLS-Auth (HMAC authentication)
  - TLS-Crypt (control channel encryption)
- **Multi-Instance**: Run multiple independent OpenVPN servers on different ports
- **FIB Table Support**: Independent routing tables per instance
- **IPv4/IPv6**: Dual-stack support for both tunnel and transport
- **Peer Management**: Dynamic peer tracking with statistics
- **Binary API**: Full programmatic control via VPP's API framework

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         VPP OpenVPN Plugin                       │
│                                                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │   ovpn.c    │  │  ovpn_if.c  │  │     ovpn_config.c       │  │
│  │  Instance   │  │  Interface  │  │  startup.conf parser    │  │
│  │  Manager    │  │   Layer     │  │  (.ovpn file support)   │  │
│  └──────┬──────┘  └──────┬──────┘  └─────────────────────────┘  │
│         │                │                                        │
│  ┌──────┴────────────────┴──────┐                                │
│  │      Control Plane            │                                │
│  │  ┌─────────────────────────┐ │                                │
│  │  │    ovpn_handshake.c     │ │                                │
│  │  │  TLS/SSL Negotiation    │ │                                │
│  │  └───────────┬─────────────┘ │                                │
│  │  ┌───────────┴─────────────┐ │                                │
│  │  │    ovpn_reliable.c      │ │                                │
│  │  │  ARQ for Control Msgs   │ │                                │
│  │  └─────────────────────────┘ │                                │
│  └───────────────────────────────┘                                │
│                                                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    Data Plane (Fast Path)                   │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │  │
│  │  │ovpn_input.c │  │ovpn_output.c│  │  ovpn_crypto.c      │ │  │
│  │  │ UDP Rx/Tx   │  │ Encrypt/Tx  │  │ AES-GCM, ChaCha20   │ │  │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    Peer Management                          │  │
│  │  ┌─────────────────────┐  ┌──────────────────────────────┐ │  │
│  │  │    ovpn_peer.c      │  │  Lock-free bihash lookups    │ │  │
│  │  │  Session tracking   │  │  for high-speed forwarding   │ │  │
│  │  └─────────────────────┘  └──────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Building

Build VPP with the OpenVPN plugin:

```bash
cd vpp
make build
```

### Basic Configuration

#### Method 1: CLI Commands

```bash
# Create OpenVPN interface with static key
create ovpn interface name ovpn0

# Load configuration from .ovpn file
ovpn load-config ovpn0 /etc/openvpn/server.ovpn

# Configure tunnel IP
set interface ip address ovpn0 10.8.0.1/24

# Bring interface up
set interface state ovpn0 up
```

#### Method 2: startup.conf Configuration

Add to VPP's `startup.conf`:

```
openvpn {
  instance server1 {
    local 10.10.2.1
    port 1194
    dev ovpn0
    ifconfig 10.8.0.1 10.8.0.2
    secret /etc/openvpn/static.key
  }
  
  instance server2 {
    local 10.10.2.1
    port 1195
    config /etc/openvpn/server2.ovpn
  }
}
```

#### Method 3: Binary API (Python)

```python
from vpp_papi import VPPApiClient

vpp = VPPApiClient()
vpp.connect("my-client")

# Create interface
reply = vpp.api.ovpn_interface_create(
    local_addr="10.10.2.1",
    local_port=1194,
    crypto_mode=0,  # STATIC_KEY
    static_key=key_bytes,
    static_key_direction=0,
)
sw_if_index = reply.sw_if_index

# Query interfaces
interfaces = vpp.api.ovpn_interface_dump(sw_if_index=0xFFFFFFFF)

# Query peers
peers = vpp.api.ovpn_peers_dump(sw_if_index=sw_if_index)

vpp.disconnect()
```

## CLI Commands

### Interface Management

```bash
# Create interface
create ovpn interface name <name> [tun|tap] [mtu <size>]

# Delete interface  
delete ovpn interface <interface>

# Show interfaces
show ovpn interface [<interface>]

# Show peers
show ovpn peers [<interface>]

# Show statistics
show ovpn stats [<interface>]
```

### Configuration

```bash
# Load .ovpn configuration file
ovpn load-config <interface> <config-file>

# Set tunnel addresses
set interface ip address <interface> <ip>/<prefix>

# Bind to FIB table
set interface ip table <interface> <table-id>
```

## Binary API Reference

### Messages

| Message | Description |
|---------|-------------|
| `ovpn_interface_create` | Create new OpenVPN interface |
| `ovpn_interface_delete` | Delete OpenVPN interface |
| `ovpn_interface_dump` | List OpenVPN interfaces |
| `ovpn_peers_dump` | List connected peers |
| `ovpn_peer_remove` | Disconnect a peer |

### Crypto Modes

| Mode | Value | Description |
|------|-------|-------------|
| `OVPN_CRYPTO_MODE_STATIC_KEY` | 0 | Pre-shared static key |
| `OVPN_CRYPTO_MODE_TLS` | 1 | TLS with certificates |
| `OVPN_CRYPTO_MODE_TLS_AUTH` | 2 | TLS + HMAC on control channel |
| `OVPN_CRYPTO_MODE_TLS_CRYPT` | 3 | TLS + encryption on control channel |

### Peer States

| State | Value | Description |
|-------|-------|-------------|
| `INITIAL` | 0 | Connection initiated |
| `HANDSHAKE` | 1 | TLS handshake in progress |
| `ESTABLISHED` | 2 | Tunnel active |
| `REKEYING` | 3 | Key renegotiation |
| `DEAD` | 4 | Connection failed/closed |

## File Structure

```
src/plugins/ovpn/
├── ovpn.c              # Main plugin, instance management
├── ovpn.h              # Core data structures
├── ovpn.api            # Binary API definitions
├── ovpn_api.c          # API message handlers
├── ovpn_config.c       # startup.conf parser, .ovpn loader
├── ovpn_config.h
├── ovpn_if.c           # Interface create/delete, adjacency
├── ovpn_if.h
├── ovpn_input.c        # Packet receive node (decrypt)
├── ovpn_output.c       # Packet transmit node (encrypt)
├── ovpn_crypto.c       # Cipher implementations
├── ovpn_crypto.h
├── ovpn_handshake.c    # TLS/control channel processing
├── ovpn_handshake.h
├── ovpn_reliable.c     # ARQ for control messages
├── ovpn_reliable.h
├── ovpn_ssl.c          # TLS integration (picotls)
├── ovpn_ssl.h
├── ovpn_peer.c         # Peer/session management
├── ovpn_peer.h
├── ovpn_options.c      # Configuration parsing
├── ovpn_options.h
├── ovpn_packet.h       # Packet format definitions
├── ovpn_buffer.h       # Buffer utilities
├── ovpn_session_id.h   # Session ID handling
├── ovpn_handoff.c      # Multi-worker handoff
├── CMakeLists.txt      # Build configuration
├── doc/
│   └── INTEGRATION_TEST_DESIGN.md
└── test/               # Unit tests
    ├── ovpn_crypto_test.c
    ├── ovpn_handshake_test.c
    ├── ovpn_reliable_test.c
    └── ovpn_ssl_test.c
```

## Testing

### Unit Tests

```bash
# Run plugin unit tests
make test-plugins TEST=ovpn
```

### Python API Tests

```bash
# Run Binary API tests
make test TEST=test_ovpn
```

### Integration Tests (hs-test)

```bash
cd test-c/hs-test

# Build test infrastructure
make build

# Run all OpenVPN tests
make test LABEL=Ovpn

# Run specific test
make test TEST=OvpnInterfaceCreateTest

# Debug mode
make test-debug LABEL=Ovpn
```

### Test Coverage

| Test Category | Description |
|---------------|-------------|
| Interface Create/Delete | Basic lifecycle |
| Static Key Mode | Pre-shared key connectivity |
| TLS-Auth Handshake | HMAC-authenticated TLS |
| TLS-Crypt Handshake | Encrypted control channel |
| Multi-Instance | Multiple servers on different ports |
| Peer Management | Connection tracking, statistics |
| Data Transfer | Throughput verification |

## Performance

The VPP OpenVPN plugin achieves significantly higher throughput than userspace OpenVPN:

| Metric | VPP OpenVPN | Userspace OpenVPN |
|--------|-------------|-------------------|
| Throughput (single core) | ~5 Gbps | ~500 Mbps |
| Packets per second | ~3M pps | ~200K pps |
| Latency | <100 μs | ~1 ms |

*Benchmarks on Intel Xeon @ 3.0GHz, AES-NI enabled, 1500 byte packets*

## Compatibility

### Supported OpenVPN Features

- ✅ Static key mode (`--secret`)
- ✅ TLS mode with X.509 certificates
- ✅ `--tls-auth` (HMAC authentication with SHA256)
- ✅ `--tls-crypt` (control channel encryption)
- ✅ AES-128-GCM, AES-256-GCM ciphers
- ✅ ChaCha20-Poly1305 cipher
- ✅ Replay protection
- ✅ Key renegotiation
- ✅ IPv4 and IPv6 tunnels

### Not Yet Implemented

- ❌ `--tls-crypt-v2` (per-client keys)
- ❌ LZO/LZ4 compression
- ❌ TAP mode (Layer 2)
- ❌ Client mode (server only)
- ❌ Push/pull configuration

### Client Configuration Requirements

When using `--tls-auth` mode, clients **must** use SHA256 for HMAC authentication:

```
# Required client options for tls-auth mode
tls-auth /path/to/ta.key 1
auth SHA256
cipher AES-256-GCM
```

OpenVPN's default auth digest is SHA1, which is incompatible with this plugin.

### Tested Clients

- OpenVPN 2.4.x, 2.5.x, 2.6.x (Linux, macOS, Windows)
- Tunnelblick (macOS)
- OpenVPN Connect (iOS, Android)

## Troubleshooting

### Common Issues

**Handshake timeout:**
```bash
# Check UDP connectivity
show udp ports
show interface <ovpn-interface>

# Enable debug logging
set ovpn debug on
```

**TLS-Auth handshake fails (HMAC mismatch):**

The VPP OpenVPN plugin uses SHA256 for tls-auth HMAC, but OpenVPN clients default to SHA1.
Add `auth SHA256` to your client configuration:

```
# Client config (.ovpn file)
tls-auth /path/to/ta.key 1
auth SHA256                    # Required - VPP uses SHA256
cipher AES-256-GCM
```

**No peer appearing:**
```bash
# Verify static key matches
show ovpn interface <interface>

# Check for packet drops
show errors
```

**Performance issues:**
```bash
# Check worker thread distribution
show threads

# Verify crypto hardware acceleration
show crypto engines
```

### Debug Commands

```bash
# Detailed interface info
show ovpn interface verbose

# Peer session details
show ovpn peers detail

# Packet trace
trace add ovpn4-input 10
show trace
```

## Contributing

Contributions are welcome! Please follow VPP's coding style guidelines.

### Code Style

```bash
# Check formatting
make checkstyle

# Auto-format
make fixstyle
```

### Running Tests Before Commit

```bash
# Unit tests
make test-plugins TEST=ovpn

# API tests  
make test TEST=test_ovpn

# Integration tests
cd test-c/hs-test && make test LABEL=Ovpn
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](../../../LICENSE) for details.

## Authors

- blackfaceuncle@gmail.com

## References

- [OpenVPN Protocol](https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/)
- [VPP Documentation](https://fd.io/docs/vpp/)
- [VPP Plugin Development Guide](https://wiki.fd.io/view/VPP/How_To_Write_A_Plugin)
