# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VPP (Vector Packet Processing) is FD.io's high-performance, extensible packet processing framework. It provides production-quality switch/router functionality using a modular, plugin-based architecture running on commodity CPUs.

**Languages:** C (core), Python (tests), Go (host stack tests)
**Build System:** CMake + Makefile hybrid

## Build Commands

```bash
# Install dependencies (required first time)
make install-dep
make install-ext-deps

# Build
make build              # Debug build
make build-release      # Release build
make rebuild            # Clean and rebuild

# Run VPP
make run                # Run debug binary
make debug              # Run with GDB

# Generate IDE support
make compdb             # Creates compile_commands.json
```

## Testing

```bash
# Python test framework
make test                       # Run all tests
make test-debug                 # Debug build tests
TEST=<name> make test           # Run specific test
STEP=yes make test              # Interactive debugging

# Go-based host stack tests
make -C test/hs-test test
make cleanup-hst                # Cleanup test containers

# Code coverage
make test-cov                   # Python tests with coverage
make test-cov-hs               # Host stack tests with coverage
```

## Code Style

```bash
make checkstyle         # Check C/C++ style
make checkstyle-python  # Check Python with Black
make checkstyle-go      # Check Go style
make fixstyle           # Auto-fix all code style
make checkstyle-commit  # Verify commit message format
```

## Architecture

### Core Libraries (in order of dependency)

- **vppinfra** (`src/vppinfra/`) - Low-level infrastructure: pools, vectors, bitmaps, hashes, memory management
- **vlib** (`src/vlib/`) - Core event loop, node-based packet processing graph, CLI framework, buffer management
- **vnet** (`src/vnet/`) - Networking stack: L2/L3/L4 protocols, device drivers, crypto, QoS
- **vlibapi/vlibmemory** (`src/vlibapi/`, `src/vlibmemory/`) - API framework and shared memory IPC
- **vpp** (`src/vpp/`) - Main application
- **vpp-api** (`src/vpp-api/`) - Client API bindings (Python, Go)

### Plugin System

Plugins in `src/plugins/` (100+ available) are loaded dynamically. Each plugin contains:
- `CMakeLists.txt` - Build configuration
- `*.api` files - Message definitions (auto-generates C/Python/Go bindings)
- `VLIB_PLUGIN_REGISTER()` macro for registration
- `*_test.c` - Unit tests
- `FEATURE.yaml` - Feature documentation

### Key Architectural Concepts

- **Node Graph**: Packet processing flows through interconnected vlib nodes
- **Per-Worker Threading**: Parallel packet processing across CPU cores
- **Zero-Copy Buffers**: Buffer pools with reference counting for efficiency
- **Binary API**: All control plane operations via message-based API

## API Development

API files (`*.api`) use VPP's IDL and are processed by `vppapigen` to generate:
- C headers and message handlers
- Python/Go bindings
- JSON schemas

Key patterns:
- `autoreply define <msg>` - Simple request/reply
- `define <msg>_dump` + `define <msg>_details` - Bulk queries
- `service { rpc want_<x>_events returns ... events <event>; }` - Event subscriptions
- Variable-length arrays: use `u8 data[]` (new style), not `u8 data[0]`

## Commit Message Format

```
<feature>: <subject (max 50 chars)>

<body explaining why, max 72 char lines>

Type: <feature|fix|refactor|improvement|style|docs|test|make>
Signed-off-by: <email>
```

Feature names: ip, fib, nat, acl, host, api, session, http, etc.

## Contributing

VPP uses Gerrit for code review at `gerrit.fd.io`:
```bash
git review           # Submit patch for review
git review -d <num>  # Download existing patch
```

## Directory Structure

```
src/
├── vppinfra/      # Infrastructure library
├── vlib/          # Core processing framework
├── vnet/          # Network stack
├── plugins/       # Loadable plugins
├── vpp/           # Main application
├── vpp-api/       # API bindings
├── tools/         # vppapigen and utilities
└── cmake/         # CMake modules

test/              # Python test framework
test/hs-test/      # Go host stack tests
test/kube-test/    # Kubernetes/perf tests
docs/              # Sphinx documentation
build-root/        # Build output
```

## Build Output

Debug builds go to `build-root/build-vpp_debug-native/` and install to `build-root/install-vpp_debug-native/`.
Release builds use `build-vpp-native/` instead.
