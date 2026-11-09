.. _native_macos:

Native builds on macOS
=====================

The Darwin build produces Mach-O executables and dynamic libraries for the
Mac running the build. It is separate from :ref:`cross_compile_macos`, which
uses a Linux cross toolchain and produces Linux binaries. Both paths remain
available.

Prerequisites
-------------

Install Xcode Command Line Tools, CMake, Git and Python 3 with venv support.
OpenSSL is optional; it enables the Prometheus push tool.

.. code-block:: console

   $ xcode-select --install
   $ brew install cmake python openssl@3

Build
-----

Run these commands in the repository root:

.. code-block:: console

   $ make build
   $ make release

``make build-release`` is also supported and is equivalent to ``make release``.
The first build creates an isolated Python environment and builds a pinned
revision of epoll-shim, which supplies epoll/eventfd/timerfd through kqueue.
This initial setup needs network access to PyPI and GitHub. Dependencies are
kept in ``build-root/build-darwin-deps`` and ``build-root/install-darwin-deps``.
No system Python packages or privileged installations are needed.
``make install-dep`` can perform this setup separately.

Debug executables are installed in
``build-root/install-vpp_debug-native/vpp/bin``; release executables are in
``build-root/install-vpp-native/vpp/bin``. Each installation includes its
epoll-shim dynamic library.

.. code-block:: console

   $ build-root/install-vpp-native/vpp/bin/vpp --version
   $ JOBS=8 make release
   $ make build VPP_EXTRA_CMAKE_ARGS="-DVPP_BUILD_VPPINFRA_TESTS=ON"

``JOBS`` controls compilation parallelism. CMake options can be passed through
``VPP_EXTRA_CMAKE_ARGS``. Build directories retain the usual
``build-root/build-vpp_debug-native/vpp`` and
``build-root/build-vpp-native/vpp`` paths, including
``compile_commands.json``.

The native make entry points pass ``VPP_PLUGINS=none`` and
``VPP_API_TEST_BUILTIN=OFF`` by default. No dataplane plugins, VAT/API test
plugins or builtin VAT test support are built. Plugin sources remain in the
tree. ``VPP_EXTRA_CMAKE_ARGS`` can override these settings in a later build.

Scope
-----

The existing Darwin source selection builds the VPP core, networking stack,
SVM, API clients, native VCL (``vppcom``) and command-line tools.
Linux and FreeBSD source selections remain available.

Darwin does not build the Linux/glibc ``vcl_ldpreload`` library. Its sources
remain in the tree, and the native VCL library is built. Hardware drivers,
the regular plugin collection, Linux netlink, virtio and FUSE are outside
the current Darwin source selection. Use the Linux build or cross-compilation
path for those components.

Linux CPU affinity, robust mutex recovery, huge pages, PCI access, queued
SVMDB signal notifications and Linux performance-counter benchmarks are not
provided by this Darwin port. Unsupported SVMDB notification registration
returns ``-ENOTSUP``; ``test_infra perf`` reports that Linux counters are
required. Functional ``test_infra`` tests remain available.

Validation
----------

.. code-block:: console

   $ build-root/build-vpp_debug-native/vpp/bin/test_infra
   $ build-root/build-vpp_debug-native/vpp/bin/test_dump_metrics

The native startup test checks the main loop, CLI and statistics client without
requiring root:

.. code-block:: console

   $ python3 extras/scripts/test_native_macos_tuntap.py --startup-only

The standard Linux startup configuration and Linux integration test harness
are not macOS runtime validation.

Native utun interface
---------------------

The core tuntap driver supports macOS utun without a dataplane plugin.
Enable it in ``startup.conf``:

.. code-block:: text

   tuntap {
     enable
     name utun
     mtu 4352
   }

``utun`` asks the kernel for an available interface number. ``utun<N>`` requests
a specific number and fails if it is already in use. The actual host interface
name appears in ``show files`` as ``vnet tuntap utun<N>``; the VPP interface is
``tuntap-0``.

macOS supports routed, layer-3 mode only. ``have-normal-interface`` is accepted
for compatibility and is the default. ``ethernet`` is rejected. Addresses and
routes on the host are configured separately; VPP interface addresses are not
mirrored into macOS. Set VPP interface addresses and administrative state through
the usual CLI commands. The startup MTU applies to both sides and must be
between 1280 and 65535 bytes.

The driver registers the nonblocking utun descriptor with ``clib_file``.
The existing epoll-shim supplies kqueue notifications; ``tuntap-rx`` and
``tuntap-tx`` strip and prepend utun's four-byte network-order address-family
header. Closing VPP removes its utun interface.

Creating utun and configuring host addresses requires root. Run the integration
test to create a temporary interface, check IPv4 and IPv6 echo replies with
56-byte and 3000-byte payloads, and verify removal at shutdown:

.. code-block:: console

   $ sudo python3 extras/scripts/test_native_macos_tuntap.py
   $ sudo python3 extras/scripts/test_native_macos_tuntap.py \
       --build-dir build-root/build-vpp-native/vpp

The test uses only a temporary utun, addresses in ``198.18.0.0/30`` and
``fd12:3456:789a::/64``, and a host route to the test IPv6 peer. It does not
change the default route. These test ranges must not already be in use.
