#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the native tuntap nodes through a temporary macOS utun."""

import argparse
import ctypes
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time


def run(*args):
    result = subprocess.run(
        [str(arg) for arg in args],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=15,
    )
    if result.returncode:
        raise RuntimeError(f"{args}: exit {result.returncode}\n{result.stdout}")
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--build-dir",
        type=Path,
        default=Path(__file__).resolve().parents[2]
        / "build-root/build-vpp_debug-native/vpp",
    )
    parser.add_argument("--startup-only", action="store_true")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("this test requires macOS")
    if not args.startup_only and os.geteuid() != 0:
        parser.error("utun creation and address configuration require sudo")

    build = args.build_dir.resolve()
    prefix = f"vut{os.getpid()}"
    page_size = f'{os.sysconf("SC_PAGE_SIZE") // 1024}k'
    process = None
    interface = None
    route6 = False
    # Use a short socket path, and no default routes or physical interfaces.
    with tempfile.TemporaryDirectory(prefix="vut-", dir="/tmp") as tmp:
        tmp = Path(tmp)
        cli_socket = tmp / "cli.sock"
        config = tmp / "startup.conf"
        config_text = (
            f"unix {{ nodaemon nosyslog runtime-dir {tmp} "
            f"cli-listen {cli_socket} }}\n"
            f"api-segment {{ prefix {prefix} }}\n"
            f"statseg {{ socket-name {tmp}/stats.sock page-size {page_size} }}\n"
            f"buffers {{ buffers-per-numa 1024 page-size {page_size} }}\n"
            f"tuntap {{ {'disable' if args.startup_only else 'enable mtu 4352'} }}\n"
        )

        def cleanup_shm():
            libc = ctypes.CDLL(None)
            for name in ("global_vm", "vpe-api"):
                libc.shm_unlink(f"/{prefix}-{name}".encode())

        # These inputs must fail before opening a privileged utun socket.
        for setting, expected in (
            ("enable ethernet", "supports routed utun only"),
            ("enable name invalid", "utun name must be"),
            ("enable mtu 1279", "utun MTU must be"),
            ("enable mtu 65536", "utun MTU must be"),
        ):
            config.write_text(
                re.sub(r"tuntap \{[^}]*\}", f"tuntap {{ {setting} }}", config_text)
            )
            try:
                result = subprocess.run(
                    [str(build / "bin/vpp"), "-c", str(config)],
                    capture_output=True, text=True, timeout=15,
                )
                if expected not in result.stdout + result.stderr:
                    raise RuntimeError(
                        f"invalid config was not rejected: {setting}\n"
                        f"{result.stdout}{result.stderr}"
                    )
            finally:
                cleanup_shm()
        print("PASS: invalid mode, name and MTU rejected", flush=True)
        config.write_text(config_text)

        def cli(command):
            result = run(build / "bin/vppctl", "-s", cli_socket, command)
            if "unknown input" in result or "failed" in result:
                raise RuntimeError(result)
            return result

        with (tmp / "vpp.log").open("w+") as log:
            try:
                process = subprocess.Popen(
                    [str(build / "bin/vpp"), "-c", str(config)],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                )
                deadline = time.monotonic() + 15
                while True:
                    if process.poll() is not None:
                        raise RuntimeError(
                            f"VPP exited during startup: {process.returncode}"
                        )
                    if time.monotonic() >= deadline:
                        raise RuntimeError("VPP CLI did not start within 15s")
                    if cli_socket.exists():
                        try:
                            version = cli("show version")
                            break
                        except RuntimeError as error:
                            if "Connection refused" not in str(error):
                                raise
                    time.sleep(0.05)
                print(version, flush=True)
                stats = ctypes.CDLL(str(build / "lib/libvppapiclient.dylib"))
                stats.stat_segment_connect.argtypes = [ctypes.c_char_p]
                if stats.stat_segment_connect(str(tmp / "stats.sock").encode()):
                    raise RuntimeError("native stats client failed to connect")
                stats.stat_segment_disconnect()
                print("PASS: statistics socket and shared memory", flush=True)
                if args.startup_only:
                    print("PASS: native VPP startup with tuntap disabled")
                    return

                files = cli("show files")
                match = re.search(r"vnet tuntap (utun\d+)", files)
                if not match:
                    raise RuntimeError(f"utun missing from clib_file:\n{files}")
                interface = match[1]
                print(f"Testing {interface} through clib_file", flush=True)
                cli("set interface state tuntap-0 up")
                cli("set interface ip address tuntap-0 198.18.0.2/30")
                cli("set interface ip address tuntap-0 fd12:3456:789a::2/64")
                run("/sbin/ifconfig", interface, "inet", "198.18.0.1", "198.18.0.2")
                run(
                    "/sbin/ifconfig", interface, "inet6",
                    "fd12:3456:789a::1", "prefixlen", "64",
                )
                run(
                    "/sbin/route", "-n", "add", "-inet6", "-host",
                    "fd12:3456:789a::2", "-interface", interface,
                )
                route6 = True
                for ping, destination in (
                    ("/sbin/ping", "198.18.0.2"),
                    ("/sbin/ping6", "fd12:3456:789a::2"),
                ):
                    for size in (56, 3000):
                        result = run(ping, "-n", "-c", "3", "-s", size, destination)
                        if not re.search(r"3 packets received|3 received", result):
                            raise RuntimeError(result)
                        print(f"PASS: {destination}, payload {size} bytes", flush=True)
                print(cli("show interface tuntap-0"), flush=True)
                print(cli("show errors"), flush=True)
            except BaseException:
                log.flush()
                log.seek(0)
                print(log.read(), file=sys.stderr)
                raise
            finally:
                if route6:
                    subprocess.run(
                        ["/sbin/route", "-n", "delete", "-inet6", "-host",
                         "fd12:3456:789a::2", "-interface", interface],
                        capture_output=True,
                        timeout=5,
                    )
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                cleanup_shm()
                if interface and subprocess.run(
                    ["/sbin/ifconfig", interface], capture_output=True
                ).returncode == 0:
                    raise RuntimeError(f"{interface} survived VPP shutdown")


if __name__ == "__main__":
    main()
