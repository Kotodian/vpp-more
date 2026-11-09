#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Native Darwin build. Keep dependencies and artifacts inside build-root;
# the Linux build-root/external dependency recipes remain unchanged.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
deps_build="$root/build-root/build-darwin-deps"
deps_prefix="$root/build-root/install-darwin-deps"
venv="$deps_build/venv"
cmake=${CMAKE:-cmake}
jobs=${JOBS:-$(sysctl -n hw.logicalcpu 2>/dev/null || echo 2)}
epoll_revision=18159584bb3d17e601b9315a7398ace018251bdc

if [[ $(uname -s) != Darwin ]]; then
  echo "This script builds native macOS binaries; use make build on other hosts." >&2
  exit 1
fi

mode=${1:-Debug}
shift || true
case "$mode" in
  deps|Debug|Release) ;;
  *) echo "Usage: $0 {deps|Debug|Release} [CMake options...]" >&2; exit 2 ;;
esac

for tool in "$cmake" git clang python3; do
  if ! command -v "$tool" >/dev/null; then
    echo "Missing $tool. Install Xcode Command Line Tools, CMake and Python 3 first." >&2
    exit 1
  fi
done

mkdir -p "$deps_build"
if [[ ! -x "$venv/bin/python3" ]]; then
  python3 -m venv "$venv"
fi
requirements="$root/extras/scripts/macos-requirements.txt"
if [[ ! -f "$deps_build/python-requirements.ok" ]] ||
   ! cmp -s "$requirements" "$deps_build/python-requirements.ok"; then
  "$venv/bin/python3" -m pip install --disable-pip-version-check \
    -r "$requirements"
  cp "$requirements" "$deps_build/python-requirements.ok"
fi
export PATH="$venv/bin:$PATH"

# Pin the shim source so a clean checkout does not silently change its ABI.
if [[ ! -f "$deps_build/epoll-revision.ok" ]] ||
   [[ $(cat "$deps_build/epoll-revision.ok") != "$epoll_revision" ]] ||
   [[ ! -f "$deps_prefix/lib/cmake/epoll-shim/epoll-shim-config.cmake" ]]; then
  if [[ ! -d "$deps_build/epoll-shim/.git" ]]; then
    git init "$deps_build/epoll-shim"
    git -C "$deps_build/epoll-shim" remote add origin \
      https://github.com/jiixyj/epoll-shim.git
  fi
  if ! git -C "$deps_build/epoll-shim" cat-file -e "$epoll_revision^{commit}" 2>/dev/null; then
    git -C "$deps_build/epoll-shim" fetch --depth 1 origin "$epoll_revision"
  fi
  git -C "$deps_build/epoll-shim" checkout --detach "$epoll_revision"
  "$cmake" -S "$deps_build/epoll-shim" -B "$deps_build/epoll-build" \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
    -DCMAKE_INSTALL_PREFIX="$deps_prefix"
  "$cmake" --build "$deps_build/epoll-build" --parallel "$jobs"
  "$cmake" --install "$deps_build/epoll-build"
  printf '%s\n' "$epoll_revision" > "$deps_build/epoll-revision.ok"
fi

[[ "$mode" != deps ]] || exit 0

tag=vpp
[[ "$mode" != Debug ]] || tag=vpp_debug
build_dir="$root/build-root/build-$tag-native/vpp"
install_dir="$root/build-root/install-$tag-native/vpp"
prefix_path="$deps_prefix"
if command -v brew >/dev/null; then
  openssl_prefix=$(brew --prefix openssl@3 2>/dev/null || true)
  [[ ! -d "$openssl_prefix" ]] || prefix_path="$prefix_path;$openssl_prefix"
fi
[[ -z ${CMAKE_PREFIX_PATH:-} ]] || prefix_path="$prefix_path;$CMAKE_PREFIX_PATH"

"$cmake" -S "$root/src" -B "$build_dir" -G Ninja \
  -DCMAKE_MAKE_PROGRAM="$venv/bin/ninja" \
  -DPython3_EXECUTABLE="$venv/bin/python3" \
  -DCMAKE_BUILD_TYPE="$mode" \
  -DCMAKE_INSTALL_PREFIX="$install_dir" \
  -DCMAKE_PREFIX_PATH="$prefix_path" \
  -DVPP_PLUGINS=none \
  -DVPP_API_TEST_BUILTIN=OFF \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON "$@"
"$cmake" --build "$build_dir" --parallel "$jobs"
"$cmake" --install "$build_dir"
printf '\nNative macOS %s binaries: %s/bin\n' "$mode" "$install_dir"
