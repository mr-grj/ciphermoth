#!/bin/sh
set -eu

version="${OPENSSL_VERSION:-4.0.1}"
target="${1:?usage: build_openssl.sh <openssl-target> <prefix>}"
prefix="${2:?usage: build_openssl.sh <openssl-target> <prefix>}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

curl -fsSL -o "$work/openssl.tar.gz" \
  "https://github.com/openssl/openssl/releases/download/openssl-$version/openssl-$version.tar.gz"
curl -fsSL -o "$work/openssl.tar.gz.sha256" \
  "https://github.com/openssl/openssl/releases/download/openssl-$version/openssl-$version.tar.gz.sha256"
expected="$(awk '{print $1}' "$work/openssl.tar.gz.sha256")"
actual="$(shasum -a 256 "$work/openssl.tar.gz" | awk '{print $1}')"
[ "$expected" = "$actual" ] || { echo "openssl checksum mismatch" >&2; exit 1; }

tar -xzf "$work/openssl.tar.gz" -C "$work"
cd "$work/openssl-$version"
./Configure "$target" no-shared no-tests no-docs no-apps --prefix="$prefix" --libdir=lib \
  ${OPENSSL_EXTRA_FLAGS:-}
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)" build_libs >/dev/null
make install_dev >/dev/null
echo "OpenSSL $version installed to $prefix"
