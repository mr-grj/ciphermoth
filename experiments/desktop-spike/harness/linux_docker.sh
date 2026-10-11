#!/bin/sh
set -eu

platform="${1:-linux/arm64}"
out="${2:?usage: linux_docker.sh <docker platform> <results dir>}"
repo="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
name="cm-spike-$(echo "$platform" | tr '/' '-')"
mkdir -p "$out"

docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --init --name "$name" --platform "$platform" --shm-size=1g ubuntu:22.04 sleep infinity >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT

git -C "$repo" archive --format=tar HEAD | docker exec -i "$name" sh -c 'mkdir -p /src && tar -x -C /src'

docker exec -i "$name" bash -s <<'EOF'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends ca-certificates curl git sudo build-essential pkg-config \
  libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev libxdo-dev libssl-dev \
  patchelf file xvfb xauth dbus-x11 lsof >/dev/null
curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null
curl -fsSL https://deb.nodesource.com/setup_22.x | bash - >/dev/null
apt-get install -y -qq nodejs >/dev/null
curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null
EOF

docker exec -i "$name" bash -lc '
  export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
  export WEBKIT_DISABLE_DMABUF_RENDERER=1 LIBGL_ALWAYS_SOFTWARE=1
  cd /src
  uv python install 3.13.15 >/dev/null
  uv run --no-project --python 3.13.15 experiments/desktop-spike/harness/spike_ci.py \
    --target "'"$platform"'-docker" --bundles deb --out /results --repeat 5 \
    --stages core vectors core_tests app install lifecycle
' || echo "spike_ci exited with $?"

docker cp "$name:/results/." "$out/"
