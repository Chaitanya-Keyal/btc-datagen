#!/usr/bin/env bash
# Build site/vendor/micropython.{mjs,wasm}: the fresh-key module.
#
# MicroPython v1.27.0's webassembly port, with the ESP32 firmware's two
# cryptographic modules (libsecp256k1 and the mbedtls hash functions) compiled in
# and embit 0.8.0 frozen into it, so the page runs the code a SeedSigner signs
# with. See tools/wasm/mpy/ for the variant, the modules, and the manifest, and
# docs/knowledge/micropython-in-the-browser.md for why each setting is what it is.
#
# Docker-only with the same pinned emsdk image as build.sh. Sources come from
# fetch_deps.sh. Run by build.sh; standalone:
#
#   bash tools/wasm/build_mpy.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

EMSDK_TAG="${EMSDK_TAG:-3.1.74}"
IMAGE="emscripten/emsdk:${EMSDK_TAG}"
OUT_DIR="$REPO_ROOT/site/vendor"
EMCACHE_HOST="$SCRIPT_DIR/.emcache"
PORT=deps/micropython/ports/webassembly
BUILD_DIR=build-btc-datagen

mkdir -p "$OUT_DIR" "$EMCACHE_HOST"

# A local esp-secp256k1 override lands in deps/ as a symlink (see build.sh).
EXTRA_MOUNTS=()
if [ -L "$REPO_ROOT/deps/esp-secp256k1" ]; then
  EXTRA_MOUNTS+=(-v "$(readlink -f "$REPO_ROOT/deps/esp-secp256k1")":/src/deps/esp-secp256k1:ro)
fi

# ASSERTIONS=0: the port's link step otherwise defaults to a debug build (no -O),
# which is twice the size. -Os matches the port's own compile flags.
echo "==> Building site/vendor/micropython.mjs with ${IMAGE}"
docker run --rm \
  -v "$REPO_ROOT":/src -w /src \
  "${EXTRA_MOUNTS[@]}" \
  -v "$EMCACHE_HOST":/emcache \
  -u "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e EM_CACHE=/emcache \
  "$IMAGE" \
  sh -c "make -C deps/micropython/mpy-cross -j\$(nproc) >/dev/null \
    && make -C $PORT -j\$(nproc) \
      BUILD=$BUILD_DIR \
      VARIANT_DIR=/src/tools/wasm/mpy/variant \
      USER_C_MODULES=/src/tools/wasm/mpy/usermods \
      FROZEN_MANIFEST=/src/tools/wasm/mpy/manifest.py \
      BTC_DEPS=/src/deps \
      'LDFLAGS=-sASSERTIONS=0 -Os'"

cp "$REPO_ROOT/$PORT/$BUILD_DIR/micropython.mjs" "$REPO_ROOT/$PORT/$BUILD_DIR/micropython.wasm" \
  "$OUT_DIR/"

echo ""
echo "==> Done:"
ls -la "$OUT_DIR"/micropython.mjs "$OUT_DIR"/micropython.wasm
