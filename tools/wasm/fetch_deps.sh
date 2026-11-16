#!/usr/bin/env bash
# Fetch the third-party code the site is built from, at pinned versions, into deps/
# (gitignored): four C libraries for the main WASM module, and for the fresh-key
# module the MicroPython runtime, embit, and the ESP32 firmware's own cryptographic
# modules. The site runs no third-party JavaScript.
#
# These are NOT git submodules of this repo on purpose. This repo is mirrored to
# four forges, and submodules make every mirror carry a URL that has to resolve from
# wherever the clone happened; a pinned manifest plus a fetch script keeps the
# mirrors plain copies. The pin is the SHA below. Moving it is a deliberate,
# reviewable edit rather than a `git submodule update --remote` that quietly slides.
# (A fetched dependency may have submodules of its own; those come along at the
# commits its pin records.)
#
# Local checkouts win when present, so you can iterate on cUR or k_quirc in
# their own working tree and rebuild here without pushing anything:
#
#   SSQR_CUR_DIR=~/dev/seedsigner-micropython-builder/deps/cUR \
#   SSQR_KQUIRC_DIR=~/dev/esp-camera-pipeline/components/k_quirc \
#     bash tools/wasm/fetch_deps.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEPS="$REPO_ROOT/deps"

# --- pins -------------------------------------------------------------------
# cUR: the same UR codec the ESP32 firmware runs, so browser-generated frames
# are byte-identical to the device's rather than merely equivalent.
CUR_URL="https://github.com/kdmukAI-bot/cUR.git"
CUR_REF="0ed276bc10b70556925bb42f85149d7c837a6c51"

# k_quirc: SeedSigner's own QR decoder (OpenMV's quirc, adapted). Using the
# device's decoder to read the device's screen means a frame the browser cannot
# read is a frame the hardware would likely also struggle with.
# Pinned to the tip of `seedsigner-dev`, the branch the SeedSigner firmware
# tracks, rather than `main`: the point of using k_quirc here is that the
# browser reads the device's screen with the device's decoder, and a pin that
# lags the firmware quietly gives that up.
KQUIRC_URL="https://github.com/kdmukAI-bot/k_quirc.git"
KQUIRC_REF="494dcc738c94533810eda2e436f832ffb72b8045"

# Nayuki's QR encoder. Chosen because it exposes the exact knobs Sparrow's zxing
# call uses (fixed EC level with no automatic boost, smallest fitting version,
# automatic mask), which is what lets tools/verify.py assert byte-equality with
# the Python `qrcode` output.
QRCODEGEN_URL="https://github.com/nayuki/QR-Code-generator.git"
QRCODEGEN_REF="2c9044de6b049ca25cb3cd1649ed7e27aa055138"

# libsecp256k1, for verifying the signatures a SeedSigner hands back. This is the
# component the ESP32 firmware compiles: ElementsProject/secp256k1-zkp at d9560e0
# (a submodule here, and the same commit embit 0.8.0 builds the Pi's bundled
# library from) plus a single-file build config and the precomputed signing table,
# which a July 2021 commit does not ship. Signature checking belongs in the
# library Bitcoin itself uses, not in a JavaScript reimplementation.
SECP256K1_URL="https://github.com/kdmukAI-bot/esp-secp256k1.git"
SECP256K1_REF="6eda9b6a8ddb2160731ebdec7800f5a488830873"

# --- the fresh-key module (tools/wasm/build_mpy.sh) --------------------------
# The fresh-key mode runs embit itself in the browser, on the interpreter the ESP32
# firmware runs, so a throwaway key's PSBT, sighashes, and reference signatures come
# from the code a SeedSigner signs with rather than from a reimplementation.
MICROPYTHON_URL="https://github.com/micropython/micropython.git"
MICROPYTHON_REF="78ff170de9e32c79db6e64d3e33d2bd60002bdcd"      # v1.27.0, the firmware's
# Freezing modules requires this submodule to be present; this is the commit
# v1.27.0 records for it. Nothing from it is frozen.
MICROPYTHON_LIB_URL="https://github.com/micropython/micropython-lib.git"
MICROPYTHON_LIB_REF="6ae440a8a144233e6e703f6759b7e7a0afaa37a4"
# Upstream embit at the v0.8.0 tag: the Python sources of the 0.8.0 release that
# SeedSigner 0.8.x pins (identical to the PyPI package).
EMBIT_URL="https://github.com/diybitcoinhardware/embit.git"
EMBIT_REF="84cce66fb831fa6d625fb73f28e03605f3c04e28"
# The firmware's SHA-512, PBKDF2, HMAC-SHA512, and RIPEMD-160 module and the frozen
# hashlib.py and hmac.py shims that route embit to it.
FIRMWARE_URL="https://github.com/kdmukAI-bot/seedsigner-micropython-builder.git"
FIRMWARE_REF="a9f865c68b20457692ab4547e3394785114b507f"
# The mbedtls that module is built on in the firmware: ESP-IDF 5.5.1's submodule.
MBEDTLS_URL="https://github.com/espressif/mbedtls.git"
MBEDTLS_REF="b5d87eaa6748b7a6fa70593178c08b4480e9b71e"

# --- fetch ------------------------------------------------------------------

link_local() {
  local name="$1" src="$2"
  [ -n "$src" ] || return 1
  if [ ! -d "$src" ]; then
    echo "ERROR: $name override '$src' is not a directory" >&2
    exit 1
  fi
  rm -rf "${DEPS:?}/$name"
  ln -s "$(cd "$src" && pwd)" "$DEPS/$name"
  echo "  $name  -> local checkout $src"
}

fetch() {
  local name="$1" url="$2" ref="$3"
  local dir="$DEPS/$name"

  if [ -L "$dir" ]; then           # previous local override; take it back over
    rm -f "$dir"
  fi
  if [ ! -d "$dir/.git" ]; then
    rm -rf "$dir"
    # Full clone rather than --depth 1: a shallow clone can only check out the
    # tip, and the pin is deliberately allowed to lag the branch.
    git clone --quiet "$url" "$dir"
  fi
  if [ "$(git -C "$dir" rev-parse HEAD)" != "$ref" ]; then
    git -C "$dir" fetch --quiet origin
    git -C "$dir" checkout --quiet --detach "$ref"
  fi
  if [ -f "$dir/.gitmodules" ]; then
    git -C "$dir" submodule --quiet update --init --recursive
  fi
  echo "  $name  @ ${ref:0:12}"
}

# One commit, no history: for the large trees, where a full clone would be hundreds
# of megabytes for a few files. GitHub serves any commit by its SHA. Submodules are
# not fetched; the one MicroPython needs is fetched on its own.
fetch_commit() {
  local name="$1" url="$2" ref="$3" dir="${4:-$DEPS/$1}"
  if [ -L "$dir" ]; then rm -f "$dir"; fi
  if [ "$(git -C "$dir" rev-parse HEAD 2>/dev/null || true)" != "$ref" ]; then
    rm -rf "$dir"
    git init --quiet "$dir"
    git -C "$dir" fetch --quiet --depth 1 "$url" "$ref"
    git -C "$dir" checkout --quiet --detach FETCH_HEAD
  fi
  echo "  $name  @ ${ref:0:12}"
}

mkdir -p "$DEPS"
echo "==> Dependencies in $DEPS"
link_local cUR       "${SSQR_CUR_DIR:-}"       || fetch cUR       "$CUR_URL"       "$CUR_REF"
link_local k_quirc   "${SSQR_KQUIRC_DIR:-}"    || fetch k_quirc   "$KQUIRC_URL"    "$KQUIRC_REF"
link_local qrcodegen "${SSQR_QRCODEGEN_DIR:-}" || fetch qrcodegen "$QRCODEGEN_URL" "$QRCODEGEN_REF"
link_local esp-secp256k1 "${SSQR_SECP256K1_DIR:-}" \
  || fetch esp-secp256k1 "$SECP256K1_URL" "$SECP256K1_REF"
fetch_commit micropython "$MICROPYTHON_URL" "$MICROPYTHON_REF"
fetch_commit micropython-lib "$MICROPYTHON_LIB_URL" "$MICROPYTHON_LIB_REF" \
  "$DEPS/micropython/lib/micropython-lib"
fetch_commit embit "$EMBIT_URL" "$EMBIT_REF"
fetch_commit seedsigner-micropython-builder "$FIRMWARE_URL" "$FIRMWARE_REF"
fetch_commit mbedtls "$MBEDTLS_URL" "$MBEDTLS_REF"

# Retired: @noble/secp256k1 used to be fetched into site/vendor/. Remove a stale
# copy so a local build cannot keep serving it.
rm -f "$REPO_ROOT/site/vendor/noble-secp256k1.js"
