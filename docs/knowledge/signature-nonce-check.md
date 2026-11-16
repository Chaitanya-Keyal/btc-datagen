# Checking a device's signing nonces against a reference signature

The scan-back step compares every valid signature the device returns, byte for byte,
with a reference signature the build makes from the same throwaway key over the same
sighash. That comparison is the check someone vetting a device for nonce-based seed
exfiltration (the Dark Skippy attack) is looking for. This note covers why the
comparison is sound, the trap that would make it raise false alarms, and what a match
does not prove.

Related: `runtime-qr-and-camera-readback.md` (the scan-back pipeline),
`embit-psbt-traps.md`.

## Why a correct SeedSigner is predictable to the byte

SeedSigner signs through embit, with `psbt.sign_with(root)` and the default sighash.
Everything that goes into the signature is a function of the key and the digest:

- **ECDSA** uses libsecp256k1's default nonce function, RFC 6979. embit's
  `PrivateKey.sign` then grinds for a low R: while the DER encoding is longer than 70
  bytes, it signs again with a counter (1, 2, ...) as 32-byte little-endian extra
  nonce data. The counter sequence is fixed, so the grinding is deterministic too.
- **Schnorr** (taproot key path) calls `schnorrsig_sign` with no auxiliary data, and
  embit writes the 64-byte signature straight into the input's final witness, with a
  flag byte only for a sighash other than DEFAULT.

**Rule:** the reference must come from that same call on a copy of the same PSBT
(`reference_signatures` in `tools/build_site.py`), not from a separate RFC 6979 signer.
A reference that skips the grinding loop, or grinds differently, disagrees with an
honest device on roughly half of all ECDSA signatures.

## The signing backends agree at embit 0.8.0

embit picks its secp256k1 backend at import: a prebuilt libsecp256k1 through ctypes
(the Pi), a pure-Python fallback, or on MicroPython the firmware's own `secp256k1`
module. The compiled backends share one source: embit 0.8.0 builds its bundled
binaries from a submodule pinned to ElementsProject/secp256k1-zkp at `d9560e0`, and
the ESP32 firmware compiles that same commit. All three backends produce the same
bytes. The ctypes and pure-Python backends agree on ECDSA, ground ECDSA, and Schnorr
across 200 random key and digest pairs, and the firmware's BIP340 nonce function uses
the same unmasked-key construction described below.

Because the source is shared, a browser can reproduce a device's signatures by running
`d9560e0` itself, compiled to WASM. The site does: its verifier is that library in the
main WASM module, and the random-key check runs embit's own `sign_with` over it in a
MicroPython build (`micropython-in-the-browser.md`). A BIP340 library written to the
current spec cannot: see the next section.

## Trap: "no aux data" changed meaning in libsecp256k1

BIP340 nonce generation masks the secret key with a hash of 32 bytes of auxiliary
data. When the caller passes none, older libsecp256k1, and every backend above, skips
the masking and hashes the key directly. Current libsecp256k1 instead treats missing
aux data as 32 zero bytes and masks the key with `TaggedHash("BIP0340/aux", 0x00..00)`.

Both produce valid signatures, and they are different signatures. If the libsecp256k1
under embit changes on one side only (this repo's venv, or SeedSigner's embit pin or
firmware), every taproot scan reports a mismatch while every ECDSA scan matches. That
pattern points at the library, not at the device.

**Rule:** whenever embit or its libsecp256k1 moves on either side, check a taproot scan
on hardware. The automated tests sign with this repo's embit on both sides of the
comparison, so they cannot see this drift.

A related limit: BIP340 recommends fresh auxiliary randomness. Its purpose is
side-channel protection, but it works by entering the nonce (`t = d xor
hash(aux)`, then `k = hash(t || P || m)`), so a signer that follows the recommendation
produces a different valid signature every time, and byte comparison cannot vet it at
all. Don't confuse it with libsecp256k1's context randomization
(`secp256k1_context_randomize`), which blinds the internal arithmetic against timing
and power analysis without changing any output: ECDSA and Schnorr signatures come out
identical across a re-randomized context. The check depends on SeedSigner signing
deterministically, with no auxiliary data.

## What a match proves, and what it does not

A match proves that the signature's nonce came from the key and the digest alone, so
nothing is hidden in that signature. It does not prove the device behaves the same
with other keys or transactions. This site's seeds and transactions are published and
fixed, so firmware written to evade exactly this check could recognize them and sign
honestly only for them. That is a limit of any black-box test with known inputs.

The random-key check (*Check my SeedSigner*) is the stronger test: a key made in the
browser on the spot, spending made-up coins with random amounts, outpoints,
recipient, and fee, so there is no published seed or transaction to recognize. It
still cannot prove the device behaves the same with a key that holds real funds, but
firmware would then have to cheat on keys it has never seen, which is the case the
attack depends on.

## What a mismatch means

The signature verifies against the right key and the right sighash, so the device
signed the right transaction with the right key, and only the nonce differs. The
possible causes are the device choosing its own nonce (the exfiltration channel), the
device adding BIP340 auxiliary randomness, or the library trap above. Only the first is
dangerous, and the page cannot tell them apart, so it shows an alarm and tells the user
not to trust the device with real funds until the cause is known.

## How the check is tested

`tools/wasm/reference.py` builds a "different nonce" case for each signing shape: the
honest PSBT with input 0 re-signed over the same digest, using constant extra nonce
data that no grinding counter reaches. The round-trip test requires that case to verify
as valid and complete while reporting `anyDifferent`, and the smoke test requires the
page to show the alarm. The honest "signed" cases must report no difference, which is
what proves the build's references and the browser's comparison agree.

For the random-key check, the round-trip test also signs each in-browser session the
way a device does (embit under CPython), and once more with a different nonce, and
requires the same verdicts against the session's own references. The smoke test does
it through the camera in a real browser for a native segwit and a taproot key.
