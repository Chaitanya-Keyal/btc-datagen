# Running embit in the browser on MicroPython

The random-key check (*Check my SeedSigner*) builds a throwaway key, a PSBT, its
sighashes, and the reference signatures in the browser. All of that is embit's
code, running on MicroPython v1.27.0's `ports/webassembly`, built by
`tools/wasm/build_mpy.sh` from the files in `tools/wasm/mpy/`. This note covers why
it is built that way and the traps in each setting.

Related: `signature-nonce-check.md` (what the reference signatures are for),
`runtime-qr-and-camera-readback.md` (the scan step that consumes them).

## Why an interpreter at all

embit is Python, and WebAssembly cannot run Python source, so something has to
interpret it. The choices:

- **MicroPython** (what this uses): the interpreter the ESP32 firmware runs. The
  module is about 390 KB gzipped with embit frozen in.
- **CPython in WASM (Pyodide)**: the Pi's interpreter, but a much larger download,
  and embit's loader for a native libsecp256k1 would find nothing to load, leaving
  its pure-Python curve code.
- **Python interpreters written in JavaScript**: the curve and hash code would then
  run in JavaScript, which is what this site avoids.
- **A C library instead of embit** (libwally, for example): no interpreter, but a
  different implementation than the one the device signs with, which defeats the
  point of a reference signature.

## What goes into the module

- **The firmware's C modules, unchanged.** `esp-secp256k1/mpy/modsecp256k1.c` (the
  `secp256k1` module embit imports on MicroPython) over secp256k1-zkp @ d9560e0,
  and the builder's `bindings/modhashlibext.c` (`_hashlib_ext`: SHA-512, PBKDF2,
  HMAC-SHA512, RIPEMD-160) over the mbedtls ESP-IDF 5.5.1 ships. Two ESP-IDF
  dependencies get stand-ins: `esp_fill_random` becomes `getentropy` (it only seeds
  context blinding, which never changes a signature), and mbedtls is built from
  source with a four-primitive config instead of IDF's component.
- **Frozen Python**: upstream embit 0.8.0, the firmware's `hashlib.py` and `hmac.py`
  shims (which route embit's SHA-512, PBKDF2, and HMAC to the C module), and
  `freshkey.py`.
- **User modules use make, not cmake.** The webassembly port reads
  `USER_C_MODULES/*/micropython.mk`; the ESP32 build's cmake files do not apply.
  Absolute paths in `SRC_USERMOD_C` work, so the firmware sources compile in place.

## Traps

**The port compiles with `-Werror`, added after the user-module flags.** A
`-Wno-error` in `CFLAGS_USERMOD` loses. Pinned third-party sources (libsecp256k1,
mbedtls) compile through one-line wrapper files that start with
`#pragma clang diagnostic ignored "-Weverything"` and `#include` the real file;
the firmware's own module sources compile cleanly as they are.

**The stock garbage collector breaks synchronous calls.** It finds live objects by
scanning the C stack and registers, and in WASM the registers are only reachable
by unwinding through Asyncify. Under the synchronous `runPython`, the first
collection throws Asyncify's unwind marker (`Infinity`) out of the call, and
`runPythonAsync` does not help. Any allocation-heavy call (signing three inputs is
enough) eventually triggers one, and the module's state is corrupt afterward.

**Rule:** build with `MICROPY_GC_SPLIT_HEAP` and `MICROPY_GC_SPLIT_HEAP_AUTO`, plus
`-s ALLOW_MEMORY_GROWTH`, as the port's pyscript variant does. The heap then grows
instead of collecting during a call, and collects between calls, when no C frame
can hold a Python object. The consequence for anything long-running: a Python call
that never returns to JavaScript never collects.

**The stock variant's node REPL hook.** It polls stdin every ten bytecodes for
Ctrl-C. Outside an interactive node REPL that hangs or trips an emscripten
assertion. **Rule:** `MICROPY_VARIANT_ENABLE_JS_HOOK 0`; a browser never needs it.

**The default Python stack is too small for embit.** `loadMicroPython` defaults to
`pystack: 2 * 1024` words, and importing `embit.bip39` builds the 2048-word list as
one literal, which raises `RuntimeError: pystack exhausted`. **Rule:** pass
`pystack: 16 * 1024`.

**The link step defaults to a debug build.** The port compiles with `-Os` but links
with no optimization flag, so emscripten keeps its assertions and the output is
about twice the size. **Rule:** pass `LDFLAGS='-sASSERTIONS=0 -Os'`.

**`makeversionhdr` runs git inside the MicroPython tree.** A clone that borrows
objects from elsewhere (`git clone --shared`, or a submodule checkout whose objects
live in a parent `.git`) hands it an error message instead of a hash when the
build runs in a container that cannot see that path, and the generated header does
not compile. A self-contained clone, shallow or full, is fine; `fetch_deps.sh`
fetches the pinned commit alone.

**Freezing needs `lib/micropython-lib` present**, even when nothing from it is
frozen. The manifest tool refuses to run without it.

**Python globals and JavaScript.** Assigning a Python global from JavaScript
(`mp.globals.set`) can fail the second time once Python has reassigned it. Pass
inputs into `runPython` as literals instead: a JSON string is a valid Python
string literal. Reading a global back (`mp.globals.get`) is fine.

**MicroPython dicts do not keep insertion order.** The same dict serializes with
its keys in a different order under MicroPython and CPython. Compare JSON from the
two after sorting keys, never as raw strings.

## How it is held to CPython

`tools/wasm/reference.py` runs `freshkey.py` under CPython for every script type on
both networks, and asserts that each session's verification data and summary equal
what `tools/build_site.py` computes for its PSBT. `tools/wasm/roundtrip_test.mjs`
then requires the WASM module, given the same random bytes, to return the same
sessions (keys sorted), and runs a device-style signature and a re-nonced one
through the scan step's verifier. `tools/smoke_site.mjs` does it end to end in a
browser: the page makes a key, embit under CPython signs it as a device would, and
the scan must report an exact match.
