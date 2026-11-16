// MicroPython variant for btc-datagen's fresh-key module (tools/wasm/build_mpy.sh).
//
// No node REPL hook: the stock variant polls stdin every 10 bytecodes for Ctrl-C,
// which hangs or aborts anywhere but an interactive node REPL.
//
// The split heap that grows on demand: the stock GC scans the C stack and registers
// through Asyncify, which throws its unwind marker (Infinity) out of a synchronous
// runPython the moment a collection runs. The split heap never scans the stack; it
// collects between calls, where nothing on the stack can hold a Python object. The
// pyscript variant uses the same two settings.
#define MICROPY_VARIANT_ENABLE_JS_HOOK          (0)
#define MICROPY_GC_SPLIT_HEAP                   (1)
#define MICROPY_GC_SPLIT_HEAP_AUTO              (1)
