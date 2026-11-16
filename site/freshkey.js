/* The fresh-key mode's link to embit.
 *
 * Loads the MicroPython module (site/vendor/micropython.{mjs,wasm}, built by
 * tools/wasm/build_mpy.sh) the first time it is needed, and asks the frozen
 * `freshkey` module for a session: a new throwaway key, a transaction that spends
 * made-up coins to it, and the verification data the scan step checks the device's
 * signatures against. Everything Bitcoin-specific happens in embit, the library a
 * SeedSigner signs with; this file only passes random bytes in and JSON out.
 *
 * Nothing is stored. A session lives in the page's memory until the next one
 * replaces it or the tab closes.
 */
import { loadMicroPython } from './vendor/micropython.mjs';

export const SCRIPT_TYPES = ['P2WPKH', 'P2TR', 'P2SH-P2WPKH', 'P2PKH'];

let mpPromise = null;

function load() {
  if (!mpPromise) {
    // pystack is in words: embit's 2048-word BIP39 list is one literal, and building
    // it overflows the default of 2K. The heap starts small and grows as needed.
    mpPromise = loadMicroPython({ pystack: 16 * 1024, heapsize: 2 * 1024 * 1024 })
      .then((mp) => { mp.runPython('import json, freshkey'); return mp; });
    mpPromise.catch(() => { mpPromise = null; });
  }
  return mpPromise;
}

/** Start loading the module ahead of need (for example while the page settles). */
export function preload() { return load(); }

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/* A new session. `rand` is for tests only: given the same bytes, the same session
   comes back, which is what lets CI hold this build to CPython's output. */
export async function newSession({ scriptType = 'P2WPKH', network = 'main', rand } = {}) {
  if (!SCRIPT_TYPES.includes(scriptType)) throw new Error(`unsupported: ${scriptType}`);
  const mp = await load();
  const randomness = rand || crypto.getRandomValues(new Uint8Array(64));
  // Inputs go in as literals: JSON strings are valid Python strings here.
  mp.runPython(`_fresh = json.dumps(freshkey.session(${JSON.stringify(hex(randomness))}, `
    + `${JSON.stringify(scriptType)}, ${JSON.stringify(network)}))`);
  const session = JSON.parse(mp.globals.get('_fresh'));
  mp.runPython('_fresh = None');
  return session;
}
