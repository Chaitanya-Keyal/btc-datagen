"""A fresh throwaway key and a transaction to sign with it, built by embit itself.

Runs in the browser, frozen into the MicroPython WASM module (tools/wasm/build_mpy.sh),
and under CPython in the tests, which require both to produce the same bytes. Written
for both interpreters: no dataclasses, no bytes.hex(), nothing outside embit and the
standard modules MicroPython ships.

Why this exists: the demo scenarios sign with published seeds and fixed transactions,
so firmware written to evade the nonce check could recognize them and sign honestly
only for them. A key generated on the spot, spending made-up coins with random
amounts and txids, gives it nothing to recognize.

Everything is derived from the caller's random bytes (the page passes 64 from
crypto.getRandomValues), so a session is a pure function of its input. The PSBT has
the shape the demo PSBTs have, which SeedSigner is known to accept: witness UTXO only
for segwit, the previous transaction for legacy, one BIP32 derivation per input, and a
derivation on the change output.
"""
import binascii
import hashlib

from embit import bip32, bip39, script
from embit.ec import PrivateKey
from embit.networks import NETWORKS
from embit.psbt import PSBT, SIGHASH, DerivationPath
from embit.transaction import Transaction, TransactionInput, TransactionOutput
from embit.wordlists.bip39 import WORDLIST

HARDENED = 0x80000000
RECEIVE_BRANCH = 0
CHANGE_BRANCH = 1
NUM_INPUTS = 3

# BIP44/49/84/86 purpose per single-sig script type, as in common/script_types.py.
PURPOSE = {"P2WPKH": 84, "P2SH-P2WPKH": 49, "P2TR": 86, "P2PKH": 44}
LABEL = {"P2WPKH": "Native SegWit", "P2SH-P2WPKH": "Nested SegWit",
         "P2TR": "Taproot", "P2PKH": "Legacy"}

# The name the scan result gives the signer ("Signed by your test key.").
SEED_NAME = "your test key"


def _hex(b):
    return binascii.hexlify(b).decode()


class _Random:
    """A deterministic stream over the caller's random bytes: SHA-256 in counter
    mode. Every value the session needs is drawn from it, in a fixed order."""

    def __init__(self, seed):
        self.seed = seed
        self.counter = 0
        self.pool = b""

    def take(self, n):
        while len(self.pool) < n:
            block = self.seed + self.counter.to_bytes(4, "big")
            self.pool += hashlib.sha256(block).digest()
            self.counter += 1
        out, self.pool = self.pool[:n], self.pool[n:]
        return out

    def randint(self, lo, hi):
        """lo..hi inclusive. The modulo bias is about 2**-32, which nothing here
        could notice."""
        return lo + int.from_bytes(self.take(8), "big") % (hi - lo + 1)


def _script_for(script_type, pub):
    """(script_pubkey, redeem_script) for one of our addresses."""
    if script_type == "P2WPKH":
        return script.p2wpkh(pub), None
    if script_type == "P2SH-P2WPKH":
        redeem = script.p2wpkh(pub)
        return script.p2sh(redeem), redeem
    if script_type == "P2TR":
        # embit's p2tr() applies the BIP86 tweak; the PSBT carries the untweaked
        # internal key with the derivation.
        return script.p2tr(pub), None
    if script_type == "P2PKH":
        return script.p2pkh(pub), None
    raise ValueError("unsupported script type: " + script_type)


def _apply(scope, script_type, pub, redeem, derivation):
    if redeem is not None:
        scope.redeem_script = redeem
    if script_type == "P2TR":
        scope.taproot_internal_key = pub
        scope.taproot_bip32_derivations[pub] = ([], derivation)
    else:
        scope.bip32_derivations[pub] = derivation


def _summary(psbt, network):
    """Same shape as common/psbt.summarize for an honest single-sig PSBT."""
    net = NETWORKS[network]
    input_amount = 0
    for inp in psbt.inputs:
        input_amount += inp.utxo.value
    outputs, output_total = [], 0
    for i, out in enumerate(psbt.outputs):
        vout = psbt.tx.vout[i]
        output_total += vout.value
        ours = out.bip32_derivations or out.taproot_bip32_derivations
        outputs.append({"address": vout.script_pubkey.address(net),
                        "value": vout.value,
                        "kind": "change" if ours else "external"})
    return {"num_inputs": len(psbt.inputs), "input_amount": input_amount,
            "outputs": outputs, "fee": input_amount - output_total}


def _verify_block(psbt, root, fingerprint_hex):
    """Same shape as tools/build_site.verification_data for one signer.

    The reference signatures come from embit's own sign_with on a copy of the PSBT,
    the call SeedSigner makes, so they carry the low-R grinding and the no-aux
    Schnorr nonce exactly as a correct device does.
    """
    taproot = psbt.inputs[0].is_taproot
    sighash_type = SIGHASH.DEFAULT if taproot else SIGHASH.ALL

    signed = PSBT.parse(psbt.serialize())
    signed.sign_with(root)

    inputs = []
    for i, inp in enumerate(psbt.inputs):
        if taproot:
            # Signatures verify against the TWEAKED key in the scriptPubKey.
            pubkey = inp.utxo.script_pubkey.data[2:34]
            witness = signed.inputs[i].final_scriptwitness
            sig = witness.items[0] if witness is not None and witness.items else None
        else:
            pub = list(inp.bip32_derivations)[0]
            pubkey = pub.sec()
            sig = signed.inputs[i].partial_sigs.get(pub)
        key = {"pubkey": _hex(pubkey), "fingerprint": fingerprint_hex,
               "seed": SEED_NAME,
               "signature": _hex(sig) if sig is not None else None}
        inputs.append({"sighash": _hex(psbt.sighash(i, sighash=sighash_type)),
                       "keys": [key]})

    return {"txid": _hex(psbt.tx.txid()),
            "unsigned_tx": _hex(psbt.tx.serialize()),
            "taproot": taproot, "threshold": 1, "inputs": inputs}


def session(rand_hex, script_type="P2WPKH", network="main", words=12):
    """A new key and a signable transaction for it, as one JSON-ready dict."""
    if script_type not in PURPOSE:
        raise ValueError("unsupported script type: " + script_type)
    rng = _Random(binascii.unhexlify(rand_hex))
    net = NETWORKS[network]
    coin = 0 if network == "main" else 1

    # --- the key ---------------------------------------------------------------
    entropy = rng.take(16 if words == 12 else 32)
    mnemonic = bip39.mnemonic_from_bytes(entropy)
    root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(mnemonic), version=net["xprv"])
    fingerprint = root.my_fingerprint
    account_path = [PURPOSE[script_type] + HARDENED, coin + HARDENED, HARDENED]
    account = root.derive(account_path).to_public()

    def ours(branch, index):
        pub = account.derive([branch, index]).key
        spk, redeem = _script_for(script_type, pub)
        return pub, spk, redeem, DerivationPath(fingerprint,
                                                account_path + [branch, index])

    # --- inputs: made-up coins at random addresses, amounts, and outpoints ------
    vin, funded = [], []
    for _ in range(NUM_INPUTS):
        pub, spk, redeem, der = ours(RECEIVE_BRANCH, rng.randint(0, 999))
        value = rng.randint(100000, 2000000)
        if script_type == "P2PKH":
            # Legacy inputs carry the whole previous transaction, which must hash
            # to the outpoint, so the randomness goes into that transaction instead.
            vout = rng.randint(0, 2)
            outs = [TransactionOutput(rng.randint(5000, 9000000),
                                      script.p2wpkh(PrivateKey(rng.take(32)).get_public_key()))
                    for _ in range(3)]
            outs[vout] = TransactionOutput(value, spk)
            prev = Transaction(vin=[TransactionInput(rng.take(32), rng.randint(0, 3))],
                               vout=outs)
            vin.append(TransactionInput(prev.txid(), vout))
        else:
            prev = None
            vin.append(TransactionInput(rng.take(32), rng.randint(0, 3)))
        funded.append((pub, spk, redeem, der, value, prev))

    total_in = 0
    for f in funded:
        total_in += f[4]
    fee = rng.randint(300, 4000)
    spendable = total_in - fee

    # --- outputs: a recipient and change, in random order ------------------------
    recipient_spk = script.p2wpkh(PrivateKey(rng.take(32)).get_public_key())
    change_pub, change_spk, change_redeem, change_der = ours(CHANGE_BRANCH,
                                                             rng.randint(0, 999))
    # The recipient always gets at least ten times the fee: SeedSigner warns when the
    # fee passes 25% of the non-change outputs, and a fresh key should never trip
    # a warning the user then has to wonder about.
    change_value = rng.randint(spendable // 10,
                               spendable - max(spendable // 10, fee * 10))
    outputs = [(TransactionOutput(spendable - change_value, recipient_spk), False),
               (TransactionOutput(change_value, change_spk), True)]
    if rng.randint(0, 1):
        outputs.reverse()

    psbt = PSBT(Transaction(vin=vin, vout=[o for o, _ in outputs]))
    for k, (pub, spk, redeem, der, value, prev) in enumerate(funded):
        inp = psbt.inputs[k]
        if prev is None:
            inp.witness_utxo = TransactionOutput(value, spk)
        else:
            inp.non_witness_utxo = prev
        _apply(inp, script_type, pub, redeem, der)
    for k, (_out, is_change) in enumerate(outputs):
        if is_change:
            _apply(psbt.outputs[k], script_type, change_pub, change_redeem, change_der)

    raw = psbt.serialize()
    fingerprint_hex = _hex(fingerprint)
    word_list = mnemonic.split()
    return {
        "id": "fresh-" + fingerprint_hex + "-" + script_type.lower(),
        "script_type": script_type,
        "script_label": LABEL[script_type],
        "network": network,
        "mnemonic": mnemonic,
        "words": len(word_list),
        "master_fingerprint": fingerprint_hex,
        "seed_name": SEED_NAME,
        # The two SeedQR payloads: four digits per word index, or the raw entropy.
        "standard_digits": "".join("%04d" % WORDLIST.index(w) for w in word_list),
        "entropy_hex": _hex(entropy),
        "psbt_base64": binascii.b2a_base64(raw).decode().strip(),
        "psbt_bytes": len(raw),
        "summary": _summary(psbt, network),
        "verify": _verify_block(psbt, root, fingerprint_hex),
    }
