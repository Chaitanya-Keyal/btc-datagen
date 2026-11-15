# embit PSBT traps

Two places where embit (pinned 0.8.0 here) does something other than what the code
appears to say. Both matter when forging a test PSBT: the first silently drops a forgery,
and the second decides which amount a signer sees for an input and how reading it can
fail.

## Writes to `psbt.tx` are lost

A `PSBT` does not store a `Transaction`. `PSBT.tx` is a **property** that reassembles a
fresh `Transaction` from the per-scope fields on every access:

```python
@property
def tx(self):
    return self.TX_CLS(
        version=self.tx_version or 2,
        locktime=self.locktime or 0,
        vin=[inp.vin for inp in self.inputs],
        vout=[out.vout for out in self.outputs],
    )
```

So this assignment **silently does nothing**. It edits a throwaway copy:

```python
psbt.tx.vout[i].script_pubkey = script.p2wpkh(attacker_key)   # LOST
```

An output's committed scriptPubKey and value live on the **output scope**
(`OutputScope.script_pubkey` and `.value`); `out.vout` is itself a property that returns
`TransactionOutput(self.value, self.script_pubkey)`. Write there instead:

```python
psbt.outputs[i].script_pubkey = script.p2wpkh(attacker_key)   # persists
```

Inputs work the same way. The prevout is `psbt.inputs[i].txid` and `.vout`, from which
`inp.vin` is rebuilt, and the rest of the input's state (`witness_utxo`,
`non_witness_utxo`, `bip32_derivations`, `witness_script`, ...) is stored on the input
scope too. Mutating `witness_utxo` in place is fine because it is a stored
`TransactionOutput`.

The lost assignment raises no error, and `psbt.tx.vout[i]` reads back the old value
because the getter rebuilt it from the unchanged scope. Check a forgery by round-tripping
it: `PSBT.parse(psbt.serialize()).outputs[i]`. Be suspicious when a forgery still gets its
expected refusal from a check that doesn't depend on the edit. A change-ownership check
keyed on the derivation entry, for example, fires whether or not the scriptPubKey actually
changed.

## How an input's amount is read

`InputScope.utxo` is a property, and the order of its fallbacks explains the rest of this
section:

```python
@property
def utxo(self):
    return (
        self._utxo
        or self.witness_utxo
        or (self.non_witness_utxo.vout[self.vout] if self.non_witness_utxo else None)
    )
```

`PSBT.utxo(i)`, which `PSBT.fee()` sums over, uses the same order. Three consequences:

**A `witness_utxo` wins, even on a legacy input.** Nothing checks that it agrees with a
`non_witness_utxo` beside it, or that a witness UTXO makes sense for the input's script
type. `verify()` only checks that the `non_witness_utxo` hashes to the prevout txid. So
a PSBT can carry the genuine previous transaction, pass `verify()`, and still have its
amount read from a `witness_utxo` that claims something else. On a legacy input the
sighash commits to no amount, so a signature stays valid whatever the claim says. This is
the fee-lie vector behind SeedSigner PR #995.

**An out-of-range outpoint index raises `IndexError`.** If `inp.vout` names an output the
previous transaction doesn't have, the third fallback is a plain list index error.
`verify()` passes, because the txid is right and only the index is impossible, so the
first code to read the amount is what fails.

**No UTXO data at all gives `None`, not an error.** With neither field set, the property
returns `None` and the caller's `.value` raises `AttributeError`. `PSBT.utxo(i)` behaves
differently and raises `PSBTError("Missing previous utxo on input %d")`, so code holding
an `InputScope` gets a silent `None` where code going through the `PSBT` gets a typed
error.

Code that reads an input amount out of an arbitrary PSBT has to guard against the last two
and treat the amount as unknown rather than produce a number. `summarize()` in
`common/psbt.py` catches `(IndexError, AttributeError)` for this reason.
