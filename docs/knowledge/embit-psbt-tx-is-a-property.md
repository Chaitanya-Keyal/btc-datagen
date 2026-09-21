# embit's `PSBT.tx` is a rebuilt copy, not stored state

## The trap

In embit (pinned 0.8.0 here), a `PSBT` does not store a `Transaction`. `PSBT.tx`
is a **property** that reassembles a fresh `Transaction` on every access from the
per-scope fields:

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

So this **silently does nothing** — you mutate a throwaway object and the edit is
discarded:

```python
psbt.tx.vout[i].script_pubkey = script.p2wpkh(attacker_key)   # LOST
```

The output's committed scriptPubKey and value live on the **output scope**
(`OutputScope.script_pubkey` / `.value`); `out.vout` is itself a property that
returns `TransactionOutput(self.value, self.script_pubkey)`. Write there instead:

```python
psbt.outputs[i].script_pubkey = script.p2wpkh(attacker_key)   # persists
```

Input prevouts are the same story: `psbt.inputs[i]` holds the real state
(`witness_utxo`, `bip32_derivations`, `witness_script`, ...). Mutating
`witness_utxo` in place is fine because it is a stored `TransactionOutput`
(`psbt.inputs[i].witness_utxo.script_pubkey = ...` sticks).

## Why it's easy to miss

The assignment looks right and raises no error; `psbt.tx.vout[i]` reads back the
*old* value because the getter rebuilt it from the unchanged scope. Nothing fails
loudly — the forgery just silently doesn't happen. Verify by round-tripping and
inspecting: `PSBT.parse(psbt.serialize()).outputs[i]`.

## Where this bit us

The multisig branch of `forge_fake_change` (PR #1013 work) still fired the right
ownership-scan error, because that scan keys on the *derivation entry*, not the
scriptPubKey — so validation passed while the shipped PSBT's scriptPubKey never
actually changed. The single-key D5 contradiction (PR #1032) exposed it: that one
needs the scriptPubKey to genuinely point elsewhere, and it "parsed clean" until
the write was moved to `psbt.outputs[i].script_pubkey`.

**Lesson:** a forgery that mutates an output's script/value must write to
`psbt.outputs[i]`, never `psbt.tx.vout[i]`. When a forged PSBT validates for the
wrong reason (an unrelated check catches it), suspect a lost `psbt.tx` write.
```
