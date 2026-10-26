# "Signing Failed" needs a psbt that gets no signature at all

## Symptom

A test psbt is built so that a device without a fix "fails at signing": the forged input
is one embit cannot sign (a taproot input whose merkle root contradicts its address, or
one spendable only through a script path). On SeedSigner the transaction is reviewed and
then the signed QR appears as usual, with no error screen.

## Cause

`PSBTFinalizeView` (`src/seedsigner/views/psbt_views.py`) counts signatures before and
after `psbt.sign_with()` and routes to `PSBTSigningErrorView` ("Signing Failed") only when
the count did not change:

```python
sig_cnt = PSBTParser.sig_count(psbt)
psbt.sign_with(psbt_parser.root)
trimmed_psbt = PSBTParser.trim(psbt)
if sig_cnt == PSBTParser.sig_count(trimmed_psbt):
    return Destination(PSBTSigningErrorView)
```

The fixtures build three inputs. Forge only input 0 and embit still signs inputs 1 and 2,
so the device shows a partly signed psbt as a success. Nothing on screen says one input
went unsigned.

PR #1060's taproot tests build one-input psbts (`SINGLE_SIG_TAPROOT_1_INPUT`), so its
description's "signing fails after the user reviews it" is true there and not for a
three-input fixture with only one input forged.

## What to do

When a scenario's blurb is going to say "stops on Signing Failed", forge every input, not
just input 0. The PR #1060 taproot builders in `common/attack_psbt.py`
(`_pr1060_taproot_root_contradicts`, `_pr1060_taproot_leaf_only`,
`_pr1060_taproot_root_omitted`) do this. `_pr1060_taproot_root_omitted_one_input` is
the deliberate exception: it records that the device signs the rest and stays silent.

To check a claim like this, reproduce the view's test rather than counting embit's
return value: `sign_with` can report more signatures than survive `trim` (a master key
input measured 4 from `sign_with` and 3 after trimming).
