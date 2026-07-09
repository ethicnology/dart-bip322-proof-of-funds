# bip322

A from-scratch Dart implementation of [BIP-322](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki)
— the Generic Signed Message Format for Bitcoin. Sign and verify messages
without a full node, a wallet daemon, or FFI bindings: pure Dart, minimal
dependencies.

"From scratch" means the BIP-322 protocol logic — message tagged-hashing, the
virtual `to_spend`/`to_sign` transactions, witness serialization, per-address
sighash (legacy / BIP-143), and the signature format codecs — is implemented
directly in this package. The underlying elliptic-curve math (secp256k1 ECDSA,
BIP-340 Schnorr, SHA-256/RIPEMD-160) is not implemented here — it's reused from
[`elliptic`](https://pub.dev/packages/elliptic),
[`ecdsa`](https://pub.dev/packages/ecdsa),
[`bip340`](https://pub.dev/packages/bip340) and
[`pointycastle`](https://pub.dev/packages/pointycastle), none of which have had
a formal security audit; they are validated here only by byte-exact agreement
with the official BIP-322/BIP-341 test vectors, not by an independent review of
their implementations. BIP-341 (Taproot)
support — the taptweak and key-path sighash — is provided by the sibling
[`bip341`](https://github.com/ethicnology/dart-bip341) package, extracted
from this one so it can be reused independently.

## Support matrix

| Address type | Sign | Verify | Format |
|---|---|---|---|
| P2WPKH (`bc1q...`, 42 chars) | ✅ | ✅ | Simple (`smp`) |
| P2TR (`bc1p...`, key-path) | ✅ | ✅ | Simple (`smp`) |
| P2WPKH / P2TR UTXO set | ✅ `signProofOfFunds` | ✅ `verifyProofOfFunds` | Proof-of-Funds (`pof`) |
| P2WSH multisig | 🚧 `UnimplementedAddressTypeError` | 🚧 `UnimplementedAddressTypeError` | not implemented — see below |
| P2PKH (legacy, `1...`) | 🚫 `UnsupportedAddressTypeError` | 🚫 `UnsupportedAddressTypeError` | out of scope — see below |
| P2SH-P2WPKH (`3...`) | 🚫 `UnsupportedAddressTypeError` | 🚫 `UnsupportedAddressTypeError` | out of scope — see below |
| Full (arbitrary transaction) | 🚧 `UnimplementedSignatureFormatError` | 🚧 `UnimplementedSignatureFormatError` | v2 (needs a script interpreter for general scripts) |

`parseAddress` still recognises P2PKH, P2SH-P2WPKH and P2WSH as valid
Bitcoin addresses — only `signMessage`/`verify` reject them, and they do so
loudly (a Dart `Error`, not a quiet `false`). See below for why.

## Getting started

```yaml
dependencies:
  bip322: ^1.0.0
```

## Usage

```dart
import 'package:bip322/bip322.dart';

void main() {
  const wif = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';
  final address = Bip322.p2wpkhAddress(wif); // or Bip322.p2trAddress(wif)

  final signature = Bip322.signMessage(
    message: 'Hello World',
    address: address,
    privateKey: wif,
  );
  print(signature); // smpAkgwRQIhAOzy...

  final valid = Bip322.verify(
    message: 'Hello World',
    address: address,
    signature: signature,
  );
  print(valid); // true
}
```

`Bip322.p2wpkhAddress`/`Bip322.p2trAddress` derive the address a given private
key can sign for on a given [Network]; you don't need another package to go
from a key to the address `signMessage` expects.

See `example/bip322_example.dart` for a P2WPKH and P2TR walkthrough.

## Proof of Funds

`Bip322.signProofOfFunds`/`Bip322.verifyProofOfFunds` implement BIP-322's
"Full (Proof of Funds)" format: an ordinary message signature plus any number
of additional, genuinely-satisfied UTXOs, demonstrating control of an
arbitrary set the signer chooses — it need not be associated with the signing
address at all. The signature is a `pof`-prefixed, base64-encoded *finalized*
PSBT (BIP-174), built and parsed by this package's own pure-Dart codec
(`lib/src/psbt.dart` — no dependency needed to produce or consume it).

```dart
final proofUtxo = ProofOfFundsUtxo(
  prevout: OutPoint(utxoTxid, utxoVout), // a real, on-chain UTXO
  amount: utxoValueSats,
  scriptPubKey: parseAddress(utxoAddress, Network.mainnet).scriptPubKey,
  privateKey: utxoPrivateKey, // must control scriptPubKey
);

final signature = Bip322.signProofOfFunds(
  message: 'I control these funds',
  address: address,       // the message-challenge address, as in signMessage
  privateKey: privateKey, // must control `address`
  proofUtxos: [proofUtxo],
);

final result = Bip322.verifyProofOfFunds(
  message: 'I control these funds',
  address: address,
  signature: signature,
);
print(result.status);       // ProofOfFundsStatus.valid
print(result.provenUtxos);  // the proof UTXOs whose signatures verified
```

Only P2WPKH and P2TR are supported for both the challenge address and every
proof UTXO — the same two types `signMessage` handles; `signProofOfFunds`
throws `UnsupportedScriptTypeError` for anything else. `verifyProofOfFunds`
returns a **three-state result** (`ProofOfFundsResult`/`ProofOfFundsStatus`)
rather than a boolean, per BIP-322's own verification model:

- `valid` — every input (the message signature and every proof UTXO)
  cryptographically checks out.
- `inconclusive` — at least one proof UTXO's scriptPubKey isn't P2WPKH/P2TR.
  Per the spec, a validator without a full script interpreter "should check
  that it understands all scripts being satisfied [and] stop here and output
  inconclusive" if it doesn't — this library follows that rule exactly rather
  than silently skipping or wrongly rejecting unrecognised scripts.
- `invalid` — a structural check or a signature failed.

**This is an offline, cryptographic check only.** It does not confirm
`result.provenUtxos` still exist or are unspent on-chain — per BIP-322,
"validators of a proof of funds need access to the current UTXO set" for
that, which is out of scope for a pure signing/verification library. Pair the
result with your own UTXO-set lookup (an Electrum/Esplora client, or a wallet
library such as [`bdk_dart`](https://github.com/bitcoindevkit/bdk-dart)) to
confirm the proof means what it claims before trusting it.

## Signature formats and verification policy

BIP-322 defines four signature variants, distinguished by an ASCII prefix:
`smp` (Simple), `ful` (Full), `pof` (Proof-of-Funds), and an unprefixed
65-byte legacy (BIP-137) form. The spec allows a verifier to assume the
Simple variant when no prefix is present — this library follows that
fallback, since several real-world wallets (e.g. `bip322-js`) emit
prefix-less Simple signatures.

`Bip322.verify` binds the decoded signature format to the address type (a
P2TR address can never be satisfied by a legacy 65-byte blob, a P2WPKH
witness must contain exactly two items, etc). This is a deliberate divergence
from `bip322-js`'s "loose" mode, which accepts a BIP-137 signature across
P2PKH/P2SH-P2WPKH/P2WPKH on the theory that one key controls all of them.
`loose: true` is reserved for that cross-type policy once legacy (BIP-137)
signing is added — it currently has no effect.

`Full` (arbitrary transactions) and `P2WSH` are not implemented —
calling `verify`/`signMessage` against them throws
`UnimplementedSignatureFormatError`/`UnimplementedAddressTypeError` (a Dart
`Error`, never silently treated as "verified"). `Proof-of-Funds` *is*
implemented, but not through `verify`/`signMessage`: a `pof`-prefixed
signature passed to `Bip322.verify` throws `IncompatibleVerificationApiError`
too, because `verify`'s boolean return type cannot express the three-state
(valid/inconclusive/invalid) result BIP-322 defines for Proof of Funds — use
the dedicated `Bip322.signProofOfFunds`/`Bip322.verifyProofOfFunds` instead
(see "Proof of Funds" above).

`verify` never throws a `Bip322Exception` for malformed *data* — a
garbled address string, invalid base64, a truncated or inconsistent witness
encoding all resolve to `false`, since `address` and `signature` are
ordinarily untrusted input. The only things `verify`/`signMessage` throw are
Dart `Error`s — see "Error handling" below — for address types or formats
this library version doesn't support *at all*: a statement about the
library's capabilities, not about a specific input's validity. A defensive
caller should not treat a caught `Error` as "not verified" the way it would
treat a caught `Bip322Exception` (which `verify` itself never throws) — see
`test/m6_hardening_test.dart` and `test/scope_test.dart`.

### P2PKH, P2SH-P2WPKH and P2WSH are not supported

`signMessage` and `verify` throw for these three address types, even though
`parseAddress` recognises all of them as valid Bitcoin addresses. This is a
deliberate scope decision, not a bug:

- **P2PKH**'s message-signing scheme is legacy **BIP-137** (65-byte
  recoverable ECDSA signatures) — a distinct, older format, not BIP-322
  proper. It has no BIP-322 "Simple" or "Full" representation of its own.
  Throws `UnsupportedAddressTypeError` (permanently out of scope for this
  format).
- **P2SH-P2WPKH** cannot be expressed in the Simple format at all: Simple
  carries only a witness stack, with no scriptSig slot for the redeemScript
  a P2SH input needs to spend. It would require the Full format (a complete
  signed transaction) — a v2 feature. Throws `UnsupportedAddressTypeError`.
- **P2WSH** multisig is not implemented. Throws `UnimplementedAddressTypeError`
  (a subtype of `UnsupportedError`, reserved for features that are a planned
  addition rather than permanently excluded) — the same distinction drawn
  for the Full format (`UnimplementedSignatureFormatError`).

## Error handling

Every capability/contract condition this package rejects — an out-of-scope or
not-yet-implemented address type, a signature format `verify`'s boolean
return type can't express, an unsupported Proof-of-Funds UTXO type, an
internal invariant — throws a specific, named `Error` subclass instead of a
bare `UnsupportedError`/`UnimplementedError`/`ArgumentError`/`StateError`
with only a message string:

- `UnsupportedAddressTypeError` / `UnimplementedAddressTypeError` — carry the
  rejected `AddressType` as a field.
- `UnimplementedSignatureFormatError` / `IncompatibleVerificationApiError` —
  thrown by `verify` for the Full and Proof-of-Funds formats respectively
  (see above for why they're distinct).
- `UnsupportedScriptTypeError` — thrown by `signProofOfFunds` for a
  non-P2WPKH/P2TR proof UTXO; carries the UTXO's index and scriptPubKey.
- `NegativeValueError` / `MismatchedSpentOutputCountError` — internal
  wire-encoding contract violations (a negative amount, a
  `spentOutputs`/inputs length mismatch in `encodeFinalizedPsbt`).

These all extend Dart's `UnsupportedError`/`UnimplementedError`/
`ArgumentError`/`StateError` (its `Error` hierarchy, not `Exception`)
deliberately — every one is a capability or caller-contract question, not a
data-validity question (that's what `Bip322Exception` and its subclasses,
below, are for). That's also why they're named `...Error`, not
`...Exception`: `catch (e) on Exception` does not catch an `Error`.

`Bip322Exception` (`UnsupportedAddressException`, `WrongNetworkException`,
`WitnessVersionChecksumMismatchException`, `InvalidPrivateKeyException`,
`MalformedSignatureException`, `DeserializationException`) covers malformed
or untrusted *data* instead — a garbled address string, an invalid private
key, a truncated witness or PSBT. `verify`/`verifyProofOfFunds` never let
these propagate (see "Never throws a `Bip322Exception`" above); `signMessage`
and PSBT-parsing functions do throw them for genuinely malformed input.

## Design notes

- **Bitcoin Core-compatible signatures.** ECDSA signing reproduces Bitcoin
  Core's exact output, including its low-R grinding (RFC-6979 with
  `extra_entropy = counter` appended to the seed until R fits in 32 bytes).
  Signatures for the official BIP-322 test vectors are byte-for-byte
  identical to the reference values.
- **BIP-341 lives in its own package.** The Taproot taptweak and key-path
  sighash are provided by [`bip341`](https://github.com/ethicnology/dart-bip341),
  a dependency of this package (currently via a local `path:` dependency
  pending its own pub.dev release) rather than embedded code — it depends only
  on `elliptic`/`pointycastle` and is independently tested against the
  official BIP-341 test vector, so it's reusable outside BIP-322 entirely.
  `bip322`'s barrel re-exports its public API (`taprootTweakKeyPath`,
  `taprootKeyPathSighash`, etc.) for convenience.
- **No script interpreter.** This library does not evaluate Bitcoin Script;
  instead it re-derives the expected witness for each supported address type
  and enforces the consensus rules BIP-322 requires by hand: low-S, minimal
  pushes, exact witness item counts (the CLEANSTACK/MINIMALIF equivalent for
  the templates it supports). Proof of Funds inherits this: an unrecognised
  proof-UTXO script yields `inconclusive`, per the spec's own sanctioned
  fallback for validators without an interpreter — see "Proof of Funds" above.
- **The PSBT codec is pure Dart, and only handles finalized PSBTs.** BIP-322
  Proof of Funds requires the signature to be a base64-encoded *finalized*
  PSBT, so `lib/src/psbt.dart` implements exactly that BIP-174 subset — no
  partial signatures, no BIP32 derivation paths, no PSBTv2 — since this
  package never produces or consumes anything else. Its output is
  cross-validated (dev-only) against
  [`bdk_dart`](https://github.com/bitcoindevkit/bdk-dart), the official
  Bitcoin Dev Kit binding, in both directions: bytes this codec encodes are
  parsed and extracted by bdk, and PSBTs bdk builds are decoded by this
  codec. `bdk_dart` is never a runtime dependency — signing and verifying
  Proof of Funds is fully pure-Dart and does not need a Rust toolchain.

## Test vectors

Golden values from the official
[`bip-0322/basic-test-vectors.json`](https://github.com/bitcoin/bips/blob/master/bip-0322/basic-test-vectors.json)
are used throughout the test suite — message hashes, `to_spend`/`to_sign`
transaction ids, and byte-exact Simple signatures for P2WPKH and P2TR. No
official test vectors exist yet for Proof of Funds, so it is instead covered
by constructed round trips, tamper/scope tests matching the rest of this
suite's style, and the `bdk_dart` cross-validation described above.

## Additional information

See `doc/bip322.md` for a walkthrough of the protocol this package
implements. Licensed under MIT (see `LICENSE`).
