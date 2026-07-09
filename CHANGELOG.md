## 1.0.0

- Initial release.
- `Bip322.signMessage` / `Bip322.verify` for P2WPKH and P2TR (Simple format, `smp`-prefixed and prefix-less fallback), byte-exact against the official BIP-322 test vectors.
- Bitcoin Core-compatible deterministic ECDSA (RFC-6979 with low-R grinding).
- BIP-341 (Taproot taptweak + key-path sighash) extracted into the sibling [`bip341`](https://github.com/ethicnology/dart-bip341) package (currently a local `path:` dependency pending its own pub.dev release); re-exported from this package's barrel.
- Address parsing for P2PKH, P2SH, P2WPKH, P2WSH, P2TR, with BIP-350 witness-version/checksum binding.
- Strict verification policy: signature format bound to address type; `loose` opt-in reserved for future BIP-137 cross-type acceptance.
- `verify` never throws a `Bip322Exception` for malformed data (garbled address, invalid base64, truncated witness) — always resolves to `false`.
- P2PKH and P2SH-P2WPKH parse as valid addresses but `signMessage`/`verify` throw `UnsupportedAddressTypeError` for them (permanently out of scope for this format — see README).
- P2WSH multisig and the Full (arbitrary-transaction) format are not implemented: both throw `UnimplementedAddressTypeError`/`UnimplementedSignatureFormatError`. Legacy BIP-137 (P2PKH) is out of scope and throws `UnsupportedAddressTypeError`.
- P2TR verification strictly requires `SIGHASH_DEFAULT`/`SIGHASH_ALL`; any other explicit sighash byte on a 65-byte witness is rejected.
- Canonical-encoding enforcement (anti-malleability): the simple-format witness stack must be consumed exactly (trailing bytes are rejected), and ECDSA signatures must be strict/minimal DER (non-canonical or trailing-byte DER is rejected) alongside low-S.
- `Bip322.p2wpkhAddress` / `Bip322.p2trAddress` derive the address a private key can sign for, without reaching into internal modules or another package.
- Flutter/dart2js compatible: 64-bit little-endian amount encoding/decoding avoids `ByteData.setUint64`/`getUint64`, which are unsupported when compiled to JavaScript.
- Licensed under MIT.
- `Bip322.signProofOfFunds` / `Bip322.verifyProofOfFunds`: BIP-322 "Full (Proof of Funds)" support for P2WPKH/P2TR UTXO sets, via a pure-Dart, finalized-only PSBT (BIP-174) codec (`lib/src/psbt.dart`) — no runtime dependency on any wallet library. `verifyProofOfFunds` returns the spec's three-state result (`valid`/`inconclusive`/`invalid`) rather than a boolean, since Proof of Funds needs the `inconclusive` state to correctly handle proof UTXOs of a script type this library doesn't understand, per BIP-322's own validator-without-an-interpreter rule. `Bip322.verify` throws `IncompatibleVerificationApiError` for `pof`-prefixed input, directing callers to the dedicated method. The PSBT codec is cross-validated (dev-only) in both directions against [`bdk_dart`](https://github.com/bitcoindevkit/bdk-dart), the official Bitcoin Dev Kit binding.
- Every capability/contract condition this package rejects throws a named `Error` subclass instead of a bare `UnsupportedError`/`UnimplementedError`/`ArgumentError`/`StateError`: `UnsupportedAddressTypeError`, `UnimplementedAddressTypeError`, `UnimplementedSignatureFormatError`, `IncompatibleVerificationApiError`, `UnsupportedScriptTypeError`, `UnreachableCaseError`, `NegativeValueError`, `MismatchedSpentOutputCountError`. Each carries the offending value as a field (e.g. `UnsupportedAddressTypeError.addressType`) for programmatic inspection, distinct from the existing `Bip322Exception` hierarchy (which covers malformed *data*, not capability/contract questions).
