# bip322_proof_of_funds

This is a discoverability alias for [`bip322`](https://pub.dev/packages/bip322) — the BIP-322 Generic Signed Message Format for Bitcoin in pure Dart: sign and verify "Simple" messages for P2WPKH and P2TR addresses, and build and verify "Proof of Funds" signatures over a UTXO set. It has no code of its own; `package:bip322_proof_of_funds/bip322_proof_of_funds.dart` re-exports `bip322`'s entire public API verbatim, so the two are interchangeable at the import site.

Use whichever name reads better in your project — `bip322` is the canonical package (this is where issues, releases, and documentation live); `bip322_proof_of_funds` exists purely so the package is findable under its Proof-of-Funds name.

```yaml
dependencies:
  bip322_proof_of_funds: ^1.0.0
```

```dart
import 'package:bip322_proof_of_funds/bip322_proof_of_funds.dart';

// `Bip322ProofOfFunds` is an alias of `Bip322` — both names work identically.
final signature = Bip322ProofOfFunds.signProofOfFunds(
  message: message,
  address: address,
  privateKey: privateKey,
  proofUtxos: proofUtxos,
);
```

See [`bip322`](https://github.com/ethicnology/dart-bip322)'s README for the full API, usage examples, test vector coverage, and scope.

Licensed under MIT (see `LICENSE`) — identical to `bip322`.
