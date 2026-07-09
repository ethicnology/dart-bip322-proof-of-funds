/// `bip322_proof_of_funds` is a discoverability alias for the [`bip322`
/// package](https://pub.dev/packages/bip322) — the BIP-322 Generic Signed
/// Message Format for Bitcoin in pure Dart, published a second time under the
/// name people reach for when they want its "Proof of Funds" capability. It
/// has no logic of its own: it re-exports `bip322`'s entire API and adds one
/// alias, [Bip322ProofOfFunds], so the front-door class name matches this
/// package's name. See `bip322`'s README for the full documentation.
library;

import 'package:bip322/bip322.dart';

export 'package:bip322/bip322.dart';

/// Alias for [Bip322], so the front-door class name matches this package's
/// name (`bip322_proof_of_funds`). `Bip322ProofOfFunds.signProofOfFunds(...)`
/// and `Bip322.signProofOfFunds(...)` are the same call — use whichever reads
/// better for how you imported the package.
typedef Bip322ProofOfFunds = Bip322;
