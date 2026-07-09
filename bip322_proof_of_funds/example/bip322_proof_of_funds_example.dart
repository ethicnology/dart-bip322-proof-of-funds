import 'package:bip322_proof_of_funds/bip322_proof_of_funds.dart';

/// A minimal smoke test showing `bip322_proof_of_funds` re-exports `bip322`'s
/// API verbatim. See `bip322`'s own `example/bip322_example.dart` for a full
/// sign/verify + proof-of-funds walkthrough.
void main() {
  const wif = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';
  const message = 'Hello World';

  // `Bip322ProofOfFunds` is an alias of `Bip322` — both names work identically.
  final address = Bip322ProofOfFunds.p2wpkhAddress(wif);
  final signature = Bip322ProofOfFunds.signMessage(
    message: message,
    address: address,
    privateKey: wif,
  );
  print('address: $address');
  print('signature: $signature');

  final valid = Bip322ProofOfFunds.verify(
    message: message,
    address: address,
    signature: signature,
  );
  print('verified: $valid');
}
