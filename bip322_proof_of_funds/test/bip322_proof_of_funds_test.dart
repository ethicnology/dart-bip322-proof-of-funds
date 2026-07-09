import 'package:bip322_proof_of_funds/bip322_proof_of_funds.dart';
import 'package:test/test.dart';

/// Confirms `bip322_proof_of_funds` is a genuine, working re-export of
/// `bip322` — not just something that compiles — by verifying one of the
/// official BIP-322 test vectors through the package's own
/// `Bip322ProofOfFunds` alias, and by checking the alias and `Bip322` are the
/// same front door.
void main() {
  const officialAddress =
      'bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler';
  const officialMessage = 'No prefix fallback';
  const officialSignature =
      'AUCJYOwOjxYAvatTAGYaVlNXBVyFuc4MwNQkOuK2tl8xhfKDONd0NjfYyNSYcRqeCp8hsAnCEPHAVEkO9h6vbQ/R';

  test('Bip322ProofOfFunds.verify accepts the official BIP-322 vector', () {
    final valid = Bip322ProofOfFunds.verify(
      message: officialMessage,
      address: officialAddress,
      signature: officialSignature,
    );
    expect(valid, isTrue);
  });

  test('Bip322ProofOfFunds and Bip322 are the same front door', () {
    const wif = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';
    const message = 'Hello World';
    final address = Bip322ProofOfFunds.p2wpkhAddress(wif);

    final viaAlias = Bip322ProofOfFunds.signMessage(
      message: message,
      address: address,
      privateKey: wif,
    );
    final viaBip322 = Bip322.signMessage(
      message: message,
      address: address,
      privateKey: wif,
    );
    expect(viaAlias, equals(viaBip322));
  });
}
