import 'package:bip322/bip322.dart';
import 'package:test/test.dart';

void main() {
  group('P2TR verify (official vector, prefix-less "simple" fallback)', () {
    const address =
        'bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler';
    const message = 'No prefix fallback';
    const signature =
        'AUCJYOwOjxYAvatTAGYaVlNXBVyFuc4MwNQkOuK2tl8xhfKDONd0NjfYyNSYcRqeCp8hsAnCEPHAVEkO9h6vbQ/R';

    test('verifies', () {
      expect(
        Bip322.verify(message: message, address: address, signature: signature),
        isTrue,
      );
    });

    test('wrong message fails', () {
      expect(
        Bip322.verify(message: 'other', address: address, signature: signature),
        isFalse,
      );
    });
  });

  group('P2TR sign + verify round-trip', () {
    const wif = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';

    test('round-trip "Hello Taproot"', () {
      final address = Bip322.p2trAddress(wif);
      final sig = Bip322.signMessage(
        message: 'Hello Taproot',
        address: address,
        privateKey: wif,
      );
      expect(sig.startsWith('smp'), isTrue);
      expect(
        Bip322.verify(
          message: 'Hello Taproot',
          address: address,
          signature: sig,
        ),
        isTrue,
      );
      expect(
        Bip322.verify(message: 'tampered', address: address, signature: sig),
        isFalse,
      );
    });
  });
}
