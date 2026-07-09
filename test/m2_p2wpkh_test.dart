import 'package:bip322/bip322.dart';
import 'package:test/test.dart';

/// Official BIP-322 basic-test-vectors.json — P2WPKH "simple" cases.
void main() {
  const wif = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';
  const address = 'bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l';

  const emptySig =
      'smpAkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=';
  const helloSig =
      'smpAkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=';

  group('sign (smp-prefixed, byte-match the official base64 payload)', () {
    test('empty message', () {
      expect(
        Bip322.signMessage(message: '', address: address, privateKey: wif),
        emptySig,
      );
    });

    test('"Hello World"', () {
      expect(
        Bip322.signMessage(
          message: 'Hello World',
          address: address,
          privateKey: wif,
        ),
        helloSig,
      );
    });
  });

  group('verify', () {
    test('official empty-message signature', () {
      expect(
        Bip322.verify(message: '', address: address, signature: emptySig),
        isTrue,
      );
    });

    test('official "Hello World" signature', () {
      expect(
        Bip322.verify(
          message: 'Hello World',
          address: address,
          signature: helloSig,
        ),
        isTrue,
      );
    });

    test('wrong message fails', () {
      expect(
        Bip322.verify(
          message: 'Goodbye',
          address: address,
          signature: helloSig,
        ),
        isFalse,
      );
    });

    test('round-trip', () {
      final sig = Bip322.signMessage(
        message: 'round trip',
        address: address,
        privateKey: wif,
      );
      expect(
        Bip322.verify(message: 'round trip', address: address, signature: sig),
        isTrue,
      );
    });
  });
}
