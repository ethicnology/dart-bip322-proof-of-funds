import 'dart:typed_data';

import 'package:bs58check/bs58check.dart' as bs58check;
import 'package:bip322/bip322.dart';
import 'package:test/test.dart';

/// P2PKH and P2SH-P2WPKH are recognised, parseable address types that this
/// library deliberately does not support signing/verifying yet — see
/// `Bip322._rejectOutOfScopeAddressType` and the README/doc/bip322.md notes.
void main() {
  // Valid-checksum addresses built directly with bs58check, independent of
  // any real-world address — only the version byte and length matter here.
  final p2pkhAddress = bs58check.encode(
    Uint8List.fromList([0x00, ...List.filled(20, 0)]),
  );
  final p2shAddress = bs58check.encode(
    Uint8List.fromList([0x05, ...List.filled(20, 0)]),
  );
  const wif = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';

  group('parseAddress still recognises them', () {
    test('P2PKH parses to AddressType.p2pkh', () {
      expect(
        parseAddress(p2pkhAddress, Network.mainnet).type,
        AddressType.p2pkh,
      );
    });

    test('P2SH parses to AddressType.p2sh', () {
      expect(parseAddress(p2shAddress, Network.mainnet).type, AddressType.p2sh);
    });
  });

  group('signMessage throws UnsupportedError (not a Bip322Exception)', () {
    test('P2PKH', () {
      expect(
        () => Bip322.signMessage(
          message: 'hello',
          address: p2pkhAddress,
          privateKey: wif,
        ),
        throwsUnsupportedError,
      );
    });

    test('P2SH', () {
      expect(
        () => Bip322.signMessage(
          message: 'hello',
          address: p2shAddress,
          privateKey: wif,
        ),
        throwsUnsupportedError,
      );
    });
  });

  group('verify throws UnsupportedError (not a Bip322Exception)', () {
    test('P2PKH', () {
      expect(
        () => Bip322.verify(
          message: 'hello',
          address: p2pkhAddress,
          signature: 'smpAA==',
        ),
        throwsUnsupportedError,
      );
    });

    test('P2SH', () {
      expect(
        () => Bip322.verify(
          message: 'hello',
          address: p2shAddress,
          signature: 'smpAA==',
        ),
        throwsUnsupportedError,
      );
    });
  });
}
