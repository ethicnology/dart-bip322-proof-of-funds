import 'dart:typed_data';

import 'package:bip322/bip322.dart' hide sighashAll;
import 'package:bs58check/bs58check.dart' as bs58check;
import 'package:test/test.dart';

/// Confirms the custom error types are actually what's thrown (not just "an
/// UnsupportedError/UnimplementedError/ArgumentError of some kind"), and that
/// their structured fields work — the whole point of naming them instead of
/// throwing bare Dart core errors.
void main() {
  const wif = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';
  final p2wpkhAddress = Bip322.p2wpkhAddress(wif);

  String p2pkhAddress() =>
      bs58check.encode(Uint8List.fromList([0x00, ...List.filled(20, 0)]));
  String p2shAddress() =>
      bs58check.encode(Uint8List.fromList([0x05, ...List.filled(20, 0)]));

  group('address-type rejection', () {
    test('P2PKH throws UnsupportedAddressTypeError carrying the type', () {
      try {
        Bip322.signMessage(
          message: 'x',
          address: p2pkhAddress(),
          privateKey: wif,
        );
        fail('expected UnsupportedAddressTypeError');
      } on UnsupportedAddressTypeError catch (e) {
        expect(e.addressType, AddressType.p2pkh);
      }
    });

    test('P2SH throws UnsupportedAddressTypeError carrying the type', () {
      try {
        Bip322.signMessage(
          message: 'x',
          address: p2shAddress(),
          privateKey: wif,
        );
        fail('expected UnsupportedAddressTypeError');
      } on UnsupportedAddressTypeError catch (e) {
        expect(e.addressType, AddressType.p2sh);
      }
    });

    test('P2WSH throws UnimplementedAddressTypeError carrying the type', () {
      const p2wshAddress =
          'bc1qp0ahvfh83088w49k405szqgg4f3pptr7p2g06tdxfjcd40z4lh4q95lsz9';
      try {
        Bip322.signMessage(
          message: 'x',
          address: p2wshAddress,
          privateKey: wif,
        );
        fail('expected UnimplementedAddressTypeError');
      } on UnimplementedAddressTypeError catch (e) {
        expect(e.addressType, AddressType.p2wsh);
      }
      // UnimplementedError is itself an UnsupportedError in Dart's own
      // hierarchy, matching the "planned, not permanent" distinction.
      expect(
        () => Bip322.signMessage(
          message: 'x',
          address: p2wshAddress,
          privateKey: wif,
        ),
        throwsA(isA<UnsupportedError>()),
      );
    });
  });

  group('verify() signature-format rejection', () {
    test(
      'a pof-prefixed signature throws IncompatibleVerificationApiError',
      () {
        expect(
          () => Bip322.verify(
            message: 'x',
            address: p2wpkhAddress,
            signature: 'pofAA==',
          ),
          throwsA(isA<IncompatibleVerificationApiError>()),
        );
      },
    );

    test(
      'a ful-prefixed signature throws UnimplementedSignatureFormatError',
      () {
        expect(
          () => Bip322.verify(
            message: 'x',
            address: p2wpkhAddress,
            signature: 'fulAA==',
          ),
          throwsA(isA<UnimplementedSignatureFormatError>()),
        );
      },
    );
  });

  group('Proof of Funds unsupported script type', () {
    test('a P2WSH proof UTXO throws UnsupportedScriptTypeError with its '
        'index and scriptPubKey', () {
      final p2wsh = ProofOfFundsUtxo(
        prevout: OutPoint(List.filled(32, 0x01), 0),
        amount: 1000,
        scriptPubKey: Script([0x00, 0x20, ...List.filled(32, 0xaa)]),
        privateKey: wif,
      );
      try {
        Bip322.signProofOfFunds(
          message: 'x',
          address: p2wpkhAddress,
          privateKey: wif,
          proofUtxos: [p2wsh],
        );
        fail('expected UnsupportedScriptTypeError');
      } on UnsupportedScriptTypeError catch (e) {
        expect(e.utxoIndex, 0);
        expect(e.scriptPubKey.bytes, p2wsh.scriptPubKey.bytes);
      }
    });
  });
}
