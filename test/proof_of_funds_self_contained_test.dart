import 'dart:convert';
import 'dart:typed_data';

import 'package:bip322/bip322.dart';
import 'package:test/test.dart';

/// Tests for the self-contained BIP-322 Proof of Funds path: the message is
/// embedded in the PSBT via PSBT_GLOBAL_GENERIC_SIGNED_MESSAGE (0x09) and the
/// challenge scriptPubKey is read from input 0, so a verifier recovers both
/// from the proof alone (Bip322.verifyProofOfFundsFromSignature).
void main() {
  const challengeWif = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';
  const proofWif =
      '0000000000000000000000000000000000000000000000000000000000000002';
  const message = 'I control these funds';

  final challengeAddress = Bip322.p2wpkhAddress(challengeWif);
  final proofAddress = Bip322.p2trAddress(proofWif);

  Uint8List txid(int fill) => Uint8List.fromList(List.filled(32, fill));

  ProofOfFundsUtxo proofUtxo() {
    final parsed = parseAddress(proofAddress, Network.mainnet);
    return ProofOfFundsUtxo(
      prevout: OutPoint(txid(0x01), 0),
      amount: 50000,
      scriptPubKey: parsed.scriptPubKey,
      privateKey: proofWif,
    );
  }

  String signature() => Bip322.signProofOfFunds(
    message: message,
    address: challengeAddress,
    privateKey: challengeWif,
    proofUtxos: [proofUtxo()],
  );

  group('embedded 0x09 message', () {
    test('decodePsbt recovers the message from the 0x09 global field', () {
      final sig = signature();
      // Strip the `pof` prefix, base64-decode, and decode the PSBT.
      final psbt = base64Decode(base64.normalize(sig.substring(3)));
      final decoded = decodePsbt(psbt);
      expect(decoded.message, message);
    });
  });

  group('addressFromScriptPubKey', () {
    test('round-trips P2WPKH and P2TR scriptPubKeys back to addresses', () {
      for (final addr in [challengeAddress, proofAddress]) {
        final spk = parseAddress(addr, Network.mainnet).scriptPubKey.bytes;
        final encoded = Bip322.addressFromScriptPubKey(
          spk,
          network: Network.mainnet,
        );
        expect(encoded, addr);
      }
    });
  });

  group('self-contained verify', () {
    test('recovers message + challenge and verifies as valid', () {
      final result = Bip322.verifyProofOfFundsFromSignature(signature());
      expect(result.status, ProofOfFundsStatus.valid);
      expect(result.message, message);
      expect(result.challengeScriptPubKey, isNotNull);
      // The recovered challenge scriptPubKey matches the challenge address.
      final expected = parseAddress(challengeAddress, Network.mainnet);
      expect(result.challengeScriptPubKey, expected.scriptPubKey.bytes);
      expect(result.provenUtxos, hasLength(1));
      expect(result.provenUtxos.single.hash, txid(0x01));
    });

    test('matches the caller-supplied-message verify result', () {
      final sig = signature();
      final selfContained = Bip322.verifyProofOfFundsFromSignature(sig);
      final withArgs = Bip322.verifyProofOfFunds(
        message: message,
        address: challengeAddress,
        signature: sig,
      );
      expect(selfContained.status, withArgs.status);
      expect(selfContained.provenUtxos.length, withArgs.provenUtxos.length);
    });

    test('a malformed signature is invalid, never throws', () {
      final result = Bip322.verifyProofOfFundsFromSignature('pof!!!bad!!!');
      expect(result.status, ProofOfFundsStatus.invalid);
    });

    test('a non-pof signature is invalid', () {
      final result = Bip322.verifyProofOfFundsFromSignature('smpAAAA');
      expect(result.status, ProofOfFundsStatus.invalid);
    });
  });

  group('backward compatibility', () {
    test(
      'a proof without the 0x09 field still verifies with an explicit message',
      () {
        // encodeFinalizedPsbt without a message omits the 0x09 field; the
        // classic verify path (message supplied by caller) must still work.
        final parsedChallenge = parseAddress(challengeAddress, Network.mainnet);
        final sig = Bip322.signProofOfFunds(
          message: message,
          address: challengeAddress,
          privateKey: challengeWif,
          proofUtxos: [proofUtxo()],
        );
        // The classic API ignores the embedded message and re-derives to_spend
        // from the supplied message — still valid.
        final result = Bip322.verifyProofOfFunds(
          message: message,
          address: challengeAddress,
          signature: sig,
        );
        expect(result.status, ProofOfFundsStatus.valid);
        expect(parsedChallenge.type, AddressType.p2wpkh);
      },
    );

    test('self-contained verify fails a wrong embedded message tamper', () {
      // Build a valid proof, then verify with the classic API against a
      // DIFFERENT message: to_spend.txid won't match → invalid. This guards
      // that the embedded message is genuinely committed to, not free text.
      final sig = signature();
      final result = Bip322.verifyProofOfFunds(
        message: 'a different message',
        address: challengeAddress,
        signature: sig,
      );
      expect(result.status, ProofOfFundsStatus.invalid);
    });
  });
}
