import 'dart:convert';

import 'package:bdk_dart/bdk.dart' as bdk;
import 'package:bip322/bip322.dart' hide sighashAll;
import 'package:hex/hex.dart';
import 'package:test/test.dart';

/// Cross-validates a real `Bip322.signProofOfFunds` signature against
/// `bdk_dart` — proving the finalized PSBT this library produces for an
/// actual BIP-322 Proof of Funds (not just a synthetic PSBT shape, as in
/// psbt_bdk_cross_check_test.dart) is accepted and extractable by an
/// independent, widely-used implementation.
void main() {
  test(
    'a real signProofOfFunds PSBT is accepted and extractable by bdk_dart',
    () {
      const challengeWif =
          'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';
      const proofWif =
          '0000000000000000000000000000000000000000000000000000000000000002';
      final challengeAddress = Bip322.p2wpkhAddress(challengeWif);
      final proofAddress = Bip322.p2trAddress(proofWif);
      final proofParsed = parseAddress(proofAddress, Network.mainnet);

      final sig = Bip322.signProofOfFunds(
        message: 'bdk cross-check',
        address: challengeAddress,
        privateKey: challengeWif,
        proofUtxos: [
          ProofOfFundsUtxo(
            prevout: OutPoint(List.filled(32, 0x07), 0),
            amount: 25000,
            scriptPubKey: proofParsed.scriptPubKey,
            privateKey: proofWif,
          ),
        ],
      );
      expect(sig.startsWith('pof'), isTrue);

      final psbtBase64 = sig.substring(3);
      final bdkPsbt = bdk.Psbt(psbtBase64: psbtBase64);
      expect(bdkPsbt.input().length, 2);

      // bdk agrees this PSBT is already finalized and well-formed: extractTx
      // throws if any input isn't finalized.
      final extracted = bdkPsbt.extractTx();
      expect(extracted.input().length, 2);
      expect(extracted.output().length, 1);

      // Our own decoder must agree byte-for-byte with what bdk extracted.
      final ourDecoded = decodePsbt(base64Decode(psbtBase64));
      expect(
        HEX.encode(ourDecoded.transaction.serialize(withWitness: true)),
        HEX.encode(extracted.serialize()),
      );

      // And our own verifier accepts the signature it just produced.
      final result = Bip322.verifyProofOfFunds(
        message: 'bdk cross-check',
        address: challengeAddress,
        signature: sig,
      );
      expect(result.status, ProofOfFundsStatus.valid);
    },
  );
}
