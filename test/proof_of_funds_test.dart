import 'dart:convert';
import 'dart:typed_data';

// `sighashAll` is hidden: this test needs bip322's own BIP-143 constant
// (imported below from src/sighash.dart), which otherwise collides with
// bip341's identically-named BIP-341 constant re-exported by this barrel.
import 'package:bip322/bip322.dart' hide sighashAll;
import 'package:bip322/src/crypto/ecdsa.dart';
import 'package:bip322/src/crypto/hashes.dart';
import 'package:bip322/src/keys.dart';
import 'package:bip322/src/sighash.dart';
import 'package:bip322/src/utils.dart';
import 'package:bs58check/bs58check.dart' as bs58check;
import 'package:test/test.dart';

/// End-to-end tests for Bip322.signProofOfFunds / Bip322.verifyProofOfFunds —
/// the BIP-322 "Full (Proof of Funds)" format: a message signature (input 0)
/// plus additional, genuinely-satisfied inputs demonstrating control of an
/// arbitrary UTXO set. No official test vectors exist for this format yet
/// (unlike Simple), so these are constructed round-trips plus the tamper /
/// scope checks the rest of this package's test suite already follows.
void main() {
  // Three independent keys: one for the challenge address, two for proof
  // UTXOs of different types (P2WPKH and P2TR), to prove nothing accidentally
  // assumes the proof UTXOs share the challenge's key or type.
  const challengeWif = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';
  const proofWifA =
      '0000000000000000000000000000000000000000000000000000000000000002';
  const proofWifB =
      '0000000000000000000000000000000000000000000000000000000000000003';

  final challengeAddress = Bip322.p2wpkhAddress(challengeWif);
  final proofAddressA = Bip322.p2wpkhAddress(proofWifA);
  final proofAddressB = Bip322.p2trAddress(proofWifB);

  ProofOfFundsUtxo utxoFor(
    String address,
    Object privateKey, {
    required Uint8List txid,
    required int vout,
    required int amount,
  }) {
    final parsed = parseAddress(address, Network.mainnet);
    return ProofOfFundsUtxo(
      prevout: OutPoint(txid, vout),
      amount: amount,
      scriptPubKey: parsed.scriptPubKey,
      privateKey: privateKey,
    );
  }

  Uint8List txid(int fill) => Uint8List.fromList(List.filled(32, fill));

  group('sign + verify round trip', () {
    test('P2WPKH challenge, P2WPKH + P2TR proof UTXOs: valid', () {
      final proofUtxos = [
        utxoFor(
          proofAddressA,
          proofWifA,
          txid: txid(0x01),
          vout: 0,
          amount: 50000,
        ),
        utxoFor(
          proofAddressB,
          proofWifB,
          txid: txid(0x02),
          vout: 1,
          amount: 75000,
        ),
      ];

      final sig = Bip322.signProofOfFunds(
        message: 'I control these funds',
        address: challengeAddress,
        privateKey: challengeWif,
        proofUtxos: proofUtxos,
      );
      expect(sig.startsWith('pof'), isTrue);

      final result = Bip322.verifyProofOfFunds(
        message: 'I control these funds',
        address: challengeAddress,
        signature: sig,
      );
      expect(result.status, ProofOfFundsStatus.valid);
      expect(result.isValid, isTrue);
      expect(result.provenUtxos.length, 2);
      expect(result.provenUtxos[0].hash, txid(0x01));
      expect(result.provenUtxos[1].hash, txid(0x02));
    });

    test('P2TR challenge with a single P2WPKH proof UTXO: valid', () {
      final sig = Bip322.signProofOfFunds(
        message: 'taproot challenge',
        address: proofAddressB,
        privateKey: proofWifB,
        proofUtxos: [
          utxoFor(
            proofAddressA,
            proofWifA,
            txid: txid(0x03),
            vout: 0,
            amount: 1000,
          ),
        ],
      );
      final result = Bip322.verifyProofOfFunds(
        message: 'taproot challenge',
        address: proofAddressB,
        signature: sig,
      );
      expect(result.status, ProofOfFundsStatus.valid);
      expect(result.provenUtxos, hasLength(1));
    });

    test('no additional UTXOs (degenerate case) still verifies', () {
      final sig = Bip322.signProofOfFunds(
        message: 'no proof utxos',
        address: challengeAddress,
        privateKey: challengeWif,
        proofUtxos: const [],
      );
      final result = Bip322.verifyProofOfFunds(
        message: 'no proof utxos',
        address: challengeAddress,
        signature: sig,
      );
      expect(result.status, ProofOfFundsStatus.valid);
      expect(result.provenUtxos, isEmpty);
    });
  });

  group('tamper detection', () {
    late String sig;
    setUp(() {
      sig = Bip322.signProofOfFunds(
        message: 'tamper check',
        address: challengeAddress,
        privateKey: challengeWif,
        proofUtxos: [
          utxoFor(
            proofAddressA,
            proofWifA,
            txid: txid(0x11),
            vout: 0,
            amount: 5000,
          ),
        ],
      );
    });

    test('wrong message fails', () {
      final result = Bip322.verifyProofOfFunds(
        message: 'wrong message',
        address: challengeAddress,
        signature: sig,
      );
      expect(result.status, ProofOfFundsStatus.invalid);
    });

    test('wrong address fails', () {
      final result = Bip322.verifyProofOfFunds(
        message: 'tamper check',
        address: proofAddressA,
        signature: sig,
      );
      expect(result.status, ProofOfFundsStatus.invalid);
    });

    test('corrupted PSBT bytes fail (never throw)', () {
      final raw = base64Decode(sig.substring(3));
      final corrupted = 'pof${base64Encode([...raw, 0xde, 0xad])}';
      final result = Bip322.verifyProofOfFunds(
        message: 'tamper check',
        address: challengeAddress,
        signature: corrupted,
      );
      expect(result.status, ProofOfFundsStatus.invalid);
    });

    test('garbled base64 fails (never throws)', () {
      final result = Bip322.verifyProofOfFunds(
        message: 'tamper check',
        address: challengeAddress,
        signature: 'pof!!!not-base64!!!',
      );
      expect(result.status, ProofOfFundsStatus.invalid);
    });

    test('missing pof prefix fails', () {
      final result = Bip322.verifyProofOfFunds(
        message: 'tamper check',
        address: challengeAddress,
        signature: sig.substring(3), // strip "pof"
      );
      expect(result.status, ProofOfFundsStatus.invalid);
    });
  });

  group('unrecognised proof-UTXO scripts', () {
    test(
      'signing for a non-P2WPKH/P2TR proof UTXO throws UnsupportedError',
      () {
        final p2wsh = ProofOfFundsUtxo(
          prevout: OutPoint(txid(0x21), 0),
          amount: 1000,
          scriptPubKey: Script([0x00, 0x20, ...List.filled(32, 0xaa)]),
          privateKey: proofWifA,
        );
        expect(
          () => Bip322.signProofOfFunds(
            message: 'x',
            address: challengeAddress,
            privateKey: challengeWif,
            proofUtxos: [p2wsh],
          ),
          throwsUnsupportedError,
        );
      },
    );

    test('a P2WSH proof UTXO in an otherwise-valid signature is inconclusive, '
        'never silently valid nor wrongly invalid', () {
      // signProofOfFunds refuses P2WSH proof UTXOs, so this constructs the
      // PSBT directly: a P2WPKH challenge input (index 0) plus a P2WSH input
      // (index 1) the library doesn't understand. Input 0 must be signed
      // against a skeleton that ALREADY includes input 1 — BIP-143's sighash
      // commits to every input's prevout/sequence, so signing against a
      // 1-input skeleton and appending a 2nd input afterward would (rightly)
      // invalidate input 0's signature; that's not what this test is about.
      final challengeKey = parsePrivateKey(challengeWif);
      final challengeParsed = parseAddress(challengeAddress, Network.mainnet);
      final toSpend = Bip322.buildToSpendFromAddress(
        'inconclusive check',
        challengeAddress,
      );
      final p2wshSpk = Script([0x00, 0x20, ...List.filled(32, 0xbb)]);

      final skeleton = Transaction(
        version: 0,
        lockTime: 0,
        inputs: [
          TxIn(prevout: OutPoint(toSpend.hashForId(), 0)),
          TxIn(prevout: OutPoint(txid(0x32), 0)),
        ],
        outputs: [TxOut(value: 0, scriptPubKey: Script.opReturn())],
      );

      final pub = compressedPublicKey(challengeKey);
      final keyHash = hash160(pub);
      final sighash = sighashSegwitV0(
        skeleton,
        0,
        p2wpkhScriptCode(keyHash),
        0,
      );
      final der = ecdsaSignDer(challengeKey, sighash);
      final challengeWitness = WitnessStack([
        [...der, sighashAll],
        pub,
      ]);
      expect(bytesEqual(keyHash, challengeParsed.payload), isTrue);

      final withExtraInput = Transaction(
        version: skeleton.version,
        lockTime: skeleton.lockTime,
        inputs: [
          TxIn(prevout: skeleton.inputs[0].prevout, witness: challengeWitness),
          TxIn(
            prevout: skeleton.inputs[1].prevout,
            witness: WitnessStack([List.filled(10, 0xff)]),
          ),
        ],
        outputs: skeleton.outputs,
      );
      final spentOutputs = [
        TxOut(value: 0, scriptPubKey: challengeParsed.scriptPubKey),
        TxOut(value: 2000, scriptPubKey: p2wshSpk),
      ];
      final crafted =
          'pof${base64Encode(encodeFinalizedPsbt(withExtraInput, spentOutputs))}';

      final result = Bip322.verifyProofOfFunds(
        message: 'inconclusive check',
        address: challengeAddress,
        signature: crafted,
      );
      expect(result.status, ProofOfFundsStatus.inconclusive);
    });
  });

  group('key/address mismatch', () {
    test('challenge private key not matching address throws', () {
      expect(
        () => Bip322.signProofOfFunds(
          message: 'x',
          address: challengeAddress,
          privateKey: proofWifA, // wrong key for challengeAddress
          proofUtxos: const [],
        ),
        throwsA(isA<InvalidPrivateKeyException>()),
      );
    });

    test('proof UTXO private key not matching its scriptPubKey throws', () {
      expect(
        () => Bip322.signProofOfFunds(
          message: 'x',
          address: challengeAddress,
          privateKey: challengeWif,
          proofUtxos: [
            utxoFor(
              proofAddressA,
              proofWifB, // wrong key for proofAddressA
              txid: txid(0x41),
              vout: 0,
              amount: 1000,
            ),
          ],
        ),
        throwsA(isA<InvalidPrivateKeyException>()),
      );
    });
  });

  group('out-of-scope address types', () {
    test('P2PKH challenge address throws UnsupportedError', () {
      // Same approach as scope_test.dart: a valid-checksum address built
      // directly, independent of any real-world address — only the version
      // byte and length matter for parseAddress to recognise it as P2PKH.
      final p2pkhAddress = bs58check.encode(
        Uint8List.fromList([0x00, ...List.filled(20, 0)]),
      );
      expect(
        () => Bip322.signProofOfFunds(
          message: 'x',
          address: p2pkhAddress,
          privateKey: challengeWif,
          proofUtxos: const [],
        ),
        throwsUnsupportedError,
      );
    });
  });
}
