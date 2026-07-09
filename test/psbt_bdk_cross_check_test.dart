import 'dart:convert';
import 'dart:typed_data';

import 'package:bdk_dart/bdk.dart' as bdk;
import 'package:bip322/src/psbt.dart';
import 'package:bip322/src/script.dart';
import 'package:bip322/src/transaction.dart';
import 'package:bip322/src/witness.dart';
import 'package:hex/hex.dart';
import 'package:test/test.dart';

/// Cross-validates [encodeFinalizedPsbt]'s output against `bdk_dart` — the
/// official Bitcoin Dev Kit binding, backed by BDK's Rust PSBT implementation
/// — so this package's hand-rolled BIP-174 codec isn't trusted on its own
/// round-trip alone. `bdk_dart` is a dev-only dependency: PoF's core assembly
/// and encoding stay pure Dart (see psbt.dart), this test just proves the
/// bytes those pure-Dart functions produce are genuinely spec-compliant PSBTs
/// that an independent, widely-used implementation accepts and agrees with.
void main() {
  Uint8List bytes32(int fill) => Uint8List.fromList(List.filled(32, fill));

  group('encodeFinalizedPsbt output is accepted by bdk_dart', () {
    test('single P2WPKH-shaped input round-trips through bdk', () {
      final spk = Script([0x00, 0x14, ...List.filled(20, 0xaa)]);
      final tx = Transaction(
        version: 2,
        lockTime: 0,
        inputs: [
          TxIn(
            prevout: OutPoint(bytes32(0x11), 0),
            sequence: 0xffffffff,
            witness: WitnessStack([
              List.filled(71, 0x30),
              List.filled(33, 0x02),
            ]),
          ),
        ],
        outputs: [
          TxOut(value: 5000, scriptPubKey: Script(const [0x6a])),
        ],
      );
      final spent = TxOut(value: 100000, scriptPubKey: spk);

      final ourBytes = encodeFinalizedPsbt(tx, [spent]);
      final bdkPsbt = bdk.Psbt(psbtBase64: base64Encode(ourBytes));

      // bdk_dart parsed the exact byte layout our codec produced.
      final bdkInputs = bdkPsbt.input();
      expect(bdkInputs.length, 1);

      // bdk can extract a finalized transaction from it — proving bdk agrees
      // our PSBT is well-formed AND already finalized (extractTx requires
      // finalized inputs; it throws otherwise). Compare full wire bytes
      // (rather than a computed txid) for a byte-exact, API-agnostic check.
      final extracted = bdkPsbt.extractTx();
      expect(
        HEX.encode(extracted.serialize()),
        HEX.encode(tx.serialize(withWitness: true)),
      );
    });

    test('multi-input Proof-of-Funds-shaped PSBT round-trips through bdk', () {
      final outputs = [
        TxOut(value: 0, scriptPubKey: Script(const [0x6a])),
      ];
      final tx = Transaction(
        version: 0,
        lockTime: 0,
        inputs: [
          TxIn(
            prevout: OutPoint(bytes32(0x01), 0),
            witness: WitnessStack([List.filled(64, 0x11)]),
          ),
          TxIn(
            prevout: OutPoint(bytes32(0x02), 1),
            witness: WitnessStack([
              List.filled(71, 0x30),
              List.filled(33, 0x02),
            ]),
          ),
        ],
        outputs: outputs,
      );
      final spent = [
        TxOut(
          value: 50000,
          scriptPubKey: Script([0x51, 0x20, ...List.filled(32, 0xbb)]),
        ),
        TxOut(
          value: 75000,
          scriptPubKey: Script([0x00, 0x14, ...List.filled(20, 0xcc)]),
        ),
      ];

      final ourBytes = encodeFinalizedPsbt(tx, spent);
      final bdkPsbt = bdk.Psbt(psbtBase64: base64Encode(ourBytes));

      expect(bdkPsbt.input().length, 2);
      final extracted = bdkPsbt.extractTx();
      expect(
        HEX.encode(extracted.serialize()),
        HEX.encode(tx.serialize(withWitness: true)),
      );
      expect(extracted.input().length, 2);
      expect(extracted.output().length, 1);
    });
  });

  group('bdk_dart-produced PSBTs are readable by decodePsbt', () {
    test('a PSBT built via bdk.Psbt.fromUnsignedTx decodes correctly', () {
      // Build the same transaction bdk-side, from its own Transaction type,
      // to prove decodePsbt isn't just decoding its own encoder's output.
      final bdkTx = bdk.Transaction(
        transactionBytes: Uint8List.fromList(
          Transaction(
            version: 2,
            lockTime: 0,
            inputs: [TxIn(prevout: OutPoint(bytes32(0x33), 0), sequence: 0)],
            outputs: [
              TxOut(value: 0, scriptPubKey: Script(const [0x6a])),
            ],
          ).serialize(withWitness: false),
        ),
      );
      final bdkPsbt = bdk.Psbt.fromUnsignedTx(tx: bdkTx);
      final ourDecoded = decodePsbt(base64Decode(bdkPsbt.serialize()));

      expect(ourDecoded.transaction.inputs.length, 1);
      expect(ourDecoded.transaction.inputs.single.prevout.hash, bytes32(0x33));
      expect(ourDecoded.transaction.outputs.single.value, 0);
    });
  });
}
