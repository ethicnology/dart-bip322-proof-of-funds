import 'dart:typed_data';

import 'package:bip322/src/exceptions.dart';
import 'package:bip322/src/psbt.dart';
import 'package:bip322/src/script.dart';
import 'package:bip322/src/transaction.dart';
import 'package:bip322/src/witness.dart';
import 'package:hex/hex.dart';
import 'package:test/test.dart';

/// Round-trip and malformed-input tests for the finalized-PSBT codec
/// ([encodeFinalizedPsbt] / [decodePsbt]). BIP-322 Proof of Funds requires the
/// signature to be exactly this: a base64-encoded finalized PSBT — see
/// bip-0322.mediawiki, "Full (Proof of Funds)".
void main() {
  Uint8List bytes32(int fill) => Uint8List.fromList(List.filled(32, fill));

  group('encodeFinalizedPsbt / decodePsbt round trip', () {
    test('single P2WPKH-shaped input, single output', () {
      final spk = Script([0x00, 0x14, ...List.filled(20, 0xaa)]);
      final tx = Transaction(
        version: 2,
        lockTime: 0,
        inputs: [
          TxIn(
            prevout: OutPoint(bytes32(0x11), 0),
            sequence: 0xffffffff,
            witness: WitnessStack([
              List.filled(71, 0x30), // fake DER+sighash sig item
              List.filled(33, 0x02), // fake compressed pubkey
            ]),
          ),
        ],
        outputs: [
          TxOut(value: 0, scriptPubKey: Script(const [0x6a])),
        ],
      );
      final spent = TxOut(value: 100000, scriptPubKey: spk);

      final psbt = encodeFinalizedPsbt(tx, [spent]);
      final decoded = decodePsbt(psbt);

      expect(decoded.transaction.version, 2);
      expect(decoded.transaction.inputs.single.prevout.hash, bytes32(0x11));
      expect(decoded.transaction.inputs.single.sequence, 0xffffffff);
      expect(
        HEX.encode(decoded.transaction.inputs.single.witness!.toBytes()),
        HEX.encode(tx.inputs.single.witness!.toBytes()),
      );
      expect(
        HEX.encode(decoded.transaction.outputs.single.toBytes()),
        HEX.encode(tx.outputs.single.toBytes()),
      );
      final resolved = decoded.utxos.single.resolve(0);
      expect(resolved.value, 100000);
      expect(HEX.encode(resolved.scriptPubKey.bytes), HEX.encode(spk.bytes));
    });

    test('multiple inputs (Proof of Funds shape) preserve order and UTXOs', () {
      final outputs = [
        TxOut(value: 0, scriptPubKey: Script(const [0x6a])),
      ];
      final tx = Transaction(
        version: 0,
        lockTime: 0,
        inputs: [
          TxIn(
            prevout: OutPoint(bytes32(0x01), 0),
            witness: WitnessStack([List.filled(64, 0x11)]), // taproot-shaped
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

      final decoded = decodePsbt(encodeFinalizedPsbt(tx, spent));
      expect(decoded.transaction.inputs.length, 2);
      expect(decoded.utxos.length, 2);
      expect(decoded.utxos[0].resolve(0).value, 50000);
      expect(decoded.utxos[1].resolve(1).value, 75000);
      // Input order must be preserved exactly (index 0 is always the BIP-322
      // challenge input; reordering would silently break verification).
      expect(decoded.transaction.inputs[0].prevout.hash, bytes32(0x01));
      expect(decoded.transaction.inputs[1].prevout.hash, bytes32(0x02));
    });

    test('input with no witness (bare scriptSig-only) round-trips', () {
      final tx = Transaction(
        version: 0,
        lockTime: 0,
        inputs: [
          TxIn(
            prevout: OutPoint(bytes32(0x05), 0),
            scriptSig: Script([0x00, 0x20, ...bytes32(0x99)]),
          ),
        ],
        outputs: [
          TxOut(value: 0, scriptPubKey: Script(const [0x6a])),
        ],
      );
      final spent = [
        TxOut(value: 0, scriptPubKey: Script([0x00, 0x20, ...bytes32(0xaa)])),
      ];
      final decoded = decodePsbt(encodeFinalizedPsbt(tx, spent));
      expect(decoded.transaction.inputs.single.witness, isNull);
      expect(
        HEX.encode(decoded.transaction.inputs.single.scriptSig.bytes),
        HEX.encode(tx.inputs.single.scriptSig.bytes),
      );
    });
  });

  group('encodeFinalizedPsbt argument validation', () {
    test('rejects mismatched spentOutputs length', () {
      final tx = Transaction(
        version: 0,
        lockTime: 0,
        inputs: [TxIn(prevout: OutPoint(bytes32(0x01), 0))],
        outputs: [
          TxOut(value: 0, scriptPubKey: Script(const [0x6a])),
        ],
      );
      expect(() => encodeFinalizedPsbt(tx, const []), throwsArgumentError);
    });
  });

  group('decodePsbt malformed input (never throws past this into verify)', () {
    test('bad magic', () {
      expect(
        () => decodePsbt(Uint8List.fromList([1, 2, 3, 4, 5, 6])),
        throwsA(isA<DeserializationException>()),
      );
    });

    test('truncated after magic', () {
      expect(
        () => decodePsbt(Uint8List.fromList([0x70, 0x73, 0x62, 0x74, 0xff])),
        throwsA(isA<DeserializationException>()),
      );
    });

    test('missing PSBT_GLOBAL_UNSIGNED_TX', () {
      final bytes = Uint8List.fromList([
        0x70, 0x73, 0x62, 0x74, 0xff, // magic
        0x00, // empty global map (just the terminator)
      ]);
      expect(() => decodePsbt(bytes), throwsA(isA<DeserializationException>()));
    });

    test('trailing garbage after a valid PSBT', () {
      final tx = Transaction(
        version: 0,
        lockTime: 0,
        inputs: [TxIn(prevout: OutPoint(bytes32(0x01), 0))],
        outputs: [
          TxOut(value: 0, scriptPubKey: Script(const [0x6a])),
        ],
      );
      final spent = [
        TxOut(value: 0, scriptPubKey: Script(const [0x51, 0x20])),
      ];
      final good = encodeFinalizedPsbt(tx, spent);
      final withGarbage = Uint8List.fromList([...good, 0xde, 0xad]);
      expect(
        () => decodePsbt(withGarbage),
        throwsA(isA<DeserializationException>()),
      );
    });
  });

  group('PsbtInputUtxo.resolve', () {
    test('throws when no UTXO field is set', () {
      expect(
        () => PsbtInputUtxo().resolve(0),
        throwsA(isA<DeserializationException>()),
      );
    });

    test('resolves from nonWitnessUtxo by output index', () {
      final prevTx = Transaction(
        version: 2,
        lockTime: 0,
        inputs: [TxIn(prevout: OutPoint(bytes32(0x01), 0))],
        outputs: [
          TxOut(value: 111, scriptPubKey: Script(const [0x51, 0x20])),
          TxOut(value: 222, scriptPubKey: Script(const [0x00, 0x14])),
        ],
      );
      final utxo = PsbtInputUtxo(
        nonWitnessUtxo: prevTx.serialize(withWitness: false),
      );
      expect(utxo.resolve(1).value, 222);
    });
  });
}
