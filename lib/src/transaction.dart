import 'dart:typed_data';

import 'package:hex/hex.dart';

import 'crypto/hashes.dart';
import 'script.dart';
import 'utils.dart';
import 'witness.dart';

/// A transaction input outpoint. [hash] is stored in internal (wire) byte
/// order — i.e. the reverse of the displayed txid.
class OutPoint {
  final Uint8List hash;
  final int index;

  OutPoint(List<int> hash, this.index) : hash = Uint8List.fromList(hash) {
    assert(this.hash.length == 32);
  }

  Uint8List toBytes() => concatBytes([hash, uint32LE(index)]);
}

/// A transaction input: the outpoint it spends, its scriptSig, sequence
/// number, and (for segwit inputs) its witness stack.
class TxIn {
  final OutPoint prevout;
  Script scriptSig;
  final int sequence;
  WitnessStack? witness;

  TxIn({
    required this.prevout,
    Script? scriptSig,
    this.sequence = 0,
    this.witness,
  }) : scriptSig = scriptSig ?? Script(const []);

  Uint8List toBytes() => concatBytes([
    prevout.toBytes(),
    compactSize(scriptSig.length),
    scriptSig.bytes,
    uint32LE(sequence),
  ]);
}

/// A transaction output: its value (satoshis) and scriptPubKey.
class TxOut {
  final int value;
  final Script scriptPubKey;

  TxOut({required this.value, required this.scriptPubKey});

  Uint8List toBytes() => concatBytes([
    uint64LE(value),
    compactSize(scriptPubKey.length),
    scriptPubKey.bytes,
  ]);
}

/// A Bitcoin transaction: version, inputs, outputs and locktime, with
/// (de)serialization and txid computation.
class Transaction {
  final int version;
  final List<TxIn> inputs;
  final List<TxOut> outputs;
  final int lockTime;

  Transaction({
    required this.version,
    required this.inputs,
    required this.outputs,
    this.lockTime = 0,
  });

  bool get hasWitness =>
      inputs.any((i) => i.witness != null && !i.witness!.isEmpty);

  /// Serializes the transaction. When [withWitness] is true and any input has a
  /// witness, the segwit marker/flag and witness stacks are included.
  Uint8List serialize({bool withWitness = true}) {
    final segwit = withWitness && hasWitness;
    final chunks = <List<int>>[uint32LE(version)];
    if (segwit) chunks.add(const [0x00, 0x01]);

    chunks.add(compactSize(inputs.length));
    for (final i in inputs) {
      chunks.add(i.toBytes());
    }

    chunks.add(compactSize(outputs.length));
    for (final o in outputs) {
      chunks.add(o.toBytes());
    }

    if (segwit) {
      for (final i in inputs) {
        chunks.add((i.witness ?? WitnessStack(const [])).toBytes());
      }
    }

    chunks.add(uint32LE(lockTime));
    return concatBytes(chunks);
  }

  /// The double-SHA256 of the non-witness serialization, in internal (wire)
  /// byte order — this is what a spending input embeds as its prevout hash.
  Uint8List hashForId() => hash256(serialize(withWitness: false));

  /// The displayed transaction id (hex, big-endian display order).
  String txid() => HEX.encode(reverseBytes(hashForId()));
}
