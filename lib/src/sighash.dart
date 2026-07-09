import 'dart:typed_data';

import 'crypto/hashes.dart';
import 'transaction.dart';
import 'utils.dart';

/// SIGHASH_ALL flag.
const int sighashAll = 0x01;

/// Computes the BIP-143 (segwit v0) signature hash for input [inputIndex] of
/// [tx], with the given [scriptCode] (raw bytes, without a length prefix) and
/// spent-output [amount].
///
/// For BIP-322 the committed [amount] is always 0 (the `to_spend` output).
/// Only SIGHASH_ALL is supported (BIP-322 requirement).
Uint8List sighashSegwitV0(
  Transaction tx,
  int inputIndex,
  List<int> scriptCode,
  int amount, {
  int hashType = sighashAll,
}) {
  final hashPrevouts = hash256(
    concatBytes([for (final i in tx.inputs) i.prevout.toBytes()]),
  );
  final hashSequence = hash256(
    concatBytes([for (final i in tx.inputs) uint32LE(i.sequence)]),
  );
  final hashOutputs = hash256(
    concatBytes([for (final o in tx.outputs) o.toBytes()]),
  );

  final input = tx.inputs[inputIndex];
  final preimage = concatBytes([
    uint32LE(tx.version),
    hashPrevouts,
    hashSequence,
    input.prevout.toBytes(),
    compactSize(scriptCode.length),
    scriptCode,
    uint64LE(amount),
    uint32LE(input.sequence),
    hashOutputs,
    uint32LE(tx.lockTime),
    uint32LE(hashType),
  ]);
  return hash256(preimage);
}

/// The implicit P2PKH scriptCode committed to by a P2WPKH (or P2SH-P2WPKH)
/// input: `OP_DUP OP_HASH160 <20-byte keyhash> OP_EQUALVERIFY OP_CHECKSIG`.
Uint8List p2wpkhScriptCode(List<int> keyHash160) {
  assert(keyHash160.length == 20);
  return concatBytes([
    const [0x76, 0xa9, 0x14],
    keyHash160,
    const [0x88, 0xac],
  ]);
}
