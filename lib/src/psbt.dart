import 'dart:typed_data';

import 'errors.dart';
import 'exceptions.dart';
import 'script.dart';
import 'transaction.dart';
import 'utils.dart';
import 'witness.dart';

/// The two-byte PSBT magic + separator (BIP-174): `0x70 0x73 0x62 0x74 0xff`.
final Uint8List _psbtMagic = Uint8List.fromList([0x70, 0x73, 0x62, 0x74, 0xff]);

// Key types this codec knows about (BIP-174). Only the fields a *finalized*
// PSBT needs are implemented — no partial signatures, no BIP32 derivation
// paths, no PSBTv2 — since bip322 only ever produces or consumes PSBTs that
// are already fully signed (BIP-322 Proof of Funds requires the encoded PSBT
// to be finalized).
const int _globalUnsignedTx = 0x00;
const int _inNonWitnessUtxo = 0x00;
const int _inWitnessUtxo = 0x01;
const int _inFinalScriptSig = 0x07;
const int _inFinalScriptWitness = 0x08;

/// The UTXO an input spends, as recorded in a PSBT input map — either the
/// [witnessUtxo] (amount + scriptPubKey only, used for segwit-native inputs)
/// or the [nonWitnessUtxo] (the full previous transaction, used for legacy
/// inputs, or provided defensively alongside a witness UTXO).
class PsbtInputUtxo {
  final TxOut? witnessUtxo;
  final Uint8List? nonWitnessUtxo;

  PsbtInputUtxo({this.witnessUtxo, this.nonWitnessUtxo});

  /// The spent output's amount and scriptPubKey, however it was recorded.
  /// Throws [DeserializationException] if neither UTXO field was present, or
  /// if [nonWitnessUtxo] doesn't actually have an output at [outputIndex].
  TxOut resolve(int outputIndex) {
    if (witnessUtxo != null) return witnessUtxo!;
    if (nonWitnessUtxo != null) {
      final prevTx = _decodeLegacyTransaction(nonWitnessUtxo!);
      if (outputIndex >= prevTx.outputs.length) {
        throw DeserializationException(
          'non-witness UTXO has no output $outputIndex',
        );
      }
      return prevTx.outputs[outputIndex];
    }
    throw DeserializationException('PSBT input has no UTXO field set');
  }
}

/// A parsed, finalized PSBT: the reconstructed [transaction] (unsigned tx with
/// each input's `final_scriptSig`/`final_scriptWitness` applied) and the
/// per-input [utxos] needed to recompute sighashes for verification.
class DecodedPsbt {
  final Transaction transaction;
  final List<PsbtInputUtxo> utxos;

  DecodedPsbt(this.transaction, this.utxos);
}

/// Encodes a *finalized* PSBT (BIP-174) wrapping [tx] — every input must
/// already carry its final witness (and/or scriptSig, for non-segwit inputs).
/// [spentOutputs] gives the (amount, scriptPubKey) of the output each input
/// spends, one entry per input in [tx], recorded as a witness UTXO (correct
/// for the segwit-native inputs — P2WPKH/P2TR — this library signs for).
///
/// The global unsigned-tx field is [tx] serialized without witness data;
/// per-input maps carry the witness UTXO plus `final_scriptSig`/
/// `final_scriptWitness`. Output maps are empty (no BIP32 paths, no proprietary
/// fields — nothing beyond what a finalized PSBT needs).
Uint8List encodeFinalizedPsbt(Transaction tx, List<TxOut> spentOutputs) {
  if (spentOutputs.length != tx.inputs.length) {
    throw MismatchedSpentOutputCountError(
      tx.inputs.length,
      spentOutputs.length,
    );
  }

  final chunks = <List<int>>[_psbtMagic];

  // Global map: PSBT_GLOBAL_UNSIGNED_TX. The unsigned tx has no witness data;
  // every input this library signs for is native segwit (empty scriptSig), so
  // tx.serialize(withWitness: false) is already the correct unsigned-tx bytes.
  chunks
    ..add(_kv(_globalUnsignedTx, const [], tx.serialize(withWitness: false)))
    ..add(_mapTerminator);

  for (var i = 0; i < tx.inputs.length; i++) {
    final input = tx.inputs[i];
    chunks.add(_kv(_inWitnessUtxo, const [], spentOutputs[i].toBytes()));
    if (input.scriptSig.length > 0) {
      chunks.add(_kv(_inFinalScriptSig, const [], input.scriptSig.bytes));
    }
    if (input.witness != null && !input.witness!.isEmpty) {
      chunks.add(
        _kv(_inFinalScriptWitness, const [], input.witness!.toBytes()),
      );
    }
    chunks.add(_mapTerminator);
  }

  // One empty output map per output — nothing to record for a finalized PSBT.
  for (var o = 0; o < tx.outputs.length; o++) {
    chunks.add(_mapTerminator);
  }

  return concatBytes(chunks);
}

/// Decodes a PSBT produced by [encodeFinalizedPsbt] (or any BIP-174-compliant
/// finalized PSBT using witness and/or non-witness UTXOs). Throws
/// [DeserializationException] for malformed input — callers verifying
/// untrusted signatures should catch it and treat the signature as invalid,
/// the same policy [WitnessStack.fromBytes] and the rest of this package use.
DecodedPsbt decodePsbt(Uint8List bytes) {
  final reader = ByteReader(bytes);
  final magic = reader.read(5);
  if (!bytesEqual(magic, _psbtMagic)) {
    throw DeserializationException('not a PSBT (bad magic)');
  }

  Uint8List? unsignedTxBytes;
  for (final (type, keyData, value) in _readMap(reader)) {
    if (type == _globalUnsignedTx && keyData.isEmpty) unsignedTxBytes = value;
  }
  if (unsignedTxBytes == null) {
    throw DeserializationException('PSBT missing PSBT_GLOBAL_UNSIGNED_TX');
  }
  final unsignedTx = _decodeLegacyTransaction(unsignedTxBytes);

  final utxos = <PsbtInputUtxo>[];
  final finalScriptSigs = <Uint8List?>[];
  final finalWitnesses = <WitnessStack?>[];
  for (var i = 0; i < unsignedTx.inputs.length; i++) {
    TxOut? witnessUtxo;
    Uint8List? nonWitnessUtxo;
    Uint8List? finalScriptSig;
    WitnessStack? finalScriptWitness;
    for (final (type, keyData, value) in _readMap(reader)) {
      if (keyData.isNotEmpty) continue; // no keyed per-input fields supported
      switch (type) {
        case _inWitnessUtxo:
          witnessUtxo = _decodeTxOut(value);
        case _inNonWitnessUtxo:
          nonWitnessUtxo = value;
        case _inFinalScriptSig:
          finalScriptSig = value;
        case _inFinalScriptWitness:
          finalScriptWitness = WitnessStack.fromBytes(value);
      }
    }
    utxos.add(
      PsbtInputUtxo(witnessUtxo: witnessUtxo, nonWitnessUtxo: nonWitnessUtxo),
    );
    finalScriptSigs.add(finalScriptSig);
    finalWitnesses.add(finalScriptWitness);
  }

  // Output maps carry nothing this codec reads; still must be consumed.
  for (var o = 0; o < unsignedTx.outputs.length; o++) {
    for (final _ in _readMap(reader)) {}
  }
  if (!reader.isEmpty) {
    throw DeserializationException('trailing bytes after PSBT');
  }

  final finalized = Transaction(
    version: unsignedTx.version,
    lockTime: unsignedTx.lockTime,
    inputs: [
      for (var i = 0; i < unsignedTx.inputs.length; i++)
        TxIn(
          prevout: unsignedTx.inputs[i].prevout,
          scriptSig: finalScriptSigs[i] == null
              ? null
              : Script(finalScriptSigs[i]!),
          sequence: unsignedTx.inputs[i].sequence,
          witness: finalWitnesses[i],
        ),
    ],
    outputs: unsignedTx.outputs,
  );
  return DecodedPsbt(finalized, utxos);
}

/// Reads key-value pairs until the zero-length-key map terminator. Each yielded
/// tuple is `(keyType, keyData, value)` — `keyData` is whatever follows the
/// single key-type byte (empty for every key type this codec supports).
Iterable<(int, Uint8List, Uint8List)> _readMap(ByteReader reader) sync* {
  while (true) {
    final keyLen = reader.readCompactSize();
    if (keyLen == 0) return; // map terminator
    final key = reader.read(keyLen);
    final valueLen = reader.readCompactSize();
    final value = reader.read(valueLen);
    yield (key[0], Uint8List.fromList(key.sublist(1)), value);
  }
}

const List<int> _mapTerminator = [0x00];

Uint8List _kv(int keyType, List<int> keyData, List<int> value) => concatBytes([
  compactSize(1 + keyData.length),
  [keyType],
  keyData,
  compactSize(value.length),
  value,
]);

TxOut _decodeTxOut(Uint8List bytes) {
  final reader = ByteReader(bytes);
  final value = reader.readUint64LE();
  final spkLen = reader.readCompactSize();
  final spk = reader.read(spkLen);
  if (!reader.isEmpty) {
    throw DeserializationException('trailing bytes after witness UTXO');
  }
  return TxOut(value: value, scriptPubKey: Script(spk));
}

/// Decodes a non-segwit-serialized transaction (as PSBT's global unsigned tx
/// and non-witness UTXOs both use — no marker/flag/witness fields).
Transaction _decodeLegacyTransaction(Uint8List bytes) {
  final reader = ByteReader(bytes);
  final version = reader.readUint32LE();
  final inCount = reader.readCompactSize();
  final inputs = <TxIn>[];
  for (var i = 0; i < inCount; i++) {
    final hash = reader.read(32);
    final index = reader.readUint32LE();
    final scriptSigLen = reader.readCompactSize();
    final scriptSig = reader.read(scriptSigLen);
    final sequence = reader.readUint32LE();
    inputs.add(
      TxIn(
        prevout: OutPoint(hash, index),
        scriptSig: Script(scriptSig),
        sequence: sequence,
      ),
    );
  }
  final outCount = reader.readCompactSize();
  final outputs = <TxOut>[];
  for (var i = 0; i < outCount; i++) {
    final value = reader.readUint64LE();
    final spkLen = reader.readCompactSize();
    final spk = reader.read(spkLen);
    outputs.add(TxOut(value: value, scriptPubKey: Script(spk)));
  }
  final lockTime = reader.readUint32LE();
  if (!reader.isEmpty) {
    throw DeserializationException('trailing bytes after legacy transaction');
  }
  return Transaction(
    version: version,
    lockTime: lockTime,
    inputs: inputs,
    outputs: outputs,
  );
}
