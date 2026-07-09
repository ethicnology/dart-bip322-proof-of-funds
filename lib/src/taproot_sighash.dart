import 'dart:typed_data';

import 'package:bip341/bip341.dart';
import 'transaction.dart';

/// Bridges a `to_sign` [Transaction] to the self-contained BIP-341 sighash,
/// for the single-input BIP-322 case (spent value is always 0).
Uint8List taprootSighashForToSign(
  Transaction toSign,
  List<int> spentScriptPubKey, {
  int hashType = sighashDefault,
}) => taprootSighashForInput(
  toSign,
  inputIndex: 0,
  amounts: const [0],
  spentScriptPubKeys: [spentScriptPubKey],
  hashType: hashType,
);

/// Bridges a (possibly multi-input) `to_sign` [Transaction] to the
/// self-contained BIP-341 key-path sighash for [inputIndex]. Used for BIP-322
/// Proof of Funds, where `to_sign` carries the challenge input plus one input
/// per proven UTXO — [amounts]/[spentScriptPubKeys] must have one entry per
/// entry in [toSign.inputs], describing every input's spent output (taproot's
/// sighash commits to all of them, not just the one being signed).
Uint8List taprootSighashForInput(
  Transaction toSign, {
  required int inputIndex,
  required List<int> amounts,
  required List<List<int>> spentScriptPubKeys,
  int hashType = sighashDefault,
}) {
  return Bip341.keyPathSighash(
    version: toSign.version,
    lockTime: toSign.lockTime,
    prevouts: [for (final i in toSign.inputs) i.prevout.toBytes()],
    amounts: amounts,
    spentScriptPubKeys: [
      for (final s in spentScriptPubKeys) Uint8List.fromList(s),
    ],
    sequences: [for (final i in toSign.inputs) i.sequence],
    outputs: [for (final o in toSign.outputs) o.toBytes()],
    inputIndex: inputIndex,
    hashType: hashType,
  );
}
