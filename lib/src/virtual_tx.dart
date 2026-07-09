import 'dart:typed_data';

import 'script.dart';
import 'transaction.dart';
import 'witness.dart';

/// The null outpoint used by the `to_spend` input: 32 zero bytes, index
/// 0xFFFFFFFF (coinbase-style).
final _nullPrevoutHash = Uint8List(32);
const _nullPrevoutIndex = 0xFFFFFFFF;

/// Builds the BIP-322 `to_spend` virtual transaction.
///
/// nVersion=0, nLockTime=0; single input with the null prevout, sequence 0 and
/// `scriptSig = OP_0 PUSH32[messageHash]`; single output value 0 whose
/// scriptPubKey is the address's [scriptPubKey] (the message challenge).
Transaction buildToSpend(Uint8List messageHash, Script scriptPubKey) {
  return Transaction(
    version: 0,
    lockTime: 0,
    inputs: [
      TxIn(
        prevout: OutPoint(_nullPrevoutHash, _nullPrevoutIndex),
        scriptSig: Script.messageChallengeSig(messageHash),
        sequence: 0,
      ),
    ],
    outputs: [TxOut(value: 0, scriptPubKey: scriptPubKey)],
  );
}

/// Builds the BIP-322 `to_sign` virtual transaction spending [toSpend]:0.
///
/// nVersion=0, nLockTime=0; single input (empty scriptSig, sequence 0, the
/// [witness] carrying the message signature); single output value 0 with an
/// `OP_RETURN` scriptPubKey.
Transaction buildToSign(Transaction toSpend, {WitnessStack? witness}) {
  return Transaction(
    version: 0,
    lockTime: 0,
    inputs: [
      TxIn(
        prevout: OutPoint(toSpend.hashForId(), 0),
        sequence: 0,
        witness: witness,
      ),
    ],
    outputs: [TxOut(value: 0, scriptPubKey: Script.opReturn())],
  );
}
