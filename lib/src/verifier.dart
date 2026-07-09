import 'address.dart';
import 'package:bip341/bip341.dart' show sighashDefault;
import 'crypto/ecdsa.dart';
import 'crypto/hashes.dart';
import 'crypto/schnorr.dart';
import 'crypto/tagged_hash.dart';
import 'enums.dart';
import 'sighash.dart';
import 'taproot_sighash.dart';
import 'utils.dart';
import 'virtual_tx.dart';
import 'witness.dart';

/// Verifies a "simple" witness [witness] against [parsed] for [message].
/// Binds the witness structure to the address type (strict policy).
///
/// [Bip322]'s `_rejectOutOfScopeAddressType` already rejects every
/// [AddressType] other than P2WPKH/P2TR before this function is reached, so
/// the `default` branch below is unreachable in practice; it stays a
/// fail-closed `false` (rather than an unreachable-`StateError`, unlike
/// [signSimple]) as defense in depth for a function whose whole purpose is
/// evaluating untrusted input.
bool verifySimple(ParsedAddress parsed, String message, WitnessStack witness) {
  switch (parsed.type) {
    case AddressType.p2wpkh:
      return _verifyP2wpkh(parsed, message, witness);
    case AddressType.p2tr:
      return _verifyP2tr(parsed, message, witness);
    default:
      return false;
  }
}

bool _verifyP2tr(ParsedAddress parsed, String message, WitnessStack witness) {
  if (witness.length != 1) return false;
  var sig = witness.items[0];
  var hashType = sighashDefault;
  if (sig.length == 65) {
    hashType = sig.last;
    if (hashType == sighashDefault) return false; // must use 64-byte form
    // BIP-322 requires SIGHASH_ALL or SIGHASH_DEFAULT only; the sighash
    // computation below does not implement NONE/SINGLE/ANYONECANPAY
    // semantics (it always hashes every field unconditionally, which is
    // only correct for ALL/DEFAULT), so any other explicit type must be
    // rejected here rather than verified against a wrongly-computed hash.
    if (hashType != sighashAll) return false;
    sig = sig.sublist(0, 64);
  } else if (sig.length != 64) {
    return false;
  }

  final toSpend = buildToSpend(bip322MessageHash(message), parsed.scriptPubKey);
  final toSign = buildToSign(toSpend);
  final sighash = taprootSighashForToSign(
    toSign,
    parsed.scriptPubKey.bytes,
    hashType: hashType,
  );
  return schnorrVerify(parsed.payload, sighash, sig);
}

bool _verifyP2wpkh(ParsedAddress parsed, String message, WitnessStack witness) {
  if (witness.length != 2) return false;
  final sigItem = witness.items[0];
  final pub = witness.items[1];

  // P2WPKH requires a 33-byte compressed key that hashes to the address.
  if (pub.length != 33) return false;
  if (!bytesEqual(hash160(pub), parsed.payload)) return false;

  if (sigItem.isEmpty) return false;
  if (sigItem.last != sighashAll) return false; // SIGHASH_ALL only
  final der = sigItem.sublist(0, sigItem.length - 1);

  final toSpend = buildToSpend(bip322MessageHash(message), parsed.scriptPubKey);
  final toSign = buildToSign(toSpend);
  final sighash = sighashSegwitV0(toSign, 0, p2wpkhScriptCode(hash160(pub)), 0);

  return ecdsaVerifyDer(pub, sighash, der);
}
