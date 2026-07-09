import 'package:elliptic/elliptic.dart' show PrivateKey;

import 'address.dart';
// Only the Bip341 facade is needed here; importing the whole barrel would
// clash with this package's own `sighashAll` (BIP-143) against bip341's
// export of the same name (BIP-341).
import 'package:bip341/bip341.dart' show Bip341;
import 'crypto/ecdsa.dart';
import 'crypto/hashes.dart';
import 'crypto/schnorr.dart';
import 'crypto/tagged_hash.dart';
import 'enums.dart';
import 'errors.dart';
import 'exceptions.dart';
import 'formats.dart';
import 'sighash.dart';
import 'taproot_sighash.dart';
import 'utils.dart';
import 'virtual_tx.dart';
import 'witness.dart';

/// Produces a BIP-322 "simple" signature for the given [parsed] address type.
///
/// Only ever called from [Bip322.signMessage] with an already-validated
/// in-scope [parsed] (P2WPKH/P2TR) — [Bip322]'s `_rejectOutOfScopeAddressType`
/// rejects every other [AddressType] before this function is reached, so the
/// remaining cases below are unreachable in practice; they exist only to keep
/// the switch exhaustive.
String signSimple(PrivateKey key, ParsedAddress parsed, String message) {
  switch (parsed.type) {
    case AddressType.p2wpkh:
      return _signP2wpkh(key, parsed, message);
    case AddressType.p2tr:
      return _signP2tr(key, parsed, message);
    case AddressType.p2pkh:
    case AddressType.p2sh:
    case AddressType.p2wsh:
      throw UnreachableCaseError(
        'unreachable: ${parsed.type.name} is rejected before signSimple is called',
      );
  }
}

String _signP2tr(PrivateKey key, ParsedAddress parsed, String message) {
  final tweaked = Bip341.tweakPrivateKey(key.D);
  if (!bytesEqual(tweaked.outputKey, parsed.payload)) {
    throw InvalidPrivateKeyException('key does not match the P2TR address');
  }

  final toSpend = buildToSpend(bip322MessageHash(message), parsed.scriptPubKey);
  final toSign = buildToSign(toSpend);
  final sighash = taprootSighashForToSign(toSign, parsed.scriptPubKey.bytes);
  final sig = schnorrSign(tweaked.outputPrivateKey, sighash); // 64 bytes

  return encodeSimple(WitnessStack([sig]));
}

String _signP2wpkh(PrivateKey key, ParsedAddress parsed, String message) {
  final pub = compressedPublicKey(key);
  final keyHash = hash160(pub);
  if (!bytesEqual(keyHash, parsed.payload)) {
    throw InvalidPrivateKeyException('key does not match the P2WPKH address');
  }

  final toSpend = buildToSpend(bip322MessageHash(message), parsed.scriptPubKey);
  final toSign = buildToSign(toSpend);
  final sighash = sighashSegwitV0(toSign, 0, p2wpkhScriptCode(keyHash), 0);

  final der = ecdsaSignDer(key, sighash);
  final sigItem = concatBytes([
    der,
    const [sighashAll],
  ]);
  return encodeSimple(WitnessStack([sigItem, pub]));
}
