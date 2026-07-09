import 'dart:typed_data';

import 'package:bip340/bip340.dart' as bip340;
import 'package:hex/hex.dart';

/// 32 zero bytes as hex — deterministic BIP-340 signing (no auxiliary rand),
/// which BIP-322 uses so signatures are reproducible.
const String _zeroAux =
    '0000000000000000000000000000000000000000000000000000000000000000';

/// Produces a 64-byte BIP-340 Schnorr signature over [message32] with the
/// (already tweaked) private key [privateKey].
Uint8List schnorrSign(BigInt privateKey, List<int> message32) {
  final sigHex = bip340.sign(
    privateKey.toRadixString(16).padLeft(64, '0'),
    HEX.encode(message32),
    _zeroAux,
  );
  return Uint8List.fromList(HEX.decode(sigHex));
}

/// Verifies a 64-byte BIP-340 Schnorr signature [sig64] over [message32] under
/// the 32-byte x-only public key [xOnlyPub].
bool schnorrVerify(List<int> xOnlyPub, List<int> message32, List<int> sig64) {
  if (xOnlyPub.length != 32 || sig64.length != 64) return false;
  return bip340.verify(
    HEX.encode(xOnlyPub),
    HEX.encode(message32),
    HEX.encode(sig64),
  );
}
