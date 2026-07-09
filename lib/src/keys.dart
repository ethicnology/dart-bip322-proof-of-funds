import 'dart:typed_data';

import 'package:bs58check/bs58check.dart' as bs58check;
import 'package:elliptic/elliptic.dart';
import 'package:hex/hex.dart';

import 'crypto/ecdsa.dart';
import 'exceptions.dart';

/// Parses a private key from a WIF string, a 64-char hex string, a 32-byte
/// [Uint8List], or an existing [PrivateKey].
///
/// The WIF compression flag is accepted but not retained: every address type
/// this library supports (P2WPKH, P2WSH, P2TR) mandates the compressed
/// public key, so an address/key mismatch (e.g. an uncompressed-flagged WIF
/// against a P2WPKH address) surfaces as [InvalidPrivateKeyException] at the
/// signing site rather than being silently accepted.
PrivateKey parsePrivateKey(Object privateKey) {
  if (privateKey is PrivateKey) return privateKey;
  if (privateKey is Uint8List) return _fromBytes(privateKey);
  if (privateKey is String) {
    final s = privateKey.trim();
    if (_isHex64(s)) return PrivateKey.fromHex(secp256k1, s);
    return _fromWif(s);
  }
  throw InvalidPrivateKeyException(
    'unsupported type ${privateKey.runtimeType}',
  );
}

PrivateKey _fromBytes(Uint8List bytes) {
  if (bytes.length != 32) {
    throw InvalidPrivateKeyException('expected 32 bytes, got ${bytes.length}');
  }
  return PrivateKey.fromHex(secp256k1, HEX.encode(bytes));
}

PrivateKey _fromWif(String wif) {
  final Uint8List data;
  try {
    data = bs58check.decode(wif);
  } catch (_) {
    // bs58check throws ArgumentError (a Dart Error, not an Exception) for a
    // malformed base58 alphabet/checksum — must still resolve to our own
    // typed exception rather than propagate uncaught.
    throw InvalidPrivateKeyException('invalid WIF encoding');
  }
  // [version(1)][key(32)] or [version(1)][key(32)][0x01 compressed flag]
  if (data.length == 34 || data.length == 33) {
    return _fromBytes(Uint8List.fromList(data.sublist(1, 33)));
  }
  throw InvalidPrivateKeyException(
    'unexpected WIF payload length ${data.length}',
  );
}

bool _isHex64(String s) =>
    s.length == 64 && RegExp(r'^[0-9a-fA-F]+$').hasMatch(s);
