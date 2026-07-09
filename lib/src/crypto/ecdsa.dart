import 'dart:typed_data';

import 'package:ecdsa/ecdsa.dart' as ecdsa;
import 'package:elliptic/elliptic.dart';
import 'package:hex/hex.dart';
import 'package:pointycastle/api.dart' show KeyParameter;
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/macs/hmac.dart';

import '../utils.dart';

/// The secp256k1 curve used throughout the library.
final Curve secp256k1 = getS256();

BigInt _bytesToBigInt(List<int> b) =>
    b.isEmpty ? BigInt.zero : BigInt.parse(HEX.encode(b), radix: 16);

Uint8List _bigIntTo32(BigInt x) =>
    Uint8List.fromList(HEX.decode(x.toRadixString(16).padLeft(64, '0')));

Uint8List _hmac(List<int> key, List<int> data) {
  final mac = HMac(SHA256Digest(), 64)
    ..init(KeyParameter(Uint8List.fromList(key)));
  return mac.process(Uint8List.fromList(data));
}

/// The RFC-6979 HMAC-SHA256 DRBG exactly as implemented by libsecp256k1 /
/// Bitcoin Core: the seed is `key32 || msg32` (message used raw), and each
/// generation after the first re-keys with `K = HMAC(K, V||0x00); V = HMAC(K,V)`.
/// This re-key-between-nonces behaviour is what makes low-R grinding (below)
/// byte-compatible with Core.
class _Rfc6979 {
  List<int> _k;
  List<int> _v;
  bool _retry = false;

  _Rfc6979(List<int> seed)
    : _k = List<int>.filled(32, 0x00),
      _v = List<int>.filled(32, 0x01) {
    _k = _hmac(_k, [..._v, 0x00, ...seed]);
    _v = _hmac(_k, _v);
    _k = _hmac(_k, [..._v, 0x01, ...seed]);
    _v = _hmac(_k, _v);
  }

  Uint8List _generate() {
    if (_retry) {
      _k = _hmac(_k, [..._v, 0x00]);
      _v = _hmac(_k, _v);
    }
    _v = _hmac(_k, _v);
    _retry = true;
    return Uint8List.fromList(_v);
  }

  /// The first RFC-6979 candidate in `[1, n)` (advancing the DRBG on rejects).
  BigInt nextNonce(BigInt n) {
    while (true) {
      final k = _bytesToBigInt(_generate());
      if (k >= BigInt.one && k < n) return k;
    }
  }
}

/// 32-byte extra-entropy buffer with [counter] as a little-endian uint32 in the
/// first four bytes — matching Bitcoin Core's low-R grinding.
Uint8List _extraEntropy(int counter) {
  final e = Uint8List(32);
  ByteData.sublistView(e).setUint32(0, counter, Endian.little);
  return e;
}

/// Signs [hash32] with [priv] using deterministic ECDSA with **low-R grinding**,
/// byte-compatible with Bitcoin Core: the first attempt uses the plain
/// `key||msg` RFC-6979 seed; if the resulting R needs 33 bytes (high bit set),
/// it re-signs with `extra_entropy = uint32LE(counter)` appended to the seed,
/// incrementing until R fits in 32 bytes. The signature is normalized to low-S
/// (BIP-62) and returned as strict DER (without a sighash byte).
Uint8List ecdsaSignDer(PrivateKey priv, List<int> hash32) {
  final n = secp256k1.n;
  final d = priv.D;
  final e = _bytesToBigInt(hash32);
  final half = n >> 1;
  final twoPow255 = BigInt.one << 255;
  final base = [..._bigIntTo32(d), ...hash32];

  for (var counter = 0; ; counter++) {
    final seed = counter == 0 ? base : [...base, ..._extraEntropy(counter)];
    final k = _Rfc6979(seed).nextNonce(n);
    final r = secp256k1.scalarBaseMul(_bigIntTo32(k)).X % n;
    if (r == BigInt.zero) continue;
    var s = (k.modInverse(n) * (e + r * d)) % n;
    if (s == BigInt.zero) continue;
    if (s.compareTo(half) > 0) s = n - s; // low-S (BIP-62)
    if (r >= twoPow255) continue; // low-R grinding (Bitcoin Core)
    return Uint8List.fromList(ecdsa.Signature.fromRS(r, s).toDER());
  }
}

/// Verifies a strict-DER ECDSA signature [der] over [hash32] with [pubBytes]
/// (compressed or uncompressed SEC point). Rejects high-S signatures.
///
/// [pubBytes] and [der] are attacker-controlled (witness data from an
/// untrusted signature) — a well-formed-length but off-curve public key or a
/// structurally-invalid DER encoding must fail closed (`false`), not throw:
/// `PublicKey.fromHex` throws for a point not on the curve, and
/// `Signature.fromDER` throws for malformed ASN.1.
bool ecdsaVerifyDer(List<int> pubBytes, List<int> hash32, List<int> der) {
  try {
    final pub = PublicKey.fromHex(secp256k1, HEX.encode(pubBytes));
    final sig = ecdsa.Signature.fromDER(der);
    // Enforce low-S (malleability / NULLFAIL discipline).
    if (sig.S.compareTo(secp256k1.n >> 1) > 0) return false;
    // Enforce strict/canonical DER: the `ecdsa` decoder tolerates non-minimal
    // encodings and trailing bytes, which would let a third party re-encode a
    // valid signature into distinct-but-still-valid blobs. Require the input to
    // round-trip to its canonical serialization byte-for-byte.
    if (!bytesEqual(der, ecdsa.Signature.fromRS(sig.R, sig.S).toDER())) {
      return false;
    }
    return ecdsa.verify(pub, hash32, sig);
  } on Exception {
    return false;
  }
}

/// The compressed (33-byte) SEC public key for [priv].
Uint8List compressedPublicKey(PrivateKey priv) => Uint8List.fromList(
  HEX.decode(priv.curve.privateToPublicKey(priv).toCompressedHex()),
);
