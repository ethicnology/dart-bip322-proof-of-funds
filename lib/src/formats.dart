import 'dart:convert';
import 'dart:typed_data';

import 'enums.dart';
import 'exceptions.dart';
import 'witness.dart';

/// ASCII variant prefixes defined by BIP-322 ("Signers MUST prefix ...").
const String simplePrefix = 'smp';
const String fullPrefix = 'ful';
const String proofOfFundsPrefix = 'pof';

/// Encodes a "simple" signature: `smp` + base64(witness stack).
String encodeSimple(WitnessStack witness) =>
    simplePrefix + base64.encode(witness.toBytes());

/// A decoded signature blob: its detected [format] and the raw [payload]
/// (base64-decoded, prefix stripped).
class DecodedSignature {
  final SignatureFormat format;
  final Uint8List payload;

  DecodedSignature(this.format, this.payload);

  /// Parses the witness stack from a simple-format payload.
  WitnessStack get witness => WitnessStack.fromBytes(payload);
}

/// Decodes a signature string into its variant and raw payload.
///
/// Recognises the explicit `smp`/`ful`/`pof` prefixes. Without a prefix, a
/// 65-byte payload is treated as legacy (BIP-137) and anything else as "simple"
/// — the backward-compatible fallback the spec permits ("a verifier might
/// assume the simple variant in the absence of a prefix"). [loose] is reserved
/// for a future BIP-137 cross-type policy and currently does not affect format
/// detection.
DecodedSignature decodeSignature(String signature, {bool loose = false}) {
  for (final entry in const {
    simplePrefix: SignatureFormat.simple,
    fullPrefix: SignatureFormat.full,
    proofOfFundsPrefix: SignatureFormat.proofOfFunds,
  }.entries) {
    if (signature.startsWith(entry.key)) {
      return DecodedSignature(
        entry.value,
        _decodeBase64(signature.substring(entry.key.length)),
      );
    }
  }

  final raw = _decodeBase64(signature);
  if (raw.length == 65) {
    return DecodedSignature(SignatureFormat.legacy, raw);
  }
  return DecodedSignature(SignatureFormat.simple, raw);
}

Uint8List _decodeBase64(String s) {
  try {
    return base64.decode(base64.normalize(s));
  } on FormatException {
    throw MalformedSignatureException('invalid base64');
  }
}
