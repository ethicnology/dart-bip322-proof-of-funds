import 'dart:typed_data';

import 'package:hex/hex.dart';

import 'utils.dart';

/// A Bitcoin script, held as raw bytes. This library only needs to *build* a
/// handful of well-known scripts (challenge scriptSig, OP_RETURN, the standard
/// scriptPubKey templates), so no full opcode model is required.
class Script {
  final Uint8List bytes;

  Script(List<int> bytes) : bytes = Uint8List.fromList(bytes);

  factory Script.fromHex(String hex) => Script(HEX.decode(hex));

  int get length => bytes.length;

  String toHex() => HEX.encode(bytes);

  /// The single-byte `OP_RETURN` script used by the `to_sign` output.
  static Script opReturn() => Script(const [0x6a]);

  /// The `to_spend` challenge scriptSig: `OP_0 PUSH32[message_hash]`.
  /// Encoded as bytes `00 20 <32-byte hash>` (minimal push).
  static Script messageChallengeSig(List<int> messageHash) {
    assert(messageHash.length == 32);
    return Script(
      concatBytes([
        const [0x00, 0x20],
        messageHash,
      ]),
    );
  }
}
