import 'dart:convert';
import 'dart:typed_data';

import 'package:bip341/bip341.dart' show taggedHash;

/// The BIP-322 message tag used by [bip322MessageHash].
const String bip322Tag = 'BIP0322-signed-message';

/// The BIP-322 message hash.
///
/// [message] is treated as an opaque byte string: it is UTF-8 encoded exactly
/// once, with **no** length prefix, null terminator, or normalization. This is
/// deliberately *not* the legacy `"Bitcoin Signed Message:\n"` construction.
Uint8List bip322MessageHash(String message) =>
    taggedHash(bip322Tag, utf8.encode(message));
