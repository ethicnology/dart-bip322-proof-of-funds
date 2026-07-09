import 'dart:typed_data';

import 'package:pointycastle/digests/ripemd160.dart';
import 'package:pointycastle/digests/sha256.dart';

/// Single SHA-256.
Uint8List sha256(List<int> data) =>
    SHA256Digest().process(Uint8List.fromList(data));

/// Double SHA-256 (`SHA256(SHA256(x))`), Bitcoin's `Hash256`.
Uint8List hash256(List<int> data) => sha256(sha256(data));

/// `RIPEMD160(SHA256(x))`, Bitcoin's `Hash160`.
Uint8List hash160(List<int> data) =>
    RIPEMD160Digest().process(Uint8List.fromList(sha256(data)));
