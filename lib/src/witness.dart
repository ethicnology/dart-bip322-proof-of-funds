import 'dart:typed_data';

import 'exceptions.dart';
import 'utils.dart';

/// A witness stack: an ordered list of byte items.
///
/// The BIP-322 "simple" signature is exactly this structure, consensus-encoded
/// (`compactSize(count)` then `compactSize(len)||bytes` per item) and base64'd —
/// it is NOT a full transaction.
class WitnessStack {
  final List<Uint8List> items;

  WitnessStack(List<List<int>> items)
    : items = items.map(Uint8List.fromList).toList();

  bool get isEmpty => items.isEmpty;
  int get length => items.length;

  /// Consensus encoding: `compactSize(count)` then each item as
  /// `compactSize(len) || bytes`.
  Uint8List toBytes() {
    final chunks = <List<int>>[compactSize(items.length)];
    for (final item in items) {
      chunks.add(compactSize(item.length));
      chunks.add(item);
    }
    return concatBytes(chunks);
  }

  /// Reads a witness stack (count-prefixed) from [reader].
  factory WitnessStack.read(ByteReader reader) {
    final count = reader.readCompactSize();
    final items = <List<int>>[];
    for (var i = 0; i < count; i++) {
      final len = reader.readCompactSize();
      items.add(reader.read(len));
    }
    return WitnessStack(items);
  }

  /// Decodes a stand-alone witness stack from [bytes] (the "simple" payload).
  ///
  /// The BIP-322 simple signature is a *consensus* encoding, so the payload
  /// must be consumed exactly: any trailing bytes after the last item make the
  /// blob non-canonical and are rejected (a third party must not be able to
  /// mint a distinct-but-still-valid signature string by appending garbage).
  factory WitnessStack.fromBytes(List<int> bytes) {
    final reader = ByteReader(bytes);
    final stack = WitnessStack.read(reader);
    if (!reader.isEmpty) {
      throw DeserializationException(
        'trailing bytes after witness stack (${reader.remaining} left)',
      );
    }
    return stack;
  }
}
