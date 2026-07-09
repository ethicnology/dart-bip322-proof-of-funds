import 'dart:typed_data';

import 'errors.dart';
import 'exceptions.dart';

/// Concatenates a list of byte chunks into a single [Uint8List].
Uint8List concatBytes(List<List<int>> chunks) {
  final builder = BytesBuilder();
  for (final c in chunks) {
    builder.add(c);
  }
  return builder.toBytes();
}

/// Returns a reversed copy of [bytes] (used to convert between internal
/// serialization order and display byte order for hashes / txids).
Uint8List reverseBytes(List<int> bytes) =>
    Uint8List.fromList(bytes.reversed.toList());

/// Constant-length byte equality.
bool bytesEqual(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// Little-endian encoding of a 32-bit unsigned integer.
Uint8List uint32LE(int value) {
  final b = ByteData(4)..setUint32(0, value, Endian.little);
  return b.buffer.asUint8List();
}

/// Little-endian encoding of a 64-bit unsigned integer (Bitcoin amounts).
///
/// Built from two 32-bit halves rather than `ByteData.setUint64`: the latter
/// throws `UnsupportedError` unconditionally when compiled to JavaScript
/// (dart2js/dartdevc have no native 64-bit integer type), which would crash
/// every sign/verify call on Flutter web. Bitcoin amounts (max ~2.1e15 sats)
/// are well within the 2^53 safe-integer range both representations share.
Uint8List uint64LE(int value) {
  if (value < 0) {
    throw NegativeValueError(value, 'uint64LE');
  }
  final b = ByteData(8);
  b.setUint32(0, value & 0xffffffff, Endian.little);
  b.setUint32(4, (value >> 32) & 0xffffffff, Endian.little);
  return b.buffer.asUint8List();
}

/// Bitcoin CompactSize (a.k.a. varint) encoding of [value].
Uint8List compactSize(int value) {
  if (value < 0) {
    throw NegativeValueError(value, 'CompactSize');
  }
  if (value < 0xfd) {
    return Uint8List.fromList([value]);
  } else if (value <= 0xffff) {
    return concatBytes([
      [0xfd],
      _uint16LE(value),
    ]);
  } else if (value <= 0xffffffff) {
    return concatBytes([
      [0xfe],
      uint32LE(value),
    ]);
  } else {
    return concatBytes([
      [0xff],
      uint64LE(value),
    ]);
  }
}

Uint8List _uint16LE(int value) {
  final b = ByteData(2)..setUint16(0, value, Endian.little);
  return b.buffer.asUint8List();
}

/// Minimal sequential reader over a byte buffer, used by the deserializers.
class ByteReader {
  final Uint8List _bytes;
  int _offset = 0;

  ByteReader(List<int> bytes) : _bytes = Uint8List.fromList(bytes);

  int get remaining => _bytes.length - _offset;
  bool get isEmpty => remaining == 0;

  Uint8List read(int n) {
    if (n < 0 || remaining < n) {
      throw DeserializationException(
        'unexpected end of input (needed $n, have $remaining)',
      );
    }
    final slice = _bytes.sublist(_offset, _offset + n);
    _offset += n;
    return slice;
  }

  int readUint8() => read(1)[0];

  int readUint32LE() =>
      ByteData.sublistView(read(4)).getUint32(0, Endian.little);

  /// See [uint64LE] for why this avoids `ByteData.getUint64` (dart2js).
  int readUint64LE() {
    final view = ByteData.sublistView(read(8));
    final low = view.getUint32(0, Endian.little);
    final high = view.getUint32(4, Endian.little);
    return high * 0x100000000 + low;
  }

  /// Reads a CompactSize integer.
  int readCompactSize() {
    final first = readUint8();
    if (first < 0xfd) return first;
    if (first == 0xfd) {
      return ByteData.sublistView(read(2)).getUint16(0, Endian.little);
    }
    if (first == 0xfe) return readUint32LE();
    return readUint64LE();
  }
}
