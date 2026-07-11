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

/// The maximum spendable Bitcoin amount, in satoshis (21e6 BTC * 1e8). No
/// valid transaction output — and therefore no valid PSBT UTXO amount — can
/// exceed this (Bitcoin consensus `MAX_MONEY`). It is also comfortably within
/// the 2^53 JS safe-integer range, so amounts up to this bound round-trip
/// identically on the VM and on the web.
const int maxMoney = 21000000 * 100000000;

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
  ///
  /// Rejects any value that does not fit in Dart's 2^53 JS-safe-integer range:
  /// a field at/above `2^53` (in particular a full `0xFFFF...FF`) would either
  /// wrap to a negative `int` on the 64-bit VM or lose precision on the web,
  /// and — for an amount — would later crash the unsigned encoder [uint64LE]
  /// with a `NegativeValueError` (an uncaught `Error`) when a sighash is
  /// recomputed, breaking the "never throws for malformed data" contract of the
  /// verify entry points. Failing closed here, as a [DeserializationException]
  /// (a [Bip322Exception] the verify paths already catch), keeps that contract.
  ///
  /// This is the raw 64-bit field reader (used for both amounts and the
  /// `0xff` CompactSize case); [readAmount] applies the additional Bitcoin
  /// `MAX_MONEY` consensus bound where an actual satoshi value is expected.
  int readUint64LE() {
    final view = ByteData.sublistView(read(8));
    final low = view.getUint32(0, Endian.little);
    final high = view.getUint32(4, Endian.little);
    final value = high * 0x100000000 + low;
    // 2^53 - 1 is the largest integer both the VM and dart2js represent
    // exactly; `value < 0` additionally catches the 64-bit-VM wrap-around.
    if (value < 0 || value > 0x1fffffffffffff) {
      throw DeserializationException(
        'unsigned 64-bit field exceeds the JS-safe integer range: raw '
        '0x${high.toRadixString(16).padLeft(8, '0')}'
        '${low.toRadixString(16).padLeft(8, '0')}',
      );
    }
    return value;
  }

  /// Reads a Bitcoin output amount (satoshis): a raw 64-bit field additionally
  /// bounded by consensus `MAX_MONEY`. Rejects out-of-range values as a
  /// [DeserializationException] so a malformed/adversarial `witness_utxo` or
  /// `non_witness_utxo` amount resolves to a fail-closed "invalid", never an
  /// uncaught `Error` from downstream unsigned encoding.
  int readAmount() {
    final value = readUint64LE();
    if (value > maxMoney) {
      throw DeserializationException(
        'amount out of range (0..$maxMoney sats): $value',
      );
    }
    return value;
  }

  /// Reads a CompactSize integer, enforcing Bitcoin's **minimal-encoding**
  /// rule: a value must use the shortest of the four length prefixes that can
  /// hold it. A non-minimal encoding (e.g. `0xfd 0x05 0x00` for the value 5,
  /// which fits in a single byte) is a serialization-malleability vector —
  /// distinct byte strings decoding to the same logical value — and is rejected
  /// as a [DeserializationException], matching Bitcoin Core's `ReadCompactSize`.
  int readCompactSize() {
    final first = readUint8();
    if (first < 0xfd) return first;
    if (first == 0xfd) {
      final value = ByteData.sublistView(read(2)).getUint16(0, Endian.little);
      if (value < 0xfd) {
        throw DeserializationException(
          'non-minimal CompactSize: $value encoded with 0xfd prefix',
        );
      }
      return value;
    }
    if (first == 0xfe) {
      final value = readUint32LE();
      if (value <= 0xffff) {
        throw DeserializationException(
          'non-minimal CompactSize: $value encoded with 0xfe prefix',
        );
      }
      return value;
    }
    final value = readUint64LE();
    if (value <= 0xffffffff) {
      throw DeserializationException(
        'non-minimal CompactSize: $value encoded with 0xff prefix',
      );
    }
    return value;
  }
}
