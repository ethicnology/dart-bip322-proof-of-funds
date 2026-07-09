import 'dart:typed_data';

import 'exceptions.dart';

/// Minimal bech32/bech32m implementation (BIP-173 / BIP-350).
///
/// The `bech32` package handles segwit v0 (bech32); this covers the bech32m
/// variant needed for P2TR (v1+). The only difference between the two is the
/// checksum constant.
const String _charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const int _bech32mConst = 0x2bc830a3;

int _polymod(List<int> values) {
  const gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  var chk = 1;
  for (final v in values) {
    final top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (var i = 0; i < 5; i++) {
      if ((top >> i) & 1 == 1) chk ^= gen[i];
    }
  }
  return chk;
}

List<int> _hrpExpand(String hrp) => [
  for (final c in hrp.codeUnits) c >> 5,
  0,
  for (final c in hrp.codeUnits) c & 31,
];

/// Squashes groups of [from]-bit values into [to]-bit values (BIP-173).
List<int> _convertBits(List<int> data, int from, int to, {required bool pad}) {
  var acc = 0;
  var bits = 0;
  final ret = <int>[];
  final maxv = (1 << to) - 1;
  for (final value in data) {
    if (value < 0 || (value >> from) != 0) {
      throw const _Bech32Error('invalid data range');
    }
    acc = (acc << from) | value;
    bits += from;
    while (bits >= to) {
      bits -= to;
      ret.add((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) ret.add((acc << (to - bits)) & maxv);
  } else if (bits >= from || ((acc << (to - bits)) & maxv) != 0) {
    throw const _Bech32Error('invalid padding');
  }
  return ret;
}

class _Bech32Error implements Exception {
  final String message;
  const _Bech32Error(this.message);
}

/// A decoded segwit address: witness [version] and [program] bytes.
class SegwitDecoded {
  final String hrp;
  final int version;
  final Uint8List program;

  SegwitDecoded(this.hrp, this.version, this.program);
}

/// Decodes a bech32m segwit address (used for witness v1+, e.g. P2TR) and
/// validates the bech32m checksum. Throws [UnsupportedAddressException] on any
/// malformed input or if the bech32 (v0) checksum constant is used instead.
SegwitDecoded decodeBech32mSegwit(String address) {
  try {
    return _decode(address, _bech32mConst);
  } on _Bech32Error {
    throw UnsupportedAddressException(address);
  }
}

/// Encodes a witness [version] (1..16) [program] as a bech32m segwit address.
String encodeBech32mSegwit(String hrp, int version, List<int> program) {
  final data = [version, ..._convertBits(program, 8, 5, pad: true)];
  final values = [..._hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  final mod = _polymod(values) ^ _bech32mConst;
  final checksum = [for (var i = 0; i < 6; i++) (mod >> (5 * (5 - i))) & 31];
  final chars = [...data, ...checksum].map((d) => _charset[d]).join();
  return '${hrp}1$chars';
}

SegwitDecoded _decode(String address, int expectedConst) {
  if (address != address.toLowerCase() && address != address.toUpperCase()) {
    throw const _Bech32Error('mixed case');
  }
  final s = address.toLowerCase();
  final sep = s.lastIndexOf('1');
  if (sep < 1 || sep + 7 > s.length || s.length > 90) {
    throw const _Bech32Error('bad separator/length');
  }
  final hrp = s.substring(0, sep);
  final dataPart = s.substring(sep + 1);
  final data = <int>[];
  for (final ch in dataPart.split('')) {
    final idx = _charset.indexOf(ch);
    if (idx == -1) throw const _Bech32Error('invalid char');
    data.add(idx);
  }
  if (_polymod(_hrpExpand(hrp) + data) != expectedConst) {
    throw const _Bech32Error('bad checksum');
  }
  final payload = data.sublist(0, data.length - 6);
  if (payload.isEmpty) throw const _Bech32Error('empty payload');
  final version = payload[0];
  if (version < 1 || version > 16) {
    throw const _Bech32Error('unexpected witness version');
  }
  final program = _convertBits(payload.sublist(1), 5, 8, pad: false);
  if (program.length < 2 || program.length > 40) {
    throw const _Bech32Error('bad program length');
  }
  return SegwitDecoded(hrp, version, Uint8List.fromList(program));
}
