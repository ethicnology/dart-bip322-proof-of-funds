import 'dart:typed_data';

import 'package:bech32/bech32.dart';
import 'package:bs58check/bs58check.dart' as bs58check;

import 'bech32m.dart';
import 'enums.dart';
import 'exceptions.dart';
import 'script.dart';
import 'utils.dart';

/// The result of parsing an address: its script type and the scriptPubKey that
/// the BIP-322 `to_spend` output commits to (the "message challenge").
class ParsedAddress {
  final AddressType type;
  final Script scriptPubKey;

  /// Witness program (segwit) or hash160 (legacy) — the 20/32-byte payload.
  final Uint8List payload;

  ParsedAddress(this.type, this.scriptPubKey, this.payload);
}

/// Parses [address] on [network] into its type and scriptPubKey.
///
/// Recognises P2PKH, P2SH, P2WPKH, P2WSH and P2TR; any other bech32m witness
/// version/length combination surfaces as [UnsupportedAddressException].
ParsedAddress parseAddress(String address, Network network) {
  final lower = address.toLowerCase();
  if (lower.startsWith('${network.bech32Hrp}1')) {
    return _parseSegwit(address, network);
  }
  return _parseBase58(address, network);
}

ParsedAddress _parseSegwit(String address, Network network) {
  // v0 uses bech32 (the `bech32` package); v1+ uses bech32m (local). Trying the
  // bech32 decoder first also enforces the BIP-350 binding: a v1+ address with a
  // bech32 checksum fails here and is not silently accepted as v0.
  Segwit? v0;
  try {
    v0 = segwit.decode(address);
  } catch (_) {
    v0 = null;
  }

  if (v0 != null) {
    if (v0.hrp != network.bech32Hrp) throw WrongNetworkException(address);
    // A v0 checksum on a v1+ program is an invalid combination (BIP-350).
    if (v0.version != 0) {
      throw WitnessVersionChecksumMismatchException(v0.version);
    }
    final program = Uint8List.fromList(v0.program);
    if (program.length == 20) {
      return ParsedAddress(
        AddressType.p2wpkh,
        Script(
          concatBytes([
            const [0x00, 0x14],
            program,
          ]),
        ),
        program,
      );
    }
    if (program.length == 32) {
      return ParsedAddress(
        AddressType.p2wsh,
        Script(
          concatBytes([
            const [0x00, 0x20],
            program,
          ]),
        ),
        program,
      );
    }
    throw UnsupportedAddressException(address);
  }

  // Fall back to bech32m (v1+).
  final v1 = decodeBech32mSegwit(address);
  if (v1.hrp != network.bech32Hrp) throw WrongNetworkException(address);
  if (v1.version == 1 && v1.program.length == 32) {
    // P2TR scriptPubKey: OP_1 PUSH32 <x-only key>.
    return ParsedAddress(
      AddressType.p2tr,
      Script(
        concatBytes([
          const [0x51, 0x20],
          v1.program,
        ]),
      ),
      v1.program,
    );
  }
  throw UnsupportedAddressException(address);
}

ParsedAddress _parseBase58(String address, Network network) {
  final Uint8List data;
  try {
    data = bs58check.decode(address);
  } catch (_) {
    // bs58check throws ArgumentError (a Dart Error, not an Exception) for a
    // malformed base58 alphabet/checksum — must still resolve to our own
    // typed exception rather than propagate uncaught.
    throw UnsupportedAddressException(address);
  }
  if (data.length != 21) throw UnsupportedAddressException(address);
  final version = data[0];
  final hash160 = Uint8List.fromList(data.sublist(1));

  if (version == network.p2pkhVersion) {
    return ParsedAddress(
      AddressType.p2pkh,
      Script(
        concatBytes([
          const [0x76, 0xa9, 0x14],
          hash160,
          const [0x88, 0xac],
        ]),
      ),
      hash160,
    );
  }
  if (version == network.p2shVersion) {
    return ParsedAddress(
      AddressType.p2sh,
      Script(
        concatBytes([
          const [0xa9, 0x14],
          hash160,
          const [0x87],
        ]),
      ),
      hash160,
    );
  }
  throw WrongNetworkException(address);
}
