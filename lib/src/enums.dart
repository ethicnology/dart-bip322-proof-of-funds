/// Bitcoin network, selecting address prefixes (bech32 HRP + base58 versions).
enum Network {
  mainnet,
  testnet,
  signet,
  regtest;

  /// The bech32/bech32m human-readable part used by segwit addresses.
  String get bech32Hrp {
    switch (this) {
      case Network.mainnet:
        return 'bc';
      case Network.testnet:
      case Network.signet:
        return 'tb';
      case Network.regtest:
        return 'bcrt';
    }
  }

  /// base58 version byte for P2PKH addresses.
  int get p2pkhVersion => this == Network.mainnet ? 0x00 : 0x6f;

  /// base58 version byte for P2SH addresses.
  int get p2shVersion => this == Network.mainnet ? 0x05 : 0xc4;
}

/// The four BIP-322 signature variants.
///
/// [simple] and [legacy] are implemented in v1. [full] and [proofOfFunds]
/// are reserved for a future release and currently throw `UnimplementedError`.
enum SignatureFormat {
  /// Witness stack, consensus-encoded, base64, prefixed with `smp`.
  simple,

  /// BIP-137 compact recoverable ECDSA signature (P2PKH). Not BIP-322 proper.
  legacy,

  /// Full signed `to_sign` transaction, base64, prefixed with `ful`. (v2)
  full,

  /// Finalized PSBT, base64, prefixed with `pof`. (v2)
  proofOfFunds,
}

/// Bitcoin address/script types recognised by this library. Determines which
/// signature format(s) an address can accept — see [SignatureFormat].
enum AddressType {
  p2pkh,
  p2sh, // P2SH-P2WPKH (nested segwit)
  p2wpkh,
  p2wsh,
  p2tr,
}
