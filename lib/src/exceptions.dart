/// Base class for every error thrown by `bip322`.
abstract class Bip322Exception implements Exception {
  final String message;

  Bip322Exception(this.message);

  @override
  String toString() => message;
}

/// Thrown when an address cannot be parsed or is not supported.
class UnsupportedAddressException extends Bip322Exception {
  UnsupportedAddressException(String address)
    : super('Unsupported or invalid address: $address');
}

/// Thrown when an address does not belong to the expected network.
class WrongNetworkException extends Bip322Exception {
  WrongNetworkException(String address)
    : super('Address does not match the expected network: $address');
}

/// Thrown when a bech32/bech32m witness version does not match its checksum
/// variant (BIP-350: v0 → bech32, v1+ → bech32m).
class WitnessVersionChecksumMismatchException extends Bip322Exception {
  WitnessVersionChecksumMismatchException(int version)
    : super(
        'Witness version $version does not match the checksum variant '
        '(v0 must be bech32, v1+ must be bech32m)',
      );
}

/// Thrown when a private key input cannot be interpreted.
class InvalidPrivateKeyException extends Bip322Exception {
  InvalidPrivateKeyException(String reason)
    : super('Invalid private key: $reason');
}

/// Thrown when a signature is malformed (bad base64, bad structure, ...).
class MalformedSignatureException extends Bip322Exception {
  MalformedSignatureException(String reason)
    : super('Malformed BIP-322 signature: $reason');
}

/// Thrown when parsing raw bytes (transaction, witness, script) fails.
class DeserializationException extends Bip322Exception {
  DeserializationException(String reason)
    : super('Deserialization failed: $reason');
}
