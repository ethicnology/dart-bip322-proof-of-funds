/// Custom [Error] subclasses (Dart's `Error` hierarchy, not `Exception`) for
/// every capability/contract condition this package rejects — a caller-scope
/// question ("does this library support X"), not a data-validity question.
/// See [Bip322Exception] (`exceptions.dart`) for the latter: malformed or
/// untrusted *data* (a garbled address string, an invalid signature) always
/// resolves to `false`/[Bip322Exception], never one of these.
///
/// Each is a named, catchable type instead of a bare [UnsupportedError]/
/// [UnimplementedError]/[ArgumentError]/[StateError] with only a message
/// string. They're named `...Error`, not `...Exception`, to match that
/// hierarchy honestly: `catch (e) on Exception` does not catch an [Error].
library;

import 'enums.dart';
import 'script.dart';

/// Thrown for an address type BIP-322 recognises as a valid Bitcoin address
/// but this library permanently does not support signing/verifying for
/// (P2PKH legacy, P2SH-P2WPKH) — a deliberate scope decision. See
/// [UnimplementedAddressTypeError] for the "planned but not built" case.
class UnsupportedAddressTypeError extends UnsupportedError {
  final AddressType addressType;

  UnsupportedAddressTypeError(this.addressType, String reason) : super(reason);
}

/// Thrown for an address type this library plans to support but has not
/// built yet (P2WSH multisig) — distinct from [UnsupportedAddressTypeError]'s
/// permanent exclusion.
class UnimplementedAddressTypeError extends UnimplementedError {
  final AddressType addressType;

  UnimplementedAddressTypeError(this.addressType, String reason)
    : super(reason);
}

/// Thrown by `Bip322.verify` for the Full (arbitrary-transaction) signature
/// format, which needs a Bitcoin Script interpreter this package does not
/// provide — a planned (v2) feature, not permanently out of scope.
class UnimplementedSignatureFormatError extends UnimplementedError {
  UnimplementedSignatureFormatError(super.reason);
}

/// Thrown by `Bip322.verify` for a `pof`-prefixed signature: its boolean
/// return type cannot express the three-state (valid/inconclusive/invalid)
/// result BIP-322 defines for Proof of Funds. This is permanent — use
/// `Bip322.verifyProofOfFunds` instead — not a missing feature.
class IncompatibleVerificationApiError extends UnsupportedError {
  IncompatibleVerificationApiError(super.reason);
}

/// Thrown when a Proof of Funds UTXO's scriptPubKey isn't P2WPKH/P2TR — the
/// same two types `Bip322.signMessage` supports.
class UnsupportedScriptTypeError extends UnsupportedError {
  final int utxoIndex;
  final Script scriptPubKey;

  UnsupportedScriptTypeError(this.utxoIndex, this.scriptPubKey)
    : super(
        'proof UTXO $utxoIndex: scriptPubKey is not P2WPKH/P2TR — unsupported',
      );
}

/// Thrown for an internal invariant this library's own exhaustiveness checks
/// force it to name, even though an earlier scope-rejection guard makes it
/// unreachable in practice. Indicates a bug in this library if ever actually
/// thrown — never a condition a caller triggers directly.
class UnreachableCaseError extends StateError {
  UnreachableCaseError(super.reason);
}

/// Thrown when encoding a negative integer into an unsigned wire-format field
/// (CompactSize, a little-endian amount) — Bitcoin has no negative-value
/// encoding for these.
class NegativeValueError extends ArgumentError {
  final int value;

  NegativeValueError(this.value, String context)
    : super('$context: cannot encode a negative value: $value');
}

/// Thrown by `encodeFinalizedPsbt` when `spentOutputs` doesn't have exactly
/// one entry per input in the transaction being encoded.
class MismatchedSpentOutputCountError extends ArgumentError {
  final int inputCount;
  final int spentOutputCount;

  MismatchedSpentOutputCountError(this.inputCount, this.spentOutputCount)
    : super(
        'spentOutputs must have one entry per input '
        '($inputCount inputs, $spentOutputCount outputs given)',
      );
}
