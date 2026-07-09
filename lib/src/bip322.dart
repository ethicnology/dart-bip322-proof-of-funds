import 'dart:typed_data';

import 'package:bech32/bech32.dart';
import 'package:bip341/bip341.dart' show Bip341;

import 'address.dart';
import 'bech32m.dart';
import 'crypto/ecdsa.dart' show compressedPublicKey;
import 'crypto/hashes.dart' show hash160;
import 'crypto/tagged_hash.dart';
import 'enums.dart';
import 'errors.dart';
import 'exceptions.dart';
import 'formats.dart';
import 'keys.dart';
import 'proof_of_funds.dart';
import 'script.dart';
import 'signer.dart';
import 'transaction.dart';
import 'verifier.dart';
import 'virtual_tx.dart' as vtx;
import 'witness.dart';

/// Entry point for BIP-322 message signing and verification.
class Bip322 {
  Bip322._();

  /// The BIP-322 tagged message hash of [message] (32 bytes).
  static Uint8List messageHash(String message) => bip322MessageHash(message);

  /// Builds the `to_spend` virtual transaction for [messageHash] committing to
  /// [scriptPubKey].
  static Transaction buildToSpend(Uint8List messageHash, Script scriptPubKey) =>
      vtx.buildToSpend(messageHash, scriptPubKey);

  /// Builds the `to_sign` virtual transaction spending [toSpend]:0, optionally
  /// carrying [witness].
  static Transaction buildToSign(
    Transaction toSpend, {
    WitnessStack? witness,
  }) => vtx.buildToSign(toSpend, witness: witness);

  /// Convenience: builds `to_spend` directly from a [message] and [address].
  static Transaction buildToSpendFromAddress(
    String message,
    String address, {
    Network network = Network.mainnet,
  }) {
    final parsed = parseAddress(address, network);
    return vtx.buildToSpend(messageHash(message), parsed.scriptPubKey);
  }

  /// Derives the P2TR (key-path, `bc1p...`) address for [privateKey] on
  /// [network] — the address [signMessage] will produce a signature for.
  static String p2trAddress(
    Object privateKey, {
    Network network = Network.mainnet,
  }) {
    final pk = parsePrivateKey(privateKey);
    final tweaked = Bip341.tweakPrivateKey(pk.D);
    return encodeBech32mSegwit(network.bech32Hrp, 1, tweaked.outputKey);
  }

  /// Derives the P2WPKH (`bc1q...`) address for [privateKey] on [network] —
  /// the address [signMessage] will produce a signature for.
  static String p2wpkhAddress(
    Object privateKey, {
    Network network = Network.mainnet,
  }) {
    final pk = parsePrivateKey(privateKey);
    final keyHash = hash160(compressedPublicKey(pk));
    return segwit.encode(Segwit(network.bech32Hrp, 0, keyHash));
  }

  /// Signs [message] for [address], returning a BIP-322 signature string.
  ///
  /// Segwit/taproot addresses produce a "simple" (`smp`-prefixed) signature.
  /// The [format] override is reserved for future variants.
  ///
  /// Throws [UnsupportedAddressTypeError]/[UnimplementedAddressTypeError] for
  /// out-of-scope or not-yet-implemented address types — see
  /// [_rejectOutOfScopeAddressType].
  static String signMessage({
    required String message,
    required String address,
    required Object privateKey,
    Network network = Network.mainnet,
    SignatureFormat? format,
  }) {
    final parsed = parseAddress(address, network);
    _rejectOutOfScopeAddressType(parsed.type);
    final pk = parsePrivateKey(privateKey);
    switch (parsed.type) {
      case AddressType.p2wpkh:
      case AddressType.p2tr:
        return signSimple(pk, parsed, message);
      case AddressType.p2pkh:
      case AddressType.p2sh:
      case AddressType.p2wsh:
        throw UnreachableCaseError(
          'unreachable: rejected by _rejectOutOfScopeAddressType',
        );
    }
  }

  /// Verifies [signature] (base64, optionally `smp`/`ful`/`pof`-prefixed) over
  /// [message] for [address].
  ///
  /// A prefix-less signature is always interpreted as the "simple" variant, the
  /// backward-compat fallback the spec permits ("a verifier might assume the
  /// simple variant in the absence of a prefix"). [loose] is reserved for a
  /// future BIP-137 cross-type acceptance policy and currently has no effect.
  ///
  /// Never throws a [Bip322Exception] for malformed *data* (a garbled
  /// address string, invalid base64, a truncated/inconsistent witness
  /// encoding) — those always resolve to `false`, since [address] and
  /// [signature] are ordinarily untrusted, externally-supplied input and a
  /// boolean-returning verify function must fail closed for any of them.
  /// It still throws [UnsupportedAddressTypeError]/[UnimplementedAddressTypeError]
  /// for address types (see [_rejectOutOfScopeAddressType]), and
  /// [UnimplementedSignatureFormatError]/[IncompatibleVerificationApiError]
  /// for signature formats this boolean-returning method can't handle —
  /// since either is a statement about the library's capabilities, not
  /// about this specific input.
  static bool verify({
    required String message,
    required String address,
    required String signature,
    Network network = Network.mainnet,
    bool loose = false,
  }) {
    final ParsedAddress parsed;
    try {
      parsed = parseAddress(address, network);
    } on Bip322Exception {
      return false;
    }
    _rejectOutOfScopeAddressType(parsed.type);
    try {
      final decoded = decodeSignature(signature, loose: loose);
      switch (decoded.format) {
        case SignatureFormat.simple:
          return verifySimple(parsed, message, decoded.witness);
        case SignatureFormat.legacy:
          // P2PKH — the only address type legacy (BIP-137) is ever valid
          // for — is already rejected above, so reaching this case always
          // means a legacy-formatted blob was sent for an in-scope
          // segwit/taproot address: a type-confusion attempt, never a
          // false accept.
          return false;
        case SignatureFormat.full:
          throw UnimplementedSignatureFormatError(
            'full (arbitrary-transaction) is a v2 feature',
          );
        case SignatureFormat.proofOfFunds:
          throw IncompatibleVerificationApiError(
            'a pof-prefixed signature cannot be checked by verify(): its '
            'spec-defined result is three-state (valid/inconclusive/invalid), '
            'which a bool cannot express — use Bip322.verifyProofOfFunds',
          );
      }
    } on Bip322Exception {
      return false;
    }
  }

  /// Signs a BIP-322 "Proof of Funds" message for [address]: an ordinary
  /// message signature (as [signMessage] produces for input 0) with
  /// [proofUtxos] added as additional, genuinely-satisfied inputs of
  /// `to_sign`, demonstrating control of an arbitrary UTXO set the signer
  /// chooses — per BIP-322, it need not be associated with [address] at all.
  ///
  /// Returns the `pof`-prefixed signature: a base64-encoded finalized PSBT,
  /// per BIP-322's "Full (Proof of Funds)" format. [address] and every
  /// [proofUtxos] entry's scriptPubKey must be P2WPKH or P2TR — the same two
  /// types [signMessage] supports; anything else throws
  /// [UnsupportedScriptTypeError].
  static String signProofOfFunds({
    required String message,
    required String address,
    required Object privateKey,
    required List<ProofOfFundsUtxo> proofUtxos,
    Network network = Network.mainnet,
  }) {
    final parsed = parseAddress(address, network);
    _rejectOutOfScopeAddressType(parsed.type);
    return buildProofOfFundsSignature(
      message: message,
      challenge: parsed,
      privateKey: parsePrivateKey(privateKey),
      proofUtxos: proofUtxos,
    );
  }

  /// Verifies a BIP-322 "Proof of Funds" [signature] over [message] for
  /// [address], returning the full three-state [ProofOfFundsResult] BIP-322
  /// defines (valid/inconclusive/invalid) rather than a lossy boolean — see
  /// [ProofOfFundsResult] and [ProofOfFundsStatus] for what each state, and
  /// [ProofOfFundsResult.provenUtxos], actually mean. In particular, this is a
  /// purely offline cryptographic check: it does not confirm the proven UTXOs
  /// still exist or are unspent on-chain.
  ///
  /// Never throws a [Bip322Exception] for malformed signature/PSBT data —
  /// same fail-closed policy as [verify] — but throws
  /// [UnsupportedAddressTypeError]/[UnimplementedAddressTypeError] for an
  /// out-of-scope [address].
  static ProofOfFundsResult verifyProofOfFunds({
    required String message,
    required String address,
    required String signature,
    Network network = Network.mainnet,
  }) {
    final ParsedAddress parsed;
    try {
      parsed = parseAddress(address, network);
    } on Bip322Exception {
      return ProofOfFundsResult(ProofOfFundsStatus.invalid, const [], 0, 0);
    }
    _rejectOutOfScopeAddressType(parsed.type);
    return verifyProofOfFundsSignature(
      message: message,
      challenge: parsed,
      signature: signature,
    );
  }

  /// P2PKH, P2SH-P2WPKH and P2WSH parse successfully as valid Bitcoin
  /// addresses — [parseAddress] recognises them — but this library does not
  /// support signing or verifying BIP-322 messages for them:
  ///
  /// - P2PKH's message-signing scheme is legacy BIP-137, a distinct
  ///   (non-BIP-322) format built around 65-byte recoverable ECDSA
  ///   signatures — not implemented.
  /// - P2SH-P2WPKH cannot be expressed in the "Simple" format at all: Simple
  ///   carries only a witness stack, with no scriptSig slot for the
  ///   redeemScript a P2SH input needs. It would require the "Full" format
  ///   (a complete signed transaction), which is a v2 feature.
  /// - P2WSH multisig is not implemented.
  ///
  /// P2PKH/P2SH-P2WPKH throw [UnsupportedAddressTypeError] (permanently out
  /// of scope); P2WSH throws [UnimplementedAddressTypeError] — Dart's own
  /// `UnimplementedError` is itself a subtype of `UnsupportedError`, the
  /// same relationship these two custom types mirror, reserving
  /// [UnimplementedAddressTypeError] for features that are a planned
  /// addition rather than permanently excluded — the same distinction drawn
  /// for the Full format ([UnimplementedSignatureFormatError]). Neither is a
  /// [Bip322Exception]: this signals "this address type isn't supported by
  /// this library", distinct from "this signature failed to verify". A
  /// defensive caller should not catch [Error]s as "not verified".
  static void _rejectOutOfScopeAddressType(AddressType type) {
    switch (type) {
      case AddressType.p2pkh:
        throw UnsupportedAddressTypeError(
          type,
          'P2PKH (legacy) addresses are not supported: BIP-322 legacy '
          'signing is BIP-137, a distinct format from Simple/Full/PoF',
        );
      case AddressType.p2sh:
        throw UnsupportedAddressTypeError(
          type,
          'P2SH-P2WPKH addresses are not supported: not expressible in the '
          'Simple format (no scriptSig slot); needs Full (v2)',
        );
      case AddressType.p2wsh:
        throw UnimplementedAddressTypeError(
          type,
          'P2WSH multisig signing/verification is not implemented',
        );
      case AddressType.p2wpkh:
      case AddressType.p2tr:
        return;
    }
  }
}
