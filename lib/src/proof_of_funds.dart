import 'dart:convert';
import 'dart:typed_data';

import 'package:bip341/bip341.dart' show Bip341, sighashDefault;
import 'package:elliptic/elliptic.dart' show PrivateKey;

import 'address.dart';
import 'crypto/ecdsa.dart';
import 'crypto/hashes.dart';
import 'crypto/schnorr.dart';
import 'crypto/tagged_hash.dart';
import 'enums.dart';
import 'errors.dart';
import 'exceptions.dart';
import 'formats.dart';
import 'keys.dart';
import 'psbt.dart';
import 'script.dart';
import 'sighash.dart';
import 'taproot_sighash.dart';
import 'transaction.dart';
import 'utils.dart';
import 'virtual_tx.dart';
import 'witness.dart';

/// One additional UTXO a signer proves control of in a BIP-322 "Proof of
/// Funds" (`pof`) signature. [scriptPubKey]/[amount]/[prevout] describe the
/// real, on-chain output being proven; [privateKey] must be able to satisfy
/// it. Only P2WPKH and P2TR outputs are supported — the same two types
/// [signSimple]/[verifySimple] handle. Per BIP-322 this UTXO set is "chosen
/// freely by the signer" and need not be associated with the signing address
/// at all.
class ProofOfFundsUtxo {
  final OutPoint prevout;
  final int amount;
  final Script scriptPubKey;
  final Object privateKey;
  final int sequence;

  ProofOfFundsUtxo({
    required this.prevout,
    required this.amount,
    required this.scriptPubKey,
    required this.privateKey,
    this.sequence = 0,
  });
}

/// The three-state outcome BIP-322 defines for verification, specialised to
/// what a template-only (non-interpreter) validator can determine:
///
/// - [valid]: the message signature (input 0) and every proof input verified.
/// - [inconclusive]: at least one proof input's scriptPubKey isn't a template
///   this library understands (not P2WPKH/P2TR). Per BIP-322's Verification
///   Process: "If the validator does not have a full script interpreter, it
///   should check that it understands all scripts being satisfied. If not, it
///   should stop here and output inconclusive" — never silently accepted.
/// - [invalid]: a structural check or a signature failed.
enum ProofOfFundsStatus { valid, inconclusive, invalid }

/// The result of verifying a Proof of Funds signature. [provenUtxos] lists the
/// additional-input prevouts (input order, excluding the challenge input)
/// whose signatures verified cryptographically.
///
/// This is purely an offline, cryptographic check: it does NOT establish that
/// [provenUtxos] still exist or are unspent on-chain. Per BIP-322: "validators
/// of a proof of funds need access to the current UTXO set... An offline
/// validator therefore can only attest to the cryptographic validity of the
/// additional inputs' witness stack, but not its blockchain state." Pair this
/// result with an external UTXO-set lookup (e.g. an Electrum/Esplora client)
/// to confirm [provenUtxos] are real and unspent before trusting the proof.
class ProofOfFundsResult {
  final ProofOfFundsStatus status;
  final List<OutPoint> provenUtxos;

  /// nLockTime of `to_sign` — "T" in the spec's "valid at time T and age S".
  final int lockTime;

  /// nSequence of `to_sign`'s first input — "S" in the same phrase.
  final int sequence;

  ProofOfFundsResult(
    this.status,
    this.provenUtxos,
    this.lockTime,
    this.sequence,
  );

  bool get isValid => status == ProofOfFundsStatus.valid;
}

/// Classifies a raw [scriptPubKey] as one of the templates this library can
/// sign/verify (P2WPKH, P2TR) without needing an address string — used for
/// proof-of-funds UTXOs, which are described by scriptPubKey (as returned by
/// a wallet's UTXO listing) rather than by address. Returns `null` for
/// anything else — callers must treat that as "not a script this library
/// understands", never as an unusable-but-ignorable input.
({AddressType type, Uint8List payload})? classifyScriptPubKey(
  Script scriptPubKey,
) {
  final b = scriptPubKey.bytes;
  if (b.length == 22 && b[0] == 0x00 && b[1] == 0x14) {
    return (
      type: AddressType.p2wpkh,
      payload: Uint8List.fromList(b.sublist(2)),
    );
  }
  if (b.length == 34 && b[0] == 0x51 && b[1] == 0x20) {
    return (type: AddressType.p2tr, payload: Uint8List.fromList(b.sublist(2)));
  }
  return null;
}

/// Builds and signs a Proof of Funds `to_sign`: the BIP-322 message-challenge
/// input (spending `to_spend:0`) plus one input per entry in [proofUtxos],
/// each satisfied for real. Returns the `pof`-prefixed base64 encoding of the
/// finalized PSBT. Throws [UnsupportedScriptTypeError] if any [proofUtxos]
/// entry's scriptPubKey isn't P2WPKH/P2TR, and [InvalidPrivateKeyException]
/// if a private key doesn't match its claimed scriptPubKey.
String buildProofOfFundsSignature({
  required String message,
  required ParsedAddress challenge,
  required PrivateKey privateKey,
  required List<ProofOfFundsUtxo> proofUtxos,
}) {
  final toSpend = buildToSpend(
    bip322MessageHash(message),
    challenge.scriptPubKey,
  );

  // Every input's (amount, scriptPubKey) is needed up front: taproot's sighash
  // commits to all of them, not just the input being signed.
  final prevouts = [
    OutPoint(toSpend.hashForId(), 0),
    for (final u in proofUtxos) u.prevout,
  ];
  final sequences = [0, for (final u in proofUtxos) u.sequence];
  final amounts = [0, for (final u in proofUtxos) u.amount];
  final scriptPubKeys = [
    challenge.scriptPubKey.bytes,
    for (final u in proofUtxos) u.scriptPubKey.bytes,
  ];

  // An unsigned skeleton to compute sighashes against — segwit/taproot
  // sighashes never depend on any input's witness contents.
  final skeleton = Transaction(
    version: 0,
    lockTime: 0,
    inputs: [
      for (var i = 0; i < prevouts.length; i++)
        TxIn(prevout: prevouts[i], sequence: sequences[i]),
    ],
    outputs: [TxOut(value: 0, scriptPubKey: Script.opReturn())],
  );

  final witnesses = <WitnessStack>[
    _signInput(
      skeleton,
      inputIndex: 0,
      type: challenge.type,
      key: privateKey,
      expectedPayload: challenge.payload,
      amounts: amounts,
      scriptPubKeys: scriptPubKeys,
    ),
  ];
  for (var i = 0; i < proofUtxos.length; i++) {
    final u = proofUtxos[i];
    final classified = classifyScriptPubKey(u.scriptPubKey);
    if (classified == null) {
      throw UnsupportedScriptTypeError(i, u.scriptPubKey);
    }
    witnesses.add(
      _signInput(
        skeleton,
        inputIndex: i + 1,
        type: classified.type,
        key: parsePrivateKey(u.privateKey),
        expectedPayload: classified.payload,
        amounts: amounts,
        scriptPubKeys: scriptPubKeys,
      ),
    );
  }

  final toSign = Transaction(
    version: skeleton.version,
    lockTime: skeleton.lockTime,
    inputs: [
      for (var i = 0; i < skeleton.inputs.length; i++)
        TxIn(
          prevout: skeleton.inputs[i].prevout,
          sequence: skeleton.inputs[i].sequence,
          witness: witnesses[i],
        ),
    ],
    outputs: skeleton.outputs,
  );

  final spentOutputs = [
    for (var i = 0; i < amounts.length; i++)
      TxOut(value: amounts[i], scriptPubKey: Script(scriptPubKeys[i])),
  ];
  final psbt = encodeFinalizedPsbt(toSign, spentOutputs);
  return proofOfFundsPrefix + base64.encode(psbt);
}

WitnessStack _signInput(
  Transaction skeleton, {
  required int inputIndex,
  required AddressType type,
  required PrivateKey key,
  required Uint8List expectedPayload,
  required List<int> amounts,
  required List<Uint8List> scriptPubKeys,
}) {
  switch (type) {
    case AddressType.p2wpkh:
      final pub = compressedPublicKey(key);
      final keyHash = hash160(pub);
      if (!bytesEqual(keyHash, expectedPayload)) {
        throw InvalidPrivateKeyException(
          'key does not match the P2WPKH scriptPubKey at input $inputIndex',
        );
      }
      final sighash = sighashSegwitV0(
        skeleton,
        inputIndex,
        p2wpkhScriptCode(keyHash),
        amounts[inputIndex],
      );
      final der = ecdsaSignDer(key, sighash);
      return WitnessStack([
        [...der, sighashAll],
        pub,
      ]);
    case AddressType.p2tr:
      final tweaked = Bip341.tweakPrivateKey(key.D);
      if (!bytesEqual(tweaked.outputKey, expectedPayload)) {
        throw InvalidPrivateKeyException(
          'key does not match the P2TR scriptPubKey at input $inputIndex',
        );
      }
      final sighash = taprootSighashForInput(
        skeleton,
        inputIndex: inputIndex,
        amounts: amounts,
        spentScriptPubKeys: scriptPubKeys,
      );
      return WitnessStack([schnorrSign(tweaked.outputPrivateKey, sighash)]);
    case AddressType.p2pkh:
    case AddressType.p2sh:
    case AddressType.p2wsh:
      throw UnreachableCaseError(
        'unreachable: only p2wpkh/p2tr reach _signInput',
      );
  }
}

/// Verifies a Proof of Funds [signature] (`pof`-prefixed base64) over
/// [message] for [challenge]. Never throws for malformed *data* — a garbled
/// prefix, invalid base64, malformed PSBT, or any failed check resolves to
/// [ProofOfFundsStatus.invalid] — matching [verifySimple]'s fail-closed
/// policy for untrusted input.
ProofOfFundsResult verifyProofOfFundsSignature({
  required String message,
  required ParsedAddress challenge,
  required String signature,
}) {
  final invalid = ProofOfFundsResult(
    ProofOfFundsStatus.invalid,
    const [],
    0,
    0,
  );

  if (!signature.startsWith(proofOfFundsPrefix)) return invalid;
  final Uint8List psbtBytes;
  try {
    psbtBytes = base64.decode(
      base64.normalize(signature.substring(proofOfFundsPrefix.length)),
    );
  } on FormatException {
    return invalid;
  }

  final DecodedPsbt decoded;
  try {
    decoded = decodePsbt(psbtBytes);
  } on Bip322Exception {
    return invalid;
  }

  final toSign = decoded.transaction;
  final toSpend = buildToSpend(
    bip322MessageHash(message),
    challenge.scriptPubKey,
  );

  if (toSign.inputs.isEmpty) return invalid;
  final first = toSign.inputs[0].prevout;
  if (!bytesEqual(first.hash, toSpend.hashForId()) || first.index != 0) {
    return invalid;
  }
  if (toSign.outputs.length != 1) return invalid;
  final out = toSign.outputs[0];
  if (out.value != 0 ||
      !bytesEqual(out.scriptPubKey.bytes, Script.opReturn().bytes)) {
    return invalid;
  }

  final amounts = <int>[];
  final scriptPubKeys = <Uint8List>[];
  for (var i = 0; i < toSign.inputs.length; i++) {
    final TxOut spent;
    try {
      spent = decoded.utxos[i].resolve(toSign.inputs[i].prevout.index);
    } on Bip322Exception {
      return invalid;
    }
    amounts.add(spent.value);
    scriptPubKeys.add(spent.scriptPubKey.bytes);
  }
  // Input 0 must actually spend to_spend's own (synthetic) output — a PSBT
  // claiming a different witness UTXO for it must not be trusted.
  if (amounts[0] != 0 ||
      !bytesEqual(scriptPubKeys[0], challenge.scriptPubKey.bytes)) {
    return invalid;
  }

  if (!_verifyInput(
    toSign,
    0,
    challenge.type,
    challenge.payload,
    amounts,
    scriptPubKeys,
  )) {
    return invalid;
  }

  final proven = <OutPoint>[];
  var inconclusive = false;
  for (var i = 1; i < toSign.inputs.length; i++) {
    final classified = classifyScriptPubKey(Script(scriptPubKeys[i]));
    if (classified == null) {
      inconclusive = true;
      continue;
    }
    if (!_verifyInput(
      toSign,
      i,
      classified.type,
      classified.payload,
      amounts,
      scriptPubKeys,
    )) {
      return invalid;
    }
    proven.add(toSign.inputs[i].prevout);
  }

  // BIP-322 "upgradeable rules": an unrecognised to_sign version is
  // inconclusive, not invalid — it may be valid under a future extension this
  // library doesn't know about.
  if (toSign.version != 0 && toSign.version != 2) inconclusive = true;

  return ProofOfFundsResult(
    inconclusive ? ProofOfFundsStatus.inconclusive : ProofOfFundsStatus.valid,
    proven,
    toSign.lockTime,
    toSign.inputs[0].sequence,
  );
}

bool _verifyInput(
  Transaction toSign,
  int inputIndex,
  AddressType type,
  Uint8List payload,
  List<int> amounts,
  List<Uint8List> scriptPubKeys,
) {
  final witness = toSign.inputs[inputIndex].witness;
  if (witness == null) return false;
  switch (type) {
    case AddressType.p2wpkh:
      if (witness.length != 2) return false;
      final sigItem = witness.items[0];
      final pub = witness.items[1];
      if (pub.length != 33) return false;
      if (!bytesEqual(hash160(pub), payload)) return false;
      if (sigItem.isEmpty || sigItem.last != sighashAll) return false;
      final der = sigItem.sublist(0, sigItem.length - 1);
      final sighash = sighashSegwitV0(
        toSign,
        inputIndex,
        p2wpkhScriptCode(hash160(pub)),
        amounts[inputIndex],
      );
      return ecdsaVerifyDer(pub, sighash, der);
    case AddressType.p2tr:
      if (witness.length != 1) return false;
      var sig = witness.items[0];
      var hashType = sighashDefault;
      if (sig.length == 65) {
        hashType = sig.last;
        if (hashType == sighashDefault || hashType != sighashAll) return false;
        sig = sig.sublist(0, 64);
      } else if (sig.length != 64) {
        return false;
      }
      final sighash = taprootSighashForInput(
        toSign,
        inputIndex: inputIndex,
        amounts: amounts,
        spentScriptPubKeys: scriptPubKeys,
        hashType: hashType,
      );
      return schnorrVerify(payload, sighash, sig);
    case AddressType.p2pkh:
    case AddressType.p2sh:
    case AddressType.p2wsh:
      return false;
  }
}
