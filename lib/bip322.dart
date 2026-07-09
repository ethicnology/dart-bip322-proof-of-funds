/// A from-scratch Dart implementation of BIP-322 — the Generic Signed Message
/// Format for Bitcoin. Sign and verify "Simple" messages for P2WPKH and P2TR
/// addresses, and build/verify "Proof of Funds" signatures over a
/// P2WPKH/P2TR UTXO set. P2WSH, legacy (BIP-137) P2PKH, and the general Full
/// (arbitrary-transaction) format are recognised but not implemented — see
/// the README's support matrix and [Bip322] for exact behavior.
library;

export 'package:bip341/bip341.dart';

export 'src/address.dart' show ParsedAddress, parseAddress;
export 'src/bip322.dart';
export 'src/crypto/tagged_hash.dart' show bip322MessageHash, bip322Tag;
export 'src/enums.dart';
export 'src/errors.dart'
    show
        UnsupportedAddressTypeError,
        UnimplementedAddressTypeError,
        UnimplementedSignatureFormatError,
        IncompatibleVerificationApiError,
        UnsupportedScriptTypeError,
        UnreachableCaseError,
        NegativeValueError,
        MismatchedSpentOutputCountError;
export 'src/exceptions.dart';
export 'src/proof_of_funds.dart'
    show
        ProofOfFundsUtxo,
        ProofOfFundsResult,
        ProofOfFundsStatus,
        classifyScriptPubKey;
export 'src/psbt.dart'
    show DecodedPsbt, PsbtInputUtxo, encodeFinalizedPsbt, decodePsbt;
export 'src/script.dart' show Script;
export 'src/transaction.dart' show Transaction, TxIn, TxOut, OutPoint;
export 'src/witness.dart' show WitnessStack;
