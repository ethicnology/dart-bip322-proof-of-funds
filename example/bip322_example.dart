import 'package:bip322/bip322.dart';

void main() {
  _p2wpkhRoundTrip();
  _p2trVerify();
  _proofOfFunds();
}

/// Sign and verify a message for a P2WPKH ("bc1q...") address, deriving the
/// address itself from the private key with [Bip322.p2wpkhAddress].
void _p2wpkhRoundTrip() {
  const wif = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';
  const message = 'Hello World';

  final address = Bip322.p2wpkhAddress(wif);
  final signature = Bip322.signMessage(
    message: message,
    address: address,
    privateKey: wif,
  );
  print('P2WPKH address: $address');
  print('P2WPKH signature: $signature');

  final valid = Bip322.verify(
    message: message,
    address: address,
    signature: signature,
  );
  print('P2WPKH verified: $valid');
}

/// Verify one of the official BIP-322 test vectors for a P2TR ("bc1p...")
/// address, then sign and verify a fresh message for a P2TR address derived
/// from a private key with [Bip322.p2trAddress].
void _p2trVerify() {
  const officialAddress =
      'bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler';
  const officialMessage = 'No prefix fallback';
  const officialSignature =
      'AUCJYOwOjxYAvatTAGYaVlNXBVyFuc4MwNQkOuK2tl8xhfKDONd0NjfYyNSYcRqeCp8hsAnCEPHAVEkO9h6vbQ/R';

  final officialValid = Bip322.verify(
    message: officialMessage,
    address: officialAddress,
    signature: officialSignature,
  );
  print('P2TR verified (official vector): $officialValid');

  const wif = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';
  final address = Bip322.p2trAddress(wif);
  final signature = Bip322.signMessage(
    message: 'Hello Taproot',
    address: address,
    privateKey: wif,
  );
  print('P2TR address: $address');
  final valid = Bip322.verify(
    message: 'Hello Taproot',
    address: address,
    signature: signature,
  );
  print('P2TR verified (derived address): $valid');
}

/// Sign and verify a "Proof of Funds": a message signature plus one
/// additional (real, on-chain) UTXO the signer proves control of. This is a
/// contrived example — [proofUtxo] doesn't need to actually exist on-chain
/// for the cryptographic check below to pass, but a real verifier would also
/// confirm it exists and is unspent, since this check is offline-only.
void _proofOfFunds() {
  const wif = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';
  const proofWif =
      '0000000000000000000000000000000000000000000000000000000000000002';
  const message = 'I control these funds';

  final address = Bip322.p2wpkhAddress(wif);
  final proofAddress = Bip322.p2trAddress(proofWif);
  final proofUtxo = ProofOfFundsUtxo(
    prevout: OutPoint(List.filled(32, 0x07), 0), // a real UTXO's txid:vout
    amount: 25000,
    scriptPubKey: parseAddress(proofAddress, Network.mainnet).scriptPubKey,
    privateKey: proofWif,
  );

  final signature = Bip322.signProofOfFunds(
    message: message,
    address: address,
    privateKey: wif,
    proofUtxos: [proofUtxo],
  );
  print('Proof of Funds signature: ${signature.substring(0, 20)}...');

  final result = Bip322.verifyProofOfFunds(
    message: message,
    address: address,
    signature: signature,
  );
  print('Proof of Funds status: ${result.status}');
  print(
    'Proven UTXOs (cryptographically, not yet checked on-chain): '
    '${result.provenUtxos.length}',
  );
}
