import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:bech32/bech32.dart';
import 'package:bip322/bip322.dart';
import 'package:bip322/src/bech32m.dart';
import 'package:bip322/src/crypto/ecdsa.dart' show secp256k1;
import 'package:bip322/src/crypto/hashes.dart' show hash160;
import 'package:ecdsa/ecdsa.dart' as ecdsa;
import 'package:test/test.dart';

/// Wraps [Bip322.verify], treating any thrown [Bip322Exception] as a failed
/// verification — this is how a defensive caller should use the API.
bool safeVerify({
  required String message,
  required String address,
  required String signature,
}) {
  try {
    return Bip322.verify(
      message: message,
      address: address,
      signature: signature,
    );
  } on Bip322Exception {
    return false;
  }
}

void main() {
  const p2wpkhAddress = 'bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l';
  const p2trAddress =
      'bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler';
  const validP2wpkhSig =
      'smpAkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=';

  group('official error vectors (basic-test-vectors.json)', () {
    test('invalid base64 encoding', () {
      expect(
        safeVerify(
          message: '',
          address: p2wpkhAddress,
          signature: 'not-valid-base64!!!',
        ),
        isFalse,
      );
    });

    test('empty signature', () {
      expect(
        safeVerify(message: '', address: p2wpkhAddress, signature: ''),
        isFalse,
      );
    });

    test('wrong message for a valid signature', () {
      expect(
        safeVerify(
          message: 'Wrong message that was not signed',
          address: p2wpkhAddress,
          signature: validP2wpkhSig,
        ),
        isFalse,
      );
    });

    test('wrong address for a valid signature', () {
      // The official vector's "wrong address" happens to be P2WSH, which
      // this library rejects up front via UnimplementedError (not
      // implemented) rather than a quiet `false` — the underlying spec
      // expectation ("this signature must not verify for this address")
      // still holds, just surfaced differently given this library's scope.
      expect(
        () => Bip322.verify(
          message: '',
          address:
              'bc1qp0ahvfh83088w49k405szqgg4f3pptr7p2g06tdxfjcd40z4lh4q95lsz9',
          signature: validP2wpkhSig,
        ),
        throwsUnimplementedError,
      );
    });

    test('empty witness stack (single zero byte)', () {
      expect(
        safeVerify(message: '', address: p2wpkhAddress, signature: 'smpAA=='),
        isFalse,
      );
    });

    test('unrecognized prefix / malformed payload', () {
      expect(
        safeVerify(message: '', address: p2wpkhAddress, signature: 'fooAA=='),
        isFalse,
      );
    });

    test('"ful" prefix is a recognised-but-unimplemented variant', () {
      // UnimplementedError is a Dart Error (not a Bip322Exception): it signals
      // a genuinely missing feature (v2), distinct from "verification failed",
      // and must never be swallowed into a false "verified" result.
      expect(
        () => Bip322.verify(
          message: 'incorrect prefix',
          address: p2trAddress,
          signature:
              'fulAUDZwFXUp+adN+/UZj5dVrGAbB3zKs1Vcalz5fCF9srxS63eSWNGvH1NYbrBkPt1BJDUyWUz9zgUxfc63/QheT6M',
        ),
        throwsUnimplementedError,
      );
    });
  });

  group('type confusion defense (format bound to address type)', () {
    // A syntactically valid 65-byte "legacy" blob must never verify against a
    // segwit/taproot address, regardless of its content.
    final random = Random(42);
    Uint8List randomBytes(int n) =>
        Uint8List.fromList(List.generate(n, (_) => random.nextInt(256)));

    test('65-byte blob rejected on P2WPKH', () {
      for (var i = 0; i < 20; i++) {
        final blob = base64Encode(randomBytes(65));
        expect(
          safeVerify(message: '', address: p2wpkhAddress, signature: blob),
          isFalse,
          reason: 'iteration $i',
        );
      }
    });

    test('65-byte blob rejected on P2TR', () {
      for (var i = 0; i < 20; i++) {
        final blob = base64Encode(randomBytes(65));
        expect(
          safeVerify(message: '', address: p2trAddress, signature: blob),
          isFalse,
          reason: 'iteration $i',
        );
      }
    });

    test('P2WSH address throws UnimplementedError, never a false accept', () {
      // Real official p2wsh-3of3 signature, wrong (unrelated) message: P2WSH
      // signing/verification isn't implemented, rejected up front by
      // Bip322's out-of-scope-address-type gate — a loud Error, not a quiet
      // `false`, matching Full's UnimplementedError policy (verify() throws
      // for a pof-prefixed signature too, but because its boolean return
      // can't express Proof of Funds' three-state result, not because PoF
      // itself is unimplemented — see Bip322.verifyProofOfFunds).
      expect(
        () => Bip322.verify(
          message: 'This is not the message that was signed',
          address:
              'bc1qp0ahvfh83088w49k405szqgg4f3pptr7p2g06tdxfjcd40z4lh4q95lsz9',
          signature:
              'smpBQBHMEQCIFX9aaqPJWq2Ff2kpen5bFDTid+ehgUOpHV0LfjncXy4AiA3GNicF7aKPzdpa9PCpmaYQs3pHd+qbvvhXdxOCKCAMAFIMEUCIQD/ELXg6CNYyUQijCg96JtgvgjZb9dsl1Ctof4QAeyTcQIgVM/1AAblFl/DCt6A1gJg+T/i2qU5SQD09+chFJzolRwBSDBFAiEAlqRfSFyWNVQhvaCnmeV5tyneiCWMTcFbuujoD/pFa3wCIGnZjfQb8NolSYq9asV+ZeBSkCGHJcqnaV4JYS5MYPEGAWlTIQJ1aLEfEi/4p7wcV+XHZCBVvGGJZ7L3v+jhH+mZA8lN0yECCovfec+kIdllXpKCgA8RX/HZ2x5yHOtCSKP8/sf6pnwhAwxSng6kCgCXXSAmJOOZFdr3vdK3HzGqCFloOHgc5fM6U64=',
        ),
        throwsUnimplementedError,
      );
    });

    test(
      'P2TR explicit non-ALL sighash type is rejected (65-byte witness)',
      () {
        // BIP-322 requires SIGHASH_DEFAULT/SIGHASH_ALL only. A real signature
        // over the sighash for hashType=DEFAULT packaged with a *different*
        // trailing byte (e.g. NONE, 0x02) must be rejected outright, not
        // verified against a wrongly-derived sighash for that type.
        const wif = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';
        final signerAddress = Bip322.p2trAddress(wif);
        final validDefault = Bip322.signMessage(
          message: 'sighash type check',
          address: signerAddress,
          privateKey: wif,
        );
        final decoded = base64Decode(validDefault.substring(3));
        // consensus witness: [count=1][len=64][64-byte sig]
        expect(decoded[0], 1);
        expect(decoded[1], 64);
        final sig64 = decoded.sublist(2, 66);

        for (final hashType in [0x02, 0x03, 0x81, 0x82, 0x83, 0xff]) {
          final witnessBytes = <int>[1, 65, ...sig64, hashType];
          final crafted = 'smp${base64Encode(witnessBytes)}';
          expect(
            safeVerify(
              message: 'sighash type check',
              address: signerAddress,
              signature: crafted,
            ),
            isFalse,
            reason: 'hashType=0x${hashType.toRadixString(16)}',
          );
        }
      },
    );
  });

  group('malformed input never throws past Bip322.verify (no safeVerify)', () {
    test('invalid base64 returns false directly', () {
      expect(
        Bip322.verify(
          message: '',
          address: p2wpkhAddress,
          signature: 'smp!!!not-base64!!!',
        ),
        isFalse,
      );
    });

    test('truncated witness (compactSize claims more than available)', () {
      // compactSize(1) item count, then compactSize(200) claiming a 200-byte
      // item but only 1 byte follows.
      final truncated = base64Encode([1, 200, 0xaa]);
      expect(
        Bip322.verify(
          message: '',
          address: p2wpkhAddress,
          signature: 'smp$truncated',
        ),
        isFalse,
      );
    });

    test('garbled address string returns false, not an uncaught exception', () {
      expect(
        Bip322.verify(
          message: '',
          address: 'not-a-bitcoin-address-at-all',
          signature: validP2wpkhSig,
        ),
        isFalse,
      );
    });
  });

  group('off-curve public key does not crash the verifier', () {
    test('a 33-byte value with a valid prefix but off-curve X is rejected', () {
      // 02 || 0x11*32 has a well-formed compressed-pubkey prefix and length,
      // but its X coordinate is not a quadratic residue (confirmed off-curve
      // via `elliptic`'s own curve membership check) — `PublicKey.fromHex`
      // throws for this, so `ecdsaVerifyDer` must catch it internally rather
      // than let the exception propagate out of `Bip322.verify`.
      final offCurvePub = [0x02, ...List.filled(32, 0x11)];
      final keyHash = hash160(offCurvePub);
      final craftedAddress = segwit.encode(Segwit('bc', 0, keyHash));

      final witnessBytes = <int>[
        2,
        1, 0x01, // a 1-byte "signature": too short to be valid DER, but
        // the point is what happens once the (also-invalid) pubkey is
        // reached — see the second case below for a real DER + bad pubkey.
        offCurvePub.length, ...offCurvePub,
      ];
      expect(
        Bip322.verify(
          message: '',
          address: craftedAddress,
          signature: 'smp${base64Encode(witnessBytes)}',
        ),
        isFalse,
      );

      // A real DER-encoded (but unrelated) signature paired with the same
      // off-curve pubkey: DER parsing succeeds, so this exercises
      // `PublicKey.fromHex` specifically, not `Signature.fromDER`.
      final realSig = Bip322.signMessage(
        message: 'x',
        address: 'bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l',
        privateKey: 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k',
      );
      final realWitness = base64Decode(realSig.substring(3));
      final realSigLen = realWitness[1];
      final realSigWithType = realWitness.sublist(2, 2 + realSigLen);
      final witnessBytes2 = <int>[
        2,
        realSigWithType.length,
        ...realSigWithType,
        offCurvePub.length,
        ...offCurvePub,
      ];
      expect(
        Bip322.verify(
          message: '',
          address: craftedAddress,
          signature: 'smp${base64Encode(witnessBytes2)}',
        ),
        isFalse,
      );
    });
  });

  group('signature malleability (BIP-62 low-S enforcement)', () {
    const wif = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';

    test('a manually re-signed high-S variant is rejected', () {
      final sig = Bip322.signMessage(
        message: 'malleability check',
        address: p2wpkhAddress,
        privateKey: wif,
      );
      expect(
        safeVerify(
          message: 'malleability check',
          address: p2wpkhAddress,
          signature: sig,
        ),
        isTrue,
        reason: 'sanity: the original low-S signature must verify',
      );

      // Decode witness = [sig||sighashByte, pubkey], flip S to its high-S
      // twin (still a mathematically valid ECDSA signature over the same
      // hash), and confirm the library rejects it (NULLFAIL/low-S discipline).
      final decoded = base64Decode(sig.substring(3));
      // consensus witness: [count][len][sig+type][len][pubkey]
      final count = decoded[0];
      expect(count, 2);
      final sigLen = decoded[1];
      final sigWithType = decoded.sublist(2, 2 + sigLen);
      final pubkeyStart = 2 + sigLen + 1;
      final pubkeyLen = decoded[2 + sigLen];
      final pubkey = decoded.sublist(pubkeyStart, pubkeyStart + pubkeyLen);

      final der = sigWithType.sublist(0, sigWithType.length - 1);
      final hashType = sigWithType.last;
      final parsed = ecdsa.Signature.fromDER(der);
      final highS = secp256k1.n - parsed.S;
      final malleated = ecdsa.Signature.fromRS(parsed.R, highS);
      final malleatedDer = malleated.toDER();

      final witnessBytes = <int>[
        2,
        malleatedDer.length + 1,
        ...malleatedDer,
        hashType,
        pubkey.length,
        ...pubkey,
      ];
      final malleatedSig = 'smp${base64Encode(witnessBytes)}';

      expect(
        safeVerify(
          message: 'malleability check',
          address: p2wpkhAddress,
          signature: malleatedSig,
        ),
        isFalse,
      );
    });
  });

  group('non-canonical encoding is rejected (malleability)', () {
    const wif = 'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k';

    test('trailing bytes after the witness stack are rejected', () {
      final sig = Bip322.signMessage(
        message: 'canonical',
        address: p2wpkhAddress,
        privateKey: wif,
      );
      expect(
        safeVerify(
          message: 'canonical',
          address: p2wpkhAddress,
          signature: sig,
        ),
        isTrue,
        reason: 'sanity: the canonical signature verifies',
      );

      final raw = base64Decode(sig.substring(3));
      final withTrailing = 'smp${base64Encode([...raw, 0xde, 0xad])}';
      expect(
        safeVerify(
          message: 'canonical',
          address: p2wpkhAddress,
          signature: withTrailing,
        ),
        isFalse,
        reason: 'appending bytes to a valid witness stack must not verify',
      );
    });

    test('non-canonical DER (trailing bytes inside the sig item) rejected', () {
      final sig = Bip322.signMessage(
        message: 'strict der',
        address: p2wpkhAddress,
        privateKey: wif,
      );
      final w = base64Decode(sig.substring(3));
      // witness = [count=2][sigLen][der+hashType][pubLen][pub]
      final sigLen = w[1];
      final der = w.sublist(2, 2 + sigLen - 1);
      final hashType = w[2 + sigLen - 1];
      final pubLen = w[2 + sigLen];
      final pub = w.sublist(2 + sigLen + 1, 2 + sigLen + 1 + pubLen);
      // Splice two extra bytes between the DER body and the sighash type: the
      // ECDSA DER parser tolerates the trailing bytes, so strict-DER
      // re-serialization enforcement is what must reject this.
      final crafted = <int>[
        2,
        der.length + 3,
        ...der,
        0x00,
        0x00,
        hashType,
        pub.length,
        ...pub,
      ];
      expect(
        safeVerify(
          message: 'strict der',
          address: p2wpkhAddress,
          signature: 'smp${base64Encode(crafted)}',
        ),
        isFalse,
      );
    });
  });

  group('BIP-350 witness-version / checksum binding', () {
    test('v0 program encoded with a bech32m checksum is rejected', () {
      final program20 = Uint8List(20); // arbitrary all-zero P2WPKH program
      final crafted = encodeBech32mSegwit('bc', 0, program20);
      expect(
        () => parseAddress(crafted, Network.mainnet),
        throwsA(isA<Bip322Exception>()),
      );
    });

    test('v1 program encoded with a bech32 (non-m) checksum is rejected', () {
      // Build a v1/32-byte payload but checksum it with plain bech32 (v0 rules).
      final program32 = Uint8List(32);
      // Reuse the P2TR address's program by re-deriving via the bech32m
      // decoder, then re-encode the same data with the *wrong* checksum type
      // using the low-level bech32 segwit codec directly.
      final decoded = decodeBech32mSegwit(p2trAddress);
      expect(decoded.version, 1);
      expect(decoded.program.length, 32);
      final wrongChecksum = _encodeBech32V0Unchecked('bc', 1, decoded.program);
      expect(
        () => parseAddress(wrongChecksum, Network.mainnet),
        throwsA(isA<WitnessVersionChecksumMismatchException>()),
      );
      // Keep the unused local meaningful for readability of the test intent.
      expect(program32.length, 32);
    });
  });
}

/// Encodes a segwit address using the plain BIP-173 (bech32, non-m) checksum
/// regardless of witness [version] — used only to construct a deliberately
/// invalid BIP-350 combination for the negative test above.
String _encodeBech32V0Unchecked(String hrp, int version, List<int> program) {
  const charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  List<int> convertBits(List<int> data, int from, int to) {
    var acc = 0, bits = 0;
    final ret = <int>[];
    final maxv = (1 << to) - 1;
    for (final v in data) {
      acc = (acc << from) | v;
      bits += from;
      while (bits >= to) {
        bits -= to;
        ret.add((acc >> bits) & maxv);
      }
    }
    if (bits > 0) ret.add((acc << (to - bits)) & maxv);
    return ret;
  }

  List<int> hrpExpand(String hrp) => [
    for (final c in hrp.codeUnits) c >> 5,
    0,
    for (final c in hrp.codeUnits) c & 31,
  ];

  int polymod(List<int> values) {
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

  final data = [version, ...convertBits(program, 8, 5)];
  final values = [...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  final mod = polymod(values) ^ 1; // bech32 (not bech32m) constant
  final checksum = [for (var i = 0; i < 6; i++) (mod >> (5 * (5 - i))) & 31];
  final chars = [...data, ...checksum].map((d) => charset[d]).join();
  return '${hrp}1$chars';
}
