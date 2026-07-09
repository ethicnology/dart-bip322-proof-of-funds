import 'package:bip322/bip322.dart';
import 'package:hex/hex.dart';
import 'package:test/test.dart';

/// Golden values from the official BIP-322 test vectors
/// (bitcoin/bips bip-0322/basic-test-vectors.json).
void main() {
  const address = 'bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l';

  group('BIP-322 message hash (tagged)', () {
    test('empty message', () {
      expect(
        HEX.encode(Bip322.messageHash('')),
        'c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1',
      );
    });

    test('"Hello World"', () {
      expect(
        HEX.encode(Bip322.messageHash('Hello World')),
        'f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a',
      );
    });
  });

  group('to_spend / to_sign txids', () {
    ({String toSpend, String toSign}) txids(String message) {
      final toSpend = Bip322.buildToSpendFromAddress(message, address);
      final toSign = Bip322.buildToSign(toSpend);
      return (toSpend: toSpend.txid(), toSign: toSign.txid());
    }

    test('empty message', () {
      final r = txids('');
      expect(
        r.toSpend,
        'c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7',
      );
      expect(
        r.toSign,
        '1e9654e951a5ba44c8604c4de6c67fd78a27e81dcadcfe1edf638ba3aaebaed6',
      );
    });

    test('"Hello World"', () {
      final r = txids('Hello World');
      expect(
        r.toSpend,
        'b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b',
      );
      expect(
        r.toSign,
        '88737ae86f2077145f93cc4b153ae9a1cb8d56afa511988c149c5c8c9d93bddf',
      );
    });
  });

  group('to_spend structure', () {
    test('scriptSig is OP_0 PUSH32[hash] (minimal push)', () {
      final toSpend = Bip322.buildToSpendFromAddress('', address);
      final scriptSig = toSpend.inputs.single.scriptSig.bytes;
      expect(scriptSig[0], 0x00); // OP_0
      expect(scriptSig[1], 0x20); // minimal 32-byte push
      expect(scriptSig.length, 34);
      expect(toSpend.inputs.single.sequence, 0);
      expect(toSpend.version, 0);
    });
  });
}
