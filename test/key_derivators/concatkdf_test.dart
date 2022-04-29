@OnPlatform({
  'chrome': Skip('Skip due to potential absence of file loading'),
  'node': Skip('Skip due to potential absence of file loading')
})
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/src/utils.dart';
import 'package:test/test.dart';

import '../test/src/helpers.dart';

dynamic loadJson(String path) {
  var file = File(path);
  return jsonDecode(file.readAsStringSync());
}

Uint8List nullSafeBytes(dynamic src) {
  if (src == null) {
    return Uint8List(0);
  }
  return createUint8ListFromHexString(src.toString());
}

void main() {
  Uint8List computerOtherInfo(String encryptionAlgorithmName, int keybitLength,
      {Uint8List? apu, Uint8List? apv}) {
    Uint8List convertToBigEndian(int l) {
      var ll = Uint8List(4);
      ll[0] = (l >> 24) & 255;
      ll[1] = (l >> 16) & 255;
      ll[2] = (l >> 8) & 255;
      ll[3] = (l) & 255;
      return ll;
    }

    var l = encryptionAlgorithmName.codeUnits.length.toUnsigned(32);
    var ll = convertToBigEndian(l);
    var a = Uint8List.fromList(encryptionAlgorithmName.codeUnits);
    var apul = convertToBigEndian(apu?.length ?? 0);
    var apvl = convertToBigEndian(apv?.length ?? 0);
    var k = convertToBigEndian(keybitLength);
    return Uint8List.fromList(
        [...ll, ...a, ...apul, ...(apu ?? []), ...apvl, ...(apv ?? []), ...k]);
  }

  var acvpToDart = Map();
  acvpToDart['SHA2-224'] = 'SHA-224';
  acvpToDart['SHA2-256'] = 'SHA-256';
  acvpToDart['SHA2-384'] = 'SHA-384';
  acvpToDart['SHA2-512'] = 'SHA-512';
  acvpToDart['SHA2-512/224'] = 'SHA-512/224';
  acvpToDart['SHA2-512/256'] = 'SHA-512/256';
  acvpToDart['SHA3-224'] = 'SHA3-224';
  acvpToDart['SHA3-256'] = 'SHA3-256';
  acvpToDart['SHA3-384'] = 'SHA3-384';
  acvpToDart['SHA3-512'] = 'SHA3-512';

  group('KDA OneStep Concat Sp800-56Cr2', () {
    test('run vectors', () {
      //
      // These vectors were generated by NIST's ACVP system.
      // The correct answers were generated by the Bouncy Castle FIPS (Java) Lib
      // and verified by submission to ACVP.
      // "req" files contain the request.
      // "rsp" files contain the response.
      // There are two types of tests, AFT where the IUT is responsible for
      // calculating the DKM and VAL where the IUT is responsible to calculating
      // a DKM that may or may not match the supplied DKM in the request.
      //

      var req = loadJson('test/test_resources/kdf-56c/KDA.req.json');
      var rsp = loadJson('test/test_resources/kdf-56c/KDA.rsp.json');

      //
      // Form a maps of known correct results.
      //

      var validDKMAFT = Map<String, Uint8List>();
      var validVALResult = Map<String, bool>();

      rsp[1]['testGroups'].forEach((group) {
        group['tests'].forEach((test) {
          if (test['dkm'] != null) {
            validDKMAFT[
                    group['tgId'].toString() + ':' + test['tcId'].toString()] =
                createUint8ListFromHexString(test['dkm']);
          } else {
            validVALResult[group['tgId'].toString() +
                ':' +
                test['tcId'].toString()] = test['testPassed'];
          }
        });
      });

      var groups = req[1]['testGroups'];
      groups.forEach((group) {
        var kdfConfig = group['kdfConfiguration'];
        group['tests'].forEach((test) {
          var kdfParams = test['kdfParameter'];
          var t = kdfParams['t'];
          var fpU = test['fixedInfoPartyU'];
          var fpV = test['fixedInfoPartyV'];
          var l = kdfParams['l'];
          var algId = nullSafeBytes(kdfParams['algorithmId']);

          var otherInfo = BytesBuilder();
          otherInfo.add(algId);
          otherInfo.add(nullSafeBytes(fpU['partyId']));
          otherInfo.add(nullSafeBytes(fpU['ephemeralData']));
          otherInfo.add(nullSafeBytes(fpV['partyId']));
          otherInfo.add(nullSafeBytes(fpV['ephemeralData']));
          otherInfo.add(createUint8ListFromHexString(t));

          var Z = createUint8ListFromHexString(kdfParams['z']);

          var c = kdfParams['salt'] != null
              ? HkdfParameters(
                  Z, l, createUint8ListFromHexString(kdfParams['salt']))
              : HkdfParameters(Z, l);

          var concatKdf =
              KeyDerivator(acvpToDart[kdfConfig['auxFunction']] + '/ConcatKDF')
                ..init(c);
          var key = concatKdf.process(otherInfo.toBytes());

          if (group['testType'] == 'AFT') {
            //
            // AFT test, IUT must generate a DKM that must match what NIST
            // is expecting.
            //
            var knownDKM = validDKMAFT[
                group['tgId'].toString() + ':' + test['tcId'].toString()];
            expect(key, equals(knownDKM));
          } else {
            // VAL test
            // DKM is supplied in request, the IUT must generate a DKM that may
            // or may not equal the supplied DKM in the request.
            //

            var dkm = createUint8ListFromHexString(test['dkm']);
            var tp = constantTimeAreEqual(dkm, key);
            expect(
                validVALResult[
                    group['tgId'].toString() + ':' + test['tcId'].toString()],
                equals(tp));
          }
        });
      });
    });
  });

  group('RFC7518', () {
    test('Test concatKDF from RFC 7518 Appendix C', () {
      List<int> intListFromJsonArray(String s) {
        return List<int>.from(jsonDecode(s));
      }

      var kdf = KeyDerivator('SHA-256/ConcatKDF');
      var Z = Uint8List.fromList(intListFromJsonArray('''
     [158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132,
      38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121,
      140, 254, 144, 196]'''));

      var otherInfo = computerOtherInfo('A128GCM', 128,
          apu: Uint8List.fromList('Alice'.codeUnits),
          apv: Uint8List.fromList('Bob'.codeUnits));

      var params = HkdfParameters(Z, 128);
      kdf.init(params);

      var key = kdf.process(otherInfo);
      expect(key, Uint8List.fromList(intListFromJsonArray('''
        [86, 170, 141, 234, 248, 35, 109, 32, 
         92, 34, 40, 205, 113, 167, 16, 26]''')));
    });

    test('Test concatKdf A1 derived from jose4j', () {
      var z = base64Url.decode('Sq8rGLm4rEtzScmnSsY5r1n-AqBl_iBU8FxN80Uc0S0=');
      var alg = 'A256CBC-HS512';
      var otherInfo = computerOtherInfo(alg, 512);
      var c = HkdfParameters(z, 512);
      var concatKdf = KeyDerivator('SHA-256/ConcatKDF')..init(c);
      var key = concatKdf.process(otherInfo);
      var keyencoded = base64UrlEncode(key);
      expect(
          'pgs50IOZ6BxfqvTSie4t9OjWxGr4whiHo1v9Dti93CRiJE2PP60FojLatVVrcjg3BxpuFjnlQxL97GOwAfcwLA==',
          keyencoded);
    });

    test('Test concatKdf A2 derived from jose4j', () {
      var z = base64Url.decode('LfkHot2nGTVlmfxbgxQfMg==');
      var alg = 'A128CBC-HS256';
      var otherInfo = computerOtherInfo(alg, 256);
      var c = HkdfParameters(z, 256);
      var concatKdf = KeyDerivator('SHA-256/ConcatKDF')..init(c);
      var key = concatKdf.process(otherInfo);
      var keyencoded = base64UrlEncode(key);
      expect('vphyobtvExGXF7TaOvAkx6CCjHQNYamP2ET8xkhTu-0=', keyencoded);
    });
  });

  group('HMAC-ConcatKDF', () {
    test('Get an HMAC-ConcatKDF derivator', () {
      var kdf = KeyDerivator('SHA-256/HMAC/ConcatKDF');
      expect(kdf, isNotNull);
    });

    test('Tests for HMAC-ConcatKDF derivator', () {
      // Test vector from https://github.com/pyca/cryptography.git
      var Z = createUint8ListFromHexString(
          '013951627c1dea63ea2d7702dd24e963eef5faac6b4af7e4b831cde499dff1ce45f6179f741c728aa733583b024092088f0af7fce1d045edbc5790931e8d5ca79c73');
      var otherInfo = createUint8ListFromHexString(
          'a1b2c3d4e55e600be5f367e0e8a465f4bf2704db00c9325c9fbd216d12b49160b2ae5157650f43415653696421e68e');
      var salt = Uint8List.fromList(List.filled(128, 0));
      var okm =
          '64ce901db10d558661f10b6836a122a7605323ce2f39bf27eaaac8b34cf89f2f';
      var parms = HkdfParameters(Z, 256, salt);
      var kdf = KeyDerivator('SHA-512/HMAC/ConcatKDF')..init(parms);
      var key = kdf.process(otherInfo);
      expect(formatBytesAsHexString(key), equals(okm));
    });
  });
}
