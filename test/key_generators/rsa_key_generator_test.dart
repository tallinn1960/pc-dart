// See file LICENSE for more information.

import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/src/platform_check/platform_check.dart';
import 'package:test/test.dart';

import '../test/runners/key_generators.dart';
import '../test/src/fixed_secure_random.dart';
import '../test/src/helpers.dart';

final sourceOfRandomValues = createUint8ListFromHexString(
    '4b 58 b6 5e a6 45 1e c4  fc ec 9a 67 ed cf 78 c7  d3 04 16 1b 7e cc 6a cb'
    '1d 1a 5d 45 9a 59 c2 78  8c 9b 5f 09 40 f2 e3 53  38 55 0c 10 3e 81 be d3'
    '12 79 a9 cb d4 a3 bb bb  75 7c aa 0c 70 6f 13 85  bf 75 24 7b e7 99 b1 9b'
    'e6 9b ef f9 d2 4f cb 52  78 1e 94 c7 e8 84 84 91  65 ba 88 59 9c 55 cc 12'
    '7e f9 18 6d dc 2a ad b5  ed ba f4 4e ea 33 d2 a4  02 6d 45 0f 7f 5e 3e db'
    'a6 11 1a 88 21 17 28 e4  75 d2 c3 87 ab fe dc fa  9f 7b 87 be 3b fd 1f 74'
    '04 82 d6 64 6c 83 62 d7  a2 2b 49 83 c8 c1 c4 19  fe 7c 6f 0c 2b be 39 eb'
    'b6 2e f5 67 0e 9c f8 06  76 2e 5a 9c a1 5c 24 e8  c0 1b 04 4f a4 ef 21 07'
    'ea 86 fb c9 b7 65 82 10  35 9c 9f 80 1f 72 66 bd  5d 92 c3 f0 da 45 c8 74'
    '26 64 96 f0 53 73 70 1a  2d e3 bb c0 d1 4e 1a 67  cd f4 10 de ce 0e 2c 89'
    '7a 5a f2 47 12 64 42 36  81 66 cc 06 b8 43 b7 96  71 31 13 27 2e 6a 9b e4'
    'c4 ac b0 87 1c be 70 f4  a5 ba 08 22 d7 c6 28 0a  89 c0 e8 73 1d eb e8 9c'
    'e4 6f 13 59 72 b3 75 62  84 3a b9 59 9c c6 1d 2d  92 89 29 fa 73 0d c7 f4'
    'a0 ff 75 36 58 da d8 8b  a0 be 7f 7b 7e fe 19 2b  7c 19 4a 29 8b 0e bf c6'
    'bb d4 a5 b4 4d 1d 90 a9  e7 85 2f c4 f3 fe 4b 96  af 9d a6 36 c9 f3 70 7c'
    '21 7d 63 ad 6b 17 fa cc  67 d5 38 22 40 32 bf 72  2d 60 1f 21 6e ec d3 da'
    '86 50 f1 bf 7c de 2c 91  fb c1 1e 7b a2 29 b1 d8  d0 0f 63 c6 76 fb 52 62'
    '0c 3c b0 4b 19 4f 41 2d  89 40 11 c1 a0 79 70 98  f9 75 e6 76 63 fa 42 4e'
    '5b 09 8f 08 6c 77 7a 1b  ad 33 1c 1a 01 92 fe 2c  1f 3d 3e 63 d2 6c c0 98'
    'b6 f9 e5 89 c9 cc 91 a0  9e f3 00 1c b7 2f 46 fe  ad 94 b0 de a3 99 54 54'
    'db 49 ec 05 8d 54 5f b7  91 64 60 74 b5 23 a1 74  a8 f7 e0 eb de 3d b3 31'
    '98 77 d2 e3 f4 6e 90 57  c6 bc cb ab ec 5d 74 55  15 78 d3 ff 89 df 1c 50'
    'ad ce a5 56 e5 93 11 c2  60 20 30 db cb a2 29 f9  dd 33 db 82 e9 3f d0 08'
    '23 67 d7 4c e6 5b 6c 99  7a d7 dc 71 25 51 38 a4  50 1d 27 0e 73 52 89 b6'
    '4a 7b 58 d5 9c d2 fe 2d  76 39 9e 6d ee 72 65 ea  bb 05 43 ac af de f2 a1'
    'd4 3e 05 e9 cd 48 05 cc  67 a3 43 80 4c 0e aa 07  2a 88 72 73 dc d7 b6 c9'
    '2d 2a a0 0c 71 3d dd f0  a8 b3 59 1a 12 e1 7f f3  6e 55 7f 10 b0 4c ce a9'
    'fa bc f4 36 b9 61 12 84  93 40 97 e4 17 de 91 98  97 21 73 e7 13 ed 34 1e'
    '8d 14 c6 07 94 51 a2 f5  17 ed 62 ed 03 1b e9 fd  5d 4b cd c9 17 c9 bb 48'
    '7c 26 55 57 d9 56 67 70  27 65 c7 63 f7 81 e6 64  05 1e ca 69 96 ac 27 fe'
    '74 93 a8 85 1e e1 1a 22  39 40 58 28 13 93 2e 6c  de 60 cf 88 a8 fd 83 6b'
    'e3 b3 3c 1f 9a 92 02 a2  21 24 9e 11 fb b8 44 21  5f ea 2d 8d d9 ad 72 8c'
    'c7 e0 80 36 f4 45 d1 90  bb c1 59 bc 57 d0 d1 f6  25 85 a5 4a 6e e0 de fe'
    '9f 1f 9a 5a 48 d0 34 6d  da 29 b9 b9 b1 f8 b4 ac  e3 6f a7 33 1f b8 ea b8'
    '84 9d d4 11 9a 09 bf c1  83 64 c5 69 81 37 19 92  61 7f ab 07 f6 4f 5d b5'
    '2a d6 f4 40 8d cb 13 aa  75 1c 2b 5c ac 81 f4 8e  f7 45 90 22 08 f1 11 ef'
    '51 38 12 f8 96 30 a7 fc  11 49 bd 9a 22 a9 22 92  5e 0e 50 b9 56 19 82 5a'
    '57 a6 bc 59 63 0a 24 1c  d6 0f 6d bb ce a6 e0 76  ba 09 bd 79 9b 06 64 04'
    'fb c5 42 e1 45 9a d7 82  ee 2d 67 2c 23 38 56 3c  65 e5 33 ac f0 8c 94 90'
    '85 2e c5 2c e3 3e 7c fb  4a 7d b0 e4 5f bb 40 ac  98 59 0b 3e f8 4f df 51'
    '31 10 d2 94 0e 6e 45 d9  f2 4f 2d 86 97 0c e3 cc  05 44 d8 56 86 ed f7 d8'
    'fc a2 75 d2 b7 21 e8 d8  11 98 7c e0 e0 a2 10 33  9d 7c a3 21 e9 d9 9b 5e'
    'f2 b0 17 24 ee 8b ce 22  52 9f 62 60 b1 a3 d4 96');

final testPublicExponent = BigInt.parse('65537');
const testBitLength = 2048;
const testCertainty = 12;

// This key pair is generated by the above inputs to the RSA key generator.

final referenceKeyPair = _keyPair(
    '24649663692047164444790643172109370056158709234977203368650147515375245495213442567159484352023028564722607846088040100966055452012530635310929880142309672672370384513414361688667706499439717428347689592753696423610988570895714214920908622106527744596538403468957028226105712420419053355165486523922578029360613666994642331140679324765028868432884033287641095549662040120859273059357594690379309402039994712237709233598606723986537440109010028591440539106473660495784943265016397899779881916920074735104005566018575893835392960697074083820748729243932835684709199184189144330411532000389215869317902155568589589990937',
    '65537',
    '4063958011391574405693927086602098714570316817735457564402777727140844524097551717932743769528797833923246071333464657993778005691371187490037648274068938358865404346665886110838985133992189859366415704864484029740707257099473459148578934981171434157279055334880764911165787611618289996529640995025458223709324848295784182981653521435775135990468151575617415377402359600649196585978093468870169020045627061059125356549455475504958158218546129405411183104108490830376537830617352916950230417099192711318868054030047466626509446719907850666657436082569747996909170379147599626458818599142452671385912424304169295269813',
    '172622988945032241272460594823465727338165469761128582817141296878210996104803340949368540074325243384642718754688224642044903791277270607713426667425998282894170126560269953218957312807290242694167112152302773291330789947866948729188625784460892934126377883318018638038433339229978409110366812585246469634979',
    '142794791369857893518216846152178512365742893193381905408671045383524196038880042688222484665321416966726996826180091369625084659347039997384427839884481875048370565094771341455209579084576003589416828973425288956690619644847967193297411322186095969144940769802524422661706293551748267739368517289465924234003',
    '65537');

void main() {
  _generationTests();
  _equalityTests();
}

void _generationTests() {
  group('rsa', () {
    // Test RSA key generation

    group('key generation', () {
      // Test RSA key generation using known source of "randomness" as input

      group('fixed', () {
        // Create an RSA key generator using fixed input instead of randomness

        var rnd = FixedSecureRandom()..seed(KeyParameter(sourceOfRandomValues));

        var keyGenerator = KeyGenerator('RSA')
          ..init(ParametersWithRandom(
              RSAKeyGeneratorParameters(
                  testPublicExponent, testBitLength, testCertainty),
              rnd));

        // Use generator to generate an RSA key pair: must produce the reference

        runKeyGeneratorTests(keyGenerator, [referenceKeyPair]);

        // Test the reference key pair

        _exponentTests(referenceKeyPair, testPublicExponent);
      });

      // Test RSA key generation using real source of randomness as input

      group('random', () {
        // Create an RSA key generator using a random number generator

        final rnd = SecureRandom('Fortuna')
          ..seed(KeyParameter(
              Platform.instance.platformEntropySource().getBytes(32)));

        var keyGenerator = KeyGenerator('RSA')
          ..init(ParametersWithRandom(
              RSAKeyGeneratorParameters(testPublicExponent, 2048, 12), rnd));

        // Use generator to generate an RSA key pair

        final kp = keyGenerator.generateKeyPair();

        // Test the generated key pair

        _exponentTests(kp, testPublicExponent);

        /*
        // Print out the generated key pair

        final rsaPublicKey = kp.publicKey as RSAPublicKey;
        final rsaPrivateKey = kp.privateKey as RSAPrivateKey;

        print('''
Generated key pair:
      final pairX = _keyPair(
          '${rsaPublicKey.modulus}',
          '${rsaPublicKey.publicExponent}',
          '${rsaPrivateKey.privateExponent}',
          '${rsaPrivateKey.p}',
          '${rsaPrivateKey.q}',
          '${rsaPrivateKey.publicExponent}');
''');
         */
      });
    });
  });
}

void _equalityTests() {
  // RSA key pair equality

  try {
    group('key equality', () {
      // Sanity test on equality.

      // Key pair [pairA] (and [sameAsPairA]) happens to be the same as the
      // [referenceKeyPair], but it does not have to be. Any valid RSA key pair
      // can be used.

      final pairA = _keyPair(
          '24649663692047164444790643172109370056158709234977203368650147515375245495213442567159484352023028564722607846088040100966055452012530635310929880142309672672370384513414361688667706499439717428347689592753696423610988570895714214920908622106527744596538403468957028226105712420419053355165486523922578029360613666994642331140679324765028868432884033287641095549662040120859273059357594690379309402039994712237709233598606723986537440109010028591440539106473660495784943265016397899779881916920074735104005566018575893835392960697074083820748729243932835684709199184189144330411532000389215869317902155568589589990937',
          '65537',
          '4063958011391574405693927086602098714570316817735457564402777727140844524097551717932743769528797833923246071333464657993778005691371187490037648274068938358865404346665886110838985133992189859366415704864484029740707257099473459148578934981171434157279055334880764911165787611618289996529640995025458223709324848295784182981653521435775135990468151575617415377402359600649196585978093468870169020045627061059125356549455475504958158218546129405411183104108490830376537830617352916950230417099192711318868054030047466626509446719907850666657436082569747996909170379147599626458818599142452671385912424304169295269813',
          '172622988945032241272460594823465727338165469761128582817141296878210996104803340949368540074325243384642718754688224642044903791277270607713426667425998282894170126560269953218957312807290242694167112152302773291330789947866948729188625784460892934126377883318018638038433339229978409110366812585246469634979',
          '142794791369857893518216846152178512365742893193381905408671045383524196038880042688222484665321416966726996826180091369625084659347039997384427839884481875048370565094771341455209579084576003589416828973425288956690619644847967193297411322186095969144940769802524422661706293551748267739368517289465924234003',
          '65537');

      final sameAsPairA = _keyPair(
          '24649663692047164444790643172109370056158709234977203368650147515375245495213442567159484352023028564722607846088040100966055452012530635310929880142309672672370384513414361688667706499439717428347689592753696423610988570895714214920908622106527744596538403468957028226105712420419053355165486523922578029360613666994642331140679324765028868432884033287641095549662040120859273059357594690379309402039994712237709233598606723986537440109010028591440539106473660495784943265016397899779881916920074735104005566018575893835392960697074083820748729243932835684709199184189144330411532000389215869317902155568589589990937',
          '65537',
          '4063958011391574405693927086602098714570316817735457564402777727140844524097551717932743769528797833923246071333464657993778005691371187490037648274068938358865404346665886110838985133992189859366415704864484029740707257099473459148578934981171434157279055334880764911165787611618289996529640995025458223709324848295784182981653521435775135990468151575617415377402359600649196585978093468870169020045627061059125356549455475504958158218546129405411183104108490830376537830617352916950230417099192711318868054030047466626509446719907850666657436082569747996909170379147599626458818599142452671385912424304169295269813',
          '172622988945032241272460594823465727338165469761128582817141296878210996104803340949368540074325243384642718754688224642044903791277270607713426667425998282894170126560269953218957312807290242694167112152302773291330789947866948729188625784460892934126377883318018638038433339229978409110366812585246469634979',
          '142794791369857893518216846152178512365742893193381905408671045383524196038880042688222484665321416966726996826180091369625084659347039997384427839884481875048370565094771341455209579084576003589416828973425288956690619644847967193297411322186095969144940769802524422661706293551748267739368517289465924234003',
          '65537');

      // Key pair [pairB] must be different from [pairA].
      //
      // It was generated by printing out a key pair generated by the "random"
      // group above.

      final pairB = _keyPair(
          '19998306328585176190366931006323279258949313181307546699816669664375919241027356951914691360578319992250399010485771130476451229840594808138101564594115773724013936584602754417070271298701696987528901888461008771284744893172122544667786764873333740745216326896528158046782247261766024669089482595105385979285059846497020559321736554684511163018198870867271603237630108207641918406339674840622347874621413157836620812448858932150510388151580106080194334580652193920929549719757990360242174059537218746801801687237676141171281586377264431453186972752634533558851854441192719423281312383801525771522400348684409782418181',
          '65537',
          '5152378081971416146212759663118064151355099456282373712962211686268632930783327313320407763909927721274211320201599791539052428641201814782670017214270485974792488506202870261565703814312192404815989569047471399410148733100558297857936425605173264148236533250650440951217148252360030616866440539212268524043264892574989944062193837186483983080645021774570356621207103577684271762737582372544866638275814427195654002085651202903221585300777616512377961344289572012376442469516292259733948327009762622317928932215997440536302741442884945463361977614033283418571310135110745254346728636868451102639703532527885300433473',
          '150184998420649548947932258643999611296181460297402912020172689683902675064609729677452625884062529296436525999147465242344088271241652573042354631277387610106715634254964478486873326919509893206720029965989460935701771076087649853048346640100380870168307353480373347027618122894629925347915349774079985870901',
          '133157815619988896034254188342686110116619401642991448852461596092802908382975330105515629389879493501891343915668062426766653101714665922211828772548885021209869316495667526636332920521836009126612102599502833008592976927333093662184588393203427464940108987342022609619311395970699227062951068719034627195281',
          '65537');

      test('equal', () {
        expect(pairA, equals(pairA)); // objects identical check
        expect(pairB, equals(pairB));

        expect(sameAsPairA, equals(pairA)); // members check
        expect(pairA, equals(sameAsPairA));
      });

      test('not equal', () {
        expect(pairA, isNot(equals(pairB)));
        expect(pairB, isNot(equals(pairA)));

        // Mix up the public key and private key values

        final badPair1 = AsymmetricKeyPair(pairB.publicKey, pairA.privateKey);
        expect(pairA, isNot(equals(badPair1)));
        expect(pairB, isNot(equals(badPair1)));
        expect(badPair1, isNot(equals(pairA)));
        expect(badPair1, isNot(equals(pairB)));

        final badPair2 = AsymmetricKeyPair(pairA.publicKey, pairB.privateKey);
        expect(pairA, isNot(equals(badPair2)));
        expect(pairB, isNot(equals(badPair2)));
        expect(badPair2, isNot(equals(pairA)));
        expect(badPair2, isNot(equals(pairB)));
      });
    });
  } catch (e, s) {
    print(s);
  }
}

void _exponentTests(AsymmetricKeyPair pair, BigInt expectedPublicExponent) {
  test('exponents', () {
    final rsaPublicKey = pair.publicKey as RSAPublicKey;
    final rsaPrivateKey = pair.privateKey as RSAPrivateKey;

    // Values are expected

    expect(rsaPublicKey.publicExponent, equals(expectedPublicExponent));
    expect(rsaPrivateKey.publicExponent, equals(expectedPublicExponent));
    expect(rsaPublicKey.publicExponent, equals(rsaPrivateKey.publicExponent));

    expect(rsaPrivateKey.privateExponent, isNot(expectedPublicExponent),
        reason: 'private exponent cannot be the same as the public exponent');

    // Deprecated getters still return correct values

    // ignore: deprecated_member_use_from_same_package
    expect(rsaPublicKey.e, equals(rsaPublicKey.publicExponent));
    // ignore: deprecated_member_use_from_same_package
    expect(rsaPrivateKey.d, equals(rsaPrivateKey.privateExponent));
    // ignore: deprecated_member_use_from_same_package
    expect(rsaPrivateKey.pubExponent, equals(expectedPublicExponent));
  });
}

AsymmetricKeyPair _keyPair(String n, String e, String d, String p, String q,
        String pubExpInPrivateKey) =>
    AsymmetricKeyPair(
      RSAPublicKey(BigInt.parse(n), BigInt.parse(e)),
      RSAPrivateKey(
        BigInt.parse(n),
        BigInt.parse(d),
        BigInt.parse(p),
        BigInt.parse(q),
        // ignore: deprecated_member_use_from_same_package
        BigInt.parse(pubExpInPrivateKey),
      ),
    );
