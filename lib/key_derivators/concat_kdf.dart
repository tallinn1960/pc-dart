import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/key_derivators/api.dart';
import 'package:pointycastle/src/impl/base_key_derivator.dart';
import 'package:pointycastle/src/registry/registry.dart';

abstract class _ConcatKDFFunction {
  int get size;
  void update(Uint8List inp, int inpOff, int len);
  int doFinal(Uint8List out, int outOff);
  void reset();
  String get algorithmName;
}

class _DigestKDFunction implements _ConcatKDFFunction {
  Digest _digest;
  _DigestKDFunction(this._digest);

  @override
  int doFinal(Uint8List out, int outOff) {
    return _digest.doFinal(out, outOff);
  }

  @override
  int get size => _digest.digestSize;

  @override
  void update(Uint8List inp, int inpOff, int len) {
    _digest.update(inp, inpOff, len);
  }

  @override
  void reset() {
    _digest.reset();
  }

  @override
  String get algorithmName => _digest.algorithmName;
}

class _MacKDFunction implements _ConcatKDFFunction {
  Mac _mac;
  _MacKDFunction(this._mac);

  void init(Uint8List salt) {
    _mac.init(KeyParameter(salt));
  }

  @override
  int doFinal(Uint8List out, int outOff) {
    return _mac.doFinal(out, outOff);
  }

  @override
  int get size => _mac.macSize;

  @override
  void update(Uint8List inp, int inpOff, int len) {
    _mac.update(inp, inpOff, len);
  }

  @override
  void reset() {
    _mac.reset();
  }

  @override
  String get algorithmName => _mac.algorithmName;
}

abstract class _BaseConcatKDFDerivator extends BaseKeyDerivator {
  late final HkdfParameters _parameters;
  _ConcatKDFFunction _h;

  _BaseConcatKDFDerivator(this._h);

  int _getReps(int keydatalen, int messagedigestlen) {
    return (keydatalen / messagedigestlen).ceil();
  }

  @override
  void init(covariant HkdfParameters params) {
    _parameters = params;
  }

  @override
  int deriveKey(Uint8List inp, int inpOff, Uint8List out, int outOff) {

    var reps = _getReps(_parameters.desiredKeyLength, _h.size * 8);
    var output = Uint8List(reps * _h.size);
    var counter = Uint8List(4);
    for (var i = 1; i <= reps; i++) {
      _h.reset();
      var counterInt = i.toUnsigned(32);
      counter[0] = (counterInt >> 24) & 255;
      counter[1] = (counterInt >> 16) & 255;
      counter[2] = (counterInt >> 8) & 255;
      counter[3] = (counterInt) & 255;
      _h.update(counter, 0, 4);
      _h.update(_parameters.ikm, 0, _parameters.ikm.length);
      _h.update(inp.sublist(inpOff), 0, inp.sublist(inpOff).length);
      _h.doFinal(output, (i - 1) * _h.size);
    }

    out.setAll(outOff, output.getRange(0, keySize));
    return keySize;
  }

  @override
  int get keySize => (_parameters.desiredKeyLength / 8).ceil();

  @override
  String get algorithmName => '${_h.algorithmName}/ConcatKDF';
}

/// Key Derivation Function in accordance with
/// NIST SP 800-56C REV.1 4.1 Option 1
///
/// Input Z is taken from HkdfParameters.ikm
/// OtherInfo is taken from the input to KeyDerivator.process()
///
class ConcatKDFDerivator extends _BaseConcatKDFDerivator {
  /// Intended for internal use.
  static final FactoryConfig factoryConfig =
      DynamicFactoryConfig.suffix(KeyDerivator, '/ConcatKDF', (_, Match match) {
    final digestName = match.group(1);
    final digest = Digest(digestName!);
    return () {
      return ConcatKDFDerivator(digest);
    };
  });

  ConcatKDFDerivator(Digest digest) : super(_DigestKDFunction(digest));
}

/// Key Derivation Function in accordance with
/// NIST SP 800-56C REV.1 4.1 Option 2
///
/// Input Z is taken from HkdfParameters.ikm
/// Input salt is taken from HkdfParameters.salt
/// Input OtherInfo is taken from the input to KeyDerivator.process()
///

class HMacConcatKDFDerivator extends _BaseConcatKDFDerivator {
  /// Intended for internal use.
  static final FactoryConfig factoryConfig = DynamicFactoryConfig.suffix(
      KeyDerivator, '/HMAC/ConcatKDF', (_, Match match) {
    final digestName = match.group(1);
    final mac = Mac('${digestName}/HMAC');
    return () {
      return HMacConcatKDFDerivator(mac);
    };
  });

  HMacConcatKDFDerivator(Mac mac) : super(_MacKDFunction(mac));

  @override
  void init(covariant HkdfParameters params) {
    super.init(params);
    if (params.salt == null) {
      throw ArgumentError('HMac salt missing in parameters');
    }
    var mac = _h as _MacKDFunction;
    mac.init(params.salt!);
  }
}
