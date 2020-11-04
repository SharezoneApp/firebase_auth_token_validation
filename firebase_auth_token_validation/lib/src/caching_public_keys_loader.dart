import 'dart:convert';
import 'dart:io';

import 'package:http_retry/http_retry.dart';
import 'package:logging/logging.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:http/http.dart' as http;
import 'package:meta/meta.dart';

import 'jwt_validation_utils.dart';
import 'firebase_auth_token_validator.dart';

class CachingPublicKeysLoader {
  CachingPublicKeysLoader({
    @required this.client,
    @required this.publicKeysUrl,
    DateTime Function() getCurrentTime,
  }) {
    _getCurrentTime = getCurrentTime ?? () => DateTime.now();
    _logger = Logger('$runtimeType');
  }

  factory CachingPublicKeysLoader.retrying({
    http.Client inner,
    String url,
  }) {
    return CachingPublicKeysLoader(
      client: RetryClient(
        inner ?? http.Client(),
        when: (res) =>
            res.statusCode == HttpStatus.internalServerError ||
            res.statusCode == HttpStatus.serviceUnavailable,
      ),
      publicKeysUrl: url ?? googleKeyIdsUrl,
    );
  }

  final http.Client client;
  DateTime Function() _getCurrentTime;
  Logger _logger;

  /// URL containing the public keys for the Google certs (whose private keys are used to sign Firebase
  /// Auth ID tokens)
  final String publicKeysUrl;
  var _cached = <String, RSAPublicKey>{};
  DateTime _cachedOn;
  Duration _validFor;
  bool get _stillValid => _getCurrentTime().isBefore(_validTill);
  DateTime get _validTill => _cachedOn.add(_validFor);

  /// Gibt eine Map zurück, welche als Schlüssel die JWT-"kid"s und als Werte
  /// die vom Zertifikat geparsten Public Keys hat.
  /// Die Werte werden beim Aufrufen von der URL nach "max-age" im
  /// "cache-control" header gecached (keine Library, die das automatisch macht
  /// gefunden). Falls kein "cache-control" oder "max-age" vorhanden ist, dann
  /// wird jedes mal die URL kontaktiert.
  Future<Map<String, RSAPublicKey>> getPublicKeys() async {
    if (_cached.isNotEmpty && _stillValid) {
      return _cached;
    }

    final res = await client.get(publicKeysUrl);
    if (res.statusCode != 200) {
      // retry?
      throw Exception(
          'Could not parse public keys, got status code ${res.statusCode}.');
    }

    if (res.body == null || res.body.isEmpty) {
      throw Exception('Could not parse public keys, got empty body.');
    }

    final parsedBody = json.decode(res.body) as Map<String, dynamic>;
    final casted = parsedBody.cast<String, String>();
    final keys = casted.map(
      (kid, pemString) => MapEntry<String, RSAPublicKey>(
        kid,
        parsePublicKeyFromX509CertificateString(pemString),
      ),
    );

    try {
      final cacheControlHeader = res.headers[HttpHeaders.cacheControlHeader];
      final maxAgeDuration = _parseMaxAge(cacheControlHeader);
      _cached = keys;
      _cachedOn = _getCurrentTime();
      _validFor = maxAgeDuration;
    } catch (e, s) {
      _logger.warning('Could not cache public keys', e, s);
    }

    return keys;
  }

  Duration _parseMaxAge(String cacheControlHeader) {
    final cacheControlHeaderParts = cacheControlHeader.split(' ');
    String maxAgePart =
        cacheControlHeaderParts.firstWhere((part) => part.contains('max-age='));
    if (maxAgePart.contains(',')) {
      maxAgePart = maxAgePart.replaceAll(',', '');
    }
    final maxAgeInSeconds =
        maxAgePart.substring(maxAgePart.lastIndexOf('=') + 1);
    final maxAgeDuration = Duration(seconds: int.parse(maxAgeInSeconds));
    return maxAgeDuration;
  }
}
