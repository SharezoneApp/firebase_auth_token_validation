import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:corsac_jwt/corsac_jwt.dart';
import 'package:http/http.dart' as http;
import 'package:http_retry/http_retry.dart';
import 'package:logging/logging.dart';
import 'package:meta/meta.dart';
import 'package:pointycastle/export.dart';

import 'jwt_validation_utils.dart';

/// URL containing the public keys for the Google certs (whose private keys are used to sign Firebase
/// Auth ID tokens)
const _googleKeyIdsUrl =
    'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';

bool isNotEmptyOrNull(String s) {
  return s != null && s.isNotEmpty;
}

class Constraint {
  Constraint(this.description, this.isSatisfiedBy);

  final FutureOr<bool> Function(JWT jwt) isSatisfiedBy;
  final String description;
}

/// See https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_a_third-party_jwt_library
class FirebaseAuthenticationTokenValidator {
  FirebaseAuthenticationTokenValidator(
      {@required this.firebaseProjectId, this.publicKeysLoader}) {
    if (!isNotEmptyOrNull(firebaseProjectId)) {
      throw ArgumentError('projectId muste be non-empty');
    }
    jwtConstraints = <Constraint>[
      Constraint('Algorithm is RS256', (jwt) => jwt.algorithm == 'RS256'),
      Constraint(
        'Contains non-empty "kid" header claim',
        (jwt) => isNotEmptyOrNull(jwt.kidHeader),
      ),
      Constraint('Contains non-empty "sub" header claim (equals the uid)',
          (jwt) => isNotEmptyOrNull(jwt.subject)),
      Constraint('Contains non-empty "auth_time" header claim',
          (jwt) => isNotEmptyOrNull(jwt.kidHeader)),
      Constraint(
          'Expiration time "exp" must be in the future. The time is measured in seconds since the UNIX epoch.',
          (jwt) => jwt.expiresAt.toDateTime().isAfter(DateTime.now())),
      Constraint(
          'Issued-at time "iat" must be in the past. The time is measured in seconds since the UNIX epoch.',
          (jwt) => jwt.issuedAt.toDateTime().isBefore(DateTime.now())),
      Constraint('Audience "aud" must be matching the Firebase project ID.',
          (jwt) => jwt.audience == firebaseProjectId),
      Constraint(
          'Issuer "iss" must be "https://securetoken.google.com/<projectId>", where <projectId> is the same project ID used for aud.',
          (jwt) =>
              jwt.issuer ==
              'https://securetoken.google.com/$firebaseProjectId'),
      Constraint('Authentication time "auth_time" must be in the past.',
          (jwt) => jwt.authTime.toDateTime().isBefore(DateTime.now())),
      Constraint(
        'Key ID "kid" header claim must be signed by one of the public keys listed at $_googleKeyIdsUrl.',
        (jwt) async {
          final publicKeys = await publicKeysLoader.getPublicKeys();
          final matchingKid =
              publicKeys.keys.where((key) => key == jwt.kidHeader).first;
          if (matchingKid.isEmpty) {
            _logger.fine(
                'No matching kid ($matchingKid) found for ${jwt.kidHeader}');
            return false;
          }
          final publicKey = publicKeys[matchingKid];
          return jwt.verifyWithRSAPublicKey(publicKey);
        },
      ),
    ];
    _logger = Logger('$runtimeType');
  }

  List<Constraint> jwtConstraints;
  final String firebaseProjectId;
  final CachingPublicKeysLoader publicKeysLoader;
  Logger _logger;

  /// Returns claims
  Future<Map<String, dynamic>> validateJwt(String encodedJwt) async {
    final jwt = JWT.parse(encodedJwt);
    _logger.finer('Successfully parsed JWT');
    for (final constraint in jwtConstraints) {
      final satisfied = await constraint.isSatisfiedBy(jwt);
      _logger.finer(
          'JWT-Token constraint ${constraint.description} satisfied: $satisfied');
      if (!satisfied) {
        throw ArgumentError(
            'JWT does not satisfy constraint: ${constraint.description}');
      }
    }

    return jwt.claims;
  }
}

class CachingPublicKeysLoader {
  CachingPublicKeysLoader({
    @required this.client,
    @required this.googleKeyIdsUrl,
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
      googleKeyIdsUrl: url ?? _googleKeyIdsUrl,
    );
  }

  final http.Client client;
  DateTime Function() _getCurrentTime;
  Logger _logger;

  /// URL containing the public keys for the Google certs (whose private keys are used to sign Firebase
  /// Auth ID tokens)
  final String googleKeyIdsUrl;
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

    final res = await client.get(googleKeyIdsUrl);
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

extension on JWT {
  String get kidHeader => headers['kid'];

  int get authTime => getClaim('auth_time') as int;

  bool verifyWithRSAPublicKey(RSAPublicKey publicKey) {
    return verifyJWTWithRSAPublicKey(jwt: this, publicKey: publicKey);
  }
}

extension UnixSecondsToDateTime on int {
  DateTime toDateTime() => DateTime.fromMillisecondsSinceEpoch(this * 1000);
}
