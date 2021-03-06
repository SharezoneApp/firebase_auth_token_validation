import 'dart:async';

import 'package:corsac_jwt/corsac_jwt.dart';
import 'package:logging/logging.dart';
import 'package:meta/meta.dart';
import 'package:pointycastle/export.dart';
import 'package:http/http.dart' as http;

import 'jwt_validation_utils.dart';
import 'caching_public_keys_loader.dart';

/// URL containing the public keys for the Google certs (whose private keys are used to sign Firebase
/// Auth ID tokens)
const googleKeyIdsUrl =
    'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';

/// Validator for JWTs generated by Firebase Authentication.
/// See: https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_a_third-party_jwt_library
class FirebaseAuthTokenValidator {
  FirebaseAuthTokenValidator({
    @required this.firebaseProjectId,
    http.Client inner,
  }) : _publicKeysLoader = CachingPublicKeysLoader.retrying(inner: inner) {
    if (!_isNotEmptyOrNull(firebaseProjectId)) {
      throw ArgumentError('projectId muste be non-empty');
    }
    _jwtConstraints = <Constraint>[
      Constraint('Algorithm is RS256', (jwt) => jwt.algorithm == 'RS256'),
      Constraint(
        'Contains non-empty "kid" header claim',
        (jwt) => _isNotEmptyOrNull(jwt.kidHeader),
      ),
      Constraint('Contains non-empty "sub" claim (equals the uid)',
          (jwt) => _isNotEmptyOrNull(jwt.subject)),
      Constraint('"sub" claim must equal the "user_id" claim',
          (jwt) => jwt.subject == jwt.userId),
      Constraint('Contains non-empty "auth_time" header claim',
          (jwt) => _isNotEmptyOrNull(jwt.kidHeader)),
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
        'Key ID "kid" header claim must be signed by one of the public keys listed at $googleKeyIdsUrl.',
        (jwt) async {
          final publicKeys = await _publicKeysLoader.getPublicKeys();
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

  List<Constraint> _jwtConstraints;
  final String firebaseProjectId;
  final CachingPublicKeysLoader _publicKeysLoader;
  Logger _logger;

  /// Validates (see below) the [encodedJwt] and returns the decoded JWT claims.
  ///
  /// Throws [ArgumentError] if the JWT can't be parsed.
  ///
  /// Throws [JWTValidationException] if the JWT does not satisfy one of the
  /// following constraints:
  /// * Key ID "kid" header claim must be signed by one of the public keys
  ///   listed at [googleKeyIdsUrl].
  /// * Issuer "iss" must be "https://securetoken.google.com/<projectId>",
  ///   where <projectId> is the same project ID used for aud.
  /// * Audience "aud" claim must be matching the [firebaseProjectId].
  /// * Subject "sub" claim be non-empty and must equal "user_id" claim.
  /// * Authentication time "auth_time" claim must be in the past.
  /// * Expiration time "exp" must be in the future.
  ///   The time is measured in seconds since the UNIX epoch.
  /// * Issued-at time "iat" must be in the past.
  ///   The time is measured in seconds since the UNIX epoch.
  /// * Signature-Algorithm is RS256
  Future<Map<String, dynamic>> validateJwt(String encodedJwt) async {
    final jwt = _parseJWT(encodedJwt);
    _logger.finer('Successfully parsed JWT');
    for (final constraint in _jwtConstraints) {
      final satisfied = await constraint.isSatisfiedBy(jwt);
      _logger.finer(
          'JWT-Token constraint ${constraint.description} satisfied: $satisfied');
      if (!satisfied) {
        throw JWTValidationException._(
          encodedJWT: encodedJwt,
          validationFailureDescription:
              'Failed to satisfy constraint "${constraint.description}"',
        );
      }
    }

    return jwt.claims;
  }

  /// Decodes the [encodedJwt] into a [JWT].
  /// Throws [ArgumentError] if the [encodedJwt] couldn't be parsed.
  ///
  /// The [JWTError] from [JWT.parse] is transformed into an [ArgumentError] as
  /// the users of this Library shouldn't need to depend on an [JWTError] from
  /// internal library.
  JWT _parseJWT(String encodedJwt) {
    try {
      return JWT.parse(encodedJwt);
    } catch (e) {
      throw ArgumentError("JWT couldn't be parsed: $e");
    }
  }
}

class JWTValidationException implements Exception {
  final String encodedJWT;
  final String _validationFailureDescription;

  JWTValidationException._({
    @required this.encodedJWT,
    @required String validationFailureDescription,
  }) : _validationFailureDescription = validationFailureDescription;

  @override
  String toString() {
    return 'The JWT failed validation: $_validationFailureDescription';
  }
}

class Constraint {
  Constraint(this.description, this.isSatisfiedBy);

  final FutureOr<bool> Function(JWT jwt) isSatisfiedBy;
  final String description;
}

bool _isNotEmptyOrNull(String s) {
  return s != null && s.isNotEmpty;
}

extension on JWT {
  String get kidHeader => headers['kid'];

  int get authTime => getClaim('auth_time') as int;

  String get userId => getClaim('user_id') as String;

  bool verifyWithRSAPublicKey(RSAPublicKey publicKey) {
    return verifyJWTWithRSAPublicKey(jwt: this, publicKey: publicKey);
  }
}

extension UnixSecondsToDateTime on int {
  DateTime toDateTime() => DateTime.fromMillisecondsSinceEpoch(this * 1000);
}
