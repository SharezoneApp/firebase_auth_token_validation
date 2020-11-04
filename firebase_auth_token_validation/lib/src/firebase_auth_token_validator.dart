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

/// See https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_a_third-party_jwt_library
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
      Constraint('Contains non-empty "sub" header claim (equals the uid)',
          (jwt) => _isNotEmptyOrNull(jwt.subject)),
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

  /// Returns claims
  Future<Map<String, dynamic>> validateJwt(String encodedJwt) async {
    final jwt = JWT.parse(encodedJwt);
    _logger.finer('Successfully parsed JWT');
    for (final constraint in _jwtConstraints) {
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

  bool verifyWithRSAPublicKey(RSAPublicKey publicKey) {
    return verifyJWTWithRSAPublicKey(jwt: this, publicKey: publicKey);
  }
}

extension UnixSecondsToDateTime on int {
  DateTime toDateTime() => DateTime.fromMillisecondsSinceEpoch(this * 1000);
}
