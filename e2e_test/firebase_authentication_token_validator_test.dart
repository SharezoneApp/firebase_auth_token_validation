import 'dart:io';

import 'package:firebase_authentication_token_validator/firebase_authentication_token_validator.dart';
import 'package:test/test.dart';
import 'package:http/http.dart' as http;

final firebaseFunctionsBaseUrl =
    Platform.environment['FIREBASE_FUNCTIONS_BASE_URL'];
final projectId = Platform.environment['FIREBASE_PROJECT_ID'];

const expiredToken =

    /// Header:
    /// {
    ///   "alg": "RS256",
    ///   "typ": "JWT"
    /// }
    /// Payload:
    /// {
    ///   "aud": "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
    ///   "iat": 1601842635,
    ///   "exp": 1601846235, // <-- Expired
    ///   "iss": "[redacted]@appspot.gserviceaccount.com",
    ///   "sub": "[redacted]@appspot.gserviceaccount.com",
    ///   "uid": "max-mustermann-uid"
    /// }
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL2lkZW50aXR5dG9vbGtpdC5nb29nbGVhcGlzLmNvbS9nb29nbGUuaWRlbnRpdHkuaWRlbnRpdHl0b29sa2l0LnYxLklkZW50aXR5VG9vbGtpdCIsImlhdCI6MTYwMTg0MjYzNSwiZXhwIjoxNjAxODQ2MjM1LCJpc3MiOiJmaXItYXV0aC10b2tlbi12YWxpZGF0b3JAYXBwc3BvdC5nc2VydmljZWFjY291bnQuY29tIiwic3ViIjoiZmlyLWF1dGgtdG9rZW4tdmFsaWRhdG9yQGFwcHNwb3QuZ3NlcnZpY2VhY2NvdW50LmNvbSIsInVpZCI6Im1heC1tdXN0ZXJtYW5uLXVpZCJ9.aI7-KTNgZSZL78jlxvGhemJyMtUPrSMYzraMY-p6UKBAhVZG_-D0WFO4zZZ8d755RonHshnaRALIl5ED5xqaRk_D55c6GLDOUnjgJIzCmfChKu7AYlj-scesO8921kMJNnIBFexdFg3g4dsdMcpoMxxwLeIzDHHu70ipVKP0jOTVrXgiH7qkY-WpDCqg-bIhvCxt-2ujvTkR6O94_wHz0P-IQ_ECto1mVJkQXH-CCz1HeuhuYWF5ylyzBf8sYN8ICJQ8_7-go2bzHFnO-lrVDVSZCUDUkcNxRVO9ccWsd6L2VEAYGeZrRZqxjXvRp10ijR6hiLNF13kN5zpWN8qIWw';

void main() {
  String validToken;
  FirebaseAuthenticationTokenValidator validator;

  setUpAll(() async {
    if (firebaseFunctionsBaseUrl == null || firebaseFunctionsBaseUrl.isEmpty) {
      throw ArgumentError('firebaseFunctionsBaseUrl cant be empty');
    }
    if (projectId == null || projectId.isEmpty) {
      throw ArgumentError('projectId cant be empty');
    }

    final res = await http.get('$firebaseFunctionsBaseUrl/getAuthToken');
    validToken = res.body;
    print('validToken: $validToken');

    validator = FirebaseAuthenticationTokenValidator(
        projectId, CachingPublicKeysLoader.retrying());
  });

  test('Is valid and returns claims', () async {
    final claims = await validator.validateJwt(validToken);

    expect(claims['uid'], 'max-mustermann-uid');
  });

  test('throws when given expired token', () async {
    // ignore: prefer_function_declarations_over_variables
    final exec = () => validator.validateJwt(validToken);

    // TODO: Shouldn't be an ArgumentError
    expect(exec, throwsArgumentError);
  });
}
