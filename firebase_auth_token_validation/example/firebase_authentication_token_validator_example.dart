import 'package:firebase_auth_token_validation/firebase_auth_token_validation.dart';

// ignore_for_file:unused_local_variable

Future<void> main() async {
  final tokenValidator =
      FirebaseAuthTokenValidator(firebaseProjectId: 'my-firebase-project');

  // From e.g. a server request
  final jwt = "your.jwt.here";
  // Throws if JWT is invalid, returns JWT claims if sucessful.
  final claims = await tokenValidator.validateJwt(jwt);
  // Firebase adds the "user_id" claim which is the uid of the FirebaseAuth
  // user.
  final uid = claims['user_id'];
}
