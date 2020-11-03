# firebase_auth_token_validation
A library to validate Firebase Auth JWTs.
This can be used to ensure that a caller of your endpoint is a authenticated user from your Firebase project.

**Authenticating the JWT on the Server**
```dart
final tokenValidator = FirebaseAuthenticationTokenValidator(firebaseProjectId: projectId);

Response handleRequest(Request request) {
    final jwt = request.headers['authorization'];
    final claims = await tokenValidator.validateJwt(jwt);
    print(claims['user_id']); // Uid of user sending the request.
}
```
If the token is valid the valid [JWT claims](https://auth0.com/docs/tokens/json-web-tokens/json-web-token-claims) are returned.  
Firebase adds a `user_id` claim to the JWT so that the uid of the client can be read.  
If the token is invalid an Exception is thrown.

**Example Request from the Client:**  
The token can be fetched from the Firebase-`User` from the [firebase_auth](https://pub.dev/packages/firebase_auth) package.
```dart
// On the client
const jwt = await firebaseAuthUser.getIdToken();
await httpClient.post(
  'your-endpoint.com/api/cake',
  headers: {
    // The important bit:
    // -- Adding the token to the request --
    'authorization': 'Bearer $jwt',
    // ---
    "Content-Type": "application/json"
  },
  body: json.encode({'cake': {'deliciousness': 'very-delicious'}}),
);
```
