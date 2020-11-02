A library to validate Firebase Auth JWTs.
This can be used to ensure that a caller of your endpoint is a authenticated user from your Firebase project

**Example Request from the Client:**
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
**Authenticating the JWT on the Server**
```dart
final tokenValidator = FirebaseAuthenticationTokenValidator(firebaseProjectId: projectId);

Response handleRequest(Request request) {
    final jwt = request.headers['authorization'];
    final claims = await tokenValidator.validateJwt(jwt);
    print(claims['user_id']); // Uid of user sending the request.
}

```