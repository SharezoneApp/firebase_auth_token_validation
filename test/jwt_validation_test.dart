import 'package:firebase_authentication_token_validator/src/jwt_validation_utils.dart';
import 'package:corsac_jwt/corsac_jwt.dart';
import 'package:test/test.dart';

const firebaseJwt =
    'eyJhbGciOiJSUzI1NiIsImtpZCI6ImRjMGMzNWZlYjBjODIzYjQyNzdkZDBhYjIwNDQzMDY5ZGYzMGZkZWEiLCJ0eXAiOiJKV1QifQ.eyJuYW1lIjoiSm9uYXMgU2FuZGVyIiwiaXNzIjoiaHR0cHM6Ly9zZWN1cmV0b2tlbi5nb29nbGUuY29tL3NoYXJlem9uZS1kZWJ1ZyIsImF1ZCI6InNoYXJlem9uZS1kZWJ1ZyIsImF1dGhfdGltZSI6MTU4NjEyNDU1NCwidXNlcl9pZCI6IkpaNGpNa0FnZXRTd01hZkZERVdCR3I0SVl1QjIiLCJzdWIiOiJKWjRqTWtBZ2V0U3dNYWZGREVXQkdyNElZdUIyIiwiaWF0IjoxNTg2Mjg4NTQzLCJleHAiOjE1ODYyOTIxNDMsImVtYWlsIjoiam9uYXNzYW5kZXIxQGdvb2dsZW1haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJmaXJlYmFzZSI6eyJpZGVudGl0aWVzIjp7ImVtYWlsIjpbImpvbmFzc2FuZGVyMUBnb29nbGVtYWlsLmNvbSJdfSwic2lnbl9pbl9wcm92aWRlciI6InBhc3N3b3JkIn19.uF7uRcarae8eUIou4oME-a3w6wLB04TDg0pbWwFUdDyl6ArNAX_6pcNBr7AN52auelmGiiZ3dGdMKZLWuHQaJyKDykwwRXL20fqXV-6eT4szuv8y3gaP_nw5FzILAE9sPnw3wLpLqxoo0O7hCBTHJf4rYXqkCMgTm2eE7X-JjMDEIedTkLV8ydenZYbEt0ServrlwCXZ-Jgn4seT9mpsbaO1f5Yx58g2j5VC8EwQWbDVd92q6YXlFW0hK66sfxbAnWZ3yIw-I_yNuiOnuH1jHSX_kLWBMvI9UoE5Dp1qbuQIrBCXBcPO69i1-XkyOxCDi2hCr5Bx5Q3kFDol4IWDCg';

const certificate = '''
-----BEGIN CERTIFICATE-----
MIIDHDCCAgSgAwIBAgIIOtjkMPRJu4swDQYJKoZIhvcNAQEFBQAwMTEvMC0GA1UE
AxMmc2VjdXJldG9rZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wHhcNMjAw
NDAzMDkxOTU2WhcNMjAwNDE5MjEzNDU2WjAxMS8wLQYDVQQDEyZzZWN1cmV0b2tl
bi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAN7dDBQlVbhsFJPjlmMzuYQkEs6YLQXQ8aZg3IZfgngQBvTp
H+avsQ5tn19Q1YDiq7Bg5euSJmFzeJBt/UeyVmCGYjLyzQ0rzfJt9JGLXSQat/C9
D7T5S32zKCHno63JFPt22+waaLsbIEwsXrNG8iiej/fNFJ6Q9YFsViEwaGZBPLcy
L3nBE0yrT2lCkE0J3Dffrc9apVlahgUx4oTue6XUxOrzi0J4D1LuGRFps4SzCXYy
Ifn+ywZC/8xuoVsXgOPuFLxhdtqpQDy611OBlD6kotWg5KbWXaNsaRfjRcuirIc3
S51fcK6/DVZXwDq/H/FqN0mO5/EUbFVeA1i74MMCAwEAAaM4MDYwDAYDVR0TAQH/
BAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJ
KoZIhvcNAQEFBQADggEBAJP4jgiyWJCeYnCK5D6siSB/RIbbCDsvRcnzOjyXohws
vlFmpl1PVMJuexmexIk+jNhBj4bpu7oGLPQ46q60fmSiAhOrNfo446LH8jv/WD4j
/byeoxyCeSb9IdK+Bkp75bP0u30jugaxq+mM3/Eiqjcj4wrgZpjbL6hFJQMEWc0J
v3q7UoLgpfi8gqE65z5AsYMx71BVAuuI6uA06U9zbQIOWetD+aGuxU/VmqZTuEWm
EqijjMI9BbX+ZjyGAHZFV+twugZve0IBKG7GUU+oZ1Uiskdk6ObcqBa494UsS+tu
crXo4Aor8b6DwJyy0vhHzy4tsrF5DGifJHa2OXhdMcM=
-----END CERTIFICATE-----''';

const certificatePublicKey = '''
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA3t0MFCVVuGwUk+OWYzO5hCQSzpgtBdDxpmDchl+CeBAG9Okf5q+x
Dm2fX1DVgOKrsGDl65ImYXN4kG39R7JWYIZiMvLNDSvN8m30kYtdJBq38L0PtPlL
fbMoIeejrckU+3bb7BpouxsgTCxes0byKJ6P980UnpD1gWxWITBoZkE8tzIvecET
TKtPaUKQTQncN9+tz1qlWVqGBTHihO57pdTE6vOLQngPUu4ZEWmzhLMJdjIh+f7L
BkL/zG6hWxeA4+4UvGF22qlAPLrXU4GUPqSi1aDkptZdo2xpF+NFy6KshzdLnV9w
rr8NVlfAOr8f8Wo3SY7n8RRsVV4DWLvgwwIDAQAB
-----END RSA PUBLIC KEY-----''';

void main() {
  test('verifyRS256JWTSignature', () {
    expect(
        verifyJWTWithRSAPublicKey(
          jwt: JWT.parse(firebaseJwt),
          publicKey: parsePublicKeyFromX509CertificateString(certificate),
        ),
        true);
  });
}
