import 'dart:convert';

import 'package:firebase_auth_token_validation/firebase_auth_token_validation.dart';
import 'package:firebase_auth_token_validation/src/jwt_validation_utils.dart'
    as validation;
import 'package:http/http.dart' as http;
import 'package:http/testing.dart' as http;
import 'package:test/test.dart';

void main() {
  group('PublicKeysLoader publicKeysLoader', () {
    CachingPublicKeysLoader publicKeysLoader;
    http.MockClient httpClient;
    http.MockClientHandler handler;
    DateTime Function() getCurrentTime;

    setUp(() {
      httpClient = http.MockClient((r) => handler(r));
      publicKeysLoader = CachingPublicKeysLoader(
        client: httpClient,
        googleKeyIdsUrl: 'https://www.some-url.com',
        getCurrentTime: () => getCurrentTime(),
      );
      getCurrentTime = () => DateTime.now();
    });

    test('Throws ParsingException if Response cant be parsed', () async {
      Future<void> expectThrowsParsingException() async {
        try {
          await publicKeysLoader.getPublicKeys();
          fail('should throw');
        } catch (e) {
          expect(e, isA<Exception>());
        }
      }

      handler = (req) async => http.Response('', 200);
      await expectThrowsParsingException();
    });

    test('parses valid response correctly', () async {
      handler = (req) async => _response;

      final keys = await publicKeysLoader.getPublicKeys();
      expect(keys, _kidPublicKeys);
    });

    test(
        'saves response according to cache-control max-age header and does not ask api again if its saved',
        () async {
      DateTime now = DateTime(2020, 02, 02, 19, 30);
      getCurrentTime = () => now;
      int called = 0;
      handler = (req) async {
        called++;
        return _response;
      };

      await publicKeysLoader.getPublicKeys();
      await publicKeysLoader.getPublicKeys();
      var keys = await publicKeysLoader.getPublicKeys();
      expect(keys, _kidPublicKeys);
      expect(called, 1);

      /// Invalidates cache
      now = now.add(const Duration(hours: 7));

      keys = await publicKeysLoader.getPublicKeys();
      expect(keys, _kidPublicKeys);
      expect(called, 2);
    });

    test('throws if exceeding cached duration and bad response', () async {
      DateTime now = DateTime(2020, 02, 02, 19, 30);
      getCurrentTime = () => now;
      handler = (req) async => _response;

      await publicKeysLoader.getPublicKeys();
      now = now.add(const Duration(hours: 7));
      handler = (req) async => http.Response('', 500);

      try {
        await publicKeysLoader.getPublicKeys();
        fail('should throw');
      } catch (e) {
        expect(e, isNotNull);
      }
    });

    test('does not cache if no cache-control header is given', () async {
      final noCacheControl = Map<String, String>.from(responseHeaders);
      noCacheControl.remove('cache-control');
      int called = 0;
      handler = (req) async {
        called++;
        return http.Response(_responseBody, 200, headers: noCacheControl);
      };

      var keys = await publicKeysLoader.getPublicKeys();
      expect(keys, _kidPublicKeys);
      keys = await publicKeysLoader.getPublicKeys();
      expect(called, 2);
    });
    test('does not cache if no cache-control header with max-age is given',
        () async {
      final noCacheControlMaxAge = Map<String, String>.from(responseHeaders);
      noCacheControlMaxAge['cache-control'] =
          noCacheControlMaxAge['cache-control']
              .replaceAll('max-age=23744, ', '');
      int called = 0;
      handler = (req) async {
        called++;
        return http.Response(_responseBody, 200, headers: noCacheControlMaxAge);
      };

      var keys = await publicKeysLoader.getPublicKeys();
      expect(keys, _kidPublicKeys);
      keys = await publicKeysLoader.getPublicKeys();
      expect(called, 2);
    });
  });
}

const responseHeaders = {
  'content-type': 'application/json; charset=UTF-8',
  "server": " ESF",
  "x-xss-protection": " 0",
  "x-frame-options": " SAMEORIGIN",
  "x-content-type-options": " nosniff",
  "cache-control": "public, max-age=23744, must-revalidate, no-transform",
  "age": " 9",
  "accept-ranges": " none",
};

final _response = http.Response(_responseBody, 200, headers: responseHeaders);
final _responseBody = json.encode(responseBodyMap);
const responseBodyMap = {
  "83a738e21b91ce24f43480fe6fee4258c84db4c5":
      "-----BEGIN CERTIFICATE-----\nMIIDHDCCAgSgAwIBAgIIa4pQdOOBfQcwDQYJKoZIhvcNAQEFBQAwMTEvMC0GA1UE\nAxMmc2VjdXJldG9rZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wHhcNMjAw\nMzI2MDkxOTU2WhcNMjAwNDExMjEzNDU2WjAxMS8wLQYDVQQDEyZzZWN1cmV0b2tl\nbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBAJyW1FTF+Akff6amUztexL4TBznAVBbngzqfGVd+cwQix9rG\nw33wE1ir0V0MQpnI+p/O6SZNSJ9Ttt7xmWwMsDGYJHWnfkb5+9h5gXbvIbyXt3pf\nnrRKY2UKaRQosBMZgtDvsTqCaYUnj30PsrGeKsCA9J+MhDLCawHTdXyUGoXlzMbR\nGaolPn5ttBX8k/oJGeWleHFXsQEm9nTdSwkyX0kshKgwVPerqrY0bs5b8CP1+JNt\nUmtwlxoL8GkpqbBWR/cqGiwbZCRwKCj4asBKfJmu3UQqCB275RGTSzeFzQNBJ48u\nnltk3lZaWGIsr8yPpoJb1vHb0OEU3WHFgfiYkZMCAwEAAaM4MDYwDAYDVR0TAQH/\nBAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJ\nKoZIhvcNAQEFBQADggEBAHS/M0CV8p27kdKZtPS5OIytT2eLkSCjfq+hlmf8sclM\nLt6m0l5tBSF8ckIoR2pdlBwRTYCcIYEIZgT6plq9Bh/oJdJ4+xQmSjVKw5N82zIP\ne12dPs08XAY13KN+Wve7hJxSSRR2IyjVhhN1jlwvkT2X+meUa/oeB0KVAssPP11/\nmgZYyWW3agOYz5xE0/r9unVyRlQtlT49zsFQgibxaYqEDn3v9bIg43wCVN7A6YX3\ngyPkfUaKlrjbEXfep7RmyHFGFYSMxLUdQCpeMr4+NVty+kIX0b3BfXr8aTJf7EYi\nlF1ewP5CBl93a/O3zYPV1dxpsWLmntW/SG4Jp+WondY=\n-----END CERTIFICATE-----\n",
  "dc0c35feb0c823b4277dd0ab20443069df30fdea":
      "-----BEGIN CERTIFICATE-----\nMIIDHDCCAgSgAwIBAgIIOtjkMPRJu4swDQYJKoZIhvcNAQEFBQAwMTEvMC0GA1UE\nAxMmc2VjdXJldG9rZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wHhcNMjAw\nNDAzMDkxOTU2WhcNMjAwNDE5MjEzNDU2WjAxMS8wLQYDVQQDEyZzZWN1cmV0b2tl\nbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBAN7dDBQlVbhsFJPjlmMzuYQkEs6YLQXQ8aZg3IZfgngQBvTp\nH+avsQ5tn19Q1YDiq7Bg5euSJmFzeJBt/UeyVmCGYjLyzQ0rzfJt9JGLXSQat/C9\nD7T5S32zKCHno63JFPt22+waaLsbIEwsXrNG8iiej/fNFJ6Q9YFsViEwaGZBPLcy\nL3nBE0yrT2lCkE0J3Dffrc9apVlahgUx4oTue6XUxOrzi0J4D1LuGRFps4SzCXYy\nIfn+ywZC/8xuoVsXgOPuFLxhdtqpQDy611OBlD6kotWg5KbWXaNsaRfjRcuirIc3\nS51fcK6/DVZXwDq/H/FqN0mO5/EUbFVeA1i74MMCAwEAAaM4MDYwDAYDVR0TAQH/\nBAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJ\nKoZIhvcNAQEFBQADggEBAJP4jgiyWJCeYnCK5D6siSB/RIbbCDsvRcnzOjyXohws\nvlFmpl1PVMJuexmexIk+jNhBj4bpu7oGLPQ46q60fmSiAhOrNfo446LH8jv/WD4j\n/byeoxyCeSb9IdK+Bkp75bP0u30jugaxq+mM3/Eiqjcj4wrgZpjbL6hFJQMEWc0J\nv3q7UoLgpfi8gqE65z5AsYMx71BVAuuI6uA06U9zbQIOWetD+aGuxU/VmqZTuEWm\nEqijjMI9BbX+ZjyGAHZFV+twugZve0IBKG7GUU+oZ1Uiskdk6ObcqBa494UsS+tu\ncrXo4Aor8b6DwJyy0vhHzy4tsrF5DGifJHa2OXhdMcM=\n-----END CERTIFICATE-----\n"
};

// ignore: unused_element
const _kidKeysStrings = {
  "83a738e21b91ce24f43480fe6fee4258c84db4c5": """
  -----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAnJbUVMX4CR9/pqZTO17EvhMHOcBUFueDOp8ZV35zBCLH2sbDffAT
WKvRXQxCmcj6n87pJk1In1O23vGZbAywMZgkdad+Rvn72HmBdu8hvJe3el+etEpj
ZQppFCiwExmC0O+xOoJphSePfQ+ysZ4qwID0n4yEMsJrAdN1fJQaheXMxtEZqiU+
fm20FfyT+gkZ5aV4cVexASb2dN1LCTJfSSyEqDBU96uqtjRuzlvwI/X4k21Sa3CX
GgvwaSmpsFZH9yoaLBtkJHAoKPhqwEp8ma7dRCoIHbvlEZNLN4XNA0Enjy6eW2Te
VlpYYiyvzI+mglvW8dvQ4RTdYcWB+JiRkwIDAQAB
-----END RSA PUBLIC KEY-----""",
  "dc0c35feb0c823b4277dd0ab20443069df30fdea": """
  -----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA3t0MFCVVuGwUk+OWYzO5hCQSzpgtBdDxpmDchl+CeBAG9Okf5q+x
Dm2fX1DVgOKrsGDl65ImYXN4kG39R7JWYIZiMvLNDSvN8m30kYtdJBq38L0PtPlL
fbMoIeejrckU+3bb7BpouxsgTCxes0byKJ6P980UnpD1gWxWITBoZkE8tzIvecET
TKtPaUKQTQncN9+tz1qlWVqGBTHihO57pdTE6vOLQngPUu4ZEWmzhLMJdjIh+f7L
BkL/zG6hWxeA4+4UvGF22qlAPLrXU4GUPqSi1aDkptZdo2xpF+NFy6KshzdLnV9w
rr8NVlfAOr8f8Wo3SY7n8RRsVV4DWLvgwwIDAQAB
-----END RSA PUBLIC KEY-----""",
};

final _kidPublicKeys = {
  "83a738e21b91ce24f43480fe6fee4258c84db4c5":
      validation.parsePublicKeyFromX509CertificateString(
          responseBodyMap['83a738e21b91ce24f43480fe6fee4258c84db4c5']),
  "dc0c35feb0c823b4277dd0ab20443069df30fdea":
      validation.parsePublicKeyFromX509CertificateString(
          responseBodyMap['dc0c35feb0c823b4277dd0ab20443069df30fdea']),
};
