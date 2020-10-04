import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:corsac_jwt/corsac_jwt.dart';
import 'package:meta/meta.dart';
import 'package:pointycastle/export.dart';

bool verifyJWTWithRSAPublicKey(
    {@required JWT jwt, @required RSAPublicKey publicKey}) {
  final headerDotPayload =
      '${jwt.encodedHeader}.${jwt.encodedPayload}'.codeUnits;
  return _rsa256Verify(
    Uint8List.fromList(headerDotPayload),
    _decodeBase64Url(jwt.signature),
    publicKey,
  );
}

Uint8List _decodeBase64Url(String encoded) {
  return base64Url
      .decode(encoded + List.filled((4 - encoded.length % 4) % 4, '=').join());
}

bool _rsa256Verify(Uint8List jwtHeaderDotPayload, Uint8List jwtSignature,
    RSAPublicKey publicKey) {
  final signer = Signer('SHA-256/RSA')
    ..init(false, PublicKeyParameter<RSAPublicKey>(publicKey));
  return signer.verifySignature(
      jwtHeaderDotPayload, RSASignature(jwtSignature));
}

// Not using x509 library here because of dependency problems (different
// PublicKey class that I can't use in the rest of the code )
RSAPublicKey parsePublicKeyFromX509CertificateString(String pemString) {
  final publicKeyDER = _getBytesFromPEMString(pemString);
  final asn1Parser = ASN1Parser(publicKeyDER);

  ///Certificate  ::=  SEQUENCE  {
  /// tbsCertificate       TBSCertificate,
  /// signatureAlgorithm   AlgorithmIdentifier,
  /// signatureValue       BIT STRING  }
  final certificateSeq = asn1Parser.nextObject() as ASN1Sequence;

  /// TBSCertificate  ::=  SEQUENCE  {
  ///  version         [0]  EXPLICIT Version DEFAULT v1,
  ///  serialNumber         CertificateSerialNumber,
  ///  signature            AlgorithmIdentifier,
  ///  issuer               Name,
  ///  validity             Validity,
  ///  subject              Name,
  ///  subjectPublicKeyInfo SubjectPublicKeyInfo,
  ///  issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
  ///                       -- If present, version MUST be v2 or v3
  ///  subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
  ///                       -- If present, version MUST be v2 or v3
  ///  extensions      [3]  EXPLICIT Extensions OPTIONAL
  ///                       -- If present, version MUST be v3
  ///  }
  final tbsCertificateSeq = certificateSeq.elements[0] as ASN1Sequence;

  /// SubjectPublicKeyInfo  ::=  SEQUENCE  {
  ///     algorithm            AlgorithmIdentifier,
  ///     subjectPublicKey     BIT STRING  }
  final subjectPublicKeyInfo = tbsCertificateSeq.elements[6] as ASN1Sequence;
  final subjectPublicKey = subjectPublicKeyInfo.elements[1] as ASN1BitString;
  final publicKeyAsn = ASN1Parser(subjectPublicKey.contentBytes());

  /// RSAPublicKey ::= SEQUENCE {
  /// modulus           INTEGER,  -- n
  /// publicExponent    INTEGER   -- e
  /// }
  final publicKeySeq = publicKeyAsn.nextObject() as ASN1Sequence;
  final modulus = publicKeySeq.elements[0] as ASN1Integer;
  final exponent = publicKeySeq.elements[1] as ASN1Integer;
  return RSAPublicKey(modulus.valueAsBigInteger, exponent.valueAsBigInteger);
}

Uint8List _getBytesFromPEMString(String pemString) {
  final lines = LineSplitter.split(pemString)
      .map((line) => line.trim())
      .where((line) => line.isNotEmpty)
      .toList();
  if (lines.length < 2 ||
      !lines.first.startsWith('-----BEGIN') ||
      !lines.last.startsWith('-----END')) {
    throw ArgumentError('The given string does not have the correct '
        'begin/end markers expected in a PEM file.');
  }
  final base64 = lines.sublist(1, lines.length - 1).join('');
  return Uint8List.fromList(base64Decode(base64));
}
