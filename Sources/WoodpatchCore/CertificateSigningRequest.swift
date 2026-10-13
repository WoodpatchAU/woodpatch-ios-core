// CertificateSigningRequest.swift
// ────────────────────────────────────────────────────────────────────
// PKCS#10 CertificationRequest for an EC P-256 key, signed
// ECDSA-with-SHA256. This is what both apps send at pairing so the server
// can mint a client certificate (softphone: SIP mTLS via RELAY; POS: the
// POS host's mTLS via step-ca, BOS #2509). The server never sees the
// private key.
//
// Provenance: the softphone's SIP/Crypto/CertificateSigningRequest.swift
// (byte-identical layout), generalised for BOS #2562 from its software
// `SIPKeyPair` to ANY `SecKey`, so a Secure Enclave key (non-exportable;
// signing happens inside the enclave) works the same as a software key.
// The POS spike proved an enclave-signed CSR passes `openssl req -verify`
// (BOS #2509, 2026-10-13).
//
// Layout (RFC 2986):
//   CertificationRequest ::= SEQUENCE {
//     certificationRequestInfo SEQUENCE { version INTEGER 0, subject Name,
//                                         subjectPKInfo, attributes [0] {} },
//     signatureAlgorithm ecdsa-with-SHA256,
//     signature BIT STRING }

import Foundation
import Security

public enum CertificateSigningRequest {
    public struct Built: Sendable {
        /// The signed-over bytes, exposed for tests that verify the signature.
        public let certificationRequestInfoDER: [UInt8]
        public let signatureDER: Data
        public let pem: String
    }

    /// X.520 upper bound for a commonName; `openssl req` refuses longer.
    public static let maxCommonNameLength = 64

    public enum BuildError: Error, Sendable, Equatable {
        case notP256PrivateKey
        case commonNameTooLong(Int)
        case publicKeyUnavailable(String)
        case signFailed(String)
    }

    /// Build and sign a CSR with `privateKey` (software or Secure Enclave).
    /// `commonName` nil gives an empty subject (`30 00`), which is the
    /// softphone's shape: the server assigns identity, not the CSR.
    public static func build(privateKey: SecKey, commonName: String? = nil) throws -> Built {
        if let commonName, commonName.count > maxCommonNameLength {
            throw BuildError.commonNameTooLong(commonName.count)
        }
        let subject: [UInt8]
        if let commonName {
            let rdn = DER.set(DER.sequence(DER.OID.commonName + DER.utf8String(commonName)))
            subject = DER.sequence(rdn)
        } else {
            subject = DER.sequence([])
        }

        let info = DER.sequence(
            DER.integer(UInt8(0)) // version 0
                + subject
                + subjectPublicKeyInfo(of: try p256PublicPoint(privateKey))
                + DER.encode(.context0, []) // attributes: empty
        )

        let signature = try sign(Data(info), with: privateKey)
        let request = DER.sequence(
            info
                + DER.sequence(DER.OID.ecdsaWithSHA256)
                + DER.bitString([UInt8](signature))
        )
        return Built(
            certificationRequestInfoDER: info,
            signatureDER: signature,
            pem: DER.pem(request, label: "CERTIFICATE REQUEST")
        )
    }

    public static func pem(privateKey: SecKey, commonName: String? = nil) throws -> String {
        try build(privateKey: privateKey, commonName: commonName).pem
    }

    /// SubjectPublicKeyInfo for an uncompressed P-256 point (04 || X || Y).
    public static func subjectPublicKeyInfo(of point: [UInt8]) -> [UInt8] {
        DER.sequence(DER.sequence(DER.OID.ecPublicKey + DER.OID.prime256v1) + DER.bitString(point))
    }

    /// The public half's X9.63 point. Exportable even for Secure Enclave keys:
    /// only the PRIVATE half is locked in the enclave.
    static func p256PublicPoint(_ privateKey: SecKey) throws -> [UInt8] {
        let attributes = SecKeyCopyAttributes(privateKey) as? [String: Any] ?? [:]
        let type = attributes[kSecAttrKeyType as String] as? String
        let bits = attributes[kSecAttrKeySizeInBits as String] as? Int
        guard type == (kSecAttrKeyTypeECSECPrimeRandom as String), bits == 256 else {
            throw BuildError.notP256PrivateKey
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw BuildError.publicKeyUnavailable("no public key")
        }
        var error: Unmanaged<CFError>?
        guard let point = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw BuildError.publicKeyUnavailable(Self.describe(error))
        }
        // Uncompressed P-256 point: 0x04 || X(32) || Y(32), as the old SIPKeyPair checked.
        guard point.count == 65, point.first == 0x04 else {
            throw BuildError.publicKeyUnavailable("unexpected public key encoding (\(point.count) bytes)")
        }
        return [UInt8](point)
    }

    static func sign(_ data: Data, with privateKey: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey, .ecdsaSignatureMessageX962SHA256, data as CFData, &error
        ) as Data? else {
            throw BuildError.signFailed(Self.describe(error))
        }
        return signature
    }

    private static func describe(_ error: Unmanaged<CFError>?) -> String {
        (error?.takeRetainedValue()).map { String(describing: $0) } ?? "unknown"
    }
}
