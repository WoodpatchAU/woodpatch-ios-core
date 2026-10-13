// CSRTests.swift: PKCS#10 layout and signature, for a software key here. The
// Secure Enclave path is exercised by the POS spike (BOS #2509); on Apple
// Silicon the Simulator also creates enclave keys, so it's tested too when
// available. Interop with openssl: the test writes the PEM where
// scripts/mac-test.sh runs `openssl req -verify` on it.

import Foundation
import Security
import Testing
@testable import WoodpatchCore

struct CSRTests {
    /// Real Secure Enclave keys exist on devices and on Apple-Silicon Simulators.
    static let enclaveAvailable: Bool = {
        var error: Unmanaged<CFError>?
        return SecKeyCreateRandomKey([
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        ] as CFDictionary, &error) != nil
    }()

    /// Where the runner (scripts/mac-test.sh) picks CSRs up for `openssl req -verify`.
    static func writeForInterop(_ pem: String, name: String) throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("woodpatchcore-interop")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try pem.write(to: dir.appendingPathComponent(name), atomically: true, encoding: .utf8)
    }

    private func p256Key(enclave: Bool = false) throws -> SecKey {
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
        ]
        if enclave {
            attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue()
        }
        return key
    }

    @Test func signatureVerifiesOverTheInfo() throws {
        let key = try p256Key()
        let built = try CertificateSigningRequest.build(privateKey: key, commonName: "device-1")
        let ok = SecKeyVerifySignature(
            SecKeyCopyPublicKey(key)!, .ecdsaSignatureMessageX962SHA256,
            Data(built.certificationRequestInfoDER) as CFData, built.signatureDER as CFData, nil
        )
        #expect(ok)
        #expect(built.pem.hasPrefix("-----BEGIN CERTIFICATE REQUEST-----\n"))
        #expect(built.pem.hasSuffix("-----END CERTIFICATE REQUEST-----\n"))
        // Interop on EVERY run (not only when an enclave exists): the runner
        // openssl-verifies this one and fails if it's missing.
        try Self.writeForInterop(built.pem, name: "software-csr.pem")
    }

    @Test func commonNameLengthIsCapped() throws {
        let key = try p256Key()
        _ = try CertificateSigningRequest.build(privateKey: key, commonName: String(repeating: "a", count: 64))
        #expect(throws: CertificateSigningRequest.BuildError.commonNameTooLong(65)) {
            try CertificateSigningRequest.build(privateKey: key, commonName: String(repeating: "a", count: 65))
        }
        // 33 Characters but 66 code points (e + combining acute): openssl refuses, so must we.
        let decomposed = String(repeating: "e\u{0301}", count: 33)
        #expect(decomposed.count == 33)
        #expect(throws: CertificateSigningRequest.BuildError.commonNameTooLong(66)) {
            try CertificateSigningRequest.build(privateKey: key, commonName: decomposed)
        }
        // Precomposed é is one code point each: 33 is fine.
        _ = try CertificateSigningRequest.build(privateKey: key, commonName: String(repeating: "\u{00E9}", count: 33))
    }

    @Test func emptySubjectIsTheSoftphoneShape() throws {
        let info = try CertificateSigningRequest.build(privateKey: try p256Key()).certificationRequestInfoDER
        // SEQUENCE { INTEGER 0, SEQUENCE {} (empty Name), … }: skip the outer
        // SEQUENCE header (short or long form length), then check the first fields.
        #expect(info.first == 0x30)
        let header = info[1] < 0x80 ? 2 : 2 + Int(info[1] & 0x7F)
        #expect(Array(info[header ..< header + 5]) == [0x02, 0x01, 0x00, 0x30, 0x00])
        #expect(Array(info.suffix(2)) == [0xA0, 0x00]) // empty attributes
    }

    @Test func rejectsANonP256Key() throws {
        var error: Unmanaged<CFError>?
        let rsa = SecKeyCreateRandomKey([
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits as String: 2048,
        ] as CFDictionary, &error)!
        #expect(throws: CertificateSigningRequest.BuildError.notP256PrivateKey) {
            try CertificateSigningRequest.build(privateKey: rsa)
        }
    }

    /// Shows as SKIPPED (not passed) where there's no enclave, and the runner
    /// then fails its enclave interop check unless told not to expect one.
    @Test(.enabled(if: CSRTests.enclaveAvailable, "no Secure Enclave on this destination"))
    func enclaveKey() throws {
        let key = try p256Key(enclave: true)
        let built = try CertificateSigningRequest.build(privateKey: key, commonName: "enclave-device")
        try Self.writeForInterop(built.pem, name: "enclave-csr.pem")
        #expect(SecKeyCopyExternalRepresentation(key, nil) == nil) // the private half never leaves
    }
}

struct DERTests {
    @Test func lengths() {
        #expect(DER.encodeLength(0x7F) == [0x7F])
        #expect(DER.encodeLength(0x80) == [0x81, 0x80])
        #expect(DER.encodeLength(0x1234) == [0x82, 0x12, 0x34])
    }

    @Test func integerMagnitude() {
        #expect(DER.integer([0x00, 0x00, 0x05]) == [0x02, 0x01, 0x05])
        #expect(DER.integer([0x80]) == [0x02, 0x02, 0x00, 0x80])
        #expect(DER.integer(UInt8(0)) == [0x02, 0x01, 0x00])
        #expect(DER.integer([]) == [0x02, 0x01, 0x00]) // empty magnitude = zero, never `02 00`
    }

    @Test func pemWrapsAt64() {
        let pem = DER.pem([UInt8](repeating: 0xAB, count: 100), label: "X")
        let body = pem.split(separator: "\n").dropFirst().dropLast()
        #expect(body.allSatisfy { $0.count <= 64 })
        #expect(body.first?.count == 64)
    }
}

/// Byte-identity with an INDEPENDENT encoder: for a fixed key, the
/// CertificationRequestInfo must equal what `openssl req` produces (fixtures
/// generated by OpenSSL 3.5, not by this code). Signatures are randomised
/// (ECDSA), so the signed-over INFO is the deterministic part. frontend-ios runs
/// the same golden against the softphone's pre-extraction builder in the
/// mobile-app PR, so old == openssl == new (device-cert enrolment depends on it).
struct CSRGoldenTests {
    private func fixture(_ name: String, _ ext: String) -> String {
        try! String(contentsOf: Fixtures.url(name, ext), encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func goldenKey() throws -> SecKey {
        let raw = Data(base64Encoded: fixture("golden-key.x963", "b64"))! // 04||X||Y||D
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(raw as CFData, [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 256,
        ] as CFDictionary, &error) else { throw error!.takeRetainedValue() }
        return key
    }

    private func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }

    @Test func emptySubjectMatchesOpenSSL() throws {
        let built = try CertificateSigningRequest.build(privateKey: goldenKey())
        #expect(hex(built.certificationRequestInfoDER) == fixture("golden-info-empty", "hex"))
    }

    @Test func commonNameMatchesOpenSSL() throws {
        let built = try CertificateSigningRequest.build(privateKey: goldenKey(), commonName: "golden")
        #expect(hex(built.certificationRequestInfoDER) == fixture("golden-info-cn", "hex"))
    }
}
