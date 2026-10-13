// Fixtures.swift: loads the TEST-ONLY PKI (scripts/make-test-fixtures.sh).

import Foundation
import Security
@testable import WoodpatchCore

enum Fixtures {
    static func url(_ name: String, _ ext: String) -> URL {
        Bundle.module.url(forResource: name, withExtension: ext, subdirectory: "Fixtures")!
    }

    static func certificate(_ name: String) -> SecCertificate {
        let pem = try! String(contentsOf: url(name, "pem"), encoding: .utf8)
        return TrustPinning.parsePEMCertificates(pem).first!
    }

    /// The client identity from the PKCS#12 fixture. SecPKCS12Import builds an
    /// identity without touching the keychain.
    static func clientIdentity() -> SecIdentity {
        let data = try! Data(contentsOf: url("client", "p12"))
        var items: CFArray?
        let status = SecPKCS12Import(data as CFData, [kSecImportExportPassphrase as String: "test"] as CFDictionary, &items)
        precondition(status == errSecSuccess, "SecPKCS12Import \(status)")
        let first = (items as! [[String: Any]]).first!
        return first[kSecImportItemIdentity as String] as! SecIdentity
    }

    /// A server trust for `leaf` as if presented for `host`.
    static func serverTrust(leaf: SecCertificate, host: String) -> SecTrust {
        var trust: SecTrust?
        let status = SecTrustCreateWithCertificates(leaf, SecPolicyCreateSSL(true, host as CFString), &trust)
        precondition(status == errSecSuccess)
        // Fixed evaluation date inside every fixture's validity window, so the
        // tests don't depend on the wall clock.
        SecTrustSetVerifyDate(trust!, Date(timeIntervalSince1970: 1_800_000_000) as CFDate)
        return trust!
    }
}
