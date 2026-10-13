// DER.swift
// ────────────────────────────────────────────────────────────────────
// The minimal DER encoders a PKCS#10 CSR for an EC P-256 key needs, plus
// the few extra the softphone uses for key export (octet string,
// context tags, magnitude-normalised INTEGER).
//
// Provenance: extracted from the softphone's SIP/Crypto/DER.swift for BOS
// #2562 (made public; behaviour unchanged). Hand-rolled on purpose: Apple
// ships no ASN.1 encoder on iOS, and a dependency for ~100 lines of
// definite-length DER isn't worth a supply-chain entry. Outputs are pinned
// by byte-exact tests and verified by `openssl req -verify` in this repo's
// fixtures.

import Foundation

public enum DER {
    public enum Tag: UInt8, Sendable {
        case integer = 0x02
        case bitString = 0x03
        case octetString = 0x04
        case null = 0x05
        case objectIdentifier = 0x06
        case utf8String = 0x0C
        case sequence = 0x30 // constructed
        case set = 0x31 // constructed
        case context0 = 0xA0
        case context1 = 0xA1
    }

    /// Definite-length encoding: short form below 128, long form above.
    public static func encodeLength(_ length: Int) -> [UInt8] {
        if length < 0x80 {
            return [UInt8(length)]
        }
        var n = length
        var bytes: [UInt8] = []
        while n > 0 {
            bytes.insert(UInt8(n & 0xFF), at: 0)
            n >>= 8
        }
        return [0x80 | UInt8(bytes.count)] + bytes
    }

    public static func encode(_ tag: Tag, _ content: [UInt8]) -> [UInt8] {
        [tag.rawValue] + encodeLength(content.count) + content
    }

    public static func encode(_ tag: Tag, _ content: Data) -> [UInt8] {
        encode(tag, [UInt8](content))
    }

    /// Unsigned big-endian magnitude → DER INTEGER: leading zero bytes are
    /// stripped, and one is re-added if the high bit would make it negative.
    public static func integer(_ magnitude: [UInt8]) -> [UInt8] {
        // An empty magnitude is zero (a bare `02 00` would be invalid DER).
        var bytes = magnitude.isEmpty ? [0x00] : magnitude
        while bytes.count > 1, bytes.first == 0x00 {
            bytes.removeFirst()
        }
        if let first = bytes.first, first & 0x80 != 0 {
            bytes.insert(0x00, at: 0)
        }
        return encode(.integer, bytes)
    }

    public static func integer(_ value: UInt8) -> [UInt8] {
        integer([value])
    }

    /// BIT STRING with zero unused bits (every bit string here is byte-aligned).
    public static func bitString(_ content: [UInt8]) -> [UInt8] {
        encode(.bitString, [0x00] + content)
    }

    public static func octetString(_ content: [UInt8]) -> [UInt8] {
        encode(.octetString, content)
    }

    public static func utf8String(_ s: String) -> [UInt8] {
        encode(.utf8String, [UInt8](Data(s.utf8)))
    }

    public static func sequence(_ content: [UInt8]) -> [UInt8] {
        encode(.sequence, content)
    }

    public static func set(_ content: [UInt8]) -> [UInt8] {
        encode(.set, content)
    }

    public static func explicit(_ tag: Tag, _ content: [UInt8]) -> [UInt8] {
        encode(tag, content)
    }

    public enum OID {
        public static let ecPublicKey: [UInt8] = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]
        public static let prime256v1: [UInt8] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
        public static let ecdsaWithSHA256: [UInt8] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]
        public static let commonName: [UInt8] = [0x06, 0x03, 0x55, 0x04, 0x03]
    }

    /// PEM armour with 64-character lines and a trailing newline.
    public static func pem(_ der: [UInt8], label: String) -> String {
        let b64 = Data(der).base64EncodedString()
        var lines: [String] = []
        var idx = b64.startIndex
        while idx < b64.endIndex {
            let end = b64.index(idx, offsetBy: 64, limitedBy: b64.endIndex) ?? b64.endIndex
            lines.append(String(b64[idx ..< end]))
            idx = end
        }
        return "-----BEGIN \(label)-----\n"
            + lines.joined(separator: "\n")
            + "\n-----END \(label)-----\n"
    }
}
