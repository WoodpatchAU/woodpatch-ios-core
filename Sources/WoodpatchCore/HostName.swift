// HostName.swift (v1.15, BOS #5566)
// ────────────────────────────────────────────────────────────────────
// The one strict hostname rule, for a host an app is CONFIGURED with (a pinned
// host, an API host, a CDN host): never a host read from a response. Lifted
// from the staff app's APIConfig.hostProblem (mobile #130, the reviewer's r2),
// so the till, the staff app and TrustPinning's pinned host all refuse the
// same things for the same reasons.
//
// A host passes when it is:
// - no scheme, userinfo, path, query, fragment or port, and not bracketed;
// - at most 253 characters, every label 1-63;
// - lower case (no folding here: a caller that wants "Host." to mean "host"
//   normalises first and says so, as validatedPinnedHost does);
// - at least TWO labels, so "localhost" or a bare search-domain name is
//   refused (the reviewer, #5566: a configured host is always an FQDN);
// - LDH labels (a-z, 0-9, '-'), not starting or ending with '-';
// - a LAST label that starts with a letter, so "0x7f.0x1" (inet_aton reads it
//   as 127.0.0.1) and "api.example.123" are refused.
//
// An IP address passes only with `allowIP`, and only as a CANONICAL dotted
// quad: exactly four decimal octets, each "0" or 1-3 digits with no leading
// zero, at most 255. Every other form inet_aton and some resolvers accept is
// refused, because core and the resolver could read different hosts from it
// (a parser differential): "127.1", "2130706433", "0177.0.0.1" (octal),
// "0x7f.0.0.1" (hex), "127.000.0.1", "010.0.0.1". IPv6 literals are refused
// (nothing pins one).
//
// `Problem` names the first rule a host breaks. Its cases are the staff app's
// MalformedReason host cases one for one, so the app's mapping is total with
// no default branch (frontend-ios, #5566).

import Foundation

public enum HostName {
    /// The first rule a host breaks.
    public enum Problem: String, Equatable, Sendable, CaseIterable {
        case scheme, userinfo, path, query, ipLiteral, port, tooLong, notLowercase, badLabel
    }

    /// nil when `host` is an acceptable configured host; otherwise the first
    /// rule it breaks. An IP address is acceptable only with `allowIP`, and only
    /// as a canonical dotted quad.
    public static func problem(_ host: String, allowIP: Bool = false) -> Problem? {
        if host.contains("://") { return .scheme }
        if host.contains("@") { return .userinfo }
        if host.contains("/") { return .path }
        if host.contains("?") || host.contains("#") { return .query }
        if host.hasPrefix("[") { return .ipLiteral }
        if host.contains(":") { return .port }
        if isCanonicalIPv4(host) { return allowIP ? nil : .ipLiteral }
        if host.utf8.count > 253 { return .tooLong }
        if host != host.lowercased() { return .notLowercase }
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        if labels.contains(where: { $0.utf8.count > 63 }) { return .tooLong }
        // Every label digits only: an IP in some non-canonical form ("127.1",
        // "2130706433", "0177.0.0.1", "127.000.0.1"), never a name.
        if labels.allSatisfy({ !$0.isEmpty && $0.utf8.allSatisfy(isDigit) }) { return .ipLiteral }
        guard labels.count >= 2 else { return .badLabel }
        for label in labels {
            let bytes = label.utf8
            guard !bytes.isEmpty, bytes.first != UInt8(ascii: "-"), bytes.last != UInt8(ascii: "-"),
                  bytes.allSatisfy(isLDH)
            else { return .badLabel }
        }
        if let last = labels.last?.utf8.first, !isLetter(last) { return .badLabel }
        return nil
    }

    /// Exactly four decimal octets, each "0" or 1-3 digits with no leading zero,
    /// and at most 255.
    public static func isCanonicalIPv4(_ host: String) -> Bool {
        let octets = host.split(separator: ".", omittingEmptySubsequences: false)
        return octets.count == 4 && octets.allSatisfy { octet in
            let bytes = octet.utf8
            return (1 ... 3).contains(bytes.count)
                && bytes.allSatisfy(isDigit)
                && (bytes.count == 1 || bytes.first != UInt8(ascii: "0"))
                && (Int(octet).map { $0 <= 255 } ?? false)
        }
    }

    private static func isDigit(_ byte: UInt8) -> Bool {
        (UInt8(ascii: "0") ... UInt8(ascii: "9")).contains(byte)
    }

    private static func isLetter(_ byte: UInt8) -> Bool {
        (UInt8(ascii: "a") ... UInt8(ascii: "z")).contains(byte)
    }

    private static func isLDH(_ byte: UInt8) -> Bool {
        isLetter(byte) || isDigit(byte) || byte == UInt8(ascii: "-")
    }
}
