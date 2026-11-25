// HostNameTests.swift (v1.15, BOS #5566)
// ────────────────────────────────────────────────────────────────────
// HostName.problem: the staff app's APIConfigTests host table (mobile #130's
// r2, each rule asserting its OWN reason so one can't refuse for another's and
// stay green), plus the reviewer's #5566 additions: leading-zero octets
// ("010.0.0.1", "127.000.0.1") and every inet_aton alias, refused even with
// allowIP.

import Foundation
import Testing
@testable import WoodpatchCore

struct HostNameTests {
    @Test("each malformed host is refused for its own reason", arguments: [
        ("https://dev-api.example.invalid", HostName.Problem.scheme),
        ("dev-api.example.invalid/x", .path),
        ("dev-api.example.invalid:443", .port),
        ("dev-api.example.invalid?a=1", .query),
        ("dev-api.example.invalid#frag", .query),
        ("u@dev-api.example.invalid", .userinfo),
        ("[2001:db8::1]", .ipLiteral),
        ("1.2.3", .ipLiteral),
        ("Dev-Api.example.invalid", .notLowercase),
        ("dev api.example.invalid", .badLabel),
        ("localhost", .badLabel),
        ("-a.example.invalid", .badLabel),
        ("a-.example.invalid", .badLabel),
        ("a..example.invalid", .badLabel),
        (".example.invalid", .badLabel),
        ("example.invalid.", .badLabel),
        ("0x7f.0x1", .badLabel),
        ("api.example.123", .badLabel),
        ("", .badLabel),
        ("pinnéd.example.test", .badLabel),
        ("pinned_x.example.test", .badLabel),
    ])
    func eachRuleRefusesForItsOwnReason(_ host: String, _ problem: HostName.Problem) {
        #expect(HostName.problem(host) == problem)
        #expect(HostName.problem(host, allowIP: true) == problem, "allowIP must change nothing for a name")
    }

    @Test func anOverlongHostOrLabelIsTooLong() {
        let label64 = String(repeating: "a", count: 64)
        #expect(HostName.problem(label64 + ".example.test") == .tooLong)
        let host254 = [63, 63, 63, 62].map { String(repeating: "a", count: $0) }.joined(separator: ".")
        #expect(HostName.problem(host254) == .tooLong)
        let host253 = [63, 63, 63, 61].map { String(repeating: "a", count: $0) }.joined(separator: ".")
        #expect(HostName.problem(host253) == nil)
    }

    @Test(arguments: ["dev-api.example.invalid", "pos-api.example.test", "xn--pinnd-fsa.example.test",
                      "123.example.test", "3com.example.test", "a.b"])
    func aStrictHostPasses(_ host: String) {
        #expect(HostName.problem(host) == nil)
    }

    /// A canonical dotted quad is an IP literal unless the caller allows one.
    @Test(arguments: ["127.0.0.1", "10.0.0.5", "0.0.0.0", "255.255.255.255", "192.168.1.10"])
    func aCanonicalIPPassesOnlyWithAllowIP(_ host: String) {
        #expect(HostName.isCanonicalIPv4(host))
        #expect(HostName.problem(host) == .ipLiteral)
        #expect(HostName.problem(host, allowIP: true) == nil)
    }

    /// Every form inet_aton (or some resolver) reads as an address other than its
    /// canonical text: refused even with allowIP, so core and the resolver can't
    /// read different hosts from one configured value.
    @Test(arguments: ["127.1", "2130706433", "0177.0.0.1", "127.000.0.1", "010.0.0.1", "1.2.3.00",
                      "0x7f.0.0.1", "0x7f.0x1", "0x7f000001", "256.1.1.1", "1.2.3.4.5", "1.1.1"])
    func noIPAliasPassesEvenWithAllowIP(_ host: String) {
        #expect(!HostName.isCanonicalIPv4(host))
        #expect(HostName.problem(host, allowIP: true) != nil)
    }

    /// The cases are the staff app's MalformedReason host cases, one for one, so
    /// its mapping can be total (frontend-ios, #5566). A case added or renamed
    /// here must be mapped there.
    @Test func theProblemsAreTheStaffAppsReasons() {
        #expect(Set(HostName.Problem.allCases.map(\.rawValue))
            == ["scheme", "userinfo", "path", "query", "ipLiteral", "port", "tooLong", "notLowercase", "badLabel"])
    }
}
