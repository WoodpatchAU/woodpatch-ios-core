// TrustPinningTests.swift: the fail-closed trust decision and the delegate's
// per-challenge dispositions (BOS #2562; logic from the softphone's #717/#1419).

import Foundation
import Security
import Testing
@testable import WoodpatchCore

struct TrustDecisionTests {
    let host = "pinned.example.test"

    @Test func acceptsChainToTheAnchor() {
        let trust = Fixtures.serverTrust(leaf: Fixtures.certificate("pinned-leaf"), host: host)
        #expect(TrustPinning.evaluate(serverTrust: trust, anchors: [Fixtures.certificate("trusted-ca")]) == .accept)
    }

    @Test func rejectsAChainToAnotherCA() {
        // The MITM case: a valid cert for the right host from a CA we don't pin.
        // Note: this would pass even without SecTrustSetAnchorCertificatesOnly,
        // because the test rogue CA isn't in the system store. That property (a
        // PUBLIC-CA cert is refused) is release-gated on device by the softphone's
        // APIPinDiagnostic, not by this unit test.
        let trust = Fixtures.serverTrust(leaf: Fixtures.certificate("rogue-leaf"), host: host)
        let decision = TrustPinning.evaluate(serverTrust: trust, anchors: [Fixtures.certificate("trusted-ca")])
        #expect(decision != .accept)
    }

    @Test func rejectsTheRightChainForTheWrongHost() {
        let trust = Fixtures.serverTrust(leaf: Fixtures.certificate("pinned-leaf"), host: "other.example.test")
        #expect(TrustPinning.evaluate(serverTrust: trust, anchors: [Fixtures.certificate("trusted-ca")]) != .accept)
    }

    @Test func noAnchorsFailsClosed() {
        let trust = Fixtures.serverTrust(leaf: Fixtures.certificate("pinned-leaf"), host: host)
        #expect(TrustPinning.evaluate(serverTrust: trust, anchors: []) == .reject("no bundled anchors"))
    }

    @Test func parsesEveryPEMBlockAndSkipsGarbage() {
        let ca = try! String(contentsOf: Fixtures.url("trusted-ca", "pem"), encoding: .utf8)
        let rogue = try! String(contentsOf: Fixtures.url("rogue-ca", "pem"), encoding: .utf8)
        let broken = "-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n"
        #expect(TrustPinning.parsePEMCertificates(ca + broken + rogue).count == 2)
        #expect(TrustPinning.parsePEMCertificates("").isEmpty)
    }

    @Test func missingAnchorResourceIsEmpty() {
        #expect(TrustPinning.loadAnchors(bundle: Fixtures.bundle, resource: "does-not-exist").isEmpty)
    }
}

/// Minimal sender: URLAuthenticationChallenge needs one, the tests never call it.
private final class NullSender: NSObject, URLAuthenticationChallengeSender {
    func use(_: URLCredential, for _: URLAuthenticationChallenge) {}
    func continueWithoutCredential(for _: URLAuthenticationChallenge) {}
    func cancel(_: URLAuthenticationChallenge) {}
}

struct PinnedSessionDelegateTests {
    let host = "pinned.example.test"

    private func challenge(host: String, method: String) -> URLAuthenticationChallenge {
        let space = URLProtectionSpace(
            host: host, port: 443, protocol: NSURLProtectionSpaceHTTPS, realm: nil, authenticationMethod: method
        )
        return URLAuthenticationChallenge(
            protectionSpace: space, proposedCredential: nil, previousFailureCount: 0,
            failureResponse: nil, error: nil, sender: NullSender()
        )
    }

    /// CF identity handles are immutable; the box only satisfies Sendable capture.
    private final class IdentityBox: @unchecked Sendable {
        let identity: SecIdentity
        init(_ identity: SecIdentity) { self.identity = identity }
    }

    private final class CertsBox: @unchecked Sendable {
        let certs: [SecCertificate]
        init(_ certs: [SecCertificate]) { self.certs = certs }
    }

    private func delegate(
        identity: SecIdentity? = nil,
        intermediates: [SecCertificate]? = nil,
        pinnedHost: String = "Pinned.Example.Test" // host match is case-insensitive
    ) -> PinnedSessionDelegate {
        var provider: (@Sendable () -> SecIdentity?)?
        if let identity {
            let box = IdentityBox(identity)
            provider = { box.identity }
        }
        var chain: (@Sendable () -> [SecCertificate])?
        if let intermediates {
            let box = CertsBox(intermediates)
            chain = { box.certs }
        }
        return PinnedSessionDelegate(
            pinnedHost: pinnedHost,
            anchors: [Fixtures.certificate("trusted-ca")],
            clientIdentity: provider,
            clientIntermediates: chain
        )
    }

    @Test func intermediatesTravelWithTheIdentity() {
        // Any certificate stands in for "the intermediate"; the test is that the
        // credential CARRIES what the provider returns (#2653).
        let intermediate = Fixtures.certificate("rogue-ca")
        let (d, c) = delegate(identity: Fixtures.clientIdentity(), intermediates: [intermediate])
            .disposition(for: challenge(host: host, method: NSURLAuthenticationMethodClientCertificate))
        #expect(d == .useCredential)
        #expect(c?.certificates.count == 1)
        #expect((c?.certificates.first as! SecCertificate) == intermediate)
    }

    @Test func noIntermediatesMeansLeafOnly() {
        let (_, c) = delegate(identity: Fixtures.clientIdentity(), intermediates: [])
            .disposition(for: challenge(host: host, method: NSURLAuthenticationMethodClientCertificate))
        #expect(c?.certificates.isEmpty == true)
    }

    @Test func trailingDotOnThePinnedHostSideStillPins() {
        // Kills the "only .lowercased() the pinned host" mutant: the fixture's other
        // tests configure the pinned host WITHOUT a trailing dot.
        let d = delegate(pinnedHost: "pinned.example.test.")
        #expect(d.disposition(for: challenge(host: host, method: NSURLAuthenticationMethodServerTrust)).0
            == .cancelAuthenticationChallenge)
    }

    @Test func otherHostsGetDefaultHandling() {
        let (d, c) = delegate().disposition(for: challenge(host: "elsewhere.test", method: NSURLAuthenticationMethodServerTrust))
        #expect(d == .performDefaultHandling && c == nil)
    }

    @Test func pinnedHostWithoutServerTrustIsCancelled() {
        // A server-trust challenge that carries no SecTrust can't be evaluated: fail closed.
        let (d, c) = delegate().disposition(for: challenge(host: host, method: NSURLAuthenticationMethodServerTrust))
        #expect(d == .cancelAuthenticationChallenge && c == nil)
    }

    @Test func clientCertWithoutIdentityIsDefault() {
        // The softphone configuration (no identity): unchanged behaviour.
        let (d, c) = delegate().disposition(for: challenge(host: host, method: NSURLAuthenticationMethodClientCertificate))
        #expect(d == .performDefaultHandling && c == nil)
    }

    @Test func clientCertForPinnedHostPresentsTheIdentity() {
        let (d, c) = delegate(identity: Fixtures.clientIdentity())
            .disposition(for: challenge(host: host, method: NSURLAuthenticationMethodClientCertificate))
        #expect(d == .useCredential)
        #expect(c?.identity != nil)
        // Never cached: an unpair (provider → nil) must mean no identity is sent.
        #expect(c?.persistence == URLCredential.Persistence.none)
    }

    /// Exact-match only: a hasSuffix/contains mutant, or dropping normalisation of
    /// the CHALLENGE host, fails one of these.
    @Test(arguments: ["sub.pinned.example.test", "pinned.example.test.evil.test", "xpinned.example.test"])
    func lookAlikeHostsAreNotPinnedAndGetNoIdentity(other: String) {
        let d = delegate(identity: Fixtures.clientIdentity())
        #expect(d.disposition(for: challenge(host: other, method: NSURLAuthenticationMethodServerTrust)).0 == .performDefaultHandling)
        let (cd, cc) = d.disposition(for: challenge(host: other, method: NSURLAuthenticationMethodClientCertificate))
        #expect(cd == .performDefaultHandling && cc == nil)
    }

    @Test(arguments: ["PINNED.EXAMPLE.TEST", "Pinned.Example.Test", "pinned.example.test.", "pinned.example.test.."])
    func caseAndTrailingDotStillPin(variant: String) {
        // Pinned → evaluated → no SecTrust in a synthetic challenge → fail-closed cancel
        // (an unpinned host would have got .performDefaultHandling instead).
        #expect(delegate().disposition(for: challenge(host: variant, method: NSURLAuthenticationMethodServerTrust)).0
            == .cancelAuthenticationChallenge)
    }

    @Test func identityIsNeverOfferedToAnotherHost() {
        let (d, c) = delegate(identity: Fixtures.clientIdentity())
            .disposition(for: challenge(host: "elsewhere.test", method: NSURLAuthenticationMethodClientCertificate))
        #expect(d == .performDefaultHandling && c == nil)
    }
}
