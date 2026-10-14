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

    /// A provider whose answer can change between challenges (renewal / unpair).
    private final class CredentialBox: @unchecked Sendable {
        private let lock = NSLock()
        private var value: ClientTLSCredential?
        init(_ value: ClientTLSCredential?) { self.value = value }
        var current: ClientTLSCredential? {
            get { lock.withLock { value } }
            set { lock.withLock { value = newValue } }
        }
    }

    private func delegate(
        credential: ClientTLSCredential? = nil,
        box: CredentialBox? = nil,
        pinnedHost: String = "Pinned.Example.Test" // host match is case-insensitive
    ) -> PinnedSessionDelegate {
        // Built explicitly: a closure-returning `Optional.map` crashes the type checker.
        var source: CredentialBox? = box
        if source == nil, let credential { source = CredentialBox(credential) }
        var provider: (@Sendable () -> ClientTLSCredential?)?
        if let source { provider = { source.current } }
        return PinnedSessionDelegate(
            pinnedHost: pinnedHost,
            anchors: [Fixtures.certificate("trusted-ca")],
            clientCredential: provider
        )
    }

    private func identityLeaf(_ identity: SecIdentity) -> SecCertificate {
        var leaf: SecCertificate?
        SecIdentityCopyCertificate(identity, &leaf)
        return leaf!
    }

    @Test func intermediatesTravelWithTheIdentity() {
        // pinned-leaf is issued by trusted-ca (not self-issued), so it stands in for
        // "an intermediate"; the test is that the credential CARRIES it (#2653).
        let intermediate = Fixtures.certificate("pinned-leaf")
        let credential = ClientTLSCredential(identity: Fixtures.clientIdentity(), intermediates: [intermediate])
        let (d, c) = delegate(credential: credential)
            .disposition(for: challenge(host: host, method: NSURLAuthenticationMethodClientCertificate))
        #expect(d == .useCredential)
        #expect(c?.certificates.count == 1)
        #expect((c?.certificates.first as! SecCertificate) == intermediate)
    }

    @Test func chainDropsTheLeafAndRoots() {
        // A sloppy provider: [own leaf, a self-signed root, the real intermediate].
        let identity = Fixtures.clientIdentity()
        let intermediate = Fixtures.certificate("pinned-leaf")
        let credential = ClientTLSCredential(
            identity: identity,
            intermediates: [identityLeaf(identity), Fixtures.certificate("rogue-ca"), intermediate]
        )
        #expect(PinnedSessionDelegate.chain(for: credential) == [intermediate])
        #expect(PinnedSessionDelegate.isSelfIssued(Fixtures.certificate("trusted-ca")))
        #expect(!PinnedSessionDelegate.isSelfIssued(intermediate))
    }

    @Test func noIntermediatesMeansLeafOnly() {
        let (_, c) = delegate(credential: ClientTLSCredential(identity: Fixtures.clientIdentity()))
            .disposition(for: challenge(host: host, method: NSURLAuthenticationMethodClientCertificate))
        #expect(c?.certificates.isEmpty == true)
    }

    @Test func credentialIsReadOnEveryChallenge() {
        // Kills a cache-at-init mutant: the provider's answer changes between two
        // challenges on the SAME delegate (renewal, then unpair).
        let box = CredentialBox(ClientTLSCredential(identity: Fixtures.clientIdentity()))
        let d = delegate(box: box)
        let clientChallenge = challenge(host: host, method: NSURLAuthenticationMethodClientCertificate)
        #expect(d.disposition(for: clientChallenge).0 == .useCredential)
        box.current = ClientTLSCredential(
            identity: Fixtures.clientIdentity(), intermediates: [Fixtures.certificate("pinned-leaf")]
        )
        #expect(d.disposition(for: clientChallenge).1?.certificates.count == 1) // renewed chain seen
        box.current = nil // unpaired
        let (after, credential) = d.disposition(for: clientChallenge)
        #expect(after == .performDefaultHandling && credential == nil)
    }

    /// Malformed pinned hosts. Before v1.4 only "", "." and ".." failed closed; the
    /// rest matched nothing, so the REAL host fell through to system trust.
    static let invalidPinnedHosts: [String] = [
        "", ".", "..",
        "https://pinned.example.test", "pinned.example.test:443", "pinned.example.test/api",
        " pinned.example.test", "pinned.example.test ", "pinned example.test",
        "-pinned.example.test", "pinned-.example.test", "pinned..example.test", ".pinned.example.test",
        "pinned_x.example.test", "pinnéd.example.test", "::1", "[::1]",
        String(repeating: "a", count: 64) + ".example.test",
        [63, 63, 63, 62].map { String(repeating: "a", count: $0) }.joined(separator: "."), // 254
    ]

    @Test(arguments: invalidPinnedHosts)
    func invalidPinnedHostFailsClosed(pinned: String) {
        #expect(PinnedSessionDelegate.validatedPinnedHost(pinned) == nil)
        let d = delegate(pinnedHost: pinned)
        // The real host the config meant, and any other host: both refused.
        for target in [host, "anything.test"] {
            #expect(d.disposition(for: challenge(host: target, method: NSURLAuthenticationMethodServerTrust)).0
                == .cancelAuthenticationChallenge)
        }
    }

    /// Reviewer, ios-core #4: with an invalid (here empty) pinned host and a
    /// credential configured, a client-certificate challenge offers no identity,
    /// even from an empty challenge host (normalised("") == "" used to match).
    @Test(arguments: ["", "https://pinned.example.test"])
    func invalidPinnedHostOffersNoIdentity(pinned: String) {
        let d = delegate(credential: ClientTLSCredential(identity: Fixtures.clientIdentity()), pinnedHost: pinned)
        for target in ["", host] {
            let (cd, cc) = d.disposition(for: challenge(host: target, method: NSURLAuthenticationMethodClientCertificate))
            #expect(cd == .performDefaultHandling && cc == nil)
        }
    }

    @Test(arguments: [
        "pinned.example.test", "Pinned.Example.Test.", "localhost", "127.0.0.1", "xn--pinnd-fsa.example.test",
        String(repeating: "a", count: 63) + ".test",
        [63, 63, 63, 61].map { String(repeating: "a", count: $0) }.joined(separator: "."), // 253
    ])
    func validPinnedHostsAreKept(pinned: String) {
        #expect(PinnedSessionDelegate.validatedPinnedHost(pinned) == pinned.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ".")))
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
        let (d, c) = delegate(credential: ClientTLSCredential(identity: Fixtures.clientIdentity()))
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
        let d = delegate(credential: ClientTLSCredential(identity: Fixtures.clientIdentity()))
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
        let (d, c) = delegate(credential: ClientTLSCredential(identity: Fixtures.clientIdentity()))
            .disposition(for: challenge(host: "elsewhere.test", method: NSURLAuthenticationMethodClientCertificate))
        #expect(d == .performDefaultHandling && c == nil)
    }
}
