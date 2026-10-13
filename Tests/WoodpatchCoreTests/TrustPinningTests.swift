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
        #expect(TrustPinning.loadAnchors(bundle: .module, resource: "does-not-exist").isEmpty)
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

    private func delegate(identity: SecIdentity? = nil) -> PinnedSessionDelegate {
        PinnedSessionDelegate(
            pinnedHost: "Pinned.Example.Test", // host match is case-insensitive
            anchors: [Fixtures.certificate("trusted-ca")],
            clientIdentity: identity.map { id in { id } }
        )
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
    }

    @Test func identityIsNeverOfferedToAnotherHost() {
        let (d, c) = delegate(identity: Fixtures.clientIdentity())
            .disposition(for: challenge(host: "elsewhere.test", method: NSURLAuthenticationMethodClientCertificate))
        #expect(d == .performDefaultHandling && c == nil)
    }
}
