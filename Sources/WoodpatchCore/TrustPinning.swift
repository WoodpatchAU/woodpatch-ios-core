// TrustPinning.swift
// ────────────────────────────────────────────────────────────────────
// Pin ONE host's server trust to a fixed set of bundled anchors,
// fail-closed, and (optionally) present a client identity to that host
// for mTLS.
//
// Provenance: extracted from the softphone's Networking/APIPinning.swift
// (#717 anchor pin, #1419 one shared trust decision, #810 ATS note) for
// BOS #2562. The DECISION LOGIC is unchanged. Two things are now injected
// rather than assumed:
//   - the anchors' bundle resource (the softphone's lives with SIPAnchor;
//     the POS bundles its own copy), and the Logger, so each app's
//     diagnostics keep filtering on its own subsystem;
//   - an optional client identity for mTLS (POS device auth, BOS #2509).
//     When it's absent, client-certificate challenges get
//     `.performDefaultHandling`, exactly as before.
//
// ⚠ SECURITY-CRITICAL: SOLE TRUST GATE. An app that pins a private-CA host
// also needs a scoped ATS exception for it (otherwise ATS's own system-trust
// check rejects the private chain with -1200). That makes THIS delegate the
// ONLY trust gate for the host. A regression here (a `.cancel` flipped to
// `.useCredential`, or a lost `SecTrustSetAnchorCertificatesOnly`) silently
// opens a public-CA MITM with nothing to catch it. Any edit to the trust logic
// needs a pinning re-review (reviewer) AND the softphone's on-device
// ACCEPT/REJECT self-test (APIPinDiagnostic) on the next rc.

import Foundation
import os
import Security

public enum TrustPinning {
    /// The outcome of the one server-trust decision. Shared by the live
    /// session delegate and any on-device self-test, so the release gate
    /// tests exactly what ships (#1419).
    public enum TrustDecision: Equatable, Sendable {
        case accept
        case reject(String)
    }

    /// Evaluates `serverTrust` against `anchors` ONLY (the system store is
    /// excluded), keeping the SSL policy's hostname check the trust was
    /// created with. FAIL-CLOSED at every step: no anchors, or an anchor
    /// setter that doesn't return success, is a rejection, never a fall-through
    /// to system trust.
    public static func evaluate(serverTrust: SecTrust, anchors: [SecCertificate]) -> TrustDecision {
        guard !anchors.isEmpty else { return .reject("no bundled anchors") }
        // Both setters are checked: if SetAnchorCertificatesOnly silently failed,
        // the system store would STILL apply and a public-CA MITM cert would pass.
        // So a non-success OSStatus fails closed rather than evaluating against a
        // mixed anchor set.
        let setAnchors = SecTrustSetAnchorCertificates(serverTrust, anchors as CFArray)
        let anchorsOnly = SecTrustSetAnchorCertificatesOnly(serverTrust, true)
        guard setAnchors == errSecSuccess, anchorsOnly == errSecSuccess else {
            return .reject(
                "anchor setters failed (setAnchors=\(setAnchors) anchorsOnly=\(anchorsOnly))"
            )
        }
        var error: CFError?
        if SecTrustEvaluateWithError(serverTrust, &error) { return .accept }
        return .reject(error.map { CFErrorCopyDescription($0) as String } ?? "trust evaluation failed")
    }

    /// Every `-----BEGIN CERTIFICATE-----` block in a PEM string, as
    /// SecCertificates. Malformed blocks are skipped. An empty result is the
    /// caller's signal to fail closed.
    public static func parsePEMCertificates(_ pem: String) -> [SecCertificate] {
        let begin = "-----BEGIN CERTIFICATE-----"
        let end = "-----END CERTIFICATE-----"
        var certs: [SecCertificate] = []
        var cursor = pem.startIndex
        while let b = pem.range(of: begin, range: cursor ..< pem.endIndex),
              let e = pem.range(of: end, range: b.upperBound ..< pem.endIndex)
        {
            let base64 = pem[b.upperBound ..< e.lowerBound].filter { !$0.isWhitespace }
            if let der = Data(base64Encoded: String(base64)),
               let cert = SecCertificateCreateWithData(nil, der as CFData)
            {
                certs.append(cert)
            }
            cursor = e.upperBound
        }
        return certs
    }

    /// The anchors from a PEM resource in `bundle`. Empty when the resource is
    /// missing, unreadable or malformed, and empty means fail closed.
    public static func loadAnchors(
        bundle: Bundle,
        resource: String,
        withExtension ext: String = "pem"
    ) -> [SecCertificate] {
        guard let url = bundle.url(forResource: resource, withExtension: ext),
              let pem = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        return parsePEMCertificates(pem)
    }

    /// A URLSession that pins `pinnedHost`'s server trust to `anchors`. All
    /// other hosts use default (system) trust. ALWAYS returns a session: with no
    /// anchors the delegate fail-closes (rejects the pinned host), so the caller
    /// must NOT substitute an unpinned session for the pinned host.
    ///
    /// `clientIdentity` is consulted ONLY for a client-certificate challenge
    /// FROM THE PINNED HOST, and never offered to any other host. Pass nil when
    /// the host doesn't do mTLS.
    public static func pinnedSession(
        pinnedHost: String,
        anchors: [SecCertificate],
        logger: Logger,
        clientIdentity: (@Sendable () -> SecIdentity?)? = nil,
        configuration: URLSessionConfiguration = .default
    ) -> URLSession {
        if anchors.isEmpty {
            // A packaging defect (an anchor-integrity test should catch it in CI).
            // Log loudly; the delegate rejects the pinned host rather than falling open.
            logger.critical(
                "NO bundled server anchor; pinned host \(pinnedHost, privacy: .public) will FAIL-CLOSED"
            )
        }
        let delegate = PinnedSessionDelegate(
            pinnedHost: pinnedHost,
            anchors: anchors,
            clientIdentity: clientIdentity
        )
        return URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
    }
}

/// URLSession delegate that pins ONE host's server trust to a fixed anchor
/// set, fail-closed, and optionally presents a client identity to that host.
/// Immutable after init. The CF anchor/trust handles are effectively
/// immutable, so @unchecked Sendable is safe for URLSession's off-main
/// delegate dispatch.
public final class PinnedSessionDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let pinnedHost: String
    private let anchors: [SecCertificate]
    private let clientIdentity: (@Sendable () -> SecIdentity?)?

    public init(
        pinnedHost: String,
        anchors: [SecCertificate],
        clientIdentity: (@Sendable () -> SecIdentity?)? = nil
    ) {
        self.pinnedHost = pinnedHost.lowercased()
        self.anchors = anchors
        self.clientIdentity = clientIdentity
    }

    /// The disposition for one challenge. Split out from the URLSession
    /// callback so tests can drive it directly.
    func disposition(
        for challenge: URLAuthenticationChallenge
    ) -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        let space = challenge.protectionSpace
        // Anything that isn't for the pinned host gets default handling: system
        // trust, and no client identity is EVER offered to another host.
        guard space.host.lowercased() == pinnedHost else {
            return (.performDefaultHandling, nil)
        }

        switch space.authenticationMethod {
        case NSURLAuthenticationMethodServerTrust:
            // FAIL-CLOSED from here: no server trust, or no anchor to pin to,
            // means REJECT (never fall through to system trust, which would
            // MITM-accept a public-CA cert here).
            guard let serverTrust = space.serverTrust else {
                return (.cancelAuthenticationChallenge, nil)
            }
            switch TrustPinning.evaluate(serverTrust: serverTrust, anchors: anchors) {
            case .accept:
                return (.useCredential, URLCredential(trust: serverTrust))
            case .reject:
                return (.cancelAuthenticationChallenge, nil)
            }

        case NSURLAuthenticationMethodClientCertificate:
            // mTLS (POS, #2509). Without a configured or available identity,
            // fall back to default handling: the handshake proceeds without a
            // certificate and a client-auth server refuses it. That's the
            // correct outcome for an unpaired device.
            guard let identity = clientIdentity?() else {
                return (.performDefaultHandling, nil)
            }
            return (.useCredential, URLCredential(identity: identity, certificates: nil, persistence: .forSession))

        default:
            return (.performDefaultHandling, nil)
        }
    }

    public func urlSession(
        _: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        let (disposition, credential) = disposition(for: challenge)
        completionHandler(disposition, credential)
    }
}
