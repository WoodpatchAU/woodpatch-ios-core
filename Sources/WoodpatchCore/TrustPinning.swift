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
    /// `clientCredential` is consulted ONLY for a client-certificate challenge
    /// FROM THE PINNED HOST, never offered to any other host, and read afresh
    /// on every challenge. Pass nil when the host doesn't do mTLS. It returns the
    /// identity AND its intermediate chain together (`ClientTLSCredential`), so a
    /// renewal can never pair a new leaf with an old chain. Without the chain the
    /// device sends only its leaf, and a server that doesn't already hold the
    /// intermediate fails the handshake, which looks exactly like "no cert" (-1005)
    /// (BOS #2509 condition 4, #2653).
    ///
    /// When the app's identity CHANGES (pair, re-pair, unpair, renewal), it must
    /// `invalidateAndCancel()` this session and build a new one: TLS session
    /// resumption can outlive what the provider closure returns.
    public static func pinnedSession(
        pinnedHost: String,
        anchors: [SecCertificate],
        logger: Logger,
        clientCredential: (@Sendable () -> ClientTLSCredential?)? = nil,
        configuration: URLSessionConfiguration = .default
    ) -> URLSession {
        // An invalid pinned host is logged (critical) by the delegate's init.
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
            clientCredential: clientCredential,
            logger: logger
        )
        return URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
    }
}

/// The client side of mTLS: an identity (leaf + its private key, e.g. Secure
/// Enclave) and the INTERMEDIATE certificates to send with it. Supplied together
/// by one provider so they can't drift apart across a renewal. CF handles are
/// immutable, hence @unchecked Sendable.
public struct ClientTLSCredential: @unchecked Sendable {
    public let identity: SecIdentity
    /// Intermediates only. The identity's own leaf and any self-issued (root)
    /// certificate are dropped when the credential is presented (see
    /// `PinnedSessionDelegate.chain(for:)`), so a sloppy provider can't send them.
    public let intermediates: [SecCertificate]

    public init(identity: SecIdentity, intermediates: [SecCertificate] = []) {
        self.identity = identity
        self.intermediates = intermediates
    }
}

/// URLSession delegate that pins ONE host's server trust to a fixed anchor
/// set, fail-closed, and optionally presents a client identity to that host.
/// Immutable after init. The CF anchor/trust handles are effectively
/// immutable, so @unchecked Sendable is safe for URLSession's off-main
/// delegate dispatch.
public final class PinnedSessionDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    /// Normalised, or nil when the configured host isn't a valid hostname (see
    /// `validatedPinnedHost`). Nil fails closed.
    private let pinnedHost: String?
    private let anchors: [SecCertificate]
    private let clientCredential: (@Sendable () -> ClientTLSCredential?)?

    /// `logger` receives the critical "invalid pinned host" line. It defaults to
    /// a WoodpatchCore logger so a direct init can't skip it; apps pass their own
    /// (via `TrustPinning.pinnedSession`) to keep their subsystem filter.
    public init(
        pinnedHost: String,
        anchors: [SecCertificate],
        clientCredential: (@Sendable () -> ClientTLSCredential?)? = nil,
        logger: Logger = Logger(subsystem: "WoodpatchCore", category: "TrustPinning")
    ) {
        self.pinnedHost = Self.validatedPinnedHost(pinnedHost)
        self.anchors = anchors
        self.clientCredential = clientCredential
        super.init()
        if self.pinnedHost == nil {
            // Constant text: the configured value is never logged.
            logger.critical("INVALID pinned host (not a hostname): every server-trust challenge on this session will FAIL-CLOSED")
        }
    }

    /// The disposition for one challenge. Split out from the URLSession
    /// callback so tests can drive it directly.
    func disposition(
        for challenge: URLAuthenticationChallenge
    ) -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        let space = challenge.protectionSpace
        // A misconfigured pinned host ("", "https://host", "host:443", a stray
        // space) would match no real host, so the real one would silently get
        // SYSTEM trust. Fail closed instead: refuse every server-trust challenge,
        // and never offer the identity to anyone.
        guard let pinnedHost else {
            return space.authenticationMethod == NSURLAuthenticationMethodServerTrust
                ? (.cancelAuthenticationChallenge, nil)
                : (.performDefaultHandling, nil)
        }
        // Anything that isn't for the pinned host gets default handling: system
        // trust, and no client identity is EVER offered to another host.
        guard Self.normalised(space.host) == pinnedHost else {
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
            // Read afresh per challenge, so a renewed credential is picked up at once.
            guard let credential = clientCredential?() else {
                return (.performDefaultHandling, nil)
            }
            let chain = Self.chain(for: credential)
            // `.none`: the delegate is asked on every challenge, so caching gains
            // nothing, and a cached credential could outlive an unpair (the
            // provider returning nil must mean no identity is sent).
            return (
                .useCredential,
                URLCredential(
                    identity: credential.identity,
                    certificates: chain.isEmpty ? nil : chain,
                    persistence: .none
                )
            )

        default:
            return (.performDefaultHandling, nil)
        }
    }

    /// The intermediates to send: the provider's list minus the identity's own
    /// leaf (DER-equal) and minus anything self-issued (a root). Servers expect
    /// leaf-then-intermediates. A duplicated leaf or a root in the list is at best
    /// noise and at worst an interop failure (reviewer, ios-core #3).
    ///
    /// Only the CURRENT leaf is dropped. An older leaf left in the list after a
    /// renewal isn't self-issued, so it would travel as an "intermediate"; the
    /// single provider (identity and chain from one place) is what prevents that.
    static func chain(for credential: ClientTLSCredential) -> [SecCertificate] {
        var leaf: SecCertificate?
        // If this fails, `leaf` stays nil and only the self-issued filter applies.
        SecIdentityCopyCertificate(credential.identity, &leaf)
        let leafDER = leaf.map { SecCertificateCopyData($0) as Data }
        return credential.intermediates.filter { cert in
            if let leafDER, SecCertificateCopyData(cert) as Data == leafDER { return false }
            return !isSelfIssued(cert)
        }
    }

    /// Subject == issuer (normalised): a self-issued certificate, i.e. a root.
    /// This also drops a CA key-rollover link certificate (self-issued under RFC
    /// 5280, though signed by a different key). The Woodpatch device CA doesn't use
    /// them; a CA that does would need its link certs supplied another way.
    static func isSelfIssued(_ cert: SecCertificate) -> Bool {
        guard let subject = SecCertificateCopyNormalizedSubjectSequence(cert) as Data?,
              let issuer = SecCertificateCopyNormalizedIssuerSequence(cert) as Data?
        else { return false }
        return subject == issuer
    }

    /// Exact host equality, case-insensitive, with trailing root dots ignored:
    /// `Host.` is the same DNS name as `Host`, and leaving it unmatched would let a
    /// trailing-dot URL skip the pin. ALL trailing dots are stripped, so a
    /// malformed `host..` pins too (fail closed) rather than falling to system
    /// trust. No suffix matching, so neither a subdomain nor a look-alike suffix
    /// inherits the pin or the identity.
    static func normalised(_ host: String) -> String {
        var lower = host.lowercased()
        while lower.hasSuffix(".") {
            lower.removeLast()
        }
        return lower
    }

    /// The normalised pinned host, or nil if it isn't a plausible DNS name or IPv4
    /// literal: dot-separated LDH labels (a-z, 0-9, '-'), each 1-63 characters and
    /// not starting or ending with '-', at most 253 characters in all. Anything
    /// else is a configuration error that would otherwise pin nothing: a URL, a
    /// port, a path, whitespace, an empty label, non-ASCII (use the punycode
    /// form), or an IPv6 literal (not supported).
    static func validatedPinnedHost(_ host: String) -> String? {
        let host = normalised(host)
        guard !host.isEmpty, host.utf8.count <= 253 else { return nil }
        for label in host.split(separator: ".", omittingEmptySubsequences: false) {
            let bytes = label.utf8
            guard (1 ... 63).contains(bytes.count),
                  bytes.first != UInt8(ascii: "-"), bytes.last != UInt8(ascii: "-"),
                  bytes.allSatisfy(isLDH)
            else { return nil }
        }
        return host
    }

    private static func isLDH(_ byte: UInt8) -> Bool {
        switch byte {
        case UInt8(ascii: "a") ... UInt8(ascii: "z"), UInt8(ascii: "0") ... UInt8(ascii: "9"), UInt8(ascii: "-"):
            true
        default:
            false
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
