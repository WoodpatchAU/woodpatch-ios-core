// APIClientError.swift
// ────────────────────────────────────────────────────────────────────
// The single `Error` type an app's API client throws. Each case maps to
// a distinct UX category:
//
//   - `.api(...)`: the backend returned a structured error envelope.
//     The app maps `APIError.rawCode` onto its OWN code enum.
//   - `.transport(...)`: couldn't reach the backend (DNS, TCP, TLS
//     handshake, timeout). An mTLS handshake failure surfaces here, not
//     as an HTTP error. A missing or rejected client certificate
//     typically arrives as NSURLErrorNetworkConnectionLost (-1005), not
//     a TLS-specific code (POS spike, BOS #2509).
//   - `.decode(...)`: 2xx, but the body wasn't the expected shape. A code
//     bug; report it and bail.
//   - `.malformedErrorResponse(...)`: 4xx/5xx, but the body wasn't a valid
//     envelope. Rare; treat it as transport-class.
//
// Extracted from the softphone (Networking/APIClientError.swift) for BOS
// #2562. The one change: `APIError` no longer carries a typed `code`.
// Error codes are per-surface (RELAY's pairing codes, SPECTRUM's
// idempotency codes…), so each app keeps its own enum and maps `rawCode`
// with an extension, e.g.
//
//     extension APIError { var code: MyErrorCode? { MyErrorCode(rawValue: rawCode) } }
//
// Unknown codes still come out as nil, with `rawCode` kept for logging.

import Foundation

public enum APIClientError: Error, Sendable {
    case api(APIError)
    case transport(underlying: any Error & Sendable)
    case decode(underlying: any Error & Sendable)
    case malformedErrorResponse(statusCode: Int, body: String)
}

/// A structured error returned by the backend.
public struct APIError: Error, Sendable, Equatable {
    public let statusCode: Int
    /// The `error.code` string exactly as the server sent it.
    public let rawCode: String
    public let message: String
    public let requestId: String?

    public init(statusCode: Int, rawCode: String, message: String, requestId: String?) {
        self.statusCode = statusCode
        self.rawCode = rawCode
        self.message = message
        self.requestId = requestId
    }
}
