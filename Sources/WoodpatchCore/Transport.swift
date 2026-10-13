// Transport.swift
// ────────────────────────────────────────────────────────────────────
// Thin protocol that hides URLSession behind a mockable seam.
// Production builds use a URLSession (usually a pinned one, see
// `PinnedSession`); tests substitute a stub that returns canned
// responses without touching the network.
//
// Kept to one method on purpose, so a test stub is two lines, not
// twenty. Further knobs (timeouts, headers) belong on the URLRequest
// at the API-client level, not here.
//
// Extracted unchanged from the softphone (woodpatch-mobile-app,
// Networking/Transport.swift) for BOS #2562.

import Foundation

public protocol Transport: Sendable {
    /// Send the request and return the raw `(data, response)` pair.
    /// URLSession transport errors (cancellation, TLS failures, DNS,
    /// timeout) are thrown as-is; the API client wraps them in
    /// `APIClientError.transport`.
    func send(_ request: URLRequest) async throws -> (Data, URLResponse)
}

extension URLSession: Transport {
    public func send(_ request: URLRequest) async throws -> (Data, URLResponse) {
        try await data(for: request)
    }
}
