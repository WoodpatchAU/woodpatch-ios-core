// Transport.swift
// ────────────────────────────────────────────────────────────────────
// Thin protocol that hides URLSession behind a mockable seam.
// Production builds use a URLSession (usually a pinned one, see
// `PinnedSession`); tests substitute a stub that returns canned
// responses without touching the network.
//
// Kept small on purpose, so a test stub is a few lines, not twenty.
// Further knobs (timeouts, headers) belong on the URLRequest at the
// API-client level, not here.
//
// v1.14 (BOS #5560): a second method, `send(_:maxBytes:)`, for replies
// whose size isn't the app's to choose (a picture, an MMS, a PDF). The
// cap holds WHILE the bytes arrive: a reply announcing more is refused
// before its body, and one that streams past the cap is cancelled the
// moment it does, so a hostile or broken server can't make the app hold
// a gigabyte to find out. It's a REQUIREMENT with no default on purpose:
// a default that read everything and checked after would let a wrapper
// (a retiring session, a pinned transport) silently lose the streaming
// cap, so every conformer says how it caps. A stub whose bytes are
// already in memory uses `ResponseTooLarge.check(_:maxBytes:)`.
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

    /// The same, but the reply's body is at most `maxBytes` (positive): more is refused with
    /// `ResponseTooLarge`, while it arrives, never after the whole body is in memory.
    func send(_ request: URLRequest, maxBytes: Int) async throws -> (Data, URLResponse)
}

/// A reply's body was over the cap a `send(_:maxBytes:)` set. Carries the cap, never any of the
/// bytes or the URL, so it's safe to log.
public struct ResponseTooLarge: Error, Equatable, Sendable {
    public let maxBytes: Int

    public init(maxBytes: Int) {
        self.maxBytes = maxBytes
    }

    /// For a stub transport whose bytes are already in memory: `data` if it's within the cap.
    public static func check(_ data: Data, maxBytes: Int) throws -> Data {
        guard maxBytes > 0, data.count <= maxBytes else { throw ResponseTooLarge(maxBytes: maxBytes) }
        return data
    }
}

/// v1.15.1 r2 (reviewer M1 on core #20): the session has a delegate that can't be the task's
/// delegate, so its trust decision can't reach `send(_:maxBytes:)`. Refused before any request:
/// going on without it would be v1.14's silent system-trust path again.
public enum TransportError: Error, Equatable, Sendable {
    case sessionDelegateNotTaskDelegate
}

extension URLSession: Transport {
    public func send(_ request: URLRequest) async throws -> (Data, URLResponse) {
        try await data(for: request)
    }

    /// Streamed: the announced length is checked before the body, and the body is counted as
    /// it arrives. Either way past the cap, the task is cancelled and nothing more is read.
    ///
    /// v1.15.1 (BOS #5678): the session's OWN delegate is passed as the task's delegate.
    /// `bytes(for:)` without one never asks the session delegate about a challenge or a
    /// redirect, so a pinned session's pin, client certificate and redirect refusal all
    /// silently didn't apply. On a private-CA host that failed closed (-1202 before any
    /// request: every MMS picture in the staff app's build 81); on a public-CA host it would
    /// have failed OPEN, trusting the system roots. Measured on macOS 27: `data(for:)` asks the
    /// session delegate, `bytes(for:)` doesn't, and `bytes(for:delegate:)` with it does.
    ///
    /// r2 (reviewer M1): fail-closed. A session delegate that isn't a `URLSessionTaskDelegate`
    /// (one implementing only the session-level challenge) can't be handed over, so the send
    /// throws `TransportError.sessionDelegateNotTaskDelegate` and sends nothing. A pinned
    /// delegate must adopt `URLSessionTaskDelegate`, as `PinnedSessionDelegate` does. A session
    /// with NO delegate keeps the system default, which is right for an unpinned session.
    public func send(_ request: URLRequest, maxBytes: Int) async throws -> (Data, URLResponse) {
        guard maxBytes > 0 else { throw ResponseTooLarge(maxBytes: maxBytes) }
        let taskDelegate: URLSessionTaskDelegate?
        if let sessionDelegate = delegate {
            guard let asTask = sessionDelegate as? URLSessionTaskDelegate else {
                throw TransportError.sessionDelegateNotTaskDelegate
            }
            taskDelegate = asTask
        } else {
            taskDelegate = nil
        }
        let (bytes, response) = try await bytes(for: request, delegate: taskDelegate)
        // -1 is "unknown" (chunked): then only the count below decides.
        if response.expectedContentLength > Int64(maxBytes) {
            bytes.task.cancel()
            throw ResponseTooLarge(maxBytes: maxBytes)
        }
        var data = Data()
        data.reserveCapacity(Int(max(0, min(response.expectedContentLength, Int64(maxBytes)))))
        for try await byte in bytes {
            guard data.count < maxBytes else {
                bytes.task.cancel()
                throw ResponseTooLarge(maxBytes: maxBytes)
            }
            data.append(byte)
        }
        return (data, response)
    }
}
