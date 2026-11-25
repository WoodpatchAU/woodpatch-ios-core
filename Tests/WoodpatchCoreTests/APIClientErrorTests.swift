// APIClientErrorTests.swift (v1.15, BOS #5566)
// ────────────────────────────────────────────────────────────────────
// APIClientError.isCancellation: a call its caller cancelled, however it
// surfaces, and nothing else (the reviewer's cases on #5566).

import Foundation
import Testing
@testable import WoodpatchCore

struct APIClientErrorTests {
    private static let cancellations: [any Error & Sendable] = [
        CancellationError(),
        URLError(.cancelled),
        NSError(domain: NSURLErrorDomain, code: NSURLErrorCancelled),
    ]

    @Test(arguments: 0 ..< 3)
    func aCancellationIsOneHoweverItSurfaces(index: Int) {
        let error = Self.cancellations[index]
        #expect(APIClientError.isCancellation(error))
        #expect(APIClientError.isCancellation(APIClientError.transport(underlying: error)), "wrapped by the client")
    }

    @Test func aWrappedTwiceCancellationStillCounts() {
        let twice = APIClientError.transport(underlying: APIClientError.transport(underlying: URLError(.cancelled)))
        #expect(APIClientError.isCancellation(twice))
    }

    private static let failures: [any Error & Sendable] = [
        URLError(.timedOut),
        URLError(.notConnectedToInternet),
        // -999 in another domain is someone else's code, not URLSession's cancel.
        NSError(domain: "au.example.other", code: -999),
        NSError(domain: NSCocoaErrorDomain, code: -999),
        APIClientError.decode(underlying: URLError(.cancelled)),
        APIClientError.api(APIError(statusCode: 499, rawCode: "CANCELLED", message: "", requestId: nil)),
    ]

    @Test(arguments: 0 ..< 6)
    func aFailureIsNotACancellation(index: Int) {
        let error = Self.failures[index]
        #expect(!APIClientError.isCancellation(error))
        if !(error is APIClientError) {
            #expect(!APIClientError.isCancellation(APIClientError.transport(underlying: error)))
        }
    }
}
