// JSONCodingTests.swift (v1.13, BOS #5481)
// The decoder's dates now come from two SHARED formatters with fixed options, instead of a
// fresh formatter per date field. These tests pin parity with the old path (a fresh
// ISO8601DateFormatter, fractional then whole) over every shape BOS sends and some it
// mustn't, and show concurrent decodes agree.

import Foundation
import Testing
@testable import WoodpatchCore

/// The v1.12 behaviour, kept here as the oracle.
private func oldParse(_ raw: String) -> Date? {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    if let date = formatter.date(from: raw) { return date }
    formatter.formatOptions = [.withInternetDateTime]
    return formatter.date(from: raw)
}

private let samples = [
    "2026-05-22T12:00:00+10:00", "2026-05-22T02:00:00Z", "2026-05-22T02:00:00.123Z",
    "2026-05-22T12:00:00.5+10:00", "2026-05-22T12:00:00.123456+10:00", "2026-11-24T23:59:59-03:30",
    "2026-02-29T00:00:00Z", "2028-02-29T00:00:00Z", "2026-05-22T12:00:00", "2026-05-22",
    "2026-05-22 12:00:00+10:00", "12:00:00Z", "", "yesterday", "2026-13-01T00:00:00Z",
    "2026-05-22T24:00:00Z", "2026-05-22T12:00:00+1000",
]

@Suite struct JSONCodingTests {

    @Test(arguments: samples)
    func theSharedParserMatchesTheOldFreshOne(_ raw: String) {
        #expect(JSONCoding.date(from: raw) == oldParse(raw), "\(raw)")
    }

    @Test func theDecoderUsesItAndStillRefusesGarbage() throws {
        struct D: Decodable { let at: Date }
        let ok = try JSONCoding.decoder().decode(D.self, from: Data(#"{"at":"2026-05-22T12:00:00+10:00"}"#.utf8))
        #expect(ok.at == oldParse("2026-05-22T12:00:00+10:00"))
        #expect(throws: DecodingError.self) {
            try JSONCoding.decoder().decode(D.self, from: Data(#"{"at":"yesterday"}"#.utf8))
        }
    }

    /// Shared across threads: many concurrent decodes give the same answers as one.
    @Test func concurrentParsesAgree() async {
        let parseable = samples.filter { oldParse($0) != nil }
        let results = await withTaskGroup(of: Bool.self) { group in
            for i in 0 ..< 400 {
                let raw = parseable[i % parseable.count]
                group.addTask { JSONCoding.date(from: raw) == oldParse(raw) }
            }
            var all: [Bool] = []
            for await r in group { all.append(r) }
            return all
        }
        #expect(results.count == 400 && results.allSatisfy { $0 })
    }
}
