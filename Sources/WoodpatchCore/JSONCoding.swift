// JSONCoding.swift
// ────────────────────────────────────────────────────────────────────
// JSONEncoder / JSONDecoder factories matching the BOS API conventions:
//
//   - snake_case keys are mapped per DTO with explicit `CodingKeys`
//     (chosen over `.convertFromSnakeCase` so each mapping is visible
//     in its DTO file rather than implicit).
//   - Dates are ISO 8601 with timezone offsets, e.g.
//     `2026-05-22T12:00:00+10:00`. Some servers emit fractional
//     seconds, so the decoder tries both forms.
//
// v1.13 (BOS #5481, the reviewer's efficiency audit): the decoder used to build a fresh
// `ISO8601DateFormatter` for EVERY date field, and mutate its options between the two tries.
// Now there are two formatters, each with its options fixed at creation and never changed
// again, shared by every decode. Apple documents the date formatters as thread-safe for
// parsing; what wasn't safe was mutating `formatOptions` on a shared instance, and nothing
// does that now. The parse semantics are the same by construction (the same class, the same
// two option sets, tried in the same order). JSONCodingTests pins parity against the old
// fresh-formatter path.
//
// Extracted from the softphone (Networking/JSONCoding.swift) for BOS #2562.

import Foundation

public enum JSONCoding {
    /// Immutable after init (options set once), so sharing it is safe. `@unchecked Sendable`
    /// because Foundation doesn't mark the class Sendable.
    private final class Parsers: @unchecked Sendable {
        let fractional: ISO8601DateFormatter
        let whole: ISO8601DateFormatter

        init() {
            fractional = ISO8601DateFormatter()
            fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            whole = ISO8601DateFormatter()
            whole.formatOptions = [.withInternetDateTime]
        }
    }

    private static let parsers = Parsers()

    /// A BOS ISO 8601 timestamp, with or without fractional seconds. nil = unparseable.
    public static func date(from raw: String) -> Date? {
        parsers.fractional.date(from: raw) ?? parsers.whole.date(from: raw)
    }

    public static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let raw = try container.decode(String.self)
            if let date = date(from: raw) { return date }
            // Never the value itself (v1.15, BOS #5566): an error's description
            // reaches logs, and the field could hold anything the server sent.
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Unparseable ISO 8601 timestamp"
            )
        }
        return decoder
    }

    public static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }
}
