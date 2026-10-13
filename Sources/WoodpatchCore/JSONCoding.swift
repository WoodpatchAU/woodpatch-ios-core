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
// `ISO8601DateFormatter` isn't `Sendable`, so no instance is shared:
// each decode gets a fresh one. That costs microseconds and avoids a
// class of cross-thread bugs that would surface as silent decode
// failures.
//
// Extracted unchanged from the softphone (Networking/JSONCoding.swift)
// for BOS #2562.

import Foundation

public enum JSONCoding {
    public static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let raw = try container.decode(String.self)

            let formatter = ISO8601DateFormatter()

            formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let date = formatter.date(from: raw) {
                return date
            }

            formatter.formatOptions = [.withInternetDateTime]
            if let date = formatter.date(from: raw) {
                return date
            }

            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Unparseable ISO 8601 timestamp: \(raw)"
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
