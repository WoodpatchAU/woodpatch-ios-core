// APIRefusal.swift (v1.16, BOS #5562)
// ────────────────────────────────────────────────────────────────────
// When a reply counts as the SERVER's answer. Lifted from the till's
// POSAPIClient (requireFromPinnedHost and errorEnvelope, on prod since #2880),
// tightened by the reviewer's A1-A4 on #5562, so the till and the staff app
// read a refusal by the same rules.
//
// Why it matters: an app acts on a refusal's code. Some codes end a session,
// and some wipe a credential (the staff app's requiresRePair, the till's
// device refusals). A captive portal's HTML page, a proxy's 502 page or a
// reply from any other host must never be able to do that.
//
// The rules, all of them, for a refusal to be decoded:
//   1. The reply comes from the PINNED ORIGIN: the final URL after any
//      redirect (`response.url`) is https, with the pinned host (compared
//      lower case; a trailing dot on either side is a mismatch, never folded)
//      and the pinned port (none means 443). Redirects are ALSO refused at
//      the session delegate (TrustPinning, v1.5): this is the second line,
//      not the only one.
//   2. Content-Type's media type is application/json, compared without case
//      (RFC 9110) and without parameters. "application/jsonx", a leading ";"
//      or no type at all fail.
//   3. The body is the envelope with `success: false` and an `error` block.
//   4. `error.code` is 1-64 of [A-Za-z0-9_]. `error.message` is cut to
//      `maxMessageCharacters`.
// Anything else is `.malformedErrorResponse`. Its carried body is at most
// `maxCarriedBodyBytes`, and EMPTY when rule 1 or 2 failed, so nothing from a
// portal or another host is carried at all.
//
// A WIPE (or any other irreversible step) stays each app's decision. It's
// keyed on the CODE of an `APIError` that `decode` returned, never on a
// status alone and never on a body that failed these rules. Log the code,
// never the body or the message.
//
// A 2xx is never a refusal: `decode` is for non-2xx replies only. A 2xx whose
// envelope says `success: false`, or has no `data`, is `.decode`
// (`APIEnvelope.requirePayload()`), core's documented meaning of "2xx, but
// not the expected shape" (agreed with frontend-ios, #5562).

import Foundation

/// A reply that didn't come from the pinned origin.
public enum ReplyOriginError: Error, Sendable, Equatable {
    case notThePinnedOrigin
}

public enum APIRefusal {
    /// The most of a malformed body a `.malformedErrorResponse` carries.
    public static let maxCarriedBodyBytes = 512
    /// A decoded message is cut to this many characters.
    public static let maxMessageCharacters = 500
    /// The longest error code accepted.
    public static let maxCodeLength = 64

    /// Throws unless `response` came from `pinned`'s origin. Call it on EVERY
    /// reply, 2xx included, before reading the body. A 2xx from elsewhere is
    /// `.decode(ReplyOriginError.notThePinnedOrigin)`, so nothing of it is
    /// read; a non-2xx is `.malformedErrorResponse` with an empty body.
    public static func requireFromPinnedOrigin(_ response: URLResponse, status: Int, pinned: URL) throws {
        guard isFromPinnedOrigin(response, pinned: pinned) else {
            if (200 ..< 300).contains(status) {
                throw APIClientError.decode(underlying: ReplyOriginError.notThePinnedOrigin)
            }
            throw APIClientError.malformedErrorResponse(statusCode: status, body: "")
        }
    }

    /// Whether `response`'s final URL has `pinned`'s scheme (https only), host
    /// and port. A missing URL, host or scheme on either side is a mismatch.
    public static func isFromPinnedOrigin(_ response: URLResponse, pinned: URL) -> Bool {
        guard let got = response.url, let want = origin(of: pinned), let have = origin(of: got) else { return false }
        return have == want
    }

    /// The server's refusal, for a non-2xx reply, or `.malformedErrorResponse`
    /// if any of the rules above fails. See the file header.
    public static func decode(status: Int, data: Data, response: URLResponse, pinned: URL) throws -> APIError {
        guard isFromPinnedOrigin(response, pinned: pinned), isJSON(response) else {
            throw APIClientError.malformedErrorResponse(statusCode: status, body: "")
        }
        guard let envelope = try? JSONCoding.decoder().decode(APIEnvelope<Empty, APIStandardMeta>.self, from: data),
              !envelope.success, let body = envelope.error, isCode(body.code)
        else {
            throw APIClientError.malformedErrorResponse(statusCode: status, body: carried(data))
        }
        return APIError(
            statusCode: status,
            rawCode: body.code,
            message: String(body.message.prefix(maxMessageCharacters)),
            requestId: envelope.meta?.requestId
        )
    }

    /// Content-Type's media type, without parameters or case, is
    /// application/json. Up to the first ";" exactly, so ";application/json"
    /// is an empty type, not JSON.
    public static func isJSON(_ response: URLResponse) -> Bool {
        let contentType = (response as? HTTPURLResponse)?.value(forHTTPHeaderField: "Content-Type") ?? ""
        let mediaType = String(contentType.prefix(while: { $0 != ";" })).trimmingCharacters(in: .whitespaces)
        return mediaType.caseInsensitiveCompare("application/json") == .orderedSame
    }

    // MARK: - Internals

    private struct Empty: Decodable, Sendable {}

    private struct Origin: Equatable {
        let host: String
        let port: Int
    }

    /// https, a host with no trailing dot (lower-cased), and the port (443 when
    /// none is given). Anything else has no origin, so it never matches.
    private static func origin(of url: URL) -> Origin? {
        guard url.scheme?.lowercased() == "https", let host = url.host?.lowercased(),
              !host.isEmpty, !host.hasSuffix(".")
        else { return nil }
        return Origin(host: host, port: url.port ?? 443)
    }

    private static func isCode(_ code: String) -> Bool {
        let bytes = code.utf8
        return (1 ... maxCodeLength).contains(bytes.count) && bytes.allSatisfy { byte in
            (UInt8(ascii: "A") ... UInt8(ascii: "Z")).contains(byte)
                || (UInt8(ascii: "a") ... UInt8(ascii: "z")).contains(byte)
                || (UInt8(ascii: "0") ... UInt8(ascii: "9")).contains(byte)
                || byte == UInt8(ascii: "_")
        }
    }

    /// At most `maxCarriedBodyBytes` of the body, as text. A cut through a
    /// multi-byte character becomes U+FFFD, never a crash.
    private static func carried(_ data: Data) -> String {
        String(decoding: data.prefix(maxCarriedBodyBytes), as: UTF8.self)
    }
}

extension APIEnvelope {
    /// The payload of a 2xx envelope. `success: false`, or no `data`, is
    /// `.decode`: a 2xx is never a refusal, so it can never drive one (v1.16,
    /// BOS #5562).
    public func requirePayload() throws -> Payload {
        guard success, let data else { throw APIClientError.decode(underlying: EnvelopeShapeError.noPayload) }
        return data
    }
}

/// A 2xx envelope that wasn't a success with data.
public enum EnvelopeShapeError: Error, Sendable, Equatable {
    case noPayload
}
