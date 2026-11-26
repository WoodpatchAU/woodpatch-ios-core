// APIRefusal.swift (v1.16, BOS #5562)
// ────────────────────────────────────────────────────────────────────
// When a reply counts as the SERVER's answer. Lifted from the till's
// POSAPIClient (requireFromPinnedHost and errorEnvelope, on prod since #2880),
// tightened by the reviewer's A1-A4 and r1 review on #5562, so the till and
// the staff app read a refusal by the same rules.
//
// Why it matters: an app acts on a refusal's code. Some codes end a session,
// and some wipe a credential (the staff app's requiresRePair, the till's
// device refusals). A captive portal's HTML page, a proxy's 502 page or a
// reply from any other host must never be able to do that.
//
// The rules, all of them, for a refusal to be decoded:
//   0. The reply is HTTP and its status is NOT 2xx (read from the reply
//      itself, never passed in separately). A 2xx is never a refusal.
//   1. The reply comes from the PINNED ORIGIN: the final URL after any
//      redirect (`response.url`) is https, with the pinned host (compared
//      lower case; a trailing dot on either side is a mismatch, never folded)
//      and the pinned port (none means 443). Redirects are ALSO refused at
//      the session delegate (TrustPinning, v1.5): this is the second line,
//      not the only one.
//   2. Content-Type's media type is application/json, compared without ASCII
//      case (RFC 9110) and without parameters. Only ASCII letters fold, and
//      only ASCII space and tab are trimmed (RFC 9110's OWS), so no Unicode
//      look-alike or Unicode space passes. "application/jsonx", a leading ";" or no
//      type at all fail.
//   3. The body is the envelope with `success: false` and an `error` block.
//   4. `error.code` is 1-64 of [A-Za-z0-9_]. `error.message` is cut to
//      `maxMessageScalars` Unicode scalars, and `meta.request_id` to
//      `maxRequestIdScalars`.
// Anything else is `.malformedErrorResponse` (a 2xx is `.decode`). Its
// carried body is at most `maxCarriedBodyBytes` of UTF-8, cut on a character
// boundary, and EMPTY when rule 0, 1 or 2 failed or the carried bytes aren't
// strict UTF-8, so nothing from a portal or another host is carried at all.
// Only the bytes within the cap are checked: bytes past it are never read.
//
// A WIPE (or any other irreversible step) stays each app's decision. It's
// keyed on the CODE of an `APIError` that `decode` returned, never on a
// status alone and never on a body that failed these rules. Log the code,
// never the body, the message or the request id.
//
// A 2xx whose envelope says `success: false`, or has no `data`, is `.decode`
// (`APIEnvelope.requirePayload()`), core's documented meaning of "2xx, but
// not the expected shape" (agreed with frontend-ios, #5562).

import Foundation

/// A reply that didn't come from the pinned origin.
public enum ReplyOriginError: Error, Sendable, Equatable {
    case notThePinnedOrigin
}

public enum APIRefusal {
    /// The most UTF-8 bytes of a malformed body a `.malformedErrorResponse`
    /// carries.
    public static let maxCarriedBodyBytes = 512
    /// A decoded message is cut to this many Unicode scalars (at most four
    /// times as many bytes).
    public static let maxMessageScalars = 500
    /// A decoded request id is cut to this many Unicode scalars.
    public static let maxRequestIdScalars = 128
    /// The longest error code accepted.
    public static let maxCodeLength = 64

    /// Throws unless `response` is HTTP and came from `pinned`'s origin. Call
    /// it on EVERY reply, 2xx included, before reading the body. A 2xx from
    /// elsewhere is `.decode(ReplyOriginError.notThePinnedOrigin)`, so nothing
    /// of it is read; anything else (a reply that isn't HTTP is status 0) is
    /// `.malformedErrorResponse` with an empty body. The same rule as `decode`.
    public static func requireFromPinnedOrigin(_ response: URLResponse, pinned: URL) throws {
        guard response is HTTPURLResponse, isFromPinnedOrigin(response, pinned: pinned) else {
            let status = statusCode(response)
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

    /// The server's refusal, for a non-2xx reply. A 2xx is `.decode` (it's
    /// never a refusal); any other broken rule is `.malformedErrorResponse`.
    /// See the file header.
    public static func decode(data: Data, response: URLResponse, pinned: URL) throws -> APIError {
        let status = statusCode(response)
        guard !(200 ..< 300).contains(status) else {
            throw APIClientError.decode(underlying: EnvelopeShapeError.noPayload)
        }
        guard response is HTTPURLResponse, isFromPinnedOrigin(response, pinned: pinned), isJSON(response) else {
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
            message: scalars(body.message, max: maxMessageScalars),
            requestId: envelope.meta?.requestId.map { scalars($0, max: maxRequestIdScalars) }
        )
    }

    /// Content-Type's media type, without parameters or ASCII case, is
    /// application/json. Up to the first ";" exactly, so ";application/json"
    /// is an empty type, not JSON.
    public static func isJSON(_ response: URLResponse) -> Bool {
        isJSON(contentType: (response as? HTTPURLResponse)?.value(forHTTPHeaderField: "Content-Type") ?? "")
    }

    /// The media-type rule on a Content-Type value itself. Only ASCII space
    /// and tab are trimmed (OWS, RFC 9110), so a no-break or other Unicode
    /// space around the type fails.
    static func isJSON(contentType: String) -> Bool {
        var got = Array(contentType.utf8.prefix(while: { $0 != UInt8(ascii: ";") }))
        while let last = got.last, isOWS(last) { got.removeLast() }
        let start = got.firstIndex(where: { !isOWS($0) }) ?? got.endIndex
        got.removeSubrange(..<start)
        let want = Array("application/json".utf8)
        return got.count == want.count && zip(got, want).allSatisfy { asciiLower($0) == $1 }
    }

    // MARK: - Internals

    private struct Empty: Decodable, Sendable {}

    private struct Origin: Equatable {
        let host: String
        let port: Int
    }

    /// The reply's HTTP status, or 0 for a reply that isn't HTTP.
    private static func statusCode(_ response: URLResponse) -> Int {
        (response as? HTTPURLResponse)?.statusCode ?? 0
    }

    /// https, a host with no trailing dot (lower-cased), and the port (443 when
    /// none is given). Anything else has no origin, so it never matches.
    private static func origin(of url: URL) -> Origin? {
        guard url.scheme?.lowercased() == "https", let host = url.host?.lowercased(),
              !host.isEmpty, !host.hasSuffix(".")
        else { return nil }
        return Origin(host: host, port: url.port ?? 443)
    }

    private static func isOWS(_ byte: UInt8) -> Bool {
        byte == UInt8(ascii: " ") || byte == UInt8(ascii: "\t")
    }

    private static func asciiLower(_ byte: UInt8) -> UInt8 {
        (UInt8(ascii: "A") ... UInt8(ascii: "Z")).contains(byte) ? byte + 32 : byte
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

    /// At most `max` Unicode scalars of `text`. A Character can hold any number
    /// of combining scalars, so scalars, not Characters, bound the size.
    private static func scalars(_ text: String, max: Int) -> String {
        var view = String.UnicodeScalarView()
        view.append(contentsOf: text.unicodeScalars.prefix(max))
        return String(view)
    }

    /// At most `maxCarriedBodyBytes` of the body, cut back to a whole UTF-8
    /// character, or "" if what's left isn't strict UTF-8. Never a U+FFFD, so
    /// the carried text is never longer than the cap. Bytes past the cap are
    /// never read or validated.
    static func carried(_ data: Data) -> String {
        var cut = Array(data.prefix(maxCarriedBodyBytes))
        if data.count > cut.count, let start = splitCharacterStart(cut) { cut.removeSubrange(start...) }
        return isStrictUTF8(cut) ? String(decoding: cut, as: UTF8.self) : ""
    }

    /// Whether `bytes` are strict UTF-8 (RFC 3629: no overlongs, surrogates,
    /// or scalars above U+10FFFF), by the standard library's decoder rather
    /// than Foundation's, so the rule doesn't vary by platform.
    static func isStrictUTF8(_ bytes: [UInt8]) -> Bool {
        var iterator = bytes.makeIterator()
        var decoder = UTF8()
        while true {
            switch decoder.decode(&iterator) {
            case .scalarValue: continue
            case .emptyInput: return true
            case .error: return false
            }
        }
    }

    /// Where the character the cap split begins, or nil when the cap split
    /// nothing. Split means: a VALID lead byte in the last three bytes, followed
    /// only by continuation bytes the lead allows, and fewer of them than it
    /// needs. That is exactly a strict decoder's "valid so far, but incomplete".
    /// Any other tail (an invalid lead such as C0, C1 or F5-F7, a surrogate
    /// ED A0-BF, an overlong E0 80-9F or F0 80-8F, or F4 90-BF above U+10FFFF)
    /// isn't a split character, so it stays in and fails validation as itself.
    static func splitCharacterStart(_ bytes: [UInt8]) -> Int? {
        var lead = bytes.count - 1
        while lead >= 0, lead >= bytes.count - 3, isContinuation(bytes[lead]) { lead -= 1 }
        guard lead >= 0, !isContinuation(bytes[lead]) else { return nil }
        let have = bytes.count - lead
        guard sequenceLength(bytes[lead]) > have else { return nil }
        if have >= 2, !secondByteRange(bytes[lead]).contains(bytes[lead + 1]) { return nil }
        return lead
    }

    private static func isContinuation(_ byte: UInt8) -> Bool {
        byte & 0xC0 == 0x80
    }

    /// How many bytes a UTF-8 sequence starting with `lead` has, or 1 for a
    /// byte that can't lead one (C0, C1, F5-FF and the continuation bytes),
    /// which then fails validation as itself (RFC 3629).
    private static func sequenceLength(_ lead: UInt8) -> Int {
        switch lead {
        case 0xC2 ... 0xDF: 2
        case 0xE0 ... 0xEF: 3
        case 0xF0 ... 0xF4: 4
        default: 1
        }
    }

    /// The second bytes `lead` allows (RFC 3629): E0 and F0 refuse overlongs,
    /// ED refuses the surrogates, F4 refuses anything above U+10FFFF.
    private static func secondByteRange(_ lead: UInt8) -> ClosedRange<UInt8> {
        switch lead {
        case 0xE0: 0xA0 ... 0xBF
        case 0xED: 0x80 ... 0x9F
        case 0xF0: 0x90 ... 0xBF
        case 0xF4: 0x80 ... 0x8F
        default: 0x80 ... 0xBF
        }
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

/// A 2xx envelope that wasn't a success with data, or a 2xx handed to
/// `APIRefusal.decode`.
public enum EnvelopeShapeError: Error, Sendable, Equatable {
    case noPayload
}
