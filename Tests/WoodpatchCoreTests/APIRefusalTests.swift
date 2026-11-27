// APIRefusalTests.swift (v1.16, BOS #5562)
// ────────────────────────────────────────────────────────────────────
// APIRefusal: a refusal counts as the server's answer only from the pinned
// origin, as JSON, as the envelope, with a well-formed code, and never on a
// 2xx. The till's own cases (POSAPIClientTests, on prod since #2880), the
// reviewer's A5 additions (a trailing-dot host, an upper-case media type, the
// wrong scheme or port, an oversized code or message) and the r1 review: a
// carried body is whole UTF-8 within the cap, a message is bounded in scalars,
// the media type folds ASCII only, and a 2xx is never decoded.

import Foundation
import Testing
@testable import WoodpatchCore

struct APIRefusalTests {
    private static let pinned = URL(string: "https://pinned.example.test/pos/v1")!

    private func reply(_ url: String = "https://pinned.example.test/pos/v1/x", status: Int = 409,
                       contentType: String? = "application/json") -> HTTPURLResponse {
        HTTPURLResponse(url: URL(string: url)!, statusCode: status, httpVersion: "HTTP/1.1",
                        headerFields: contentType.map { ["Content-Type": $0] })!
    }

    private func envelope(code: String = "NO_OPEN_SHIFT", message: String = "Open a shift first.",
                          success: Bool = false, requestId: String = "r-1") -> Data {
        let body: [String: Any] = ["success": success,
                                   "error": ["code": code, "message": message],
                                   "meta": ["request_id": requestId]]
        return try! JSONSerialization.data(withJSONObject: body)
    }

    private func decode(_ data: Data, _ response: URLResponse) throws -> APIError {
        try APIRefusal.decode(data: data, response: response, pinned: Self.pinned)
    }

    /// The body a malformed refusal carries, or nil if `run` didn't throw one.
    private func malformedBody(_ run: () throws -> Any) -> String? {
        do {
            _ = try run()
            return nil
        } catch let APIClientError.malformedErrorResponse(_, body) {
            return body
        } catch {
            return nil
        }
    }

    private func isDecodeError(_ run: () throws -> Any) -> Bool {
        do {
            _ = try run()
            return false
        } catch APIClientError.decode {
            return true
        } catch {
            return false
        }
    }

    // MARK: - decode

    @Test func aPinnedJSONEnvelopeIsTheServersAnswer() throws {
        let error = try decode(envelope(), reply())
        #expect(error == APIError(statusCode: 409, rawCode: "NO_OPEN_SHIFT", message: "Open a shift first.", requestId: "r-1"))
    }

    /// The reviewer's r1 S2: a 2xx is never a refusal, whatever its body says,
    /// so no app can key a wipe on one.
    @Test(arguments: [200, 201, 204, 299])
    func aTwoHundredIsNeverDecodedAsARefusal(status: Int) {
        let data = envelope(code: "DEVICE_REVOKED")
        #expect(isDecodeError { try decode(data, reply(status: status)) })
    }

    @Test func aReplyThatIsntHTTPIsMalformed() {
        let response = URLResponse(url: URL(string: "https://pinned.example.test/x")!, mimeType: "application/json",
                                   expectedContentLength: 0, textEncodingName: nil)
        #expect(malformedBody { try decode(envelope(), response) } == "")
    }

    @Test(arguments: [("application/json", true), ("application/json; charset=utf-8", true),
                      ("Application/JSON", true), ("APPLICATION/JSON;charset=UTF-8", true),
                      (" application/json ", true),
                      ("application/jsonx", false), ("text/json", false), ("text/html", false),
                      (";application/json", false), ("", false),
                      // Only ASCII folds (r1 nit): a Unicode look-alike isn't JSON.
                      ("application/ſon", false), ("applicatıon/json", false)])
    func onlyJSONIsDecoded(contentType: String, decoded: Bool) {
        let data = envelope()
        let response = reply(contentType: contentType)
        if decoded {
            #expect((try? decode(data, response)) != nil)
        } else {
            // Not JSON: nothing of the body is carried.
            #expect(malformedBody { try decode(data, response) } == "")
        }
    }

    /// The reviewer's r2 nit: only ASCII space and tab (OWS) are trimmed, so a
    /// no-break or other Unicode space around the type fails.
    @Test(arguments: [("\tapplication/json\t", true), ("  application/json ;charset=utf-8", true),
                      ("\u{00A0}application/json", false), ("application/json\u{00A0}", false),
                      ("\u{2003}application/json", false), ("\u{3000}application/json", false),
                      ("\napplication/json", false)])
    func onlyASCIISpaceAndTabAreTrimmed(contentType: String, json: Bool) {
        #expect(APIRefusal.isJSON(contentType: contentType) == json)
    }

    @Test func noContentTypeIsNotJSON() {
        #expect(malformedBody { try decode(envelope(), reply(contentType: nil)) } == "")
    }

    /// The reviewer's A1: scheme, host and port, all of them; a trailing dot on
    /// either side never matches.
    @Test(arguments: ["https://other.example.test/pos/v1/x",
                      "https://pinned.example.test./pos/v1/x",
                      "http://pinned.example.test/pos/v1/x",
                      "https://pinned.example.test:8443/pos/v1/x",
                      "https://sub.pinned.example.test/pos/v1/x",
                      "https://pinned.example.test.evil.test/x"])
    func anotherOriginsRefusalIsMalformedAndCarriesNothing(url: String) {
        let response = reply(url, status: 401)
        #expect(malformedBody { try decode(envelope(code: "DEVICE_REVOKED"), response) } == "")
    }

    @Test(arguments: ["https://PINNED.example.test/pos/v1/x", "https://pinned.example.test:443/pos/v1/x"])
    func theSameOriginWrittenDifferentlyMatches(url: String) {
        #expect((try? decode(envelope(), reply(url))) != nil)
    }

    @Test func aTrailingDotOnThePinnedHostMatchesNothing() {
        let pinnedWithDot = URL(string: "https://pinned.example.test./pos/v1")!
        #expect(!APIRefusal.isFromPinnedOrigin(reply(), pinned: pinnedWithDot))
        #expect(!APIRefusal.isFromPinnedOrigin(reply("https://pinned.example.test./x"), pinned: pinnedWithDot))
    }

    @Test func anExplicitPinnedPortMustMatch() {
        let pinned8443 = URL(string: "https://pinned.example.test:8443/pos/v1")!
        #expect(APIRefusal.isFromPinnedOrigin(reply("https://pinned.example.test:8443/x"), pinned: pinned8443))
        #expect(!APIRefusal.isFromPinnedOrigin(reply(), pinned: pinned8443))
    }

    @Test func anHttpPinIsNeverAnOrigin() {
        let http = URL(string: "http://pinned.example.test/pos/v1")!
        #expect(!APIRefusal.isFromPinnedOrigin(reply("http://pinned.example.test/x"), pinned: http))
    }

    @Test func aReplyWithNoHostIsNotFromThePinnedOrigin() {
        let response = URLResponse(url: URL(string: "about:blank")!, mimeType: nil, expectedContentLength: 0, textEncodingName: nil)
        #expect(!APIRefusal.isFromPinnedOrigin(response, pinned: Self.pinned))
    }

    @Test func aSuccessEnvelopeOnAnErrorStatusIsMalformed() {
        #expect(malformedBody { try decode(envelope(success: true), reply(status: 500)) } != nil)
    }

    @Test func anEnvelopeWithNoErrorBlockIsMalformed() {
        let data = Data(#"{"success":false,"meta":{}}"#.utf8)
        #expect(malformedBody { try decode(data, reply(status: 400)) } == #"{"success":false,"meta":{}}"#)
    }

    // MARK: - The carried body (r1 M1)

    @Test func notJSONAtAllCarriesAtMost512Bytes() {
        let page = Data(String(repeating: "x", count: 4000).utf8)
        let body = malformedBody { try decode(page, reply(status: 502)) }
        #expect(body?.utf8.count == APIRefusal.maxCarriedBodyBytes)
    }

    /// 511 ASCII bytes then "é" (2 bytes): the cap would split it, so the cut
    /// backs off to the whole character before it. No U+FFFD, never over 512.
    @Test func aCutThroughAMultiByteCharacterBacksOffToABoundary() {
        let data = Data((String(repeating: "a", count: 511) + "é").utf8)
        let body = malformedBody { try decode(data, reply(status: 502)) }
        #expect(body == String(repeating: "a", count: 511))
        #expect(body?.contains("\u{FFFD}") == false)
    }

    @Test(arguments: [1, 2, 3])
    func aCutThroughAFourByteCharacterBacksOff(asciiBefore: Int) {
        // A 4-byte emoji placed so the 512 cap splits it at every offset.
        let lead = String(repeating: "a", count: APIRefusal.maxCarriedBodyBytes - 4 + asciiBefore)
        let data = Data((lead + "🪵" + "tail").utf8)
        let body = malformedBody { try decode(data, reply(status: 502)) }
        #expect(body == lead)
        #expect((body?.utf8.count ?? .max) <= APIRefusal.maxCarriedBodyBytes)
    }

    /// 512 bytes that aren't UTF-8 at all carry nothing (they'd be 1,536 bytes
    /// of U+FFFD otherwise).
    @Test func aBodyThatIsNotUTF8CarriesNothing() {
        let body = malformedBody { try decode(Data(repeating: 0xFF, count: 512), reply(status: 502)) }
        #expect(body == "")
    }

    @Test func aBodyWithABadByteBeforeTheCutCarriesNothing() {
        let body = malformedBody { try decode(Data([0x41, 0xFF, 0x41]), reply(status: 502)) }
        #expect(body == "")
    }

    // MARK: - The carried body, strict UTF-8 at the cut (r2 S1)

    /// 512 - tail.count ASCII bytes, then `tail` ending at byte 511, then more
    /// bytes, so the cap always cuts right after `tail`.
    private func cutAfter(_ tail: [UInt8]) -> Data {
        Data(Array(repeating: UInt8(ascii: "a"), count: APIRefusal.maxCarriedBodyBytes - tail.count) + tail
            + Array("more".utf8))
    }

    /// The reviewer's r2 cases: an invalid tail at the cut isn't a split
    /// character, so it isn't dropped; it fails, and nothing is carried.
    @Test(arguments: [[0xC0], [0xC1], [0xF5], [0xF7], // bytes that never lead
                      [0xED, 0xA0], [0xED, 0xBF], // a surrogate's first two bytes
                      [0xE0, 0x80], [0xE0, 0x9F], // an overlong 3-byte form
                      [0xF0, 0x80, 0x80], [0xF0, 0x8F, 0xBF], // an overlong 4-byte form
                      [0xF4, 0x90], [0xF4, 0x90, 0x80], [0xF4, 0xBF, 0xBF]] as [[UInt8]]) // above U+10FFFF
    func anInvalidTailAtTheCutCarriesNothing(tail: [UInt8]) {
        #expect(malformedBody { try decode(cutAfter(tail), reply(status: 502)) } == "")
    }

    /// A valid start of a character that the cap cut is dropped, and the rest
    /// carried: the edges of each lead's allowed second byte.
    @Test(arguments: [[0xC2], [0xDF], [0xE0], [0xE0, 0xA0], [0xED, 0x9F], [0xEF, 0xBF],
                      [0xF0, 0x90], [0xF0, 0x90, 0x80], [0xF4, 0x8F, 0xBF], [0xF1, 0x80, 0x80]] as [[UInt8]])
    func aValidStartAtTheCutIsDropped(tail: [UInt8]) {
        let body = malformedBody { try decode(cutAfter(tail), reply(status: 502)) }
        #expect(body == String(repeating: "a", count: APIRefusal.maxCarriedBodyBytes - tail.count))
    }

    /// A whole invalid sequence inside the cap is never carried, whatever the
    /// platform's own decoder thinks of it: a surrogate (CESU-8), overlongs
    /// (2-, 3- and 4-byte), and a scalar above U+10FFFF. These pin
    /// isStrictUTF8 itself, which the model test below uses as its reference
    /// (the reviewer's r3 nit).
    @Test(arguments: [[0xED, 0xA0, 0x80], [0xC0, 0x80], [0xC1, 0xBF], [0xE0, 0x80, 0x80],
                      [0xF0, 0x80, 0x80, 0x80], [0xF4, 0x90, 0x80, 0x80]] as [[UInt8]])
    func aWholeInvalidSequenceIsNotUTF8(sequence: [UInt8]) {
        let body = malformedBody { try decode(Data([0x41] + sequence + [0x41]), reply(status: 502)) }
        #expect(body == "")
        #expect(!APIRefusal.isStrictUTF8([0x41] + sequence + [0x41]))
    }

    /// The reviewer's model, as a test: every tail of up to three bytes from an
    /// alphabet of each byte class's edges, at the cut, against a reference that
    /// asks the strict decoder directly. The answer is the longest prefix that
    /// drops nothing but a character the cap split (a tail some continuation
    /// completes into strict UTF-8), or "" when there's none.
    @Test func everyTailAtTheCutMatchesAStrictDecoder() {
        let alphabet: [UInt8] = [0x41, 0x7F, 0x80, 0x8F, 0x90, 0x9F, 0xA0, 0xBF, 0xC0, 0xC1, 0xC2, 0xDF,
                                 0xE0, 0xE1, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF3, 0xF4, 0xF5, 0xF7, 0xF8, 0xFF]
        var tails: [[UInt8]] = alphabet.map { [$0] }
        for a in alphabet { for b in alphabet { tails.append([a, b]) } }
        for a in alphabet { for b in alphabet { for c in alphabet { tails.append([a, b, c]) } } }
        var mismatches: [[UInt8]] = []
        for tail in tails {
            let data = cutAfter(tail)
            if APIRefusal.carried(data) != reference(Array(data.prefix(APIRefusal.maxCarriedBodyBytes))) {
                mismatches.append(tail)
            }
        }
        #expect(tails.count == 18_278)
        #expect(mismatches.isEmpty, "\(mismatches.count) tails differ, first \(mismatches.prefix(5))")
    }

    /// The strict answer for a cut body, from the standard library's decoder.
    private func reference(_ cut: [UInt8]) -> String {
        for dropped in 0 ... 3 where dropped <= cut.count {
            let kept = Array(cut.dropLast(dropped))
            let tail = Array(cut.suffix(dropped))
            guard APIRefusal.isStrictUTF8(kept), dropped == 0 || completes(tail) else { continue }
            return String(decoding: kept, as: UTF8.self)
        }
        return ""
    }

    /// Whether some continuation bytes turn `tail` (1-3 bytes, cut short) into
    /// exactly one strict scalar. Only the second byte is ever restricted, so
    /// trying each second byte and padding with 0x80 covers every completion.
    private func completes(_ tail: [UInt8]) -> Bool {
        for length in (tail.count + 1) ... 4 {
            let seconds: [UInt8] = tail.count >= 2 ? [tail[1]] : Array(0x80 ... 0xBF)
            for second in seconds {
                var bytes = Array(tail.prefix(1)) + [second] + Array(tail.dropFirst(2))
                while bytes.count < length { bytes.append(0x80) }
                var iterator = bytes.makeIterator()
                var decoder = UTF8()
                if case .scalarValue = decoder.decode(&iterator), case .emptyInput = decoder.decode(&iterator) {
                    return true
                }
            }
        }
        return false
    }

    @Test func aWholeShortUTF8BodyIsCarriedAsIs() {
        let body = malformedBody { try decode(Data("Bad Gateway: café".utf8), reply(status: 502)) }
        #expect(body == "Bad Gateway: café")
    }

    // MARK: - The code, the message and the request id (A3, r1 S1)

    /// The code drives decisions, so a code outside 1-64 of [A-Za-z0-9_] is
    /// malformed, not the server's answer.
    @Test(arguments: ["", String(repeating: "A", count: 65), "NO OPEN", "NO-OPEN", "NÖ_OPEN", "NO_OPEN\n", "<script>"])
    func aBadCodeIsMalformed(code: String) {
        #expect(malformedBody { try decode(envelope(code: code), reply()) } != nil)
    }

    @Test(arguments: ["A", String(repeating: "A", count: 64), "cluster_conflict", "CARD_3DS_REQUIRED"])
    func aWellFormedCodeIsKept(code: String) throws {
        #expect(try decode(envelope(code: code), reply()).rawCode == code)
    }

    @Test func aLongMessageIsCutInScalars() throws {
        let error = try decode(envelope(message: String(repeating: "m", count: 5000)), reply(status: 422))
        #expect(error.message.unicodeScalars.count == APIRefusal.maxMessageScalars)
    }

    /// One Character can hold any number of combining marks: the cut counts
    /// scalars, so 500 "characters" of zalgo can't run to megabytes.
    @Test func aMessageOfCombiningMarksIsBoundedInBytes() throws {
        let zalgo = String(repeating: "a" + String(repeating: "\u{0301}", count: 200), count: 100)
        let error = try decode(envelope(message: zalgo), reply(status: 422))
        #expect(error.message.unicodeScalars.count == APIRefusal.maxMessageScalars)
        #expect(error.message.utf8.count <= APIRefusal.maxMessageScalars * 4)
    }

    @Test func aNonASCIIMessageIsKeptWhole() throws {
        #expect(try decode(envelope(message: "Ouvrez une caisse d'abord — 先开班"), reply()).message
            == "Ouvrez une caisse d'abord — 先开班")
    }

    @Test func aLongRequestIdIsCut() throws {
        let error = try decode(envelope(requestId: String(repeating: "r", count: 10_000)), reply())
        #expect(error.requestId?.unicodeScalars.count == APIRefusal.maxRequestIdScalars)
    }

    // MARK: - requireFromPinnedOrigin

    @Test func aPinnedReplyPasses() throws {
        try APIRefusal.requireFromPinnedOrigin(reply(status: 200), pinned: Self.pinned)
        try APIRefusal.requireFromPinnedOrigin(reply(status: 500), pinned: Self.pinned)
    }

    @Test func aSuccessFromElsewhereIsADecodeError() {
        do {
            try APIRefusal.requireFromPinnedOrigin(reply("https://other.example.test/x", status: 200), pinned: Self.pinned)
            Issue.record("a 2xx from another origin passed")
        } catch let APIClientError.decode(underlying) {
            #expect(underlying as? ReplyOriginError == .notThePinnedOrigin)
        } catch {
            Issue.record("unexpected \(error)")
        }
    }

    @Test func aRefusalFromElsewhereIsMalformedWithNoBody() {
        #expect(malformedBody {
            try APIRefusal.requireFromPinnedOrigin(reply("https://other.example.test/x", status: 401), pinned: Self.pinned)
        } == "")
    }

    /// The reviewer's r2 nit: the same rule as decode, so a reply that isn't
    /// HTTP never passes, even with the pinned URL.
    @Test func aReplyThatIsntHTTPNeverPasses() {
        let response = URLResponse(url: URL(string: "https://pinned.example.test/x")!, mimeType: "application/json",
                                   expectedContentLength: 0, textEncodingName: nil)
        #expect(malformedBody { try APIRefusal.requireFromPinnedOrigin(response, pinned: Self.pinned) } == "")
    }

    // MARK: - requirePayload

    private struct Thing: Decodable, Sendable, Equatable { let id: Int }

    private func decoded(_ json: String) throws -> APIEnvelope<Thing, APIStandardMeta> {
        try JSONCoding.decoder().decode(APIEnvelope<Thing, APIStandardMeta>.self, from: Data(json.utf8))
    }

    @Test func aSuccessWithDataIsThePayload() throws {
        #expect(try decoded(#"{"success":true,"data":{"id":7}}"#).requirePayload() == Thing(id: 7))
    }

    @Test(arguments: [#"{"success":false,"data":{"id":7},"error":{"code":"DEVICE_REVOKED","message":"x"}}"#,
                      #"{"success":true}"#,
                      #"{"success":false,"error":{"code":"DEVICE_REVOKED","message":"x"}}"#])
    func aTwoHundredThatIsntASuccessWithDataIsADecodeError(json: String) throws {
        let envelope = try decoded(json)
        do {
            _ = try envelope.requirePayload()
            Issue.record("passed")
        } catch let APIClientError.decode(underlying) {
            #expect(underlying as? EnvelopeShapeError == .noPayload)
        }
    }
}
