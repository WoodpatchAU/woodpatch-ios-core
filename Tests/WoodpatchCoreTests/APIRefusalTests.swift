// APIRefusalTests.swift (v1.16, BOS #5562)
// ────────────────────────────────────────────────────────────────────
// APIRefusal: a refusal counts as the server's answer only from the pinned
// origin, as JSON, as the envelope, with a well-formed code. The till's own
// cases (POSAPIClientTests, on prod since #2880) plus the reviewer's A5
// additions: a trailing-dot host, an upper-case media type, the wrong scheme
// or port, an oversized code or message.

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
                          success: Bool = false) -> Data {
        let body: [String: Any] = ["success": success,
                                   "error": ["code": code, "message": message],
                                   "meta": ["request_id": "r-1"]]
        return try! JSONSerialization.data(withJSONObject: body)
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

    // MARK: - decode

    @Test func aPinnedJSONEnvelopeIsTheServersAnswer() throws {
        let error = try APIRefusal.decode(status: 409, data: envelope(), response: reply(), pinned: Self.pinned)
        #expect(error == APIError(statusCode: 409, rawCode: "NO_OPEN_SHIFT", message: "Open a shift first.", requestId: "r-1"))
    }

    @Test(arguments: [("application/json", true), ("application/json; charset=utf-8", true),
                      ("Application/JSON", true), ("APPLICATION/JSON;charset=UTF-8", true),
                      (" application/json ", true),
                      ("application/jsonx", false), ("text/json", false), ("text/html", false),
                      (";application/json", false), ("", false)])
    func onlyJSONIsDecoded(contentType: String, decoded: Bool) {
        let data = envelope()
        let response = reply(contentType: contentType)
        if decoded {
            #expect((try? APIRefusal.decode(status: 409, data: data, response: response, pinned: Self.pinned)) != nil)
        } else {
            // Not JSON: nothing of the body is carried.
            #expect(malformedBody { try APIRefusal.decode(status: 409, data: data, response: response, pinned: Self.pinned) } == "")
        }
    }

    @Test func noContentTypeIsNotJSON() {
        let response = reply(contentType: nil)
        #expect(malformedBody { try APIRefusal.decode(status: 409, data: envelope(), response: response, pinned: Self.pinned) } == "")
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
        let response = reply(url)
        #expect(malformedBody { try APIRefusal.decode(status: 401, data: envelope(code: "DEVICE_REVOKED"), response: response, pinned: Self.pinned) } == "")
    }

    @Test(arguments: ["https://PINNED.example.test/pos/v1/x", "https://pinned.example.test:443/pos/v1/x"])
    func theSameOriginWrittenDifferentlyMatches(url: String) {
        #expect((try? APIRefusal.decode(status: 409, data: envelope(), response: reply(url), pinned: Self.pinned)) != nil)
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

    @Test func aReplyWithNoURLIsNotFromThePinnedOrigin() {
        let response = URLResponse(url: URL(string: "about:blank")!, mimeType: nil, expectedContentLength: 0, textEncodingName: nil)
        #expect(!APIRefusal.isFromPinnedOrigin(response, pinned: Self.pinned))
    }

    @Test func aSuccessEnvelopeOnAnErrorStatusIsMalformed() {
        #expect(malformedBody { try APIRefusal.decode(status: 500, data: envelope(success: true), response: reply(), pinned: Self.pinned) } != nil)
    }

    @Test func anEnvelopeWithNoErrorBlockIsMalformed() {
        let data = Data(#"{"success":false,"meta":{}}"#.utf8)
        #expect(malformedBody { try APIRefusal.decode(status: 400, data: data, response: reply(), pinned: Self.pinned) } == #"{"success":false,"meta":{}}"#)
    }

    @Test func notJSONAtAllCarriesAtMost512Bytes() {
        let page = Data(String(repeating: "x", count: 4000).utf8)
        let body = malformedBody { try APIRefusal.decode(status: 502, data: page, response: reply(), pinned: Self.pinned) }
        #expect(body?.utf8.count == APIRefusal.maxCarriedBodyBytes)
    }

    @Test func aCutThroughAMultiByteCharacterIsReplacedNotACrash() {
        // 511 ASCII bytes, then "é" (2 bytes): the cap cuts it in half.
        let data = Data((String(repeating: "a", count: 511) + "é").utf8)
        let body = malformedBody { try APIRefusal.decode(status: 502, data: data, response: reply(), pinned: Self.pinned) }
        #expect(body?.hasSuffix("\u{FFFD}") == true)
    }

    @Test func aBodyThatIsNotUTF8IsCarriedAsReplacements() {
        let data = Data([0xFF, 0xFE, 0x00, 0x41])
        let body = malformedBody { try APIRefusal.decode(status: 502, data: data, response: reply(), pinned: Self.pinned) }
        #expect(body?.contains("\u{FFFD}") == true)
    }

    /// The reviewer's A3: the code drives decisions, so a code outside 1-64 of
    /// [A-Za-z0-9_] is malformed, not the server's answer.
    @Test(arguments: ["", String(repeating: "A", count: 65), "NO OPEN", "NO-OPEN", "NÖ_OPEN", "NO_OPEN\n", "<script>"])
    func aBadCodeIsMalformed(code: String) {
        #expect(malformedBody { try APIRefusal.decode(status: 409, data: envelope(code: code), response: reply(), pinned: Self.pinned) } != nil)
    }

    @Test(arguments: ["A", String(repeating: "A", count: 64), "cluster_conflict", "CARD_3DS_REQUIRED"])
    func aWellFormedCodeIsKept(code: String) throws {
        let error = try APIRefusal.decode(status: 409, data: envelope(code: code), response: reply(), pinned: Self.pinned)
        #expect(error.rawCode == code)
    }

    @Test func aLongMessageIsCut() throws {
        let error = try APIRefusal.decode(status: 422, data: envelope(message: String(repeating: "m", count: 5000)),
                                          response: reply(), pinned: Self.pinned)
        #expect(error.message.count == APIRefusal.maxMessageCharacters)
    }

    // MARK: - requireFromPinnedOrigin

    @Test func aPinnedReplyPasses() throws {
        try APIRefusal.requireFromPinnedOrigin(reply(status: 200), status: 200, pinned: Self.pinned)
        try APIRefusal.requireFromPinnedOrigin(reply(status: 500), status: 500, pinned: Self.pinned)
    }

    @Test func aSuccessFromElsewhereIsADecodeError() {
        do {
            try APIRefusal.requireFromPinnedOrigin(reply("https://other.example.test/x", status: 200), status: 200, pinned: Self.pinned)
            Issue.record("a 2xx from another origin passed")
        } catch let APIClientError.decode(underlying) {
            #expect(underlying as? ReplyOriginError == .notThePinnedOrigin)
        } catch {
            Issue.record("unexpected \(error)")
        }
    }

    @Test func aRefusalFromElsewhereIsMalformedWithNoBody() {
        #expect(malformedBody {
            try APIRefusal.requireFromPinnedOrigin(reply("https://other.example.test/x", status: 401), status: 401, pinned: Self.pinned)
        } == "")
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
