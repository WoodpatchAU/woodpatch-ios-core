// BoundedImageTests.swift (v1.14, BOS #5560)
// The bounded decode lifted from the till's ImageGate, and the byte-capped send. The pictures
// are made here with CoreGraphics and ImageIO (no UIKit, like the code under test), except the
// WebP, which ImageIO can't write.

import CoreGraphics
import Foundation
import ImageIO
import Testing
import UniformTypeIdentifiers
@testable import WoodpatchCore

@Suite struct BoundedImageTests {
    private let web = BoundedImage.webRenditionTypes
    private let fortyMP = 40_000_000

    private func thumb(_ data: Data?, _ size: Int = 600, types: Set<UTType>? = nil) -> CGImage? {
        guard let data else { return nil }
        return BoundedImage.thumbnail(data, maxPixelSize: size, maxSourcePixels: fortyMP, allowedTypes: types ?? web)
    }

    @Test func theTypeIsReadFromTheBytesAndMustBeAllowed() throws {
        #expect(thumb(try #require(Pictures.encoded(.png, width: 40, height: 40))) != nil)
        #expect(thumb(try #require(Pictures.encoded(.jpeg, width: 40, height: 40))) != nil)
        #expect(thumb(Pictures.webp) != nil, "WebP: VAULT's renditions")
        #expect(thumb(Pictures.svg) == nil, "never SVG")
        #expect(thumb(Pictures.pdf) == nil, "never PDF")
        #expect(thumb(Data("not a picture".utf8)) == nil)
        #expect(thumb(Data()) == nil)
        let gif = try #require(Pictures.encoded(.gif, width: 8, height: 8))
        #expect(thumb(gif) == nil, "a type the caller didn't allow is refused")
        #expect(thumb(gif, types: [.gif]) != nil, "and allowed when it does")
        // A PNG is a PNG whatever it's called: only the bytes decide.
        #expect(thumb(try #require(Pictures.encoded(.png, width: 8, height: 8)), types: [.jpeg]) == nil)
        #expect(BoundedImage.type(of: gif) == .gif && BoundedImage.type(of: Pictures.svg) == nil)
    }

    /// Exact types only: allowing a supertype (.image) must not let every parser in.
    @Test func aSupertypeAllowsNothing() throws {
        let png = try #require(Pictures.encoded(.png, width: 8, height: 8))
        #expect(thumb(png, types: [.image]) == nil)
        #expect(thumb(png, types: []) == nil)
    }

    @Test func theLongSideIsBoundedAndASmallPictureIsntEnlarged() throws {
        let big = try #require(thumb(Pictures.encoded(.png, width: 1200, height: 800)))
        #expect(big.width == 600 && big.height == 400)
        let tall = try #require(thumb(Pictures.encoded(.jpeg, width: 300, height: 900), 450))
        #expect(tall.width == 150 && tall.height == 450)
        let small = try #require(thumb(Pictures.encoded(.png, width: 120, height: 90)))
        #expect(small.width == 120 && small.height == 90)
        #expect(thumb(Pictures.encoded(.png, width: 40, height: 40), 0) == nil, "no size is no picture, never full size")
        #expect(thumb(Pictures.encoded(.png, width: 40, height: 40), -1) == nil)
    }

    /// A real PNG whose IHDR then claims 8000 × 6000 (48 MP): refused from the header, unread.
    @Test func aHeaderOverTheBudgetIsRefusedUndecoded() throws {
        let png = try #require(Pictures.encoded(.png, width: 8, height: 8))
        #expect(thumb(png) != nil)
        #expect(thumb(Pictures.withPNGSize(png, width: 8000, height: 6000)) == nil)
        #expect(BoundedImage.thumbnail(png, maxPixelSize: 600, maxSourcePixels: 63, allowedTypes: web) == nil, "64 px over a 63 budget")
        #expect(BoundedImage.thumbnail(png, maxPixelSize: 600, maxSourcePixels: 64, allowedTypes: web) != nil)
    }

    @Test func thePixelBudgetNeverWraps() {
        #expect(BoundedImage.withinPixelBudget(width: 6000, height: 6000, maxSourcePixels: fortyMP))
        #expect(!BoundedImage.withinPixelBudget(width: 8000, height: 6000, maxSourcePixels: fortyMP))
        #expect(!BoundedImage.withinPixelBudget(width: 0, height: 10, maxSourcePixels: fortyMP))
        #expect(!BoundedImage.withinPixelBudget(width: 10, height: -1, maxSourcePixels: fortyMP))
        #expect(!BoundedImage.withinPixelBudget(width: 10, height: 10, maxSourcePixels: 0))
        // A forged header's product overflows: refused, never a wrapped negative that "passes".
        #expect(!BoundedImage.withinPixelBudget(width: 4_294_967_295, height: 4_294_967_295, maxSourcePixels: .max))
        #expect(!BoundedImage.withinPixelBudget(width: Int.max, height: 2, maxSourcePixels: .max))
        #expect(!BoundedImage.withinPixelBudget(width: 3_037_000_500, height: 3_037_000_500, maxSourcePixels: .max))
    }

    /// The till's exact rules give the till's answers (it adopts this with its own constants).
    @Test func theTillsRulesAsBefore() throws {
        let png = try #require(Pictures.encoded(.png, width: 1200, height: 800))
        let tills = try #require(BoundedImage.thumbnail(png, maxPixelSize: 600, maxSourcePixels: 40_000_000,
                                                        allowedTypes: [.jpeg, .png, .webP]))
        #expect(tills.width == 600 && tills.height == 400)
    }
}

/// `send(_:maxBytes:)` on a real URLSession over a stub protocol: the cap holds while the
/// bytes arrive, from the announced length or the count.
@Suite(.serialized, .timeLimit(.minutes(1)))
struct ByteCappedSendTests {
    private func session() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [ChunkedStub.self]
        return URLSession(configuration: configuration)
    }

    private func request(_ path: String) -> URLRequest { URLRequest(url: URL(string: "https://stub.invalid\(path)")!) }

    @Test func withinTheCapTheWholeBodyComesBack() async throws {
        ChunkedStub.serve(chunks: [Data(count: 300), Data(count: 300)], announce: false)
        let (data, response) = try await session().send(request("/ok"), maxBytes: 600)
        #expect(data.count == 600 && (response as? HTTPURLResponse)?.statusCode == 200)
    }

    @Test func anAnnouncedLengthOverTheCapIsRefusedBeforeTheBody() async {
        ChunkedStub.serve(chunks: [Data(count: 2_000)], announce: true)
        await #expect(throws: ResponseTooLarge(maxBytes: 1_000)) { try await session().send(request("/big"), maxBytes: 1_000) }
    }

    /// No Content-Length (chunked): counted as it arrives, and refused at the byte past the cap.
    @Test func anUnannouncedBodyIsRefusedAsItPassesTheCap() async {
        ChunkedStub.serve(chunks: Array(repeating: Data(count: 400), count: 5), announce: false)
        await #expect(throws: ResponseTooLarge(maxBytes: 1_000)) { try await session().send(request("/stream"), maxBytes: 1_000) }
    }

    @Test func aCapOfNothingIsRefused() async {
        ChunkedStub.serve(chunks: [Data(count: 1)], announce: false)
        await #expect(throws: ResponseTooLarge(maxBytes: 0)) { try await session().send(request("/zero"), maxBytes: 0) }
    }

    @Test func aStubsCheck() throws {
        #expect(try ResponseTooLarge.check(Data(count: 10), maxBytes: 10).count == 10)
        #expect(throws: ResponseTooLarge(maxBytes: 9)) { try ResponseTooLarge.check(Data(count: 10), maxBytes: 9) }
        #expect(throws: ResponseTooLarge(maxBytes: 0)) { try ResponseTooLarge.check(Data(), maxBytes: 0) }
    }
}

// MARK: - Test doubles

/// Serves one scripted body in chunks, with or without a Content-Length.
final class ChunkedStub: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) private static var chunks: [Data] = []
    nonisolated(unsafe) private static var announce = false
    private static let lock = NSLock()

    static func serve(chunks: [Data], announce: Bool) {
        lock.withLock { self.chunks = chunks; self.announce = announce }
    }

    override class func canInit(with _: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let (chunks, announce) = Self.lock.withLock { (Self.chunks, Self.announce) }
        var headers = ["Content-Type": "application/octet-stream"]
        if announce { headers["Content-Length"] = String(chunks.reduce(0) { $0 + $1.count }) }
        let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: headers)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        for chunk in chunks { client?.urlProtocol(self, didLoad: chunk) }
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

private enum Pictures {
    /// A width × height picture in `type`, drawn and encoded with CoreGraphics and ImageIO.
    static func encoded(_ type: UTType, width: Int, height: Int) -> Data? {
        guard let context = CGContext(data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0,
                                      space: CGColorSpaceCreateDeviceRGB(),
                                      bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)
        else { return nil }
        context.setFillColor(CGColor(red: 0.2, green: 0.5, blue: 0.4, alpha: 1))
        context.fill(CGRect(x: 0, y: 0, width: width, height: height))
        guard let image = context.makeImage() else { return nil }
        let data = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(data, type.identifier as CFString, 1, nil) else { return nil }
        CGImageDestinationAddImage(destination, image, nil)
        return CGImageDestinationFinalize(destination) ? data as Data : nil
    }

    /// An 8 × 8 lossless WebP (made with Pillow), as bytes: the till's fixture.
    static let webp = Data(base64Encoded: "UklGRh4AAABXRUJQVlA4TBEAAAAvB8ABAAdQvOIVr/+BiOh/AAA=")!

    /// `png` with its IHDR's width and height replaced (and the chunk's CRC recomputed), so the
    /// header claims a size the bytes don't hold.
    static func withPNGSize(_ png: Data, width: UInt32, height: UInt32) -> Data {
        var bytes = [UInt8](png)
        // Signature (8), length (4), "IHDR" (4), then width and height, big-endian.
        for (offset, value) in [(16, width), (20, height)] {
            for i in 0 ..< 4 { bytes[offset + i] = UInt8((value >> (24 - 8 * UInt32(i))) & 0xFF) }
        }
        let crc = crc32(bytes[12 ..< 29]) // "IHDR" + its 13 data bytes
        for i in 0 ..< 4 { bytes[29 + i] = UInt8((crc >> (24 - 8 * UInt32(i))) & 0xFF) }
        return Data(bytes)
    }

    private static func crc32(_ bytes: ArraySlice<UInt8>) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in bytes {
            crc ^= UInt32(byte)
            for _ in 0 ..< 8 { crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB8_8320 : crc >> 1 }
        }
        return ~crc
    }

    static let svg = Data(#"<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect width="10" height="10"/></svg>"#.utf8)
    static let pdf = Data("%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF".utf8)
}
