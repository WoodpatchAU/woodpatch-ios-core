// EnvelopeAndKeychainTests.swift: wire envelope decoding, JSON dates, and the
// generic KeychainStore (BOS #2562).

import Foundation
import Security
import Testing
@testable import WoodpatchCore

struct EnvelopeTests {
    struct Item: Decodable, Sendable, Equatable { let id: Int }
    /// An app adding its own meta field (the softphone's `total_unread` shape).
    struct CommsMeta: Decodable, Sendable { let totalUnread: Int?
        enum CodingKeys: String, CodingKey { case totalUnread = "total_unread" }
    }

    @Test func successWithStandardMeta() throws {
        let json = #"{"success":true,"data":{"id":7},"meta":{"request_id":"r1","next_cursor":"c2","has_more":true,"pagination":{"current_page":1,"last_page":3,"per_page":25,"total":61}}}"#
        let env = try JSONCoding.decoder().decode(APIEnvelope<Item, APIStandardMeta>.self, from: Data(json.utf8))
        #expect(env.success && env.data == Item(id: 7) && env.error == nil)
        #expect(env.meta?.requestId == "r1" && env.meta?.hasMore == true && env.meta?.pagination?.total == 61)
    }

    @Test func errorEnvelope() throws {
        let json = #"{"success":false,"error":{"code":"IDEMPOTENCY_KEY_REQUIRED","message":"x"},"meta":{}}"#
        let env = try JSONCoding.decoder().decode(APIEnvelope<Item, APIStandardMeta>.self, from: Data(json.utf8))
        #expect(!env.success && env.data == nil)
        #expect(env.error == APIErrorBody(code: "IDEMPOTENCY_KEY_REQUIRED", message: "x"))
    }

    @Test func appSpecificMeta() throws {
        let json = #"{"success":true,"data":{"id":1},"meta":{"total_unread":4}}"#
        let env = try JSONCoding.decoder().decode(APIEnvelope<Item, CommsMeta>.self, from: Data(json.utf8))
        #expect(env.meta?.totalUnread == 4)
    }

    @Test(arguments: ["2026-05-22T12:00:00+10:00", "2026-05-22T12:00:00.250+10:00"])
    func isoDatesWithAndWithoutFractions(raw: String) throws {
        struct D: Decodable { let at: Date }
        let d = try JSONCoding.decoder().decode(D.self, from: Data(#"{"at":"\#(raw)"}"#.utf8))
        #expect(abs(d.at.timeIntervalSince1970 - 1_779_415_200) < 1)
    }

    @Test func badDateThrows() {
        struct D: Decodable { let at: Date }
        #expect(throws: DecodingError.self) { try JSONCoding.decoder().decode(D.self, from: Data(#"{"at":"yesterday"}"#.utf8)) }
    }
}

/// Keychain tests run in the iOS Simulator test host. Each test uses a unique
/// service so runs can't see each other's items.
@Suite(.serialized)
struct KeychainStoreTests {
    enum Key: String, CaseIterable, Sendable { case alpha, beta }

    private func store(_ accessibility: KeychainAccessibility = .whenUnlockedThisDeviceOnly) -> KeychainStore<Key> {
        KeychainStore(service: "au.com.woodpatch.core.tests.\(UUID().uuidString)", accessibility: accessibility)
    }

    @Test func roundTripUpdateAndDelete() throws {
        let s = store()
        defer { try? s.deleteAll() }
        #expect(try s.read(.alpha) == nil)
        try s.write(.alpha, value: "one")
        #expect(try s.read(.alpha) == "one")
        try s.write(.alpha, value: "two") // update path
        #expect(try s.read(.alpha) == "two")
        try s.delete(.alpha)
        try s.delete(.alpha) // absent: still success
        #expect(try s.read(.alpha) == nil)
    }

    @Test func servicesAreIsolated() throws {
        let a = store(), b = store()
        defer { try? a.deleteAll(); try? b.deleteAll() }
        try a.write(.alpha, value: "a")
        #expect(try b.read(.alpha) == nil)
    }

    @Test(arguments: [KeychainAccessibility.afterFirstUnlockThisDeviceOnly, .whenUnlockedThisDeviceOnly])
    func addUsesTheChosenAccessibility(accessibility: KeychainAccessibility) throws {
        let s = store(accessibility)
        defer { try? s.deleteAll() }
        try s.write(.beta, value: "v")
        var out: AnyObject?
        let status = SecItemCopyMatching([
            kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: s.service,
            kSecAttrAccount as String: "beta", kSecReturnAttributes as String: true,
        ] as CFDictionary, &out)
        #expect(status == errSecSuccess)
        let stored = (out as? [String: Any])?[kSecAttrAccessible as String] as? String
        #expect(stored == (accessibility.secAttribute as String))
    }

    @Test func deleteAllClearsEveryKey() throws {
        let s = store()
        try s.write(.alpha, value: "1")
        try s.write(.beta, value: "2")
        try s.deleteAll()
        #expect(try s.read(.alpha) == nil && s.read(.beta) == nil)
    }
}
