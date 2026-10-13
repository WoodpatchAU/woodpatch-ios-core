// KeychainStore.swift
// ────────────────────────────────────────────────────────────────────
// A typed wrapper over the iOS Security framework's generic-password
// items, generic over the app's own key enum.
//
// Provenance: extracted from the softphone's Storage/KeychainStore.swift
// for BOS #2562. Read/write/delete/deleteAll behave identically. What
// changed, and why:
//
//   - KEYS are the app's: `KeychainStore<SecretKey>`, where `SecretKey`
//     is a String-backed CaseIterable enum. The softphone keeps its
//     `SecretKey` (sip_password, …); the POS has its own. `deleteAll()`
//     iterates that enum's cases, so it only touches the app's own keys.
//
//   - The SERVICE id is an OPAQUE string the app supplies. The package
//     never derives it. #810/#817: the softphone once derived it from the
//     API host, #717 repointed the host, and every installed phone looked
//     in a new service, found nothing, and silently unpaired. A one-byte
//     change to the service id means every installed device must re-pair,
//     so it stays in app code next to that app's pin test.
//
//   - The ACCESSIBILITY class is an init parameter with NO default. The
//     softphone needs AfterFirstUnlockThisDeviceOnly (a VoIP push wakes it
//     on a locked phone and the SIP registrar needs the password); the POS
//     wants WhenUnlockedThisDeviceOnly. Both are `ThisDeviceOnly`, so they
//     never travel in iCloud backups. A default would let one app silently
//     inherit the other's choice.
//
// All methods are synchronous because the Security framework is. They're
// sub-millisecond in normal use.

import Foundation
import Security

/// The accessibility classes an app may choose. Only `ThisDeviceOnly`
/// variants are offered, so no secret stored through this type can leave
/// the device in a backup.
public enum KeychainAccessibility: Sendable, Equatable {
    /// Readable once the device has been unlocked after boot, including while
    /// it's locked again (needed by background wake-ups, e.g. VoIP push).
    case afterFirstUnlockThisDeviceOnly
    /// Readable only while the device is unlocked.
    case whenUnlockedThisDeviceOnly

    var secAttribute: CFString {
        switch self {
        case .afterFirstUnlockThisDeviceOnly: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .whenUnlockedThisDeviceOnly: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
    }
}

public struct KeychainStore<SecretKey>: Sendable
    where SecretKey: RawRepresentable & CaseIterable & Sendable, SecretKey.RawValue == String
{
    /// The app-supplied service id (opaque; see the header).
    public let service: String
    /// Applied when an item is first ADDED. Updates keep the existing item's
    /// class (the recommended pattern), as before.
    public let accessibility: KeychainAccessibility

    public init(service: String, accessibility: KeychainAccessibility) {
        self.service = service
        self.accessibility = accessibility
    }

    /// The stored value, or nil if there's no entry for this key under this
    /// service.
    public func read(_ key: SecretKey) throws -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key.rawValue,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let data = result as? Data,
                  let string = String(data: data, encoding: .utf8)
            else {
                throw KeychainError.unexpectedData
            }
            return string
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainError.osStatus(status)
        }
    }

    /// Upserts the value: `SecItemUpdate` first, falling back to `SecItemAdd`.
    /// This is the recommended pattern because it preserves an existing item's
    /// accessibility class on update.
    public func write(_ key: SecretKey, value: String) throws {
        let data = Data(value.utf8)

        let baseQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key.rawValue,
        ]

        let updateStatus = SecItemUpdate(
            baseQuery as CFDictionary,
            [kSecValueData as String: data] as CFDictionary
        )
        if updateStatus == errSecSuccess {
            return
        }
        if updateStatus != errSecItemNotFound {
            throw KeychainError.osStatus(updateStatus)
        }

        var addQuery = baseQuery
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] = accessibility.secAttribute

        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw KeychainError.osStatus(addStatus)
        }
    }

    /// Removes the entry. Deleting an absent key succeeds: it's the same
    /// logical outcome as deleting a present one.
    public func delete(_ key: SecretKey) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key.rawValue,
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess, status != errSecItemNotFound {
            throw KeychainError.osStatus(status)
        }
    }

    /// Removes every key of this app's enum under this service (the unpair /
    /// wipe flow).
    public func deleteAll() throws {
        for key in SecretKey.allCases {
            try delete(key)
        }
    }
}

public enum KeychainError: Error, Sendable, Equatable {
    /// A Security framework call returned a non-success OSStatus.
    case osStatus(OSStatus)
    /// `SecItemCopyMatching` returned data that wasn't UTF-8: the store is
    /// corrupted, or the entry was written with a different encoding.
    case unexpectedData
}
