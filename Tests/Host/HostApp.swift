// HostApp.swift: an empty app that exists only to HOST the test bundle.
// Unhosted SwiftPM test bundles have no keychain entitlement in the Simulator
// (every SecItem call returns -34018), so the keychain and Secure Enclave tests
// need a host app. Never shipped.

import SwiftUI

@main
struct CoreTestHostApp: App {
    var body: some Scene {
        WindowGroup { Text("WoodpatchCore test host") }
    }
}
