// swift-tools-version: 6.0
// WoodpatchCore: the app-agnostic iOS foundation shared by the softphone and the POS
// (BOS #2562). iOS only; the platform floor matches the softphone's deployment target
// (it must never exceed it). Vendored into each app at a pinned commit, not fetched.
//
// LIBRARY ONLY, on purpose: apps vendor Package.swift + Sources/ (never Tests/, whose
// fixtures include a test client key), and a manifest that declared a test target over
// a Tests/ directory that isn't there fails to resolve in the app ("overlapping
// sources"). The tests run HOSTED instead (Tests/Host, because unhosted bundles get
// -34018 from the keychain); see scripts/mac-test.sh.

import PackageDescription

let package = Package(
    name: "WoodpatchCore",
    platforms: [.iOS("26.0")],
    products: [
        .library(name: "WoodpatchCore", targets: ["WoodpatchCore"]),
    ],
    targets: [
        .target(
            name: "WoodpatchCore",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
