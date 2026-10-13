// swift-tools-version: 6.0
// WoodpatchCore: the app-agnostic iOS foundation shared by the softphone and the POS
// (BOS #2562). iOS only; the platform floor matches the softphone's deployment target
// (it must never exceed it). Vendored into each app at a pinned commit, not fetched.

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
        .testTarget(
            name: "WoodpatchCoreTests",
            dependencies: ["WoodpatchCore"],
            resources: [.copy("Fixtures")],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
