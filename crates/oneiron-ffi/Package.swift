// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "OneironFFI",
    platforms: [
        .iOS(.v13),
        .macOS(.v12),
    ],
    products: [
        .library(
            name: "OneironFFI",
            targets: ["OneironFFI"]
        ),
    ],
    targets: [
        .systemLibrary(
            name: "COneironFFI",
            path: "Sources/COneironFFI"
        ),
        .target(
            name: "OneironFFI",
            dependencies: ["COneironFFI"]
        ),
    ]
)
