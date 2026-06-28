// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "OneironStorage",
    platforms: [
        .iOS(.v16),
        .macOS(.v14),
    ],
    products: [
        .library(
            name: "OneironStorage",
            targets: ["OneironStorage"]
        ),
    ],
    targets: [
        .systemLibrary(
            name: "COneironFFI",
            path: "crates/oneiron-ffi/swift/COneironFFI"
        ),
        .target(
            name: "OneironStorage",
            dependencies: ["COneironFFI"],
            path: "crates/oneiron-ffi/swift/OneironStorage"
        ),
    ]
)
