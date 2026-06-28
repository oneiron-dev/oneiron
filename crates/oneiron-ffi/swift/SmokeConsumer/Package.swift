// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "OneironStorageSmoke",
    platforms: [
        .macOS(.v14),
    ],
    dependencies: [
        .package(name: "OneironStorage", path: "../../../.."),
    ],
    targets: [
        .executableTarget(
            name: "OneironStorageSmoke",
            dependencies: [
                .product(name: "OneironStorage", package: "OneironStorage"),
            ]
        ),
    ]
)
