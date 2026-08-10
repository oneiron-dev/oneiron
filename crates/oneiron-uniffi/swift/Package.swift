// swift-tools-version: 6.0
import PackageDescription

// Standalone compile-proof package for the generated UniFFI Swift bindings
// of the WIRE head contract.
//
// This package is deliberately self-contained: it has no dependency on the
// repository-root Swift package and imports no downstream product. The
// generated sources are build outputs placed under `.generated/` by
// `run-stub-compile.sh`; only the stub under `Sources/` is committed.
let package = Package(
    name: "OneironUniFFIStub",
    platforms: [
        .macOS(.v14),
    ],
    targets: [
        // The C module UniFFI emits next to the Swift bindings. The header
        // and module map are copied verbatim from the bindgen output; only
        // the placeholder translation unit is committed-side scaffolding,
        // because a C target cannot be header-only.
        .target(
            name: "OneironUniFFIFFI",
            path: ".generated/OneironUniFFIFFI",
            sources: ["placeholder.c"],
            publicHeadersPath: "."
        ),
        // The generated Swift bindings: one file, unedited.
        .target(
            name: "OneironUniFFI",
            dependencies: ["OneironUniFFIFFI"],
            path: ".generated/OneironUniFFI",
            sources: ["OneironUniFFI.swift"]
        ),
        // The committed, never-run compile consumer.
        .executableTarget(
            name: "OneironUniFFIStub",
            dependencies: ["OneironUniFFI"],
            path: "Sources/OneironUniFFIStub"
        ),
    ]
)
