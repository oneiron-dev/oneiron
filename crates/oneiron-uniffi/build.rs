//! Generates the SDK outputs oneiron-uniffi includes at build time (crates/oneiron-sdk-build).

fn main() {
    // The SDK outputs this crate includes, generated at build time (crates/oneiron-sdk-build).
    oneiron_sdk_build::generate(&[
        "crates/oneiron-uniffi/src/generated/facade_generated.rs",
        "crates/oneiron-uniffi/src/generated/facade_types_generated.rs",
    ]);
}
