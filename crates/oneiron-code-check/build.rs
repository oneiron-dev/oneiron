//! Generates the SDK outputs oneiron-code-check includes at build time (crates/oneiron-sdk-build).

fn main() {
    // The SDK outputs this crate includes, generated at build time (crates/oneiron-sdk-build).
    oneiron_sdk_build::generate(&[
        "crates/oneiron/src/verbs/generated/catalog_fragment.d.ts",
        "crates/oneiron/src/verbs/generated/code-mode.d.ts",
        "crates/oneiron/src/verbs/generated/catalog_fragment_revision.rs",
    ]);
}
