//! Generates the SDK outputs oneiron-remote includes at build time (crates/oneiron-sdk-build).

fn main() {
    // The SDK outputs this crate includes, generated at build time (crates/oneiron-sdk-build).
    oneiron_sdk_build::generate(&["crates/oneiron-remote/src/generated/agent_verbs.rs"]);
}
