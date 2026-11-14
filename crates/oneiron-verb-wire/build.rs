fn main() {
    // The SDK output this crate includes, generated at build time (crates/oneiron-sdk-build): the input checks and
    // input schemas of the verb rows whose input type this crate holds (lib split W3-GEN).
    oneiron_sdk_build::generate(&["crates/oneiron-verb-wire/src/generated/verb_input_checks.rs"]);
}
