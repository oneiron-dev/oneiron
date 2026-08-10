//! Local bindgen entry point, behind the `bindgen-cli` feature.
//!
//! Generating through this binary rather than a separately installed CLI is
//! what keeps the generator pinned to the exact `uniffi` version the library
//! compiles against: the two can never drift.

fn main() {
    uniffi::uniffi_bindgen_main();
}
