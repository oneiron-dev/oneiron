//! Doors for the integration tests to crate-private items, as in
//! `oneiron::test_doors`. Compiled only under `--cfg oneiron_test_support`,
//! which only the test command sets (`RUSTFLAGS="--cfg oneiron_test_support"
//! cargo test ... --test <stem>`); never behind a cargo feature, so no
//! `--all-features` build reaches them. Hidden; never API.

pub mod big_rung;
pub mod coach_round;
