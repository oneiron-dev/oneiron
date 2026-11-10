//! Doors for the integration tests to crate-private items (Engine 19:23
//! HARNESS-GUARD). Compiled only under `--cfg oneiron_test_support`, which only
//! the test command sets (`RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! ... --test <stem>`); never behind a cargo feature, so no `--all-features`
//! build reaches them. Hidden; never API.

pub mod consolidation;
pub mod lifted_text;
pub mod live_run_claim_put;
pub mod membership;
pub mod run_hold;
pub mod spend;
pub mod untangle_regressions;
pub mod wake_d1_park_release;
