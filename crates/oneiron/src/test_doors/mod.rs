//! Doors for the integration tests to crate-private items (Engine 19:23
//! HARNESS-GUARD). Compiled only under `--cfg oneiron_test_support`, which only
//! the test command sets (`RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! ... --test <stem>`); never behind a cargo feature, so no `--all-features`
//! build reaches them. Hidden; never API.

pub mod callable_skill;
pub mod coach;
pub mod code_reply_healer;
pub mod code_run_answer;
pub mod consolidation;
pub mod dag_append;
pub mod label_writers;
pub mod live_run_claim_put;
pub mod retrieval_policy_default_floor;
pub mod run_hold;
pub mod scope_summary;
pub mod source_audience_binding;
pub mod steward;
pub mod untangle_regressions;
pub mod wake_d1_park_release;
