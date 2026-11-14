//! Doors for the integration tests to crate-private items, as in
//! `oneiron::test_doors`. Compiled only under `--cfg oneiron_test_support`,
//! which only the test command sets (`RUSTFLAGS="--cfg oneiron_test_support"
//! cargo test ... --test <stem>`); never behind a cargo feature, so no
//! `--all-features` build reaches them. Hidden; never API.

pub mod big_rung;
pub mod build_server;
pub mod coach_round;
#[cfg(unix)]
pub mod hosted_import;
pub mod lfs_install_line;
pub mod live_lease;
pub mod live_run_payer;
pub mod live_run_step;
pub mod mcp_surface;
pub mod media_job_spend;
pub mod native_board;
pub mod openapi_document;
pub mod replay_admission;
pub mod resident_pump;
pub mod siwc_seat;
pub mod solved_runs;
pub mod wire_health_sweep;
pub mod workflow_park;
