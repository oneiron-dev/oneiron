//! Measurement only, not for merge (OPUS-E2E-1, FIX row
//! [AGENT-RUN-START-LATENCY-4S]): times a code-mode step request's stages
//! before its model call, through the door
//! `oneiron::engine_executor::capture_cost_door`.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test code_mode_capture_cost -- --nocapture`.
#![cfg(oneiron_test_support)]

use oneiron::{Vault, VaultConfig};

#[test]
fn code_mode_step_request_costs_before_its_model_call() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    oneiron::engine_executor::capture_cost_door::measure_code_mode_step_capture(&vault);
}
