//! Doors for the integration tests to crate-private items, as in
//! `oneiron::test_doors`. Compiled only under `--cfg oneiron_test_support`,
//! which only the test command sets (`RUSTFLAGS="--cfg oneiron_test_support"
//! cargo test ... --test <stem>`); never behind a cargo feature, so no
//! `--all-features` build reaches them. Hidden; never API.

pub mod background_embedding;
pub mod big_rung;
pub mod booking_turn_line;
pub mod build_server;
pub mod calendar_ics_egress;
pub mod catch_all_status;
pub mod coach_round;
pub mod compaction_pass;
pub mod connector_sends;
pub mod history_import;
#[cfg(unix)]
pub mod hosted_import;
pub mod lens_frames;
pub mod lfs_install_line;
pub mod live_fork_rung;
pub mod live_lease;
pub mod live_run_payer;
pub mod live_run_step;
pub mod mcp_carrier_release;
pub mod mcp_code_mode_verbs;
pub mod mcp_page_mint;
pub mod mcp_refusal_status;
pub mod mcp_surface;
pub mod media_job_spend;
#[cfg(unix)]
pub mod merge_queue_checker_pressure;
pub mod native_board;
pub mod off_router_wire_counts;
pub mod one_click_wire_counter;
pub mod openapi_document;
pub mod parked_step_resume;
pub mod pre_idle_reuse;
#[cfg(unix)]
pub mod recovery_box_hold;
pub mod replay_admission;
pub mod residence_connection;
pub mod resident_pump;
pub mod seal_judge;
pub mod signing_session;
pub mod siwc_seat;
pub mod solved_runs;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod supervised_rerank;
pub mod system_one_leg;
pub mod voice_call;
pub mod wire_health_sweep;
pub mod wire_thresholds;
pub mod workflow_park;
