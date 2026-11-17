//! Doors for the integration tests to crate-private items, as in
//! `oneiron::test_doors`. Compiled only under `--cfg oneiron_test_support`,
//! which only the test command sets (`RUSTFLAGS="--cfg oneiron_test_support"
//! cargo test ... --test <stem>`); never behind a cargo feature, so no
//! `--all-features` build reaches them. Hidden; never API.

pub mod background_embedding;
pub mod big_rung;
pub mod board_keyframe_child_release;
pub mod booking_turn_line;
pub mod build_server;
pub mod calendar_egress;
pub mod calendar_ics_egress;
pub mod catch_all_status;
pub mod coach_round;
pub mod coach_wake;
pub mod compaction_pass;
pub mod connector_sends;
pub mod embedding_line;
pub mod history_import;
#[cfg(unix)]
pub mod hosted_import;
pub mod lens_frames;
pub mod lfs_install_line;
pub mod live_fork_rung;
pub mod live_lease;
pub mod live_merge_queue_checker_pass;
pub mod live_run_payer;
pub mod live_run_step;
pub mod lost_training_waiter;
pub mod mcp_carrier_release;
pub mod mcp_code_mode_verbs;
pub mod mcp_page_mint;
pub mod mcp_refusal_status;
pub mod mcp_run_claim_lane;
pub mod mcp_surface;
pub mod media_job_spend;
#[cfg(unix)]
pub mod merge_queue_checker_pressure;
pub mod native_board;
pub mod off_router_wire_counts;
pub mod one_click_wire_counter;
pub mod openapi_document;
pub mod owner_backup;
pub mod parked_step_resume;
pub mod pre_idle_reuse;
pub mod question_heads;
pub mod raw_stream;
#[cfg(unix)]
pub mod recovery_box_hold;
pub mod refusal_wire;
pub mod replay_admission;
pub mod residence;
pub mod residence_connection;
pub mod resident_pump;
#[cfg(target_os = "linux")]
pub mod sandbox_vendor;
pub mod seal_judge;
pub mod signing_session;
pub mod siwc_seat;
pub mod solved_runs;
pub mod system_one_leg;
pub mod system_one_rung;
pub mod voice_call;
pub mod web_search_count;
pub mod wire_health_sweep;
pub mod wire_thresholds;
pub mod workflow_park;
