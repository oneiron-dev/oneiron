//! Doors for the integration tests to crate-private items (Engine 19:23
//! HARNESS-GUARD). Compiled only under `--cfg oneiron_test_support`, which only
//! the test command sets (`RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! ... --test <stem>`); never behind a cargo feature, so no `--all-features`
//! build reaches them. Hidden; never API.

pub mod agent_definition_scans;
pub mod approval_target_round_trip;
pub mod archive_import;
pub mod authority_stored_damage;
pub mod authority_view_grant;
pub mod authority_world_undo;
pub mod callable_skill;
pub mod campaign_opt_out_line;
pub mod check_in;
pub mod checkpoint_registry;
pub mod claim_facet_birth;
pub mod claim_source_recheck;
pub mod claim_transition;
pub mod claim_value_redaction;
pub mod coach;
pub mod code_mode_capture;
pub mod code_reply_healer;
pub mod code_run_answer;
pub mod code_run_write_identity;
pub mod code_view_fork;
pub mod comm_thread_member_claim_reads;
pub mod connector_key_suspend;
pub mod consolidation;
pub mod credit_decay_fit;
pub mod dag_append;
pub mod derivation_floor;
pub mod derive;
pub mod derive_verbs;
pub mod dreamer_attempt_binding;
pub mod dreamer_stage_line;
pub mod esign_commitments;
pub mod fanout_admission;
pub mod feeds;
pub mod free_time_cycle_writer;
#[cfg(feature = "sync")]
pub mod free_time_handoff;
pub mod grant_roles;
pub mod graph_ask_centre;
#[cfg(feature = "sync")]
pub mod guest_turn_counterparty;
#[cfg(feature = "sync")]
pub mod home_handoff_retire;
#[cfg(feature = "sync")]
pub mod home_sections;
pub mod house_link;
pub mod hydration_decode_guard;
pub mod identity_recheck;
pub mod inquiry;
pub mod label_writers;
pub mod learning_claim_value;
pub mod learning_setting_sourced;
pub mod lifted_text;
pub mod live_run_claim_put;
pub mod mail_counterparty;
pub mod mail_landing;
pub mod membership;
pub mod meso_extraction_width;
pub mod model_binding_proposer;
pub mod nightly;
pub mod note_bm25f_repair;
pub mod off_record_shell;
pub mod outbound_grant_index;
pub mod own_device_message_replay;
pub mod pad_offer_invalidation;
pub mod park_typed_wait;
pub mod provenance_body_checkpoint;
pub mod re_root_stale_sweep;
pub mod repo_base_manifest;
pub mod repo_secret_marks;
pub mod research_continuation;
pub mod resident_wake_hold;
pub mod retrieval_policy_default_floor;
pub mod room_turn_backfill;
pub mod run_changes;
pub mod run_hold;
pub mod run_lifecycle;
pub mod scope_summary;
pub mod seat_park_model_step;
pub mod shared_act_family;
pub mod skill_gate;
pub mod skill_hub_restore;
pub mod skill_package;
pub mod skill_read_hold;
pub mod source_audience;
pub mod source_audience_binding;
pub mod spend;
pub mod split_phrase_carrier;
pub mod steward;
pub mod stretch_pack_finalize;
pub mod substrate_reads;
pub mod tray_answered_removal;
pub mod turn_programs;
pub mod uncertain_send_questions;
pub mod untangle_regressions;
pub mod verb_hook_ask;
pub mod wake_d1_park_release;
#[cfg(feature = "sync")]
pub mod world_follow;
#[cfg(feature = "sync")]
pub use crate::sync::connection::sync_outbox;

/// Runs the identity-topology reconcile that a replica's sync ingest runs,
/// over this vault's own ledger: shell edges, redirects and split assignment
/// rows re-derived from the fold. A test compares what a replica derives
/// from a history with what the local doors left.
pub fn reconcile_identity_topology(vault: &crate::Vault) -> crate::error::Result<()> {
    vault.with_write_txn(|wtxn| vault.reconcile_identity_topology_edges_in_txn(wtxn))
}
