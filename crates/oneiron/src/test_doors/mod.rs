//! Doors for the integration tests to crate-private items (Engine 19:23
//! HARNESS-GUARD). Compiled only under `--cfg oneiron_test_support`, which only
//! the test command sets (`RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! ... --test <stem>`); never behind a cargo feature, so no `--all-features`
//! build reaches them. Hidden; never API.

pub mod agent_definition_scans;
pub mod authority_view_grant;
pub mod authority_world_undo;
pub mod callable_skill;
pub mod checkpoint_registry;
pub mod coach;
pub mod code_reply_healer;
pub mod code_run_answer;
pub mod consolidation;
pub mod dag_append;
pub mod derivation_floor;
pub mod derive;
pub mod derive_verbs;
pub mod dreamer_stage_line;
pub mod fanout_admission;
pub mod feeds;
pub mod grant_roles;
pub mod graph_ask_centre;
pub mod house_link;
pub mod inquiry;
pub mod label_writers;
pub mod learning_claim_value;
pub mod lifted_text;
pub mod live_run_claim_put;
pub mod membership;
pub mod model_binding_proposer;
pub mod note_bm25f_repair;
pub mod park_typed_wait;
pub mod provenance_body_checkpoint;
pub mod repo_base_manifest;
pub mod retrieval_policy_default_floor;
pub mod run_hold;
pub mod run_lifecycle;
pub mod scope_summary;
pub mod skill_package;
pub mod skill_read_hold;
pub mod source_audience;
pub mod source_audience_binding;
pub mod spend;
pub mod split_phrase_carrier;
pub mod steward;
pub mod substrate_reads;
pub mod turn_programs;
pub mod untangle_regressions;
pub mod wake_d1_park_release;

/// Runs the identity-topology reconcile that a replica's sync ingest runs,
/// over this vault's own ledger: shell edges, redirects and split assignment
/// rows re-derived from the fold. A test compares what a replica derives
/// from a history with what the local doors left.
pub fn reconcile_identity_topology(vault: &crate::Vault) -> crate::error::Result<()> {
    vault.with_write_txn(|wtxn| vault.reconcile_identity_topology_edges_in_txn(wtxn))
}
