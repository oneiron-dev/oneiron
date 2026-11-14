//! Measurement harness, not for merge (TEST-SELECTION TS-FOLD-AB, OPUS-TOOLCHAIN, 15 Nov 2026).
//!
//! The 23 integration test files of the `verbs` area, each included as a module, so one fleet job can compare one test
//! binary per file (`--test <stem>`) with one binary for the area (`--test all_verbs`): build wall, link, disk, and
//! the per-head rebuild after a lib change or a test file change.

#[path = "../agent_append_provenance.rs"]
mod agent_append_provenance;

#[path = "../agent_room_offer.rs"]
mod agent_room_offer;

#[path = "../can_verb_gate.rs"]
mod can_verb_gate;

#[path = "../change_actor_attribution.rs"]
mod change_actor_attribution;

#[path = "../dag_append_source_label.rs"]
mod dag_append_source_label;

#[path = "../embedded_owner_bound_credential.rs"]
mod embedded_owner_bound_credential;

#[path = "../google_connection_routes.rs"]
mod google_connection_routes;

#[path = "../note_subject_reference.rs"]
mod note_subject_reference;

#[path = "../primitive_a_evidence_spans.rs"]
mod primitive_a_evidence_spans;

#[path = "../primitive_a_policy_preflight.rs"]
mod primitive_a_policy_preflight;

#[path = "../primitive_a_policy_preflight_derive.rs"]
mod primitive_a_policy_preflight_derive;

#[path = "../primitive_a_run_reader.rs"]
mod primitive_a_run_reader;

#[path = "../primitive_a_skill_reader.rs"]
mod primitive_a_skill_reader;

#[path = "../primitive_a_snapshot_pages.rs"]
mod primitive_a_snapshot_pages;

#[path = "../primitive_a_steward_run_reader.rs"]
mod primitive_a_steward_run_reader;

#[path = "../room_offer_ageing.rs"]
mod room_offer_ageing;

#[path = "../room_thread_task_parity.rs"]
mod room_thread_task_parity;

#[path = "../room_turn_backfill.rs"]
mod room_turn_backfill;

#[path = "../run_tree_reader.rs"]
mod run_tree_reader;

#[path = "../thread_task_from_message.rs"]
mod thread_task_from_message;

#[path = "../thread_task_one_surface.rs"]
mod thread_task_one_surface;

#[path = "../turn_retry_regenerated_turn.rs"]
mod turn_retry_regenerated_turn;

#[path = "../whole_vault_restore_edited_seed_skills.rs"]
mod whole_vault_restore_edited_seed_skills;
