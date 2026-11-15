//! Door for `tests/fingerprint_keep_index_keys.rs` (PLAN-UC-04 stage 5): the keys local
//! vault tables are indexed and deduplicated by (a channel assignment, a wave plan's seal,
//! per-task rows and frozen statement, a policy change's follow-up, a skill or amendment
//! receipt's causes, a workflow wrapper's dedupe row, a graduation threshold pattern and a
//! booking lifecycle receipt), which the engine computes in private code.

use crate::channel_identity::AssignmentKey;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::temporal::TimeRange;

/// The key an assignment's two slots are kept under.
#[must_use]
pub fn assignment_index_key(key: &AssignmentKey) -> [u8; 32] {
    crate::channel_identity::assignment_index_key_for_test(key)
}

/// The key a wave plan's seal (`local` empty) or one of its per-task rows is kept under.
#[must_use]
pub fn wave_plan_index_key(plan: &str, local: &str) -> [u8; 32] {
    crate::task_verb::wave_plan_index_key_for_test(plan, local)
}

/// The key a wave plan's frozen statement is kept under.
#[must_use]
pub fn wave_plan_statement_key(plan: &str) -> [u8; 32] {
    crate::task_verb::wave_plan_statement_key_for_test(plan)
}

/// The vault_meta key of a policy change's human follow-up index row.
#[must_use]
pub fn policy_change_followup_index_key(receipt_id: &str, recipient: EntityId) -> Vec<u8> {
    crate::task_verb::policy_change_followup_index_key_for_test(receipt_id, recipient)
}

/// The key a skill attribution receipt's causes are kept under.
#[must_use]
pub fn skill_cause_receipt_key(receipt: &str) -> [u8; 32] {
    crate::skill_attribution::cause_receipt_key_for_test(receipt)
}

/// The key an amendment receipt's causes are kept under.
#[must_use]
pub fn amendment_cause_receipt_key(receipt: &str) -> [u8; 32] {
    crate::edit_distance::attribution::cause_receipt_key_for_test(receipt)
}

/// The key a workflow wrapper's dedupe index row is kept under.
#[must_use]
pub fn workflow_dedupe_key_hash(key: &str) -> [u8; 32] {
    crate::agent_dispatch::workflow_dedupe_key_hash_for_test(key)
}

/// The 16-byte key a graduation threshold row is kept under.
#[must_use]
pub fn graduation_pattern_key(pattern: &str) -> [u8; ENTITY_ID_LEN] {
    crate::edit_distance::graduation::pattern_key_for_test(pattern)
}

/// The key a booking confirm's receipt is kept under.
#[must_use]
pub fn booking_confirm_receipt_key(hold_hash: &[u8; 32]) -> [u8; 32] {
    crate::booking::lifecycle::confirm_receipt_key_for_test(hold_hash)
}

/// The key a booking revision's receipt (a reschedule to `target_slot`, or a cancel) is
/// kept under.
#[must_use]
pub fn booking_revision_receipt_key(
    event_ref: &EntityId,
    target_slot: Option<TimeRange>,
) -> [u8; 32] {
    crate::booking::lifecycle::revision_receipt_key_for_test(event_ref, target_slot)
}
