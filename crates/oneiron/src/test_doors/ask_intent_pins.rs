//! Doors for `tests/ask_intent_keys.rs` (UC-06 PR 8): each ask module's intent key for given
//! parts, and that module's read of a key. The text is stored in ask group bodies and in
//! `LIVE_EDIT_GROUPS`, and an answer is routed by it, so the tests pin it exactly. Compiled only
//! under `--cfg oneiron_test_support`; never API.

use crate::EntityId;
use crate::agent_dispatch::CommReach;
use crate::attempt_queue::AttemptId;
use crate::entity_id::bytes_to_hex_lower;

/// A training offer ask's intent key: `(offer, owner, digest)` asked in `turn`.
pub fn training_offer_key(
    offer: EntityId,
    owner: EntityId,
    digest: &str,
    turn: EntityId,
) -> String {
    crate::task_verb::training_offer_intent_key(&(offer, owner, digest.to_owned()), &turn)
}

/// The `(offer, owner, digest, turn)` a training offer ask's intent key names.
pub fn training_offer_read(intent_key: &str) -> Option<(EntityId, EntityId, String, EntityId)> {
    crate::task_verb::training_offer_ask_key(intent_key)
}

/// A training swap ask's intent key: `(run, owner, digest)` asked in `turn`.
pub fn training_swap_key(run: EntityId, owner: EntityId, digest: &str, turn: EntityId) -> String {
    crate::task_verb::training_swap_intent_key(&(run, owner, digest.to_owned()), &turn)
}

/// The `(run, owner, digest, turn)` a training swap ask's intent key names.
pub fn training_swap_read(intent_key: &str) -> Option<(EntityId, EntityId, String, EntityId)> {
    crate::task_verb::training_swap_ask_key(intent_key)
}

/// A comm widen ask's intent key: the child attempt `child` asks for `needed` (a reach's wire
/// spelling) in `turn`; `None` when `needed` names no reach.
pub fn comm_widen_key(child: EntityId, needed: &str, turn: EntityId) -> Option<String> {
    let child = AttemptId::from_bytes(child.as_bytes()).ok()?;
    Some(crate::task_verb::comm_widen_intent_key(
        child,
        CommReach::parse(needed)?,
        turn,
    ))
}

/// The `(child attempt hex, reach spelling, turn)` a comm widen ask's intent key names.
pub fn comm_widen_read(intent_key: &str) -> Option<(String, String, EntityId)> {
    let (child, needed, turn) = crate::task_verb::comm_widen_intent_parts(intent_key)?;
    Some((
        bytes_to_hex_lower(child.as_bytes()),
        needed.as_str().to_owned(),
        turn,
    ))
}

/// A code consent ask's intent key for the wait `wait`.
pub fn code_consent_key(wait: EntityId) -> String {
    crate::task_verb::code_consent_intent_key(wait)
}

/// The wait a code consent ask's intent key names.
pub fn code_consent_read(intent_key: &str) -> Option<EntityId> {
    crate::task_verb::code_consent_intent_wait(intent_key)
}

/// A contribution pair ask's intent key for the pair `handle`.
pub fn contribution_pair_key(handle: EntityId) -> String {
    crate::task_verb::pair_intent_key(handle)
}

/// The pair handle a contribution pair ask's intent key names.
pub fn contribution_pair_read(intent_key: &str) -> Option<EntityId> {
    crate::task_verb::pair_handle(intent_key)
}

/// The case intent of the consult case `case_ref`, the text a case ask's anchor is derived for.
pub fn consult_case_intent(case_ref: EntityId) -> String {
    crate::task_verb::consult_case_intent(case_ref)
}

/// The case intent and anchor `intent_key` names when it is the intent of the case ask kept
/// under `id`.
pub fn consult_case_read(intent_key: &str, id: EntityId) -> Option<(String, EntityId)> {
    crate::task_verb::consult_case_ask_anchor(intent_key, id)
}

/// A live-edit holder ask's intent key for the route `(artifact, editor, revision)`; the route's
/// owners are not part of it.
pub fn live_edit_key(artifact: EntityId, editor: EntityId, revision: u64) -> String {
    crate::office_body::live_edit_intent_key(&crate::office_body::LiveEditRoute {
        artifact,
        editor,
        owners: Vec::new(),
        revision,
    })
}

/// Whether `intent_key` passes the live-edit ask's prefix gate.
pub fn live_edit_gate(intent_key: &str) -> bool {
    crate::office_body::is_live_edit_ask(intent_key)
}
