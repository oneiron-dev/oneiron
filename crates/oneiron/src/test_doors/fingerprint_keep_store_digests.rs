//! K-proof door for store digests that existing rows, files and acks hold.
//! Compiled only under `oneiron_test_support`; never part of the engine API.
#![cfg(oneiron_test_support)]

use std::collections::BTreeMap;

use crate::EntityId;
use crate::store::code_revision_record::{CodeRevision, CodeTreeBlob, CodeTreeInventory};
use crate::store::{
    critical_confirm_record, drafter_custody, grant_scope_custody, row_birth, skill_source_carrier,
};
use crate::write_envelope::skill_record::SkillContentHash;

/// An off-record session's spill directory name.
#[cfg(unix)]
#[must_use]
pub fn session_spill_name(session_ref: &str) -> String {
    crate::store::session_spill_name_for_test(session_ref)
}

/// A revision's complete code-tree inventory digest.
///
/// # Errors
/// A document frontier that does not encode.
pub fn code_tree_inventory(revision: &CodeRevision) -> crate::Result<[u8; 32]> {
    CodeTreeInventory::digest(revision)
}

/// The inventory digest of a tree with no documents and exactly `blobs`.
#[must_use]
pub fn code_tree_blob_inventory(blobs: &BTreeMap<String, CodeTreeBlob>) -> [u8; 32] {
    CodeTreeInventory::blob_digest(blobs)
}

/// A critical confirm's effect digest.
#[must_use]
pub fn critical_confirm_effect(
    claim_id: &EntityId,
    decision_id: [u8; 16],
    diff_handle: &[u8],
    read_frontier_hash: [u8; 32],
) -> [u8; 32] {
    critical_confirm_record::confirm_effect_digest_for_test(
        claim_id,
        &decision_id,
        diff_handle,
        &read_frontier_hash,
    )
}

/// A critical write confirm's id.
#[must_use]
pub fn critical_write_confirm_id(
    decision_id: [u8; 16],
    claim_id: &EntityId,
    effect_digest: [u8; 32],
    read_frontier_hash: [u8; 32],
    nonce: [u8; 16],
    expires_at: u64,
) -> [u8; 32] {
    critical_confirm_record::write_confirm_id_for_test(
        &decision_id,
        claim_id,
        &effect_digest,
        &read_frontier_hash,
        &nonce,
        expires_at,
    )
}

/// The key incarnation of a sealed drafter artifact.
#[must_use]
pub fn drafter_incarnation(artifact: &[u8; 16]) -> [u8; 32] {
    drafter_custody::incarnation_for_test(artifact)
}

/// The key incarnation of a grant-scope pact at an epoch.
#[must_use]
pub fn grant_incarnation(pact_id: &[u8; 32], epoch: u64) -> [u8; 32] {
    grant_scope_custody::incarnation_for_test(pact_id, epoch)
}

/// A drained member's ack digest, over the ack's encoded bytes.
#[must_use]
pub fn custody_drain_ack(encoded: &[u8]) -> [u8; 32] {
    crate::store::drain_ack_digest_for_test(encoded)
}

/// The item hash an owner-answer obligation names.
#[must_use]
pub fn owner_answer_item(diff_handle: &[u8]) -> [u8; 32] {
    crate::store::owner_answer_item_hash(diff_handle)
}

/// A write door's params hash, as lowercase hex.
#[must_use]
pub fn write_door_params_hash() -> String {
    row_birth::write_door_params_hash_for_test()
}

/// A skill source carrier's id, for `holder` and the skill content hash.
///
/// # Errors
/// Never in practice: the first 16 digest bytes always make an id.
pub fn skill_source_carrier(holder: &EntityId, content_hash: [u8; 32]) -> crate::Result<EntityId> {
    skill_source_carrier::source_carrier_id(holder, &SkillContentHash::from_bytes(content_hash))
}
