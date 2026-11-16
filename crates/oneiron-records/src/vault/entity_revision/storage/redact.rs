//! Moved from `crates/oneiron/src/vault/entity_revision/storage/redact.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::revision_ref::RevisionRef;

/// One retained frontier's exact old/new reference and citation status.
/// An old content hash is never silently assigned to different bytes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ClaimValueRedactionBinding {
    pub previous_revision: RevisionRef,
    pub revision: RevisionRef,
    pub frontier: Vec<u8>,
    pub body_changed: bool,
    /// A saved `short:hh@rev` needs a new hash byte when this is true.
    /// False does not prove content equality: an 8-bit hash can collide.
    pub short_hash_changed: bool,
}

/// Content-free local result, not peer convergence or an export receipt.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LocalClaimValueRedaction {
    pub record: EntityId,
    pub value_fields: Vec<String>,
    pub changed_history_rows: usize,
    pub bindings: Vec<ClaimValueRedactionBinding>,
}
