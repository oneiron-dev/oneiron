//! Moved from `crates/oneiron/src/deletion/coop_delivery/types.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_store::deletion::coop_delivery::types::*;
pub use oneiron_verb_wire::deletion::coop_delivery::types::CooperativeDeletionDispositionKind;
use serde::Deserialize;
use serde::Serialize;

/// A local selected-field action, not a peer/export erasure proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CooperativeLocalRedaction {
    pub applied_by: EntityId,
    pub applied_at: u64,
    pub result: crate::vault::entity_revision::storage::redact::LocalClaimValueRedaction,
}

/// The owner's recorded choice on one filed ask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CooperativeDeletionDisposition {
    pub kind: CooperativeDeletionDispositionKind,
    /// A concise reason code for any choice but delete; never free text.
    pub reason_code: Option<String>,
    /// When a choice other than delete comes up for review, unix seconds.
    pub review_at: Option<u64>,
    /// The records the owner's delete choice removed, hex.
    pub deleted: Vec<String>,
    pub recorded_at: u64,
    /// The customer hold a legal hold choice placed or kept (FIX 2924).
    pub hold_ids: Vec<EntityId>,
    /// Selected records left out of the hold, retention or restriction:
    /// non-copies, or (for retention/restriction) no longer present here.
    pub excluded: Vec<String>,
    /// A delete choice's operation and each record's state (FIX 2926).
    pub delete_operation: Option<CooperativeDeleteOperation>,
    /// The copies retained here under the owner's recorded basis and class.
    pub retention: Option<CooperativeDeletionRetention>,
    /// Copies this answer placed or refreshed under storage-only restriction.
    pub restricted: Vec<EntityId>,
    /// Selected local CLAIM field/history actions. Peer scope stays open.
    pub local_redactions: Vec<CooperativeLocalRedaction>,
}
