//! Moved from `crates/oneiron/src/deletion/coop_delivery/types.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::deletion::coop_delivery::CooperativeDeletionDeliveryStatus;
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

/// One filed ask, for the recipient owner's review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncomingCooperativeDeletion {
    /// The ask's nonce, hex.
    pub request_id: String,
    /// The pact, hex.
    pub connection_id: String,
    pub requester_vault_id: String,
    /// The worlds named, hex; none asks about everything the pact delivered.
    pub worlds: Vec<String>,
    pub epoch_cutoff: u64,
    /// The requester's clock when it signed.
    pub requested_at: u64,
    pub received_at: u64,
    /// The signed ask exactly as received.
    pub request: Vec<u8>,
    pub disposition: Option<CooperativeDeletionDisposition>,
    /// Delivery of the owner's answer back to the requester, once one is queued.
    pub reply_status: Option<CooperativeDeletionDeliveryStatus>,
    pub reply_started_at: Option<u64>,
    /// Every customer hold an answer to this ask placed or kept, a later
    /// choice's and an earlier one's alike (FIX 2924).
    pub courtesy_hold_ids: Vec<EntityId>,
    /// Records this ask has restricted; markers say which remain active.
    pub courtesy_restriction_records: Vec<EntityId>,
    /// Prior external-notice attestations, kept across later choices.
    pub restriction_lifts: Vec<CooperativeRestrictionLiftAttestation>,
    /// Local selected-field receipts retained across later choices.
    pub local_redactions: Vec<CooperativeLocalRedaction>,
}
