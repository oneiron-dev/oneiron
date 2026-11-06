//! Core half of `deletion::coop_delivery::types`: its store-layer items live in `oneiron_store::deletion::coop_delivery::types` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::deletion::coop_delivery::types::*;

use super::super::coop_reply::CooperativeDeletionReplyOutcome;
use super::CooperativeDeletionDeliveryStatus;
use crate::deletion::{LegalHold, LegalHoldKind};
use crate::store::legal_hold as hold_store;
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};

/// A local selected-field action, not a peer/export erasure proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CooperativeLocalRedaction {
    pub applied_by: EntityId,
    pub applied_at: u64,
    pub result: crate::vault::entity_revision::LocalClaimValueRedaction,
}

/// The recipient owner's menu (BIZ-LEGAL-0004 B2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CooperativeDeletionDispositionKind {
    Delete,
    Redact,
    RestrictPendingReview,
    RetainUnderBasis,
    LegalHold,
    Decline,
}

impl CooperativeDeletionDispositionKind {
    /// What the requester learns of this choice.
    #[must_use]
    pub const fn reply_outcome(self) -> CooperativeDeletionReplyOutcome {
        match self {
            Self::Decline => CooperativeDeletionReplyOutcome::Declined,
            _ => CooperativeDeletionReplyOutcome::Acknowledged,
        }
    }
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

/// What the owner chose for one filed ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CooperativeDeletionAnswer {
    pub kind: CooperativeDeletionDispositionKind,
    pub reason_code: Option<String>,
    pub review_at: Option<u64>,
    /// Under a delete choice, the records to hard-delete, each once in the
    /// order first named. Each goes through the owner's delete rail, one by
    /// one, once no legal hold keeps any of them.
    pub delete: Vec<EntityId>,
    /// Under a legal hold choice, this vault's records to hold, each once.
    /// They take one customer hold, written with the answer.
    pub hold: Vec<EntityId>,
    /// Under retain-under-basis, the copies, basis code and retention class.
    pub retention: Option<CooperativeDeletionRetention>,
    /// Under restrict-pending-review, copies to place or refresh. Other
    /// restrictions remain until explicitly lifted with prior-notice attestation.
    pub restrict: Vec<EntityId>,
    /// The owner attests the requester was already told externally before
    /// lifting these copies' restrictions under this ask only.
    pub restriction_notice_given: Vec<EntityId>,
    /// Under Redact, exact value-map fields on covered CLAIM copies.
    pub redact: Vec<CooperativeClaimValueRedaction>,
}

impl Vault {
    /// The courtesy holds `ids` name, each as its customer hold row reads
    /// now: standing or lifted, with what it names (FIX 2924). `None` once
    /// that row is gone, as a released hold's row ages out. Only customer
    /// rows are read: a host order is never named here.
    ///
    /// # Errors
    /// Storage errors.
    pub fn courtesy_holds(&self, ids: &[EntityId]) -> Result<Vec<(EntityId, Option<LegalHold>)>> {
        let txn = self.store.env.read_txn()?;
        ids.iter()
            .map(|id| {
                let hold = hold_store::hold_in_txn(&self.store, &txn, id)?
                    .filter(|hold| hold.kind == LegalHoldKind::Customer);
                Ok((*id, hold))
            })
            .collect()
    }
}
