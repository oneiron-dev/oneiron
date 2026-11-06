//! What a courtesy delete answer keeps beside its choice: the customer
//! holds it placed (FIX 2924), the records a hold choice left out as no
//! copy this ask covers (FIX 2927), and a delete choice's operation, its
//! records each once (FIX 2925) with each one's observed state (FIX 2926).
//! Ids and codes only: no content, no error text and no host order.

use serde::{Deserialize, Serialize};

use super::super::coop_reply::CooperativeDeletionReplyOutcome;
use super::CooperativeDeletionDeliveryStatus;
use crate::deletion::{LegalHold, LegalHoldKind};
use crate::store::legal_hold as hold_store;
use crate::{EntityId, Result, Vault};

/// The owner's retain-under-basis selection (BIZ-LEGAL-0004 B2/A8).
/// Codes and opaque record ids only; the class names a caller's retention
/// policy, not an engine-chosen duration or a permanent-retention default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CooperativeDeletionRetention {
    pub records: Vec<EntityId>,
    pub basis_code: String,
    pub retention_class: String,
}

/// Exact value-map keys on one covered CLAIM copy. Keys are literal,
/// never dotted paths, inferred names, source/scope fields or replacements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CooperativeClaimValueRedaction {
    pub record: EntityId,
    pub value_fields: Vec<String>,
}

/// A local selected-field action, not a peer/export erasure proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CooperativeLocalRedaction {
    pub applied_by: EntityId,
    pub applied_at: u64,
    pub result: crate::vault::entity_revision::LocalClaimValueRedaction,
}

/// The recipient owner attests that they already told the requester,
/// outside the engine, before these restrictions lifted. This is NOT an
/// engine-delivery receipt and carries no message content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CooperativeRestrictionLiftAttestation {
    pub records: Vec<EntityId>,
    pub attested_by: EntityId,
    pub attested_at: u64,
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

/// What became of one record of a delete choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CooperativeDeleteRecordState {
    /// Not removed yet: its delete has not run, or did not finish.
    Pending,
    /// Its delete removed it here.
    Removed,
    /// Its delete found nothing here to remove.
    Missing,
}

impl CooperativeDeleteRecordState {
    /// Stable string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Removed => "removed",
            Self::Missing => "missing",
        }
    }
}

/// One record of a delete choice, with what became of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CooperativeDeleteRecord {
    pub record: EntityId,
    pub state: CooperativeDeleteRecordState,
}

/// A delete choice's operation, saved with the answer before any record is
/// deleted (FIX 2926): the records it names, each once, in the order first
/// named (FIX 2925), and each one's state as observed. A newer answer's
/// operation replaces it, and its run stops before its next record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CooperativeDeleteOperation {
    pub operation_id: EntityId,
    pub records: Vec<CooperativeDeleteRecord>,
}

impl CooperativeDeleteOperation {
    /// A new operation over `records`, each one pending.
    pub(super) fn new(operation_id: EntityId, records: &[EntityId]) -> Self {
        Self {
            operation_id,
            records: records
                .iter()
                .map(|&record| CooperativeDeleteRecord {
                    record,
                    state: CooperativeDeleteRecordState::Pending,
                })
                .collect(),
        }
    }

    /// Whether this operation deletes exactly `records`, in their order: a
    /// retry of it resumes it.
    pub(super) fn deletes(&self, records: &[EntityId]) -> bool {
        self.records.len() == records.len()
            && self
                .records
                .iter()
                .zip(records)
                .all(|(saved, record)| saved.record == *record)
    }

    /// The records still pending, in order.
    pub(super) fn pending(&self) -> Vec<EntityId> {
        self.records
            .iter()
            .filter(|saved| saved.state == CooperativeDeleteRecordState::Pending)
            .map(|saved| saved.record)
            .collect()
    }

    /// The records removed, as hex.
    pub(super) fn removed_hex(&self) -> Vec<String> {
        self.records
            .iter()
            .filter(|saved| saved.state == CooperativeDeleteRecordState::Removed)
            .map(|saved| saved.record.to_hex())
            .collect()
    }

    /// Saves what became of pending `record`. False when it is no pending
    /// record of this operation.
    pub(super) fn settle(&mut self, record: EntityId, state: CooperativeDeleteRecordState) -> bool {
        match self.records.iter_mut().find(|saved| {
            saved.record == record && saved.state == CooperativeDeleteRecordState::Pending
        }) {
            Some(saved) => {
                saved.state = state;
                true
            }
            None => false,
        }
    }
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
