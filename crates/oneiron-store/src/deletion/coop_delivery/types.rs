//! What a courtesy delete answer keeps beside its choice: the customer
//! holds it placed (FIX 2924), the records a hold choice left out as no
//! copy this ask covers (FIX 2927), and a delete choice's operation, its
//! records each once (FIX 2925) with each one's observed state (FIX 2926).
//! Ids and codes only: no content, no error text and no host order.

use serde::{Deserialize, Serialize};

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

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
    pub fn new(operation_id: EntityId, records: &[EntityId]) -> Self {
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
    pub fn deletes(&self, records: &[EntityId]) -> bool {
        self.records.len() == records.len()
            && self
                .records
                .iter()
                .zip(records)
                .all(|(saved, record)| saved.record == *record)
    }

    /// The records still pending, in order.
    pub fn pending(&self) -> Vec<EntityId> {
        self.records
            .iter()
            .filter(|saved| saved.state == CooperativeDeleteRecordState::Pending)
            .map(|saved| saved.record)
            .collect()
    }

    /// The records removed, as hex.
    pub fn removed_hex(&self) -> Vec<String> {
        self.records
            .iter()
            .filter(|saved| saved.state == CooperativeDeleteRecordState::Removed)
            .map(|saved| saved.record.to_hex())
            .collect()
    }

    /// Saves what became of pending `record`. False when it is no pending
    /// record of this operation.
    pub fn settle(&mut self, record: EntityId, state: CooperativeDeleteRecordState) -> bool {
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
