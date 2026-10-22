//! What a courtesy delete answer keeps beside its choice: the customer
//! holds it placed (FIX 2924), the records a hold choice left out as no
//! copy this ask covers (FIX 2927), and a delete choice's operation, its
//! records each once (FIX 2925) with each one's observed state (FIX 2926).
//! Ids and codes only: no content, no error text and no host order.

use serde::{Deserialize, Serialize};

use crate::deletion::{LegalHold, LegalHoldKind};
use crate::store::legal_hold as hold_store;
use crate::{EntityId, Result, Vault};

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
