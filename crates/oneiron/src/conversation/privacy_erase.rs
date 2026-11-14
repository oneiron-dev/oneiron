//! A room privacy erase's report.
use crate::deletion::DeleteEntityOutcome;
use crate::error::Result;
use crate::{EntityId, Vault};
use std::collections::BTreeSet;

/// What [`Vault::erase_room_person`] did: the deletes it ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomPersonEraseOutcome {
    pub outcomes: Vec<DeleteEntityOutcome>,
}

/// The erase request's progress. No hold keeps any record, so nothing is
/// tracked; kept as the callers' threading point.
#[derive(Default)]
pub(super) struct PrivacyEraseProgress;

impl PrivacyEraseProgress {
    /// Of the records a privacy erase selected, the ones to erase: all of
    /// them. No hold keeps any (LEGAL-HOLD-USE = B).
    /// `authorize` re-proves the erase first, in a read of its own; each
    /// record is named once.
    pub(super) fn unheld(
        &mut self,
        vault: &Vault,
        records: &[EntityId],
        authorize: impl FnOnce(&heed::RoTxn<'_>) -> Result<()>,
    ) -> Result<Vec<EntityId>> {
        if records.is_empty() {
            return Ok(Vec::new());
        }
        authorize(&vault.store.env.read_txn()?)?;
        let mut seen = BTreeSet::new();
        Ok(records
            .iter()
            .copied()
            .filter(|id| seen.insert(*id))
            .collect())
    }
}
