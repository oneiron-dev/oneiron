//! A room privacy erase's report, and the re-proof before each batch.
use crate::deletion::DeleteEntityOutcome;
use crate::error::Result;
use crate::{EntityId, Vault};
use std::collections::BTreeSet;

/// What [`Vault::erase_room_person`] did: the deletes it ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomPersonEraseOutcome {
    pub outcomes: Vec<DeleteEntityOutcome>,
}

/// The records a privacy erase selected, each once, after `authorize`
/// re-proves the erase in a read of its own. No legal hold keeps any of them
/// (LEGAL-HOLD-USE = B).
pub(super) fn reauthorized_targets(
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
