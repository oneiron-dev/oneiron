//! A room privacy erase's report.
use crate::deletion::DeleteEntityOutcome;
use crate::error::Result;
use crate::{EntityId, Vault, WriteActor};

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
    pub(super) fn unheld(
        &mut self,
        _vault: &Vault,
        records: &[EntityId],
        _actor: WriteActor,
        _authorize: impl FnOnce(&heed::RoTxn<'_>) -> Result<()>,
    ) -> Result<Vec<EntityId>> {
        Ok(records.to_vec())
    }
}
