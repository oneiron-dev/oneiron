//! A room privacy erase's request-local legal-hold split and its report.
use crate::deletion::{DeleteEntityOutcome, LegalHoldActorKind};
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::store::legal_hold::{self, HoldActor};
use crate::{EntityId, Vault, WriteActor};
use std::collections::BTreeSet;

/// What [`Vault::erase_room_person`] did: the deletes it ran, and how many
/// distinct records it kept because a legal hold names them (C5). The count
/// names no hold and no reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomPersonEraseOutcome {
    pub outcomes: Vec<DeleteEntityOutcome>,
    pub kept: usize,
}

/// The held records one erase request has already selected. A record kept
/// once is neither split nor logged again through another path of the same
/// request; a new request starts empty and re-proves every hold.
#[derive(Default)]
pub(super) struct PrivacyEraseProgress {
    pub(super) kept: BTreeSet<EntityId>,
}

/// Who a room erase's legal-hold refusal names. Its authority is the
/// person's own `GdprSelf` or the room role's `GdprManage`, never vault
/// ownership, so a human is a member here.
fn hold_actor(actor: WriteActor) -> HoldActor {
    let kind = match actor.actor_class() {
        EdgeActorClass::Human => LegalHoldActorKind::Member,
        EdgeActorClass::Agent => LegalHoldActorKind::Agent,
        EdgeActorClass::System => LegalHoldActorKind::Unattributed,
    };
    HoldActor::new(kind, Some(actor.entity_ref().to_hex()))
}

impl PrivacyEraseProgress {
    /// Of the records a privacy erase selected, the ones no legal hold names
    /// (C5). Each newly held one logs its refusal and stays; `authorize`
    /// re-proves the erase in the same write. A record this request already
    /// kept is skipped, and a kept record joins the set only once that write
    /// commits. The delete door still refuses a hold placed after this split.
    pub(super) fn unheld(
        &mut self,
        vault: &Vault,
        records: &[EntityId],
        actor: WriteActor,
        authorize: impl FnOnce(&heed::RoTxn<'_>) -> Result<()>,
    ) -> Result<Vec<EntityId>> {
        let mut seen = BTreeSet::new();
        let pending: Vec<EntityId> = records
            .iter()
            .copied()
            .filter(|id| !self.kept.contains(id) && seen.insert(*id))
            .collect();
        if pending.is_empty() {
            return Ok(Vec::new());
        }
        let by = hold_actor(actor);
        let (erase, kept) = vault.with_write_txn_grouped(|txn| {
            authorize(txn)?;
            legal_hold::split_privacy_erase_in_txn(&vault.store, txn, &pending, &by)
        })?;
        self.kept.extend(kept);
        Ok(erase)
    }
}
