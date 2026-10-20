//! A room privacy erase's request-local legal-hold split and its report.
use crate::deletion::{DeleteEntityOutcome, LegalHoldActorKind, LegalHoldTarget};
use crate::edge::EdgeActorClass;
use crate::error::{LegalHoldNotice, LegalHoldState, Result};
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
    /// The law bound of the standing host orders the owner may see that
    /// keep any of the `kept` records (FIX 5229, #3182): the order that
    /// ends last, as each refusal names it. `None` while only customer
    /// holds, or only orders whose silence runs, keep them: a secret order
    /// is never named, and the erase stands either way.
    pub law_notice: Option<LegalHoldNotice>,
}

/// The held records one erase request has already selected. A record kept
/// once is neither split nor logged again through another path of the same
/// request; a new request starts empty and re-proves every hold.
#[derive(Default)]
pub(super) struct PrivacyEraseProgress {
    pub(super) kept: BTreeSet<EntityId>,
    /// The law bound of a visible host order that keeps one of `kept`, the
    /// one that ends last of those the request met (FIX 5229).
    pub(super) law_notice: Option<LegalHoldNotice>,
}

/// The law bound the standing host orders the owner may see on `kept`
/// name, read in the split's own write: the order that ends last
/// ([`legal_hold::law_notice`]). Best-effort: a record whose holds do not
/// read is logged and adds no bound; it never fails the erase.
fn kept_law_notice_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    kept: &[EntityId],
) -> Option<LegalHoldNotice> {
    let mut holds = Vec::new();
    for record in kept {
        match legal_hold::holds_on_in_txn(&vault.store, txn, &LegalHoldTarget::Record(*record)) {
            Ok(found) => holds.extend(found),
            Err(error) => tracing::warn!(
                record = %record.to_hex(),
                %error,
                "privacy erase: a kept record's holds not read; no law bound named for it"
            ),
        }
    }
    legal_hold::law_notice(
        &holds,
        vault.store.clock.now_recorded_at(),
        LegalHoldState::RetainedForLaw,
    )
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
        let (erase, kept, notice) = vault.with_write_txn_grouped(|txn| {
            authorize(txn)?;
            let (erase, kept) =
                legal_hold::split_privacy_erase_in_txn(&vault.store, txn, &pending, &by)?;
            let notice = kept_law_notice_in(vault, txn, &kept);
            Ok((erase, kept, notice))
        })?;
        self.kept.extend(kept);
        // The bound kept longest names the request's kept count (FIX 5229).
        if let Some(notice) = notice
            && self
                .law_notice
                .as_ref()
                .is_none_or(|held| held.bound.ends_at < notice.bound.ends_at)
        {
            self.law_notice = Some(notice);
        }
        Ok(erase)
    }
}
