//! What an erase reaches of the Coach's drafts on live agent-health cards
//! (FIX 9221). A draft's diagnosis and proposal are text copied out of the
//! rows its answer froze (`sources.rs`). An erase or hard delete of one of
//! them clears that text on every card whose draft was written from it and
//! marks the answer erased; the card, its evidence and outcome, the draft's
//! route and target and the owner's application stay. The same scrub runs
//! at both delete doors (`maintenance::erase_source_copies_in_txn`), for an
//! erased actor and for a restored image's replay, and a saved Weave copy
//! runs it too. An answer that lands after such an erase is checked against
//! its rows first and lands without its draft's text.
use std::collections::BTreeSet;

use super::ask::AgentHealthCoachAnswer;
use super::{AgentHealthCard, CARDS};
use crate::ports::TombstoneStoreRead;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Result, Vault};

/// Each live card under every row its standing Coach draft was written from
/// (FIX 10434): `draft_source_rows`. Key: id16(source) + the card key.
const CARD_BY_SOURCE: SideTable<(EntityId, ([u8; 16], [u8; 1], [u8; 16])), (), Raw> =
    SideTable::new(&side_table::COACH_AGENT_HEALTH_CARD_BY_SOURCE);

impl AgentHealthCoachAnswer {
    /// Clears the draft's diagnosis and proposal and marks the answer
    /// erased; the draft's route and target stay. `true` when it held a
    /// draft.
    pub(super) fn erase_draft_text(&mut self) -> bool {
        let Some(draft) = self.draft.as_mut() else {
            return false;
        };
        draft.diagnosis.clear();
        draft.proposal.clear();
        self.draft_erased = Some(true);
        true
    }
}

impl AgentHealthCard {
    /// Clears this card's Coach draft text and marks its answer erased: the
    /// one scrub a live card and a saved Weave copy share. `true` when it
    /// held a draft.
    pub(crate) fn scrub_coach_draft(&mut self) -> bool {
        self.coach
            .as_mut()
            .and_then(|ask| ask.answer.as_mut())
            .is_some_and(AgentHealthCoachAnswer::erase_draft_text)
    }

    /// Whether an erase cleared this card's Coach draft text.
    pub(crate) fn coach_draft_erased(&self) -> bool {
        self.coach
            .as_ref()
            .and_then(|ask| ask.answer.as_ref())
            .is_some_and(|answer| answer.draft_erased == Some(true))
    }
}

/// Keeps [`CARD_BY_SOURCE`] in step with one card write, in the caller's
/// transaction: drops the rows of sources the card no longer names, adds the
/// rows of sources it newly names (FIX 10434). Both sets come from
/// [`AgentHealthCard::draft_source_rows`] on the card before and after the
/// write.
pub(super) fn sync_card_membership(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    key: &([u8; 16], [u8; 1], [u8; 16]),
    old: &BTreeSet<EntityId>,
    new: &BTreeSet<EntityId>,
) -> Result<()> {
    for gone in old.difference(new) {
        CARD_BY_SOURCE.delete(store, txn, &(*gone, *key))?;
    }
    for added in new.difference(old) {
        CARD_BY_SOURCE.put(store, txn, &(*added, *key), &())?;
    }
    Ok(())
}

/// Clears the Coach draft text of every live card whose draft was written
/// from the erased `id`, in the erase's own transaction. A no-op for an id
/// no standing draft names. Cards are found through the by-source index
/// (FIX 10434); the live row is rechecked before the scrub, so a stale
/// membership row causes an extra read, never a wrong scrub.
pub(crate) fn erase_sources_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    for (_, key) in CARD_BY_SOURCE.scan_keys(store, txn, id.as_bytes())? {
        let Some(mut card) = CARDS.get(store, txn, &key)? else {
            continue;
        };
        let old = card.draft_source_rows();
        if old.contains(id) && card.scrub_coach_draft() {
            let new = card.draft_source_rows();
            sync_card_membership(store, txn, &key, &old, &new)?;
            CARDS.put(store, txn, &key, &card)?;
        }
    }
    Ok(())
}

/// The live card table's actor scrub: an actor's erase, and a restored
/// image's replay of every erased id, run [`erase_sources_in_txn`].
pub(crate) fn erase_actor_sources_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    erase_sources_in_txn(&vault.store, txn, id)
}

/// Whether any of `rows` is erased or stale now, by its tombstone, in `txn`.
pub(super) fn any_gone_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    rows: &[EntityId],
) -> Result<bool> {
    for row in rows {
        let state = store.port_deletion_state(txn, row)?;
        if state.deleted || state.stale {
            return Ok(true);
        }
    }
    Ok(false)
}
