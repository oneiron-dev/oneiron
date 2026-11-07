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
//!
//! A skill erase also clears what names that revision as the reviewer
//! (FIX 10881): the `reviewer_revision` on every card and review receipt
//! that names it, and each such receipt's rule-outcome row in the skill
//! reliability ledger. Unrelated cards, receipts, source history and
//! learning evidence stay as they are.
//!
//! An answer that predates `source_rows` names none of the SKILLs or the
//! CLAIM its text was written from (FIX 10432): the erase of a SKILL or a
//! CLAIM scrubs every such standing draft, fail-closed, since no index can
//! attribute them. The widened pass reads the live cards, so it needs no
//! backfill and no new index; an erase whose kind no longer reads cannot
//! rule either out and scrubs too.
use std::collections::BTreeSet;

use super::ask::AgentHealthCoachAnswer;
use super::{AgentHealthCard, CARDS, HEALTH_REVIEW_RECEIPT_PREFIX, card_key};
use crate::batch::EntityMetadataHeader;
use crate::ports::{EntityStoreRead, TombstoneStoreRead};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_SKILL};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Result, Vault};

/// Each live card under every row its standing Coach draft was written from
/// (FIX 10434): `draft_source_rows`. Key: id16(source) + the card key.
const CARD_BY_SOURCE: SideTable<(EntityId, ([u8; 16], [u8; 1], [u8; 16])), (), Raw> =
    SideTable::new(&side_table::COACH_AGENT_HEALTH_CARD_BY_SOURCE);
/// Each live card under every reviewer revision it names (FIX 10434):
/// `reviewer_revisions`. Key: id16(revision) + the card key.
const CARD_BY_REVIEWER: SideTable<(EntityId, ([u8; 16], [u8; 1], [u8; 16])), (), Raw> =
    SideTable::new(&side_table::COACH_AGENT_HEALTH_CARD_BY_REVIEWER);
/// The reviewer's rule-outcome rows as the reliability ledger keeps them
/// (FIX 10881): the same `SKILL_RELIABILITY_OUTCOME` rows
/// `skill_reliability::rule_outcome` keys `(skill, receipt)`, named here by
/// exact key only. The erase deletes; it never decodes a value, so the
/// value type is bytes it never reads.
const REVIEWER_RULE_OUTCOME: SideTable<(EntityId, String), Vec<u8>, Raw> =
    SideTable::new(&side_table::SKILL_RELIABILITY_OUTCOME);

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

/// Keeps [`CARD_BY_REVIEWER`] in step with one card write, in the caller's
/// transaction: drops the rows of reviewer revisions the card no longer
/// names, adds the rows of revisions it newly names (FIX 10434). Both sets
/// come from [`AgentHealthCard::reviewer_revisions`] on the card before and
/// after the write.
pub(super) fn sync_reviewer_membership(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    key: &([u8; 16], [u8; 1], [u8; 16]),
    old: &BTreeSet<EntityId>,
    new: &BTreeSet<EntityId>,
) -> Result<()> {
    for gone in old.difference(new) {
        CARD_BY_REVIEWER.delete(store, txn, &(*gone, *key))?;
    }
    for added in new.difference(old) {
        CARD_BY_REVIEWER.put(store, txn, &(*added, *key), &())?;
    }
    Ok(())
}

/// Clears the Coach draft text of every live card whose draft was written
/// from the erased `id`, in the erase's own transaction. A no-op for an id
/// no standing draft or reviewer names. Cards are found through the
/// by-source and by-reviewer indexes (FIX 10434); the live row is rechecked
/// before the scrub, so a stale membership row causes an extra read, never
/// a wrong scrub. An erased reviewer revision (FIX 10881) is also cleared
/// from every card and review receipt that names it, and each such
/// receipt's rule-outcome row goes with it. A card or receipt that names
/// another revision, and a receipt a revision never seeded, stay as they
/// are. A SKILL or CLAIM erase additionally scrubs every standing draft
/// that predates `source_rows` (FIX 10432), which no index attributes.
pub(crate) fn erase_sources_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let mut keys: BTreeSet<([u8; 16], [u8; 1], [u8; 16])> = CARD_BY_SOURCE
        .scan_keys(store, txn, id.as_bytes())?
        .into_iter()
        .map(|(_, key)| key)
        .collect();
    keys.extend(
        CARD_BY_REVIEWER
            .scan_keys(store, txn, id.as_bytes())?
            .into_iter()
            .map(|(_, key)| key),
    );
    for key in keys {
        let Some(mut card) = CARDS.get(store, txn, &key)? else {
            continue;
        };
        let old_sources = card.draft_source_rows();
        let old_reviewers = card.reviewer_revisions();
        let mut changed = false;
        if old_sources.contains(id) && card.scrub_coach_draft() {
            changed = true;
        }
        if card.reviewer_revision == Some(*id) {
            card.reviewer_revision = None;
            changed = true;
        }
        for held in &mut card.review_outcomes {
            if held.reviewer_revision != Some(*id) {
                continue;
            }
            held.reviewer_revision = None;
            changed = true;
            // The bridge keys the receipt's rule-outcome row by this same
            // `(skill, receipt)` pair; a receipt id of another shape names
            // no row of ours.
            if held.receipt.starts_with(HEALTH_REVIEW_RECEIPT_PREFIX) {
                REVIEWER_RULE_OUTCOME.delete(store, txn, &(*id, held.receipt.clone()))?;
            }
        }
        if changed {
            sync_card_membership(store, txn, &key, &old_sources, &card.draft_source_rows())?;
            sync_reviewer_membership(store, txn, &key, &old_reviewers, &card.reviewer_revisions())?;
            super::receipt_index::put_card_in_txn(store, txn, &key, &card)?;
        }
    }
    // FIX 10432: a standing draft that predates `source_rows` names none of
    // the SKILLs or the CLAIM its text was written from, so the loop above
    // cannot find it. On a SKILL or CLAIM erase every such draft goes,
    // fail-closed; the live row is rechecked here too, and the pass keeps
    // the indexes in step exactly as the loop above does.
    if widened_scrub_owed(store, txn, id)? {
        for (key, mut card) in CARDS.scan(store, txn)? {
            let unknown = card
                .coach
                .as_ref()
                .and_then(|ask| ask.answer.as_ref())
                .is_some_and(|answer| {
                    answer.draft.is_some()
                        && answer.draft_erased != Some(true)
                        && answer.source_rows.is_none()
                });
            if !unknown {
                continue;
            }
            let old_sources = card.draft_source_rows();
            let old_reviewers = card.reviewer_revisions();
            if card.scrub_coach_draft() {
                sync_card_membership(store, txn, &key, &old_sources, &card.draft_source_rows())?;
                sync_reviewer_membership(
                    store,
                    txn,
                    &key,
                    &old_reviewers,
                    &card.reviewer_revisions(),
                )?;
                super::receipt_index::put_card_in_txn(store, txn, &key, &card)?;
            }
        }
    }
    Ok(())
}

/// Whether the erased `id` owes the fail-closed scrub of every standing
/// draft that predates `source_rows` (FIX 10432): a SKILL or a CLAIM may
/// have written text such a draft holds, and no index attributes them. The
/// row still stands at both delete doors, since the erasers run before its
/// body goes, so its kind reads there; a kind that no longer reads, or a
/// row that no longer parses, cannot rule either out and scrubs too, as an
/// unreadable row names an actor for the actor scrubs (FIX 8908).
fn widened_scrub_owed(store: &Store, txn: &mut heed::RwTxn<'_>, id: &EntityId) -> Result<bool> {
    let Some(raw) = store.port_entity_raw(txn, id)? else {
        return Ok(true);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(true);
    };
    Ok(matches!(
        header.entity_type,
        ENTITY_TYPE_SKILL | ENTITY_TYPE_CLAIM
    ))
}

/// Whether the live card standing under `card`'s key holds its Coach draft
/// erased (FIX 10432): a saved Weave copy's serve-time recheck asks it for
/// a draft that predates `source_rows`, whose sources no tombstone check
/// can name. `false` when no live card stands there, the row does not parse,
/// or its draft reads unerased: only a positive erase signal clears the
/// copy's text (L07-A's FIX 10432 condition).
pub(crate) fn live_coach_draft_erased_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    card: &AgentHealthCard,
) -> Result<bool> {
    let key = card_key(card.subject, card.signal, card.task);
    Ok(CARDS
        .get(store, txn, &key)
        .ok()
        .flatten()
        .is_some_and(|live| live.coach_draft_erased()))
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
