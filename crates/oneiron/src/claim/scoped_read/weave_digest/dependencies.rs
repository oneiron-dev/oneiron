//! The rows a saved weave period's copies depend on, for its erase index:
//! the sources its own checks read, each loop row's refs, and the rows a
//! health card's Coach draft was written from (FIX 8672). The draft's
//! diagnosis and proposal are text copied out of the agent's TASK and its
//! sealed pads, so the card's copy depends on every row its answer froze
//! (FIX 9220). A hard delete of one scrubs the text from the period's
//! copy (`rewrite.rs`); a served copy whose row is gone is scrubbed again
//! at serve, so a missed index entry never serves erased text.
use std::collections::BTreeSet;

use super::{ScopedRead, WeaveItem, WeaveReport, loop_decisions, report_sources};
use crate::EntityId;
use crate::dreamer_runner::maintenance::agent_health::AgentHealthCard;
use crate::error::Result;
use crate::ports::TombstoneStoreRead;
use crate::store::Store;

/// Every ref a saved period carries, for its erase index: the sources its
/// checks read, each loop row's claim, actor and evidence refs, and the
/// rows each card's unscrubbed draft text was written from. A hard delete
/// of a source erases the period; of any other ref, it rewrites the rows
/// that name it (`rewrite.rs`).
pub(super) fn indexed_sources(report: &WeaveReport) -> Result<BTreeSet<EntityId>> {
    let mut sources = report_sources(report)?;
    for item in report.sections.iter().flat_map(|section| &section.items) {
        sources.extend(loop_decisions::row_refs(item));
        if let WeaveItem::AgentHealth {
            card,
            draft_erased: false,
        } = item
        {
            sources.extend(draft_sources(card));
        }
    }
    Ok(sources)
}

/// The rows a card's Coach draft was written from, as its answer froze
/// them (FIX 9220): the agent, its TASK and each pinned brief's TASK, the
/// skills its run loaded, the observed brief's source and the pad read's
/// row and pads. None while the card holds no draft text.
fn draft_sources(card: &AgentHealthCard) -> BTreeSet<EntityId> {
    card.draft_source_rows()
}

/// Scrubs a card's draft text, its diagnosis and proposal, from this copy
/// and marks it, the copy's answer as the live card's scrub does (FIX
/// 9221); the draft's route and target and the card's other fields stay.
fn scrub_draft(card: &mut AgentHealthCard, draft_erased: &mut bool) {
    card.scrub_coach_draft();
    *draft_erased = true;
}

/// A hard delete of `source` in a saved card row: its draft text goes when
/// it was written from `source`. `true` when the row was rewritten.
pub(super) fn scrub_draft_of(item: &mut WeaveItem, source: &EntityId) -> bool {
    let WeaveItem::AgentHealth { card, draft_erased } = item else {
        return false;
    };
    if *draft_erased || !draft_sources(card).contains(source) {
        return false;
    }
    scrub_draft(card, draft_erased);
    true
}

/// The serve-time recheck of each card's draft in a served copy: a draft
/// written from a row now erased or stale, by its tombstone, is scrubbed
/// from the copy served, whether or not the erase index named the period.
/// The period and the card still serve.
fn scrub_erased_drafts_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    report: &mut WeaveReport,
) -> Result<()> {
    for item in report
        .sections
        .iter_mut()
        .flat_map(|section| &mut section.items)
    {
        let WeaveItem::AgentHealth { card, draft_erased } = item else {
            continue;
        };
        if *draft_erased {
            continue;
        }
        let mut gone = false;
        for row in draft_sources(card) {
            let state = store.port_deletion_state(txn, &row)?;
            if state.deleted || state.stale {
                gone = true;
                break;
            }
        }
        if gone {
            scrub_draft(card, draft_erased);
        }
    }
    Ok(())
}

impl ScopedRead<'_> {
    /// A saved period's copy as this read serves it, in `txn`: draft text
    /// written from an erased row scrubbed, indexed or not (FIX 8672), and
    /// each audit decision's refs past this reader's own floor (FIX 8322).
    /// Every row and the period stay.
    pub(super) fn serve_saved_copy_in(
        &self,
        txn: &heed::RoTxn<'_>,
        report: &mut WeaveReport,
    ) -> Result<()> {
        scrub_erased_drafts_in(&self.vault.store, txn, report)?;
        let (filter, policy) = self.resolve_retrieval_filter_in(txn, None)?;
        self.redact_sieve_decisions_in(txn, &policy, &filter, report);
        // A saved card's moves are judged again for this reader (FIX 8536).
        self.project_card_moves_in(txn, &policy, &filter, report);
        Ok(())
    }
}
