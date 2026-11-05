//! Core half of `scope_summary::doors::note_versions`: its store-layer items live in `oneiron_store::scope_summary::doors::note_versions` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::scope_summary::doors::note_versions::*;

use super::super::codec::{ScopeSummaryBody, invalid};
use crate::error::Result;
use crate::scope_summary::SummaryStale;
use crate::{EntityId, Vault};
use heed::RoTxn;

/// Each NOTE `body` pins, as it reads now.
fn notes_now_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    body: &ScopeSummaryBody,
) -> Result<Vec<(EntityId, NoteNow)>> {
    if body.notes.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<EntityId> = body.notes.iter().map(|note| note.id).collect();
    let current = crate::dreamer_consolidation::note_source_pins_in_txn(vault, txn, &ids)?;
    Ok(body
        .notes
        .iter()
        .zip(current)
        .map(|(pinned, now)| {
            let now = match now {
                None => NoteNow::Unread,
                Some(now) if now == *pinned => NoteNow::Unchanged,
                Some(_) => NoteNow::Edited,
            };
            (pinned.id, now)
        })
        .collect())
}

/// The NOTE half of a NOTE set's serve check: every NOTE it covers is
/// pinned, and each is still one the Dreamer reads. An edited one passes.
pub(super) fn validate_note_pins_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    body: &ScopeSummaryBody,
) -> Result<()> {
    // The codec keeps each pin once and on a cover: as many pins as covers
    // is every cover pinned.
    if body.notes.len() != body.covers.len() {
        return Err(invalid("a NOTE set's summary pins every NOTE it covers"));
    }
    for (_, now) in notes_now_in_txn(vault, txn, body)? {
        if matches!(now, NoteNow::Unread) {
            return Err(invalid("summary source NOTE is no longer read"));
        }
    }
    Ok(())
}

/// Why `summary`, as it serves now, is stale: the NOTEs edited since it was
/// composed, in its pins' order; `None` when none was. A summary that does
/// not serve answers its refusal.
pub(in crate::scope_summary) fn summary_stale_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    summary: &EntityId,
) -> Result<Option<SummaryStale>> {
    let body = super::summary_in_txn(vault, txn, summary)?;
    let notes: Vec<String> = notes_now_in_txn(vault, txn, &body)?
        .into_iter()
        .filter(|(_, now)| matches!(now, NoteNow::Edited))
        .map(|(id, _)| id.to_hex())
        .collect();
    Ok((!notes.is_empty()).then_some(SummaryStale::NoteSourceEdited { notes }))
}
