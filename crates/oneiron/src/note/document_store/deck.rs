//! What a deck keep reads of the NOTE spans its outline cites, in the deck's
//! own transaction: a span with or without a cited CLAIM (FIX 9813, 9814),
//! and the outline's text at its keep, whose lifted keys a reader masked from
//! them reads as handles (FIX 9605).

use super::super::citation_erase::NOTE_ERASE_SOURCE;
use super::super::document::invalid;
use super::load;
use crate::error::Result;
use crate::side_table::HexId;
use crate::{EntityId, Vault};

/// One cited span as the engine sees it now.
pub(crate) struct DeckSpanObservation {
    /// The cited document's frontier.
    pub(crate) frontier: Vec<u8>,
    /// Whether the span maps onto live characters with its quote.
    pub(crate) mapped: bool,
}

/// What `document`'s span from `start_cursor` to `end_cursor`, quoting
/// `quote_hash`, is in `txn`: the document's frontier and whether the span
/// still stands. Its sources' erasure is judged as a pin's is: the document
/// always, `claim` only when the span names one.
///
/// # Errors
///
/// An erased or unreadable source, an undecodable cursor, storage errors.
pub(crate) fn observe_deck_span_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    document: EntityId,
    claim: Option<EntityId>,
    start_cursor: &[u8],
    end_cursor: &[u8],
    quote_hash: &[u8; 32],
) -> Result<DeckSpanObservation> {
    for id in std::iter::once(document).chain(claim) {
        if vault.local_hard_delete_marker_exists_in_txn(txn, &id)?
            || NOTE_ERASE_SOURCE.contains(&vault.store, txn, &HexId(id))?
        {
            return Err(invalid("NOTE citation source was erased"));
        }
    }
    let doc = load(vault, txn, document)?;
    let mapped = doc
        .live_span(start_cursor, end_cursor, quote_hash)?
        .is_some();
    Ok(DeckSpanObservation {
        frontier: doc.doc.oplog_frontiers().encode(),
        mapped,
    })
}

/// The markdown `note` held at `frontier`, read in `txn`; `None` once that
/// frontier is no longer in the NOTE's history.
///
/// # Errors
///
/// An unreadable NOTE, storage errors.
pub(crate) fn deck_outline_markdown_at_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    frontier: &[u8],
) -> Result<Option<String>> {
    let Ok(at) = load(vault, txn, note)?.fork_at(frontier) else {
        return Ok(None);
    };
    Ok(Some(at.view()?.markdown))
}
