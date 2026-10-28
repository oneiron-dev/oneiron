//! Engine-issued span quotes as citation pins (FIX 9894, 9895).
//!
//! A reader's quote of a document span is pinned as a citation in
//! `ENTITY_DOC_PIN`, so its origin frontier floors any later history purge,
//! as every citation's does. The reader's read admitted the document, so no
//! edit grant is asked: a quote adds no text operation. The pin keeps the
//! stored quote; no door here returns it. A span or a pinned quote is
//! resolved by its stable cursors, then projected into the reader's current
//! sight, so its caller can prove the hash of the text that reader was
//! issued.

use std::ops::Range;

use super::doc_actor::DocActor;
use super::pins::{CitationPin, ENTITY_DOC_PIN};
use super::side_keys::HexPair;
use super::verbs::resolve_cursors;
use super::{EntityDoc, TextAnchor, invalid, storage};
use crate::batch::secret_scan::LiftedKeys;
use crate::error::Result;
use crate::side_table::HexId;
use crate::store::Store;
use crate::{EntityId, Vault};

/// Where an issued span stands now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IssuedSpan {
    /// The id of the document the span belongs to.
    pub(crate) document: String,
    /// The span in the reader's current sight; `None` when it drifted.
    pub(crate) sight: Option<SpanInSight>,
}

/// A live span, in the stored text and in the reader's sight. The two ranges
/// differ wherever the reader reads a lifted key as its handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SpanInSight {
    pub(crate) stored: Range<usize>,
    pub(crate) shown: Range<usize>,
    /// The lowercase hex BLAKE3 hash of the span's text as the reader reads
    /// it now.
    pub(crate) quote_hash: String,
}

impl Vault {
    /// Pins the span `start..end` (stable cursors issued at `frontier`) of
    /// `entity` as citation `citation`, cited by `actor` (FIX 9894). The
    /// quote is proved against its origin version, as `pin_entity_text`
    /// proves one, and returns the id of the document it quotes.
    pub(crate) fn pin_issued_quote(
        &self,
        citation: &EntityId,
        entity: &EntityId,
        frontier: &[u8],
        start: &[u8],
        end: &[u8],
        actor: EntityId,
    ) -> Result<String> {
        self.with_write_txn_grouped(|txn| {
            let h = storage::head(&self.store, txn, entity)?;
            let doc = storage::load(&self.store, txn, &h)?;
            let origin = doc.fork(frontier)?;
            let (from, to) = resolve_cursors(&origin, frontier, start, end)?;
            let quote: String = origin.text().chars().skip(from).take(to - from).collect();
            if quote.is_empty() {
                return Err(invalid("quote span is empty"));
            }
            let key = HexPair(HexId(*entity), HexId(*citation));
            if ENTITY_DOC_PIN.contains(&self.store, txn, &key)? {
                return Err(invalid("citation pin is immutable"));
            }
            let pin = CitationPin {
                citation: citation.to_hex(),
                entity: entity.to_hex(),
                document: h.document.clone(),
                anchor: TextAnchor {
                    entity: entity.to_hex(),
                    frontier: frontier.to_vec(),
                    start: start.to_vec(),
                    end: end.to_vec(),
                    hash: *blake3::hash(quote.as_bytes()).as_bytes(),
                    quote,
                },
                actor: DocActor::Actor(actor),
            };
            ENTITY_DOC_PIN.put(&self.store, txn, &key, &pin)?;
            // The pin rides beside the document's entity, as a reply's does.
            #[cfg(feature = "sync")]
            crate::batch::queue_committed_rows(self, txn, std::iter::once(*entity).collect());
            Ok(h.document)
        })
    }

    /// Where the stable cursors of a span issued at `frontier` stand in
    /// `entity`'s live text, in a reader's sight (`masked` for a reader other
    /// than the owner), with the id of the document they belong to (FIX
    /// 9895). An edit elsewhere in the document moves the span and keeps it.
    pub(crate) fn entity_text_issued_span(
        &self,
        entity: &EntityId,
        frontier: &[u8],
        start: &[u8],
        end: &[u8],
        masked: bool,
    ) -> Result<IssuedSpan> {
        let txn = self.store.env.read_txn()?;
        let h = storage::head(&self.store, &txn, entity)?;
        let doc = storage::load(&self.store, &txn, &h)?;
        let sight = span_in_sight(&self.store, &txn, &doc, frontier, start, end, masked)?;
        Ok(IssuedSpan {
            document: h.document,
            sight,
        })
    }

    /// [`Self::entity_text_issued_span`] for the quote pinned as citation
    /// `citation` on `entity` (FIX 9895): its cursors resolve through the
    /// pin, whose origin no purge drops.
    pub(crate) fn issued_quote_in_sight(
        &self,
        entity: &EntityId,
        citation: &EntityId,
        masked: bool,
    ) -> Result<IssuedSpan> {
        let txn = self.store.env.read_txn()?;
        let pin = ENTITY_DOC_PIN
            .get(&self.store, &txn, &HexPair(HexId(*entity), HexId(*citation)))?
            .ok_or(invalid("quote citation is not pinned"))?;
        let h = storage::head(&self.store, &txn, entity)?;
        let doc = storage::load(&self.store, &txn, &h)?;
        let anchor = &pin.anchor;
        let sight = span_in_sight(
            &self.store,
            &txn,
            &doc,
            &anchor.frontier,
            &anchor.start,
            &anchor.end,
            masked,
        )?;
        Ok(IssuedSpan {
            document: pin.document,
            sight,
        })
    }
}

/// The live span of cursors issued at `frontier` in `doc`, projected into the
/// reader's sight, when the stored text between them is the text they
/// selected at `frontier`. `None` is drift: a cursor that no longer maps, an
/// origin a purge dropped, changed text, or a lifted key that now splits the
/// span in the reader's sight.
fn span_in_sight(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    doc: &EntityDoc,
    frontier: &[u8],
    start: &[u8],
    end: &[u8],
    masked: bool,
) -> Result<Option<SpanInSight>> {
    let Ok(origin) = doc.fork(frontier) else {
        return Ok(None);
    };
    let Ok((from, to)) = resolve_cursors(&origin, frontier, start, end) else {
        return Ok(None);
    };
    let Ok((live_from, live_to)) = resolve_cursors(doc, frontier, start, end) else {
        return Ok(None);
    };
    let quoted: String = origin.text().chars().skip(from).take(to - from).collect();
    let text: Vec<char> = doc.text().chars().collect();
    let live: String = text[live_from..live_to].iter().collect();
    if quoted != live {
        return Ok(None);
    }
    if !masked {
        return Ok(Some(SpanInSight {
            stored: live_from..live_to,
            shown: live_from..live_to,
            quote_hash: blake3::hash(live.as_bytes()).to_hex().to_string(),
        }));
    }
    // The reader reads each lifted key as its handle. The span projects
    // cleanly when no key straddles its edges: masking the text before it,
    // the span and the text after it apart reads as masking them together.
    let whole: String = text.iter().collect();
    let keys = LiftedKeys::of_in_txn(store, txn, [whole.as_str()])?;
    let before: String = text[..live_from].iter().collect();
    let after: String = text[live_to..].iter().collect();
    let (before, shown, after) = (
        keys.masked_text(&before).text(),
        keys.masked_text(&live).text(),
        keys.masked_text(&after).text(),
    );
    if format!("{before}{shown}{after}") != keys.masked_text(&whole).text() {
        return Ok(None);
    }
    let shown_from = before.chars().count();
    Ok(Some(SpanInSight {
        stored: live_from..live_to,
        shown: shown_from..shown_from + shown.chars().count(),
        quote_hash: blake3::hash(shown.as_bytes()).to_hex().to_string(),
    }))
}
