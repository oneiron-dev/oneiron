//! Revision-pinned quote citations derived from engine-issued span selections.
//!
//! A quote handle is a citation reference (FIX 9894): issuing it pins the
//! span as a document citation (`ENTITY_DOC_PIN`), so a purge keeps its
//! origin, and the handle names that citation with the message, its
//! document, the pinned frontier, the stable cursor pair and the quote's
//! hash, never the quoted text. Proving it re-proves disclosure, resolves
//! the pinned cursors through the citation and re-projects them into the
//! reader's current sight (FIX 9895), so a quote stays valid across edits
//! outside it and drift is answered as drift.

use serde::Serialize;

use crate::EntityId;
#[cfg(feature = "sync")]
use crate::claim::ScopedRead;
#[cfg(feature = "sync")]
use crate::error::{Error, Result};
#[cfg(feature = "sync")]
use crate::lens::generated_ui::GeneratedUiRender;
#[cfg(feature = "sync")]
use crate::ports::EntityStoreRead;
#[cfg(feature = "sync")]
use crate::registry::ENTITY_TYPE_MESSAGE;

use super::LensReadHandle;
#[cfg(feature = "sync")]
use super::mediation_frame_read::LENS_SPAN_DRIFTED;
#[cfg(feature = "sync")]
use super::{LensRenderFrame, LensSpanSelectionRequest};

/// Half-open offsets in Unicode scalar values, not UTF-8 bytes or UTF-16 units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LensQuoteRange {
    pub start: usize,
    pub end: usize,
}

/// An engine-issued quote citation. It carries no copy of the selected text.
/// The private selection is used to re-prove the citation at the render boundary.
/// Cursors are lowercase hex of their encoded bytes; the range is in the reader's
/// sight at the pinned revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LensQuoteHandle {
    reply_to_message_id: EntityId,
    /// The citation the quote is pinned as on the message.
    citation_ref: String,
    document: String,
    reply_to_revision_id: String,
    reply_to_range: LensQuoteRange,
    start_cursor: String,
    end_cursor: String,
    quote_hash: String,
    #[serde(skip)]
    selection: LensReadHandle,
}

/// What proving an issued quote found (FIX 9895; the drift answer is a call,
/// canon silent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LensQuoteProof {
    /// The reader may still read the message, and its cursors still select
    /// the text they quoted, wherever edits elsewhere moved them.
    Live,
    /// The reader may still read the message, but the quote no longer reads
    /// as issued: its text was edited or deleted, or a key lifted inside it
    /// since now reads to this reader as its handle.
    Drifted,
}

impl LensQuoteHandle {
    #[must_use]
    pub fn reply_to_message_id(&self) -> EntityId {
        self.reply_to_message_id
    }

    #[must_use]
    pub fn reply_to_revision_id(&self) -> &str {
        &self.reply_to_revision_id
    }

    #[must_use]
    pub fn reply_to_range(&self) -> LensQuoteRange {
        self.reply_to_range
    }

    /// The citation the quote is pinned as on its message.
    #[must_use]
    pub fn citation_ref(&self) -> &str {
        &self.citation_ref
    }

    /// The id of the message's document.
    #[must_use]
    pub fn document(&self) -> &str {
        &self.document
    }

    /// The stable cursor pair, as lowercase hex of the encoded cursors.
    #[must_use]
    pub fn cursors(&self) -> (&str, &str) {
        (&self.start_cursor, &self.end_cursor)
    }

    /// The lowercase hex BLAKE3 hash of the quoted text, as its reader read it.
    #[must_use]
    pub fn quote_hash(&self) -> &str {
        &self.quote_hash
    }
}

#[cfg(feature = "sync")]
impl LensRenderFrame {
    /// Select a MESSAGE span and issue its revision-pinned quote triple.
    /// The client supplies only a rendered atom, handle name and scalar offsets.
    pub fn select_quote(
        &self,
        read: &ScopedRead<'_>,
        render: &GeneratedUiRender,
        request: &LensSpanSelectionRequest,
    ) -> Result<LensQuoteHandle> {
        let selected = self.select_span(read, render, request)?;
        self.quote_from_span(read, render, &selected)
    }

    /// Convert an issued span selection to a quote, re-proving its render,
    /// disclosure scope and MESSAGE identity, and resolving its pinned cursors,
    /// at the boundary, then pin it as a citation on the message under the
    /// reader's own read (no edit grant).
    pub fn quote_from_span(
        &self,
        read: &ScopedRead<'_>,
        render: &GeneratedUiRender,
        selected: &LensReadHandle,
    ) -> Result<LensQuoteHandle> {
        let (row, issued) = self.resolve_issued_handle(read, render, selected)?;
        let span = selected
            .span()
            .ok_or_else(|| Error::InvalidConfig("quote requires a selected span".into()))?;
        if issued.is_none_or(|issued| issued.live.is_none()) {
            return Err(Error::InvalidConfig(LENS_SPAN_DRIFTED.into()));
        }
        let (start, end) = span.range();
        if start == end {
            return Err(Error::InvalidConfig(
                "quote requires a nonempty span".into(),
            ));
        }
        let id = *row.target().entity_id();
        let txn = read.vault().store.env.read_txn()?;
        let record = read.vault().store.port_entity_record(&txn, &id)?;
        if record.is_none_or(|record| record.entity_type != ENTITY_TYPE_MESSAGE) {
            return Err(Error::InvalidConfig("quote requires a MESSAGE".into()));
        }
        drop(txn);
        let (start_cursor, end_cursor) = span.cursors();
        let reader = EntityId::from_hex(read.actor_key().actor_ref()).map_err(|_| {
            Error::InvalidConfig("a quote is cited by an actor this vault holds".into())
        })?;
        let citation = EntityId::now();
        let document = read.vault().pin_issued_quote(
            &citation,
            &id,
            span.frontier(),
            start_cursor,
            end_cursor,
            reader,
        )?;
        Ok(LensQuoteHandle {
            reply_to_message_id: id,
            citation_ref: citation.to_hex(),
            document,
            reply_to_revision_id: lower_hex(span.frontier()),
            reply_to_range: LensQuoteRange { start, end },
            start_cursor: lower_hex(start_cursor),
            end_cursor: lower_hex(end_cursor),
            quote_hash: span.quote_hash().to_owned(),
            selection: selected.clone(),
        })
    }

    /// Prove an issued quote now: its render, disclosure scope and document
    /// are re-proved under the current read, and a failure there is an error,
    /// so revoked access stays revoked. Its pinned cursors then resolve: an
    /// edit outside the quote keeps it [`LensQuoteProof::Live`], and a quote
    /// that no longer reads to this reader as it was issued answers
    /// [`LensQuoteProof::Drifted`] (FIX 9895).
    pub fn prove_quote(
        &self,
        read: &ScopedRead<'_>,
        render: &GeneratedUiRender,
        quote: &LensQuoteHandle,
    ) -> Result<LensQuoteProof> {
        // Disclosure first: the reader must still be issued this reach.
        self.resolve_issued_handle(read, render, &quote.selection)?;
        let citation = EntityId::from_hex(&quote.citation_ref)
            .map_err(|_| Error::InvalidConfig("quote names no citation".into()))?;
        let masked = !read.actor_key().reads_as_vault_owner();
        let issued = read
            .vault()
            .issued_quote_in_sight(&quote.reply_to_message_id, &citation, masked)?;
        if issued.document != quote.document {
            return Err(Error::InvalidConfig(
                "quote no longer names its message's document".into(),
            ));
        }
        let live = issued.sight.is_some_and(|sight| sight.quote_hash == quote.quote_hash);
        Ok(if live {
            LensQuoteProof::Live
        } else {
            LensQuoteProof::Drifted
        })
    }
}

#[cfg(feature = "sync")]
fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
