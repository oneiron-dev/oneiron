//! Plan mode's markup (agent-runtime-v1.md, "Plan mode reuses built review
//! parts"): the owner marks up a plan-doc with the built anchored-comment
//! threads, "lifted from office files to a markdown plan-doc": "the anchor
//! becomes a document, a frontier and a cursor span, and an anchor that
//! cannot be mapped is marked drifted rather than silently repositioned".
//!
//! A thread on a plan-doc stores the NOTE, the frontier its span was read at
//! and the span's Unicode scalar offsets there (`anchored_annotation`'s text
//! locator and body anchor). The span's characters are those a NOTE citation
//! would quote at that frontier ([`NoteDocument::quoted_span`]). Each read
//! follows them to the head ([`NoteDocument::live_span`]): the span maps
//! while every quoted character still stands, in order, with no other text
//! between them. A rewritten or deleted line, text typed inside the span, a
//! rewrite of the whole text, or a frontier the document no longer holds is
//! drift, and the thread stays on the span it was opened on. An edit writes
//! nothing to a thread; where its span stands is read each time.
//!
//! Only a plan-doc takes a thread: any other NOTE keeps refusing one, as it
//! did before plan mode.

use serde::{Deserialize, Serialize};

use super::document::NoteDocument;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::memory::{Memory, MemoryResult};

/// A plan-doc span as one read sees it at a frontier of its document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PlanDocSpan {
    /// The document frontier the offsets count at.
    pub(crate) frontier: Vec<u8>,
    /// The first character's Unicode scalar offset.
    pub(crate) char_start: u64,
    /// One past the last character's Unicode scalar offset.
    pub(crate) char_end: u64,
    /// The span's characters.
    pub(crate) quote: String,
}

/// A thread's span on a plan-doc: the words it was opened on, and where
/// they stand at the head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PlanDocSpanRead {
    /// The span's characters at the frontier it was read at; `None` when
    /// the document no longer holds that frontier.
    pub(crate) quote: Option<String>,
    /// The same characters at the head; `None` when the span drifted.
    pub(crate) head: Option<PlanDocSpan>,
}

fn no_anchor(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidAnchor(reason))
}

/// Refuses `id` unless it names a plan-doc: a NOTE `plugin/plan` with its
/// review row, the only NOTE a thread anchors on.
fn require_plan_doc_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<()> {
    if super::plan_doc::PLAN_DOC_REVIEW
        .get(&vault.store, txn, &id)?
        .is_some()
    {
        let (_, core) = super::verbs::note_core(vault, txn, id)?;
        if super::plan_doc::is_plan_doc_kind(&core.kind) {
            return Ok(());
        }
    }
    Err(no_anchor("only a plan-doc NOTE takes an anchored thread"))
}

/// Offsets that index a document's text, or `None`.
fn offsets(char_start: u64, char_end: u64) -> Option<(usize, usize)> {
    Some((
        usize::try_from(char_start).ok()?,
        usize::try_from(char_end).ok()?,
    ))
}

/// The span `char_start..char_end` of `doc` at its head.
fn head_span(doc: &NoteDocument, char_start: u64, char_end: u64) -> Result<PlanDocSpan> {
    let outside = || no_anchor("the span is not in the plan-doc's text");
    let (start, end) = offsets(char_start, char_end).ok_or_else(outside)?;
    let span = doc.quoted_span(start, end).map_err(|_| outside())?;
    Ok(PlanDocSpan {
        frontier: doc.doc.oplog_frontiers().encode(),
        char_start,
        char_end,
        quote: span.quote,
    })
}

/// The span `char_start..char_end` of `doc` read at `frontier`, and the same
/// characters at `doc`'s head while they all stand with the same text.
fn span_read(
    doc: &NoteDocument,
    frontier: &[u8],
    char_start: u64,
    char_end: u64,
) -> Result<PlanDocSpanRead> {
    let unread = PlanDocSpanRead {
        quote: None,
        head: None,
    };
    let Some((start, end)) = offsets(char_start, char_end) else {
        return Ok(unread);
    };
    // A frontier the document no longer holds (a rewrite's new head, an
    // erased history) reads no words, and the span is drift.
    let Ok(at) = doc.fork_at(frontier) else {
        return Ok(unread);
    };
    let Ok(span) = at.quoted_span(start, end) else {
        return Ok(unread);
    };
    let quote_hash = *blake3::hash(span.quote.as_bytes()).as_bytes();
    let head = doc
        .live_span(&span.start_cursor, &span.end_cursor, &quote_hash)?
        .map(|(start, end, quote)| PlanDocSpan {
            frontier: doc.doc.oplog_frontiers().encode(),
            char_start: start as u64,
            char_end: end as u64,
            quote,
        });
    Ok(PlanDocSpanRead {
        quote: Some(span.quote),
        head,
    })
}

/// Refuses a thread anchor on `plan` unless `plan` is a plan-doc whose text
/// at `frontier` holds the span `char_start..char_end`. The thread writer
/// calls it in its own transaction.
///
/// # Errors
///
/// [`ArtifactError::InvalidAnchor`] for a NOTE that is no plan-doc, a
/// frontier its document does not hold, or a span outside its text there;
/// storage errors.
pub(crate) fn require_plan_doc_span_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    plan: EntityId,
    frontier: &[u8],
    char_start: u64,
    char_end: u64,
) -> Result<()> {
    require_plan_doc_in_txn(vault, txn, plan)?;
    let doc = super::document_store::load(vault, txn, plan)?;
    if span_read(&doc, frontier, char_start, char_end)?
        .quote
        .is_none()
    {
        return Err(no_anchor(
            "the span is not in the plan-doc's text at its frontier",
        ));
    }
    Ok(())
}

impl Memory<'_> {
    /// Plan-doc `plan`'s span `char_start..char_end` at its head, read
    /// through the caller's NOTE read; `None` where the caller does not read
    /// the NOTE.
    ///
    /// # Errors
    ///
    /// [`ArtifactError::InvalidAnchor`] for a NOTE that is no plan-doc or a
    /// span outside its text; the NOTE read's refusals.
    pub(crate) fn plan_doc_head_span(
        &self,
        plan: EntityId,
        char_start: u64,
        char_end: u64,
    ) -> MemoryResult<Option<PlanDocSpan>> {
        let read = self.project_note_read(&access(plan), |txn, doc, _| {
            require_plan_doc_in_txn(self.vault(), txn, plan)?;
            let doc = NoteDocument::from_loro(doc.note, doc.doc)?;
            head_span(&doc, char_start, char_end).map_err(Into::into)
        })?;
        Ok(read.value)
    }

    /// Where plan-doc `plan`'s span `char_start..char_end`, read at
    /// `frontier`, stands now, read through the caller's NOTE read; `None`
    /// where the caller does not read the NOTE.
    ///
    /// # Errors
    ///
    /// [`ArtifactError::InvalidAnchor`] for a NOTE that is no plan-doc; the
    /// NOTE read's refusals.
    pub(crate) fn plan_doc_span_read(
        &self,
        plan: EntityId,
        frontier: &[u8],
        char_start: u64,
        char_end: u64,
    ) -> MemoryResult<Option<PlanDocSpanRead>> {
        let read = self.project_note_read(&access(plan), |txn, doc, _| {
            require_plan_doc_in_txn(self.vault(), txn, plan)?;
            let doc = NoteDocument::from_loro(doc.note, doc.doc)?;
            span_read(&doc, frontier, char_start, char_end).map_err(Into::into)
        })?;
        Ok(read.value)
    }
}

/// The NOTE read of plan-doc `plan`.
fn access(plan: EntityId) -> super::NoteAccessRequest {
    super::NoteAccessRequest {
        note_ref: plan.to_hex(),
        reason: None,
    }
}
