//! The redacted view of a tainted result body (ARCH-0069 `#result-bodies`,
//! L6-31). Build exhaust that the store-time scan marked, or that a lease's
//! secret tainted, is read with each secret span blanked instead of being
//! withheld whole. Each byte of a span reads as [`FILLER`], as a masked
//! file's key does, but a newline stays a newline, so offsets, lengths and
//! line numbers stay true against the body's own line index. Every facet
//! reads the view unchanged: a `search` cannot match a blanked byte, and a
//! `query` sees `*`. The stored bytes, their digest and their marks are
//! never rewritten; the view is made at each read.
//!
//! The spans are those the write door's text rules place ([`file_spans`])
//! and the values custody knows now ([`KnownSource`]), found in the bytes
//! read widened on each side by [`SECRET_SPAN_REACH`] or the known values'
//! reach, whichever is longer, so a span the read's edges cut is found
//! whole. Each reply is still checked for an unmarked secret before it
//! leaves (`facets`).

use std::ops::Range;

use super::ResultBody;
use super::run_body::LiveCutoff;
use crate::batch::secret_scan::file_spans;
use crate::code_run::{CodeRunOutputKind, ExecutorStorage};
use crate::file_secret_marks::FILLER;
use crate::secret_custody::{KnownSource, KnownValues};
use crate::{Error, Result};

/// Bytes a read is widened by on each side, at the least, so that a secret
/// span it cuts is found whole: the head a card's shape is sniffed from,
/// which holds the longest private-key block the text rules place.
const SECRET_SPAN_REACH: usize = 64 * 1024;

/// The values custody knows, as `storage`'s output sweeps read them: its
/// ids and handles, each pass reading the values again (KS-3).
pub(super) fn known_source(storage: &ExecutorStorage<'_>) -> Result<Option<KnownSource>> {
    match storage {
        ExecutorStorage::Canonical(vault) => vault.known_source(),
        ExecutorStorage::Session(binding) => binding.answered(|| binding.session.known_source()),
    }
}

/// One result body as a tainted occurrence of it is shown: the window
/// `shown` reads, with each secret span blanked.
pub(super) struct RedactedBody<'b> {
    /// The window the facets read: the whole body, or a range of it.
    shown: &'b dyn ResultBody,
    /// The whole body `shown` is a window of, read for the margins.
    whole: &'b dyn ResultBody,
    /// The values custody knows, if it knows any.
    known: Option<KnownSource>,
    /// Bytes each read is widened by on each side.
    margin: u64,
}

impl<'b> RedactedBody<'b> {
    /// The view of `shown`, a window of `whole`, blanking the text rules'
    /// spans and the values `known` holds.
    pub(super) fn new(
        shown: &'b dyn ResultBody,
        whole: &'b dyn ResultBody,
        known: Option<KnownSource>,
    ) -> Result<Self> {
        let reach = match &known {
            Some(source) => source.pass(|values| values.map_or(0, KnownValues::reach))?,
            None => 0,
        };
        Ok(Self {
            shown,
            whole,
            known,
            margin: SECRET_SPAN_REACH.max(reach) as u64,
        })
    }

    /// The secret spans in `bytes`, at their offsets in it: the text rules'
    /// and each value custody knows now.
    fn spans(&self, bytes: &[u8]) -> Result<Vec<Range<usize>>> {
        let mut spans: Vec<Range<usize>> = file_spans(bytes)
            .into_iter()
            .map(|(span, _)| span)
            .collect();
        if let Some(source) = &self.known {
            let found = source.pass(|values| {
                values.map_or_else(Vec::new, |values| {
                    values
                        .spans(bytes)
                        .into_iter()
                        .map(|hit| hit.span)
                        .collect::<Vec<_>>()
                })
            })?;
            spans.extend(found);
        }
        Ok(spans)
    }
}

impl ResultBody for RedactedBody<'_> {
    fn len(&self) -> u64 {
        self.shown.len()
    }

    fn kind(&self) -> CodeRunOutputKind {
        self.shown.kind()
    }

    /// The window's bytes from `offset`, read with a margin of the whole
    /// body on each side; each span found there is blanked where it meets
    /// the bytes returned.
    fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let take = self.shown.len().saturating_sub(offset).min(len as u64);
        if take == 0 {
            return Ok(Vec::new());
        }
        let start = self.shown.base().saturating_add(offset);
        let from = start.saturating_sub(self.margin);
        let to = start
            .saturating_add(take)
            .saturating_add(self.margin)
            .min(self.whole.len());
        let overflow = |_| Error::ArithmeticOverflow("redacted result read");
        let wide = usize::try_from(to.saturating_sub(from)).map_err(overflow)?;
        let lead = usize::try_from(start - from).map_err(overflow)?;
        let take = usize::try_from(take).map_err(overflow)?;
        let mut bytes = self.whole.read(from, wide)?;
        let end = lead.saturating_add(take).min(bytes.len());
        if lead >= end {
            return Ok(Vec::new());
        }
        for span in self.spans(&bytes)? {
            let blanked = bytes.get_mut(span.start.max(lead)..span.end.min(end));
            for byte in blanked.into_iter().flatten() {
                if *byte != b'\n' {
                    *byte = FILLER;
                }
            }
        }
        bytes.truncate(end);
        bytes.drain(..lead);
        Ok(bytes)
    }

    fn line_index(&self) -> Option<Vec<u64>> {
        self.shown.line_index()
    }

    fn base(&self) -> u64 {
        self.shown.base()
    }

    fn note_search_credit(&self, offset: u64, line: u64, credit: u64) {
        self.shown.note_search_credit(offset, line, credit);
    }

    fn valid_search_credit(&self, offset: u64, line: u64, credit: u64) -> bool {
        self.shown.valid_search_credit(offset, line, credit)
    }

    fn live_cutoff(&self) -> LiveCutoff<'_> {
        self.shown.live_cutoff()
    }
}
