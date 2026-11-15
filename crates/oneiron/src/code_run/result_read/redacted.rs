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
//! and the values custody knows now ([`KnownSource`]), found once per view
//! in the whole body, as the write door read it whole when it marked it
//! (`batch::secret_scan::mask::spool`). A span is found from its own
//! anchors however far it runs, so a read anywhere inside it is blanked,
//! even one that holds neither end of a long key block. A mark's reason
//! names no span: the structured reading shares `sensitive_env` with the
//! assignment rule, and a credential field's value may be no assignment the
//! text rules place. So the scan that marked the body reads the whole body
//! again with its spans blanked, and a body in which it still finds a secret
//! has no view: it is withheld whole (REVIEW-7800 round 2). Each reply is
//! still checked for an unmarked secret before it leaves (`facets`).

use std::ops::Range;

use super::ResultBody;
use super::run_body::LiveCutoff;
use crate::batch::secret_scan::file_spans;
use crate::code_run::{CodeRunOutputKind, ExecutorStorage};
use crate::file_secret_marks::FILLER;
use crate::secret_custody::KnownSource;
use crate::store::BodyMeter;
use crate::{Error, Result};

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
    /// The whole body `shown` is a window of.
    whole: &'b dyn ResultBody,
    /// The secret spans at their offsets in `whole`.
    spans: Vec<Range<usize>>,
}

impl<'b> RedactedBody<'b> {
    /// The view of `shown`, a window of `whole`, blanking the text rules'
    /// spans and the values `known` holds, found once in the whole body.
    /// `None` when the scan that marks a stored body still finds a secret
    /// in the whole body with those spans blanked: the body is withheld
    /// whole.
    pub(super) fn of(
        shown: &'b dyn ResultBody,
        whole: &'b dyn ResultBody,
        known: Option<KnownSource>,
    ) -> Result<Option<Self>> {
        let len = usize::try_from(whole.len())
            .map_err(|_| Error::ArithmeticOverflow("redacted result read"))?;
        let mut bytes = whole.read(0, len)?;
        let mut spans: Vec<Range<usize>> = file_spans(&bytes)
            .into_iter()
            .map(|(span, _)| span)
            .collect();
        if let Some(source) = &known {
            let found = source.pass(|values| {
                values.map_or_else(Vec::new, |values| {
                    values
                        .spans(&bytes)
                        .into_iter()
                        .map(|hit| hit.span)
                        .collect::<Vec<_>>()
                })
            })?;
            spans.extend(found);
        }
        blank(&mut bytes, 0, &spans);
        if marked_secret(&bytes).is_some() {
            return Ok(None);
        }
        Ok(Some(Self {
            shown,
            whole,
            spans,
        }))
    }
}

/// Blanks each of `spans` where it meets `bytes`, which start at `start` in
/// the whole body: each byte reads as [`FILLER`], a newline as a newline.
fn blank(bytes: &mut [u8], start: usize, spans: &[Range<usize>]) {
    let end = start.saturating_add(bytes.len());
    for span in spans {
        let (from, to) = (span.start.max(start), span.end.min(end));
        if from >= to {
            continue;
        }
        let blanked = bytes.get_mut(from - start..to - start);
        for byte in blanked.into_iter().flatten() {
            if *byte != b'\n' {
                *byte = FILLER;
            }
        }
    }
}

/// The first secret the scan that marks a stored body ([`BodyMeter`],
/// ARCH-0069 S5) finds in `bytes`, if any.
fn marked_secret(bytes: &[u8]) -> Option<&'static str> {
    let mut meter = BodyMeter::new();
    meter.feed(bytes);
    meter.finish(0).secret
}

impl ResultBody for RedactedBody<'_> {
    fn len(&self) -> u64 {
        self.shown.len()
    }

    fn kind(&self) -> CodeRunOutputKind {
        self.shown.kind()
    }

    /// The window's bytes from `offset`; each span of the whole body is
    /// blanked where it meets the bytes returned.
    fn read(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let take = self.shown.len().saturating_sub(offset).min(len as u64);
        if take == 0 {
            return Ok(Vec::new());
        }
        let overflow = |_| Error::ArithmeticOverflow("redacted result read");
        let at = self.shown.base().saturating_add(offset);
        let mut bytes = self
            .whole
            .read(at, usize::try_from(take).map_err(overflow)?)?;
        let start = usize::try_from(at).map_err(overflow)?;
        blank(&mut bytes, start, &self.spans);
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
