//! The spans a plan's text reads found, kept for the pass that reads the
//! same texts again (speed). A batch's minted pass reads the batch's own ops,
//! which its plan read as a copy before it masked them: the same texts, in
//! the same order. Each text's spans are taken from the plan's log, never
//! found again; a text whose bytes differ from the one logged at its place
//! is read afresh, and so is every text after it.

use std::ops::Range;

/// What one text's rules found, before any ruling of the record it sits
/// in: each value custody holds, with its record's handle, and each span
/// the door's text rules place, with its reason.
#[derive(Clone, Default)]
pub(super) struct TextSpans {
    pub(super) known: Vec<(Range<usize>, String)>,
    pub(super) shapes: Vec<(Range<usize>, &'static str)>,
}

/// The texts a pass read, each by the BLAKE3 of its bytes, with their
/// spans, in reading order: logged by a plan, taken in order by the pass
/// that reads the same texts again.
#[derive(Default)]
pub(super) struct TextLog {
    /// Whether each text read is logged: a plan's pass.
    records: bool,
    entries: Vec<([u8; 32], TextSpans)>,
    /// The entry the reading pass takes next.
    next: usize,
}

impl TextLog {
    /// The log a plan keeps of each text it reads.
    pub(super) fn recording() -> Self {
        Self {
            records: true,
            ..Self::default()
        }
    }

    /// One text's spans, for a pass whose first text read is that text.
    pub(super) fn seeded(text: &[u8], spans: TextSpans) -> Self {
        Self {
            records: false,
            entries: vec![(*blake3::hash(text).as_bytes(), spans)],
            next: 0,
        }
    }

    /// This log, for the pass that reads the same texts in the same order.
    pub(super) fn replayed(self) -> Self {
        Self {
            records: false,
            entries: self.entries,
            next: 0,
        }
    }

    /// The spans logged for `text`, when it is the text logged next. A text
    /// that differs ends the log: each text after it is read afresh.
    pub(super) fn take(&mut self, text: &[u8]) -> Option<TextSpans> {
        if self.records {
            return None;
        }
        let (digest, spans) = self.entries.get_mut(self.next)?;
        if *digest != *blake3::hash(text).as_bytes() {
            self.entries.clear();
            return None;
        }
        self.next += 1;
        Some(std::mem::take(spans))
    }

    /// Logs `text` with its `spans`, when this log records.
    pub(super) fn record(&mut self, text: &[u8], spans: &TextSpans) {
        if self.records {
            self.entries.push((*blake3::hash(text).as_bytes(), spans.clone()));
        }
    }
}
