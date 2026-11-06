//! Exact canonical evidence and the body bytes used to derive a draft.
use std::ops::Range;
use std::sync::Arc;

use oneiron::dreamer_runner::maintenance::representation::RepresentationSource;

#[derive(Clone)]
pub(in crate::ai_host::stewardship) struct EvidenceSpan {
    pub(in crate::ai_host::stewardship) source: Arc<RepresentationSource>,
    pub(in crate::ai_host::stewardship) range: Range<usize>,
}

impl EvidenceSpan {
    pub(in crate::ai_host::stewardship) fn whole(source: RepresentationSource) -> Self {
        let end = source.text.len();
        Self {
            source: Arc::new(source),
            range: 0..end,
        }
    }

    pub(in crate::ai_host::stewardship) fn text(&self) -> &str {
        &self.source.text[self.range.clone()]
    }

    /// Bisect only at a character boundary, with no omitted body bytes.
    pub(in crate::ai_host::stewardship) fn split(&self) -> Option<(Self, Self)> {
        let middle = self.range.start + self.range.len() / 2;
        let mut cut = self.source.text.floor_char_boundary(middle);
        if cut == self.range.start {
            cut = self.source.text.ceil_char_boundary(middle);
        }
        if cut <= self.range.start || cut >= self.range.end {
            return None;
        }
        Some((
            Self {
                source: self.source.clone(),
                range: self.range.start..cut,
            },
            Self {
                source: self.source.clone(),
                range: cut..self.range.end,
            },
        ))
    }
}

/// Coverage is derived from completed calls, not from a full-source citation.
pub(in crate::ai_host::stewardship) fn covers(
    source: &RepresentationSource,
    spans: &[EvidenceSpan],
) -> bool {
    let mut ranges: Vec<_> = spans
        .iter()
        .filter(|span| span.source.as_ref() == source)
        .map(|span| span.range.clone())
        .collect();
    ranges.sort_unstable_by_key(|range| range.start);
    let mut end = 0;
    for range in ranges {
        if range.start > end || range.end > source.text.len() {
            return false;
        }
        end = end.max(range.end);
    }
    end == source.text.len()
}
