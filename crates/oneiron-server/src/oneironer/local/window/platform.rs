//! The window as a platform worker tags it (FIX 6755 slice 3): the text it
//! is sent, the current turn's byte range in it, and the mapping of its
//! spans back to the turn's messages; or, for the Core ML worker, its token
//! ids (slice 2c). The window is Candle's own
//! (`Window::new`), so a worker's call holds the same tokens the dispatcher
//! counted, and its spans are kept and moved by Candle's own rules.

use std::ops::Range;

use oneiron::memory::extraction::{EncoderOutput, NerSpan};

use super::Window;

impl Window<'_> {
    /// Its text: what a platform worker is sent and tags whole (FIX 6755).
    pub(in crate::oneironer) fn text(&self) -> &str {
        &self.text
    }

    /// Its token ids, special tokens included: what the Core ML worker
    /// looks its input up by, one column each (FIX 6755 slice 2c). Their
    /// count is the window's length.
    pub(in crate::oneironer) fn ids(&self) -> &[u32] {
        self.encoding.get_ids()
    }

    /// The current turn's UTF-8 byte range in [`Self::text`]: from its first
    /// message's start, after its speaker prefix, to its last message's end,
    /// before the trailing newline, with the separators between its messages
    /// inside. A turn with no message is the empty range at the text's end.
    /// The cut never reaches the current turn, so its messages are whole.
    pub(in crate::oneironer) fn turn_range(&self) -> Range<usize> {
        let mut current = self.segments.iter().filter(|segment| segment.current);
        let Some(first) = current.next() else {
            return self.text.len()..self.text.len();
        };
        let end = current.last().map_or(first.end, |last| last.end);
        first.base..end
    }

    /// A platform worker's answer for this window, its spans in window byte
    /// offsets, as Candle returns its own (FIX 6755). Each span must lie in
    /// the text on character boundaries; it is kept only when it lies wholly
    /// inside one current message ([`Self::segment`], Candle's containment),
    /// and moved into that message by Candle's offset formula. A context
    /// span, a prefix or separator span and a run across messages are
    /// dropped, never clipped or split, and no span is refined again. Spans
    /// come out in Candle's order: by segment, start and end.
    pub(in crate::oneironer) fn map_window_spans(
        &self,
        mut output: EncoderOutput,
    ) -> anyhow::Result<EncoderOutput> {
        let spans = std::mem::take(&mut output.spans);
        let mut kept = Vec::with_capacity(spans.len());
        for span in spans {
            anyhow::ensure!(
                span.start < span.end
                    && span.end <= self.text.len()
                    && self.text.is_char_boundary(span.start)
                    && self.text.is_char_boundary(span.end),
                "a worker span is not a range of its window's characters"
            );
            let Some((index, segment)) = self.segment(span.start, span.end) else {
                continue;
            };
            if !segment.current {
                continue;
            }
            let mapped = NerSpan {
                message: segment.message_index,
                start: span.start - segment.base + segment.source_offset,
                end: span.end - segment.base + segment.source_offset,
                label: span.label,
                confidence: span.confidence,
            };
            kept.push(((index, span.start, span.end), mapped));
        }
        kept.sort_by_key(|(key, _)| *key);
        output.spans = kept.into_iter().map(|(_, span)| span).collect();
        Ok(output)
    }
}
