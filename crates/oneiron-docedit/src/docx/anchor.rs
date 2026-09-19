//! Pure final-view Word character-span replay, without any storage dependency.
use super::{DocxAnchorEffect, DocxSpan};

/// Move a half-open anchor across a known text edit. Replaced content drifts:
/// it must never silently attach to the replacement's unrelated text.
#[must_use]
pub fn replay_span(span: DocxSpan, effect: &DocxAnchorEffect) -> Option<DocxSpan> {
    if span.paragraph == 0 || span.start > span.end {
        return None;
    }
    match *effect {
        DocxAnchorEffect::JoinParagraphs {
            paragraph,
            first_len,
        } => {
            let next = paragraph.checked_add(1)?;
            if span.paragraph == next {
                DocxSpan::new(
                    paragraph,
                    first_len.checked_add(span.start)?,
                    first_len.checked_add(span.end)?,
                )
                .ok()
            } else if span.paragraph > next {
                DocxSpan::new(span.paragraph - 1, span.start, span.end).ok()
            } else {
                Some(span)
            }
        }
        DocxAnchorEffect::ShiftWithinParagraph {
            paragraph,
            at,
            removed,
            inserted,
        } => {
            if paragraph != span.paragraph {
                return Some(span);
            }
            let end = at.checked_add(removed)?;
            if removed > 0 && span.start < end && span.end > at {
                return None;
            }
            if removed > 0 && span.is_caret() && span.start >= at && span.start < end {
                return None;
            }
            let shift = |offset: u32| offset.checked_sub(removed)?.checked_add(inserted);
            let start = if span.start >= end {
                shift(span.start)?
            } else {
                span.start
            };
            let finish = if span.end > end || (span.end == end && span.start >= end) {
                shift(span.end)?
            } else {
                span.end
            };
            DocxSpan::new(paragraph, start, finish).ok()
        }
    }
}
