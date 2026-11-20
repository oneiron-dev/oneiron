//! Edits of a NOTE's live body at known offsets, with no diff over the body,
//! so every other character keeps its identity, and the cursors on it, at
//! any size (FIX LORO-TEXT-UPDATE-UNBOUNDED-DIFF-CALLERS).

use std::ops::Range;

use loro::LoroText;

use super::invalid;
use crate::error::Result;

/// Puts each handle of `masked`, the body as masked, in `body` at the span
/// of `replaced` it names (FIX 6144), the last first. Spans that do not
/// make `masked` of `body` refuse before any edit.
pub(super) fn splice_handles(
    body: &LoroText,
    replaced: &[(Range<usize>, Range<usize>)],
    masked: &str,
) -> Result<()> {
    if spliced(&body.to_string(), replaced, masked).as_deref() != Some(masked) {
        return Err(invalid("NOTE mask spans"));
    }
    for (span, handle) in replaced.iter().rev() {
        body.delete_utf8(span.start, span.len())
            .and_then(|()| body.insert_utf8(span.start, &masked[handle.clone()]))
            .map_err(|_| invalid("NOTE mask update"))?;
    }
    Ok(())
}

/// For each `(text_form, value)` of `values` in turn, puts `value` at each
/// place `body` then holds `text_form`, as [`str::replace`] puts it, the
/// last place first.
pub(super) fn splice_values(body: &LoroText, values: &[(&str, &str)]) -> Result<()> {
    for &(text_form, value) in values {
        let text = body.to_string();
        let places: Vec<usize> = text.match_indices(text_form).map(|(at, _)| at).collect();
        for at in places.into_iter().rev() {
            body.delete_utf8(at, text_form.len())
                .and_then(|()| body.insert_utf8(at, value))
                .map_err(|_| invalid("NOTE restore update"))?;
        }
    }
    Ok(())
}

/// `text` with each span of `replaced` taking the span of `masked` it
/// names, in order: `None` when a span runs backwards, overlaps the one
/// before it, or falls outside its text or off a char boundary there.
fn spliced(text: &str, replaced: &[(Range<usize>, Range<usize>)], masked: &str) -> Option<String> {
    let mut out = String::with_capacity(masked.len());
    let mut from = 0;
    for (span, handle) in replaced {
        out.push_str(text.get(from..span.start)?);
        text.get(span.clone())?;
        out.push_str(masked.get(handle.clone())?);
        from = span.end;
    }
    out.push_str(text.get(from..)?);
    Some(out)
}
