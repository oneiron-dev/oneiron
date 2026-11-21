//! Where exposures and the console sit in a request as the wall admitted
//! it: their spans moved from the request as sent by the replacements the
//! wall made.

use super::*;

/// `slots`, located in `sent`, moved to where they sit in the request as
/// the wall admitted it.
pub(super) fn stored_slots(
    slots: &[ExposureSlot],
    sent: &LlmRequest,
    admitted: &AdmittedRequest,
) -> Vec<ExposureSlot> {
    let Some(replaced) = &admitted.replaced else {
        return slots.to_vec();
    };
    slots
        .iter()
        .map(|slot| ExposureSlot {
            stored: stored_span(
                (slot.message, slot.part),
                slot.stored,
                sent,
                &admitted.request,
                replaced,
            ),
            ..slot.clone()
        })
        .collect()
}

/// `console`, located in `sent`, moved to where it sits in the request as
/// the wall admitted it (FIX 3608), as an exposure moves.
pub(super) fn stored_console(
    console: Option<&ConsoleSlot>,
    sent: &LlmRequest,
    admitted: &AdmittedRequest,
) -> Option<ConsoleSlot> {
    let console = console?;
    let stored = match &admitted.replaced {
        Some(replaced) => {
            let at = (console.message, console.part);
            stored_span(at, console.stored, sent, &admitted.request, replaced)
        }
        None => console.stored,
    };
    Some(ConsoleSlot {
        stored,
        ..console.clone()
    })
}

/// `console` kept with no stored span: its request was withheld.
pub(super) fn unstored_console(console: Option<&ConsoleSlot>) -> Option<ConsoleSlot> {
    console.map(|console| ConsoleSlot {
        stored: None,
        ..console.clone()
    })
}

/// Where `span`, in part `at` (its message and part) of `sent`, sits in
/// `stored`, the request as the wall admitted it: its bounds moved by the
/// replacements the wall made in its text, and the hash of the masked bytes
/// between them. `None` when a bound falls inside a replaced span, or the
/// text changed by more than those replacements.
fn stored_span(
    at: (u32, u32),
    span: Option<StoredSpan>,
    sent: &LlmRequest,
    stored: &LlmRequest,
    replaced: &TextReplacements,
) -> Option<StoredSpan> {
    let span = span?;
    let (sent_text, stored_text) = (text_part(sent, at)?, text_part(stored, at)?);
    let Some(moves) = replaced.get(blake3::hash(sent_text.as_bytes()).as_bytes()) else {
        // The wall left this text as it was.
        return (sent_text == stored_text).then_some(span);
    };
    if !moved_only(sent_text, stored_text, moves) {
        return None;
    }
    let start = remap_bound(usize::try_from(span.start).ok()?, moves)?;
    let end = remap_bound(usize::try_from(span.end).ok()?, moves)?;
    let bytes = stored_text.get(start..end)?;
    Some(StoredSpan {
        start: start as u64,
        end: end as u64,
        content_hash: *blake3::hash(bytes.as_bytes()).as_bytes(),
    })
}

/// Where `bound`, a byte offset in a text as sent, is in the text as the
/// wall masked it, by the replacements it made there in order (FIX 6144):
/// moved past each one before it. `None` when it falls inside a replaced
/// span, where a secret's handle now stands: an exposure cut there is
/// unavailable, never guessed at.
fn remap_bound(bound: usize, moves: &[(Range<usize>, Range<usize>)]) -> Option<usize> {
    let mut moved = bound;
    for (replaced, handle) in moves {
        if bound <= replaced.start {
            break;
        }
        if bound < replaced.end {
            return None;
        }
        moved = handle.end + (bound - replaced.end);
    }
    Some(moved)
}

/// Whether `stored` is `sent` with exactly `moves` made: every byte outside
/// the replaced spans where the moves put it.
fn moved_only(sent: &str, stored: &str, moves: &[(Range<usize>, Range<usize>)]) -> bool {
    let (sent, stored) = (sent.as_bytes(), stored.as_bytes());
    let (mut from, mut to) = (0, 0);
    for (cut, put) in moves {
        if !same_bytes(sent.get(from..cut.start), stored.get(to..put.start)) {
            return false;
        }
        (from, to) = (cut.end, put.end);
    }
    same_bytes(sent.get(from..), stored.get(to..))
}

/// Whether both are there and the same bytes.
fn same_bytes(kept: Option<&[u8]>, held: Option<&[u8]>) -> bool {
    kept.is_some() && kept == held
}

/// The text of part `at` (its message and part) in `request`.
fn text_part(request: &LlmRequest, (message, part): (u32, u32)) -> Option<&str> {
    let message = request.messages.get(usize::try_from(message).ok()?)?;
    match message.content.get(usize::try_from(part).ok()?)? {
        ContentPart::Text { text, .. } => Some(text.as_str()),
        _ => None,
    }
}
