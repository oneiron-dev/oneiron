//! The live fork's span input (FIX 4931): the house document the sealed
//! request renders, with each window step the captured prefix already holds
//! byte for byte sent as a reference to where it sits there, in place of its
//! text again. A step the prefix does not hold, or holds otherwise, keeps its
//! full text, so a missing span is never read as present. A just-completed
//! answer is not in the request it answered, so its step goes in full. The
//! sealed request stays the whole authority of the gate and the mint: its
//! pins, sources, watermark, note and job, and the gate's size, pin and
//! coverage checks over the full window. A reference grants nothing and
//! names no durable record.

use oneiron::compaction::{CompactionCheck, CompactionRequest, compaction_request_input};
use oneiron::llm::{ContentPart, LlmRequest};
use serde_json::Value;

/// The key the house document lists its window's steps under: one entry
/// per window message, in window order.
const STEPS_KEY: &str = "steps";

/// The words before a span input that references steps (FIX 4931). The
/// house compaction prompt reads each step's `text`; these name the
/// reference form beside it.
const PREFIX_REFERENCE_NOTE: &str = "Some entries of `steps` hold `prefix` in place of `text`. \
    Such a step's text is not sent again: the conversation above this message already holds it, \
    byte for byte. `prefix.from` and `prefix.through` name its first and last part there, each as \
    a `message` and a `part` counted from 0, and its parts read as one text joined by newlines. \
    Find the step there by its number, read it, and cover it exactly as you cover a step whose \
    `text` is given.";

/// Where a part sits in the captured prefix: its message, and its place in
/// that message's content.
#[derive(Clone, Copy)]
struct PartAt {
    message: usize,
    part: usize,
}

/// One part of the captured prefix, with its text; `None` for a part that
/// holds no text, which no step's text runs through.
struct PrefixPart<'a> {
    at: PartAt,
    text: Option<&'a str>,
}

/// `live_fork_span_input` (FIX 4931): the span's input for a live fork's
/// call on `request` after `prefix`, the immutable captured request. A
/// window step `prefix` holds byte for byte, as a run of whole text parts
/// joined by newlines after the step before it, is sent as its logical step
/// number and that run's first and last part, where that is shorter than
/// its text; every other step keeps its text. `from`, `through`, the
/// summary budget, pins, note and retry stay the house document's own. The
/// referencing input goes out only when it counts no more tokens than the
/// full one, so the window sized for the full input still fits.
pub(super) fn live_fork_span_input(
    prefix: &LlmRequest,
    request: &CompactionRequest,
    retry: Option<CompactionCheck>,
) -> String {
    let mut document = compaction_request_input(request, retry);
    let full = document.to_string();
    let Some(steps) = document
        .get_mut(STEPS_KEY)
        .and_then(Value::as_array_mut)
        .filter(|steps| steps.len() == request.window.len())
    else {
        return full;
    };
    let parts = prefix_parts(prefix);
    let mut cursor = 0;
    let mut referenced = false;
    for (entry, step) in steps.iter_mut().zip(&request.window) {
        let Some((from, through, next)) = locate(&parts, cursor, &step.content) else {
            continue;
        };
        cursor = next;
        let reference = step_reference(step.turn, from, through);
        if reference.to_string().len() < entry.to_string().len() {
            *entry = reference;
            referenced = true;
        }
    }
    if !referenced {
        return full;
    }
    let referencing = format!("{PREFIX_REFERENCE_NOTE}\n\n{document}");
    if oneiron::count_context_pack_tokens(&referencing) <= oneiron::count_context_pack_tokens(&full)
    {
        referencing
    } else {
        full
    }
}

/// Every part of `prefix`, in order.
fn prefix_parts(prefix: &LlmRequest) -> Vec<PrefixPart<'_>> {
    prefix
        .messages
        .iter()
        .enumerate()
        .flat_map(|(message, held)| {
            held.content
                .iter()
                .enumerate()
                .map(move |(part, content)| PrefixPart {
                    at: PartAt { message, part },
                    text: match content {
                        ContentPart::Text { text, .. } => Some(text.as_str()),
                        _ => None,
                    },
                })
        })
        .collect()
}

/// Where `text` sits in `parts` at or after `from`: the first run of whole
/// text parts that, joined by newlines, is `text` byte for byte, as its
/// first and last part and the index after it. `None` when no run is.
fn locate(parts: &[PrefixPart<'_>], from: usize, text: &str) -> Option<(PartAt, PartAt, usize)> {
    (from..parts.len()).find_map(|start| {
        let mut rest = text.strip_prefix(parts[start].text?)?;
        let mut end = start;
        while !rest.is_empty() {
            let next = parts.get(end + 1)?.text?;
            rest = rest.strip_prefix('\n')?.strip_prefix(next)?;
            end += 1;
        }
        Some((parts[start].at, parts[end].at, end + 1))
    })
}

/// A step's entry as a reference to the run of prefix parts that holds its
/// text: its logical step number, and the run's first and last part.
fn step_reference(step: u64, from: PartAt, through: PartAt) -> Value {
    serde_json::json!({
        "step": step,
        "prefix": {
            "from": {"message": from.message, "part": from.part},
            "through": {"message": through.message, "part": through.part},
        },
    })
}
