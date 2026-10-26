//! What a tagger's answer must satisfy before a marker settles on it: its
//! structure, never its size. An answer with any number of spans or links
//! that holds every rule settles, held import and worker answer alike
//! (FIX 9944, 10166).

use serde::{Deserialize, Serialize};

use crate::memory::extraction::{EncoderInput, EncoderOutput, NerSpan};

const MAX_LABEL_BYTES: usize = 64;

/// Why an answer was refused. Each code names the rule it broke and carries
/// none of the answer or the turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputRefusal {
    /// A mood value outside valence −1..1, arousal and dominance 0..1.
    MoodOutOfRange,
    /// A span names a message the input does not have.
    UnknownMessage,
    /// A span is empty, runs past its message, or splits a character.
    BadOffsets,
    /// A label is empty or longer than 64 bytes.
    BadLabel,
    /// A confidence is not a finite value in 0..1.
    BadConfidence,
    /// A link names a missing span or points forward, or a span carries a
    /// second link of any kind.
    BadLink,
    /// A context link names a turn or a message the input did not send as
    /// context.
    UnknownContext,
    /// Spans are out of (message, start, end) order, or two share
    /// coordinates.
    SpanOrder,
    /// The answer names another stack than the one the marker is owed to.
    OtherStack,
}

/// The rules an answer meets before it settles a marker owed to `stack`,
/// when one is pinned: `Memory::witness_with_shadow`'s rules, applied to the
/// same contract types, and the pinned stack named.
pub(super) fn check_output(
    input: &EncoderInput,
    output: &EncoderOutput,
    stack: Option<&str>,
) -> Result<(), OutputRefusal> {
    check_span_order(output)?;
    check_moved_output(input, output, stack)
}

/// [`check_output`] for held spans moved onto the turn's message order from
/// the order a witness sent them in: the order rule holds where the spans
/// were made, so the caller asks [`check_span_order`] there.
pub(super) fn check_moved_output(
    input: &EncoderInput,
    output: &EncoderOutput,
    stack: Option<&str>,
) -> Result<(), OutputRefusal> {
    if stack.is_some_and(|stack| output.stack_sha16.as_deref() != Some(stack)) {
        return Err(OutputRefusal::OtherStack);
    }
    if output.vad.is_some_and(|vad| vad.validate().is_err()) {
        return Err(OutputRefusal::MoodOutOfRange);
    }
    check_mood_parts(input, output)?;
    for span in &output.spans {
        let Some(message) = input.messages.get(span.message) else {
            return Err(OutputRefusal::UnknownMessage);
        };
        if !offsets_fit(&message.text, span.start, span.end) {
            return Err(OutputRefusal::BadOffsets);
        }
        if span.label.is_empty() || span.label.len() > MAX_LABEL_BYTES {
            return Err(OutputRefusal::BadLabel);
        }
        if !is_confidence(span.confidence) {
            return Err(OutputRefusal::BadConfidence);
        }
    }
    check_links(input, output)
}

/// The windows' moods of a turn read in several (FIX 9518): each in range,
/// from a place in one of the input's messages to a later or equal place in
/// another, on character boundaries.
pub(crate) fn check_mood_parts(
    input: &EncoderInput,
    output: &EncoderOutput,
) -> Result<(), OutputRefusal> {
    let place = |message: usize, at: usize| {
        input
            .messages
            .get(message)
            .is_some_and(|each| at <= each.text.len() && each.text.is_char_boundary(at))
    };
    for part in &output.mood_parts {
        if part.vad.validate().is_err() {
            return Err(OutputRefusal::MoodOutOfRange);
        }
        if !place(part.message, part.start)
            || !place(part.end_message, part.end)
            || (part.message, part.start) > (part.end_message, part.end)
        {
            return Err(OutputRefusal::BadOffsets);
        }
    }
    Ok(())
}

/// The order rule: spans come in (message, start, end) order and never
/// share coordinates, so an index or a later context link's coordinates name
/// one span.
pub(crate) fn check_span_order(output: &EncoderOutput) -> Result<(), OutputRefusal> {
    let at = |span: &NerSpan| (span.message, span.start, span.end);
    if output
        .spans
        .windows(2)
        .any(|pair| at(&pair[0]) >= at(&pair[1]))
    {
        return Err(OutputRefusal::SpanOrder);
    }
    Ok(())
}

/// The link rules: each link of the three kinds names a span of the answer,
/// carries a confidence in 0..1 where it has one, and is the only link its
/// span carries. An in-turn link points back; a context link names a turn
/// and a message the input sent as context, and offsets on character
/// boundaries of that message's text as sent.
pub(crate) fn check_links(
    input: &EncoderInput,
    output: &EncoderOutput,
) -> Result<(), OutputRefusal> {
    let mut linked = std::collections::BTreeSet::new();
    let mut claim = |span: usize| {
        if span < output.spans.len() && linked.insert(span) {
            Ok(())
        } else {
            Err(OutputRefusal::BadLink)
        }
    };
    for link in &output.links {
        claim(link.span)?;
        if link.antecedent >= link.span {
            return Err(OutputRefusal::BadLink);
        }
        if link
            .confidence
            .is_some_and(|confidence| !is_confidence(confidence))
        {
            return Err(OutputRefusal::BadConfidence);
        }
    }
    for link in &output.context_links {
        claim(link.span)?;
        let Some(text) = context_text(input, &link.turn, &link.message) else {
            return Err(OutputRefusal::UnknownContext);
        };
        if !offsets_fit(text, link.start, link.end) {
            return Err(OutputRefusal::BadOffsets);
        }
        if !is_confidence(link.confidence) {
            return Err(OutputRefusal::BadConfidence);
        }
    }
    for link in &output.speaker_links {
        claim(link.span)?;
        if !is_confidence(link.confidence) {
            return Err(OutputRefusal::BadConfidence);
        }
    }
    Ok(())
}

/// The text the input sent for `message` of context turn `turn`: an earlier
/// turn, or a later one of a conversation register (FIX 10167).
pub(super) fn context_text<'a>(
    input: &'a EncoderInput,
    turn: &str,
    message: &str,
) -> Option<&'a str> {
    crate::memory::extraction::register_turn(input, turn)?
        .messages
        .iter()
        .find(|each| each.id == message)
        .map(|each| each.text.as_str())
}

/// A nonempty half-open byte range inside `text`, on character boundaries.
fn offsets_fit(text: &str, start: usize, end: usize) -> bool {
    start < end && end <= text.len() && text.is_char_boundary(start) && text.is_char_boundary(end)
}

fn is_confidence(value: f32) -> bool {
    value.is_finite() && (0.0..=1.0).contains(&value)
}
