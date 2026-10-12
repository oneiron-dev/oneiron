//! What a tagger's answer must satisfy before a marker settles on it.

use serde::{Deserialize, Serialize};

use crate::memory::extraction::{EncoderInput, EncoderOutput};

const MAX_ROWS: usize = 4096;
const MAX_LABEL_BYTES: usize = 64;

/// Why an answer was refused. Each code names the rule it broke and carries
/// none of the answer or the turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputRefusal {
    /// More than 4,096 spans, links, context links or speaker links.
    TooManyRows,
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
}

/// The rules `Memory::witness_with_shadow` applies to an answer, applied to
/// the same contract types.
pub(super) fn check_output(
    input: &EncoderInput,
    output: &EncoderOutput,
) -> Result<(), OutputRefusal> {
    if output.spans.len() > MAX_ROWS {
        return Err(OutputRefusal::TooManyRows);
    }
    if output.vad.is_some_and(|vad| vad.validate().is_err()) {
        return Err(OutputRefusal::MoodOutOfRange);
    }
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

/// The link rules: each link of the three kinds names a span of the answer,
/// carries a confidence in 0..1 where it has one, and is the only link its
/// span carries. An in-turn link points back; a context link names a turn
/// and a message the input sent as context, and offsets on character
/// boundaries of that message's text as sent.
pub(crate) fn check_links(
    input: &EncoderInput,
    output: &EncoderOutput,
) -> Result<(), OutputRefusal> {
    if output.links.len() > MAX_ROWS
        || output.context_links.len() > MAX_ROWS
        || output.speaker_links.len() > MAX_ROWS
    {
        return Err(OutputRefusal::TooManyRows);
    }
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
        if link.confidence.is_some_and(|confidence| !is_confidence(confidence)) {
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

/// The text the input sent for `message` of context turn `turn`.
pub(super) fn context_text<'a>(input: &'a EncoderInput, turn: &str, message: &str) -> Option<&'a str> {
    input
        .context
        .iter()
        .find(|each| each.turn == turn)?
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
