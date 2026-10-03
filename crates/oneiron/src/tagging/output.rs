//! What a tagger's answer must satisfy before a marker settles on it.

use serde::Serialize;

use crate::affect::Vad;
use crate::memory::extraction::{EncoderInput, EncoderOutput};

const MAX_ROWS: usize = 4096;
const MAX_LABEL_BYTES: usize = 64;

/// Why an answer was refused. Each code names the rule it broke and carries
/// none of the answer or the turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputRefusal {
    /// More than 4,096 spans or links.
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
    /// A link names a missing span, points forward, or is a second link from
    /// one span.
    BadLink,
}

/// The mood of an answer is a value today and optional once a spans-only
/// tagger is admitted (ONE-2167); both shapes read the same here.
pub(super) trait AnswerMood {
    /// Whether an answer may come without a mood.
    const OPTIONAL: bool;
    fn present(&self) -> bool;
    fn in_range(&self) -> bool;
}

impl AnswerMood for Vad {
    const OPTIONAL: bool = false;
    fn present(&self) -> bool {
        true
    }
    fn in_range(&self) -> bool {
        self.validate().is_ok()
    }
}

impl AnswerMood for Option<Vad> {
    const OPTIONAL: bool = true;
    fn present(&self) -> bool {
        self.is_some()
    }
    fn in_range(&self) -> bool {
        self.as_ref().is_none_or(AnswerMood::in_range)
    }
}

fn mood_optional<T: AnswerMood>(_field: fn(&EncoderOutput) -> &T) -> bool {
    T::OPTIONAL
}

/// Whether the contract admits an answer with no mood, so a tagger that
/// declares no mood head can be served. Read off the contract type itself.
#[must_use]
pub fn spans_only_answers_admitted() -> bool {
    mood_optional(|output: &EncoderOutput| &output.vad)
}

/// The rules `Memory::witness_with_shadow` applies to an answer, applied to
/// the same contract types.
pub(super) fn check_output(
    input: &EncoderInput,
    output: &EncoderOutput,
) -> Result<(), OutputRefusal> {
    if output.spans.len() > MAX_ROWS || output.links.len() > MAX_ROWS {
        return Err(OutputRefusal::TooManyRows);
    }
    if !output.vad.in_range() {
        return Err(OutputRefusal::MoodOutOfRange);
    }
    for span in &output.spans {
        let Some(message) = input.messages.get(span.message) else {
            return Err(OutputRefusal::UnknownMessage);
        };
        if span.start >= span.end
            || span.end > message.text.len()
            || !message.text.is_char_boundary(span.start)
            || !message.text.is_char_boundary(span.end)
        {
            return Err(OutputRefusal::BadOffsets);
        }
        if span.label.is_empty() || span.label.len() > MAX_LABEL_BYTES {
            return Err(OutputRefusal::BadLabel);
        }
        if !span.confidence.is_finite() || !(0.0..=1.0).contains(&span.confidence) {
            return Err(OutputRefusal::BadConfidence);
        }
    }
    let mut linked = std::collections::BTreeSet::new();
    for link in &output.links {
        if link.span >= output.spans.len()
            || link.antecedent >= link.span
            || !linked.insert(link.span)
        {
            return Err(OutputRefusal::BadLink);
        }
    }
    Ok(())
}
