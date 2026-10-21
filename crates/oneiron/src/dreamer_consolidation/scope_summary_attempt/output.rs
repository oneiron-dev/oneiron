//! A sitting's summary reply (FIX 7509): lines, each citing the TURNs it came
//! from by the labels the engine minted for the call, never by an id the
//! model wrote.

use crate::EntityId;
use crate::llm::{ContentPart, LlmResponse};
use crate::scope_summary::SummaryLineSources;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

/// The label the `index`th TURN a sitting's call reads goes by: `T1`, `T2`,
/// and on, 1-based in the order its evidence renders them.
pub(super) fn turn_label(index: usize) -> String {
    format!("T{}", index.saturating_add(1))
}

/// Each label a call showed, to the TURN it stands for.
pub(super) fn turn_labels(turns: &[EntityId]) -> BTreeMap<String, EntityId> {
    turns
        .iter()
        .enumerate()
        .map(|(index, turn)| (turn_label(index), *turn))
        .collect()
}

/// The typed output contract of a sitting's summary call.
pub(super) fn session_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object", "additionalProperties": false,
        "required": ["lines", "keep"],
        "properties": {
            "lines": {"type": "array", "items": {
                "type": "object", "additionalProperties": false,
                "required": ["text", "turn_refs"],
                "properties": {
                    "text": {"type": "string"},
                    "turn_refs": {"type": "array", "items": {"type": "string"}}
                }
            }},
            "keep": {"type": "string"}
        }
    })
}

/// A reply's text parts, as one string.
pub(super) fn reply_text(response: &LlmResponse) -> String {
    response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionReply {
    lines: Vec<SessionLine>,
    keep: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionLine {
    text: String,
    turn_refs: Vec<String>,
}

/// A sitting's summary as composed: its text, rendered once from its lines,
/// and each line's range in that text with the TURNs it came from.
pub(super) struct SessionComposition {
    pub(super) text: String,
    pub(super) keep: String,
    pub(super) line_sources: Vec<SummaryLineSources>,
}

/// The reply's session summary, or the static reason it is none. Each line
/// is one line of words that are not blank, citing at least one TURN, each
/// once, by a label in `labels`. The lines join with a newline, and each
/// one's range counts Unicode scalars in the text so joined. The step's
/// check and the landing both read the reply through this one parse.
pub(super) fn session_output(
    response: &LlmResponse,
    labels: &BTreeMap<String, EntityId>,
) -> Result<SessionComposition, &'static str> {
    let reply: SessionReply = serde_json::from_str(reply_text(response).trim())
        .map_err(|_| "the model wrote an invalid session summary/keep result")?;
    let mut text = String::new();
    let mut scalars = 0_usize;
    let mut line_sources = Vec::with_capacity(reply.lines.len());
    for line in &reply.lines {
        let words = line.text.trim();
        if words.is_empty() {
            return Err("the model wrote a blank session summary line");
        }
        if words.chars().any(is_line_break) {
            return Err("the model wrote a session summary line that breaks");
        }
        let turn_refs = cited_turns(&line.turn_refs, labels)?;
        if !text.is_empty() {
            text.push('\n');
            scalars += 1;
        }
        let output_start = scalars;
        text.push_str(words);
        scalars += words.chars().count();
        line_sources.push(SummaryLineSources {
            output_start,
            output_end: scalars,
            turn_refs,
        });
    }
    if text.is_empty() {
        return Err("the model wrote an empty summary");
    }
    Ok(SessionComposition {
        text,
        keep: reply.keep,
        line_sources,
    })
}

/// The full ids of the TURNs one line cites: at least one, each once, and
/// each by a label its call showed.
fn cited_turns(
    cited: &[String],
    labels: &BTreeMap<String, EntityId>,
) -> Result<Vec<String>, &'static str> {
    if cited.is_empty() {
        return Err("a session summary line cites no turn");
    }
    let mut seen = BTreeSet::new();
    let mut turns = Vec::with_capacity(cited.len());
    for label in cited {
        let turn = labels
            .get(label)
            .ok_or("a session summary line cites a turn its call did not show")?;
        if !seen.insert(*turn) {
            return Err("a session summary line cites a turn twice");
        }
        turns.push(turn.to_hex());
    }
    Ok(turns)
}

/// Whether `c` breaks a line.
const fn is_line_break(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r' | '\u{0b}' | '\u{0c}' | '\u{85}' | '\u{2028}' | '\u{2029}'
    )
}
