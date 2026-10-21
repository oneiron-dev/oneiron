//! A sitting's summary reply (FIX 7509): lines, each citing the TURNs it came
//! from by the call-local `T` labels the engine minted for the call (FIX
//! 7574, [`CallLabelMap`]), read back to their durable ids after the call,
//! never by an id the model wrote.

use super::super::call_labels::{CallLabelMap, LabelKind};
use crate::EntityId;
use crate::llm::{ContentPart, LlmResponse};
use crate::scope_summary::{SummaryLineSources, SummaryLineSpan};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

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
    labels: &CallLabelMap,
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
            source_spans: Vec::new(),
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
/// each by a `T` label its call showed.
fn cited_turns(cited: &[String], labels: &CallLabelMap) -> Result<Vec<String>, &'static str> {
    if cited.is_empty() {
        return Err("a session summary line cites no turn");
    }
    let mut seen = BTreeSet::new();
    let mut turns = Vec::with_capacity(cited.len());
    for label in cited {
        let turn = labels
            .resolve_as(LabelKind::Turn, label)
            .ok_or("a session summary line cites a turn its call did not show")?;
        if !seen.insert(turn) {
            return Err("a session summary line cites a turn twice");
        }
        turns.push(turn.to_hex());
    }
    Ok(turns)
}

/// What one label a page of a sitting showed stands for (FIX 7509 P7b): its
/// TURN, and for a part of one the exact slices the part holds. A whole
/// TURN holds none.
#[derive(Debug, Clone)]
pub(super) struct PageRef {
    pub(super) turn: EntityId,
    pub(super) spans: Vec<SummaryLineSpan>,
}

/// One line a page wrote: its words, the TURNs it came from, each once in
/// citation order, and the slices of the parts it cites.
struct PageLine {
    text: String,
    turn_refs: Vec<String>,
    source_spans: Vec<SummaryLineSpan>,
}

/// One page's reply as checked: its lines, possibly none, and its keep.
pub(super) struct PageLines {
    lines: Vec<PageLine>,
    keep: String,
}

/// One page's reply, or the static reason it is none. A page may write no
/// line. Each line it writes is one line of words that are not blank,
/// citing at least one label, each once, all of them labels `labels` (this
/// page's) holds. The step's check and the assembly both read a page
/// through this one parse.
pub(super) fn paged_output(
    response: &LlmResponse,
    labels: &BTreeMap<String, PageRef>,
) -> Result<PageLines, &'static str> {
    let reply: SessionReply = serde_json::from_str(reply_text(response).trim())
        .map_err(|_| "the model wrote an invalid session summary/keep result")?;
    let mut lines = Vec::with_capacity(reply.lines.len());
    for line in &reply.lines {
        let words = line.text.trim();
        if words.is_empty() {
            return Err("the model wrote a blank session summary line");
        }
        if words.chars().any(is_line_break) {
            return Err("the model wrote a session summary line that breaks");
        }
        if line.turn_refs.is_empty() {
            return Err("a session summary line cites no turn");
        }
        let mut seen = BTreeSet::new();
        let mut turns = BTreeSet::new();
        let mut turn_refs = Vec::new();
        let mut source_spans = Vec::new();
        for label in &line.turn_refs {
            let cited = labels
                .get(label)
                .ok_or("a session summary line cites a turn its page did not show")?;
            if !seen.insert(label.as_str()) {
                return Err("a session summary line cites one label twice");
            }
            if turns.insert(cited.turn) {
                turn_refs.push(cited.turn.to_hex());
            }
            source_spans.extend(cited.spans.iter().cloned());
        }
        lines.push(PageLine {
            text: words.to_owned(),
            turn_refs,
            source_spans,
        });
    }
    Ok(PageLines {
        lines,
        keep: reply.keep,
    })
}

/// A paged sitting's summary (FIX 7509 P7b): every page's lines in page
/// order, joined with a newline, each line's range counted in Unicode
/// scalars of the text so joined, with its TURNs and slices as its page
/// cited them. Its keep is the pages' distinct keeps that are not blank, in
/// page order, one per line.
pub(super) fn assemble(pages: Vec<PageLines>) -> Result<SessionComposition, &'static str> {
    let mut text = String::new();
    let mut scalars = 0_usize;
    let mut line_sources = Vec::new();
    let mut keeps = Vec::new();
    let mut kept = BTreeSet::new();
    for page in pages {
        for line in page.lines {
            if !text.is_empty() {
                text.push('\n');
                scalars += 1;
            }
            let output_start = scalars;
            text.push_str(&line.text);
            scalars += line.text.chars().count();
            line_sources.push(SummaryLineSources {
                output_start,
                output_end: scalars,
                turn_refs: line.turn_refs,
                source_spans: line.source_spans,
            });
        }
        if !page.keep.trim().is_empty() && kept.insert(page.keep.clone()) {
            keeps.push(page.keep);
        }
    }
    if text.is_empty() {
        return Err("the model wrote an empty summary");
    }
    Ok(SessionComposition {
        text,
        keep: keeps.join("\n"),
        line_sources,
    })
}

/// Whether `c` breaks a line.
const fn is_line_break(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r' | '\u{0b}' | '\u{0c}' | '\u{85}' | '\u{2028}' | '\u{2029}'
    )
}
