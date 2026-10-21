//! An Arc call's reply (FIX 7509 P8, its parts in PR3): `{lines: [{text,
//! turn_refs}], keep, open_turns}`, each line citing the TURNs it came from
//! by the `T` labels its call showed, read back through the call's map. A
//! `T` label is always a TURN; a sitting's line shows under an `L` label of
//! its own, in its own input field, which no reply cites.
//!
//! One call over the whole Arc reads its reply through [`arc_output`]. A
//! part of an Arc composed in parts reads it through [`child_output`],
//! against what that one call showed ([`ArcCitationContext`]): a TURN shown
//! only in part is cited with the slices it showed. Either way a TURN shown
//! only by a sitting's line is cited as that line came from it (FIX 8289):
//! the line's own recorded slices of it, or whole.

use super::super::call_labels::{CallLabelMap, LabelKind};
use super::output::reply_text;
use crate::EntityId;
use crate::llm::LlmResponse;
use crate::scope_summary::{SummaryLineSources, SummaryLineSpan};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

/// The typed output contract of every Arc call.
pub(super) fn arc_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object", "additionalProperties": false,
        "required": ["lines", "keep", "open_turns"],
        "properties": {
            "lines": {"type": "array", "items": {
                "type": "object", "additionalProperties": false,
                "required": ["text", "turn_refs"],
                "properties": {
                    "text": {"type": "string"},
                    "turn_refs": {"type": "array", "items": {"type": "string"}}
                }
            }},
            "keep": {"type": "string"},
            "open_turns": {"type": "array", "items": {"type": "string"}}
        }
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArcWire {
    pub(super) lines: Vec<ArcWireLine>,
    pub(super) keep: String,
    open_turns: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArcWireLine {
    pub(super) text: String,
    turn_refs: Vec<String>,
}

/// The reply as written, or the static reason it is none.
pub(super) fn arc_wire(response: &LlmResponse) -> Result<ArcWire, &'static str> {
    serde_json::from_str(reply_text(response).trim())
        .map_err(|_| "the model wrote an invalid arc summary result")
}

/// An Arc's lines as composed: its text, rendered once from its lines, and
/// each line's range in that text with the TURNs it came from.
pub(super) struct ArcLines {
    pub(super) text: String,
    pub(super) keep: String,
    pub(super) line_sources: Vec<SummaryLineSources>,
}

/// What a checked reply asks.
pub(super) enum ArcReply {
    /// Open these turns first, each one the call showed by label and not
    /// yet open; write nothing.
    Open(Vec<EntityId>),
    Lines(ArcLines),
}

/// How a call's sitting lines, or a part's observations, cite one TURN
/// (FIX 8289): `None` whole, else by the slices they came from.
pub(super) type Inherited = Option<Vec<SummaryLineSpan>>;

/// Joins one citation of `turn` into `cited`: the slices of `spans` that
/// are `turn`'s, or the TURN whole when `spans` hold none of it. A TURN
/// cited whole once stays whole; slices are kept once each, in order.
pub(super) fn inherit(
    cited: &mut BTreeMap<EntityId, Inherited>,
    turn: EntityId,
    spans: &[SummaryLineSpan],
) {
    let handle = turn.to_hex();
    let own: Vec<&SummaryLineSpan> = spans.iter().filter(|span| span.turn == handle).collect();
    match cited.get_mut(&turn) {
        None => {
            let held = (!own.is_empty()).then(|| own.into_iter().cloned().collect());
            cited.insert(turn, held);
        }
        Some(held) => {
            if own.is_empty() {
                *held = None;
            } else if let Some(held) = held {
                for span in own {
                    if !held.contains(span) {
                        held.push(span.clone());
                    }
                }
            }
        }
    }
}

/// The reply, or the static reason it is none. Each turn it names to open
/// is a `T` label its call showed; naming only turns already open asks for
/// none. Otherwise each line is one line of words that are not blank,
/// citing at least one TURN, each once, by a `T` label of a TURN whose
/// words the Arc covers; the lines join with a newline, each range counted
/// in Unicode scalars, each with the slices `inherited` holds of a TURN it
/// cites whose words the call does not show (FIX 8289). The step's check
/// and the landing read the reply through this one parse.
pub(super) fn arc_output(
    response: &LlmResponse,
    labels: &CallLabelMap,
    (opened, inherited): (&BTreeSet<EntityId>, &BTreeMap<EntityId, Inherited>),
    covers: &BTreeSet<EntityId>,
) -> Result<ArcReply, &'static str> {
    let reply = arc_wire(response)?;
    let mut ask = Vec::new();
    for label in &reply.open_turns {
        let turn = labels
            .resolve_as(LabelKind::Turn, label)
            .ok_or("an arc reply opens a turn its call did not show")?;
        if !opened.contains(&turn) && !ask.contains(&turn) {
            ask.push(turn);
        }
    }
    if !ask.is_empty() {
        return Ok(ArcReply::Open(ask));
    }
    let mut text = String::new();
    let mut scalars = 0_usize;
    let mut line_sources = Vec::with_capacity(reply.lines.len());
    for line in &reply.lines {
        let words = line_words(&line.text)?;
        if line.turn_refs.is_empty() {
            return Err("an arc line cites no turn");
        }
        let mut seen = BTreeSet::new();
        let mut turn_refs = Vec::with_capacity(line.turn_refs.len());
        let mut source_spans: Vec<SummaryLineSpan> = Vec::new();
        for label in &line.turn_refs {
            let turn = labels
                .resolve_as(LabelKind::Turn, label)
                .filter(|turn| covers.contains(turn))
                .ok_or("an arc line cites a turn its call did not show")?;
            if !seen.insert(turn) {
                return Err("an arc line cites a turn twice");
            }
            turn_refs.push(turn.to_hex());
            if !opened.contains(&turn)
                && let Some(Some(spans)) = inherited.get(&turn)
            {
                for span in spans {
                    if !source_spans.contains(span) {
                        source_spans.push(span.clone());
                    }
                }
            }
        }
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
            source_spans,
        });
    }
    if text.is_empty() {
        return Err("the model wrote an empty arc");
    }
    Ok(ArcReply::Lines(ArcLines {
        text,
        keep: reply.keep,
        line_sources,
    }))
}

/// A line's words, trimmed: not blank, and one line.
pub(super) fn line_words(text: &str) -> Result<&str, &'static str> {
    let words = text.trim();
    if words.is_empty() {
        return Err("the model wrote a blank arc line");
    }
    if words.chars().any(|c| {
        matches!(
            c,
            '\n' | '\r' | '\u{0b}' | '\u{0c}' | '\u{85}' | '\u{2028}' | '\u{2029}'
        )
    }) {
        return Err("the model wrote an arc line that breaks");
    }
    Ok(words)
}

/// What one call of an Arc composed in parts shows (FIX 7509 PR3): the
/// Arc's labels, and each TURN the call shows, by words or by a line's
/// refs. A reply's `T` label resolves only to one of these.
#[derive(Debug, Clone, Default)]
pub(super) struct ArcCitationContext {
    pub(super) labels: CallLabelMap,
    pub(super) shown: BTreeMap<EntityId, ArcCitation>,
}

/// How one call shows one TURN.
#[derive(Debug, Clone, Default)]
pub(super) struct ArcCitation {
    /// The slices of its words the call shows, when it shows only part of
    /// them; none when it shows them whole, or only cites the TURN.
    pub(super) source_spans: Vec<SummaryLineSpan>,
}

/// One line a part wrote: its words, the TURNs it cites, each once, and
/// the slices of those shown only in part.
pub(super) struct ChildLine {
    pub(super) text: String,
    pub(super) turn_refs: Vec<String>,
    pub(super) source_spans: Vec<SummaryLineSpan>,
}

/// A part's checked reply: its lines (possibly none) and the TURNs it asks
/// opened that it showed and that are not open to it yet.
pub(super) struct ChildReply {
    pub(super) lines: Vec<ChildLine>,
    pub(super) open: Vec<EntityId>,
}

/// One part's reply, or the static reason it is none. Each line is one line
/// of words that are not blank, citing at least one TURN, each once, by a
/// `T` label the call showed of a TURN the Arc covers; each turn it names to
/// open is a `T` label the call showed. A part may write no line. The step's
/// check and the part's record read the reply through this one parse.
pub(super) fn child_output(
    response: &LlmResponse,
    context: &ArcCitationContext,
    opened: &BTreeSet<EntityId>,
    covers: &BTreeSet<EntityId>,
) -> Result<ChildReply, &'static str> {
    let reply = arc_wire(response)?;
    let shown = |label: &str| {
        context
            .labels
            .resolve_as(LabelKind::Turn, label)
            .filter(|turn| context.shown.contains_key(turn))
    };
    let mut open = Vec::new();
    for label in &reply.open_turns {
        let turn =
            shown(label.as_str()).ok_or("an arc reply opens a turn its call did not show")?;
        if !opened.contains(&turn) && !open.contains(&turn) {
            open.push(turn);
        }
    }
    let mut lines = Vec::with_capacity(reply.lines.len());
    for line in &reply.lines {
        let words = line_words(&line.text)?;
        if line.turn_refs.is_empty() {
            return Err("an arc line cites no turn");
        }
        let mut seen = BTreeSet::new();
        let mut turn_refs = Vec::with_capacity(line.turn_refs.len());
        let mut source_spans: Vec<SummaryLineSpan> = Vec::new();
        for label in &line.turn_refs {
            let turn = shown(label.as_str())
                .filter(|turn| covers.contains(turn))
                .ok_or("an arc line cites a turn its call did not show")?;
            if !seen.insert(turn) {
                return Err("an arc line cites a turn twice");
            }
            turn_refs.push(turn.to_hex());
            if let Some(citation) = context.shown.get(&turn) {
                for span in &citation.source_spans {
                    if !source_spans.contains(span) {
                        source_spans.push(span.clone());
                    }
                }
            }
        }
        lines.push(ChildLine {
            text: words.to_owned(),
            turn_refs,
            source_spans,
        });
    }
    Ok(ChildReply { lines, open })
}
