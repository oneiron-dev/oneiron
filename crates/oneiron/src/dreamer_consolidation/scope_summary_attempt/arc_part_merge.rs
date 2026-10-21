//! One Arc part's pieces, merged before the Arc is assembled (FIX 8285). A
//! part that reviews composes over an exhaustive partition of its
//! observations, one compose piece each, and every piece writes over the
//! same part's lines: the pieces' lines would repeat each other in the
//! assembled Arc.
//!
//! The merge drops no prose and rewrites none. A line whose words are,
//! exactly, a line the part already holds is that line: the TURNs it cites
//! and the slices it came from join the held line's. Every other line is
//! kept as written, in piece order. A TURN either line cites whole stays
//! cited whole; slices of one cited in part are kept, each once.

use crate::scope_summary::SummaryLineSpan;
use std::collections::BTreeMap;

/// One line of a part: its words, the TURNs it cites, each once in first
/// citation order, and the slices of those it cites in part.
pub(super) struct PartLine {
    pub(super) text: String,
    pub(super) turn_refs: Vec<String>,
    pub(super) source_spans: Vec<SummaryLineSpan>,
}

/// The lines of one part's pieces, in piece order, each distinct line once.
pub(super) fn merge_part(lines: Vec<PartLine>) -> Vec<PartLine> {
    let mut merged: Vec<PartLine> = Vec::with_capacity(lines.len());
    let mut held: BTreeMap<String, usize> = BTreeMap::new();
    for line in lines {
        match held.get(&line.text) {
            Some(index) => join(&mut merged[*index], line),
            None => {
                held.insert(line.text.clone(), merged.len());
                merged.push(line);
            }
        }
    }
    merged
}

/// Joins `line`'s citations into `kept`, a line of the same words.
fn join(kept: &mut PartLine, line: PartLine) {
    for turn in &line.turn_refs {
        let cites = kept.turn_refs.contains(turn);
        let kept_whole = cites && !in_part(&kept.source_spans, turn);
        if !cites {
            kept.turn_refs.push(turn.clone());
        }
        if kept_whole {
            continue;
        }
        if !in_part(&line.source_spans, turn) {
            // This line cites the TURN whole: so does the merged line.
            kept.source_spans.retain(|span| span.turn != *turn);
            continue;
        }
        for span in line.source_spans.iter().filter(|span| span.turn == *turn) {
            if !kept.source_spans.contains(span) {
                kept.source_spans.push(span.clone());
            }
        }
    }
}

/// Whether `spans` cite `turn` in part.
fn in_part(spans: &[SummaryLineSpan], turn: &str) -> bool {
    spans.iter().any(|span| span.turn == turn)
}
