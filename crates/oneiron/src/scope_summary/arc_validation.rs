//! An Arc's landing check (FIX 7509 P8), read in the landing writer before
//! its body is minted: no Arc lands while a sitting below it is owed, and
//! every line it lands keeps turn refs, each a TURN of the Arc it covers,
//! with ranges that tile its text in order. Every other summary passes
//! untouched.

use super::codec::invalid;
use super::request::{ComposedSummary, ScopeSummaryPlan};
use crate::error::Result;
use std::collections::BTreeSet;

pub(super) fn validate_landing(
    plan: &ScopeSummaryPlan,
    composed: &ComposedSummary<'_>,
) -> Result<()> {
    let Some(arc) = &plan.arc else {
        return Ok(());
    };
    if !arc.owed.is_empty() {
        return Err(invalid("an arc lands only with every sitting below it"));
    }
    let lines = match &composed.line_sources {
        Some(lines) if !lines.is_empty() => lines,
        _ => return Err(invalid("an arc lands with its lines")),
    };
    let turns: BTreeSet<String> = arc.turns.iter().map(|turn| turn.to_hex()).collect();
    let covers: BTreeSet<String> = composed.covers.iter().map(|turn| turn.to_hex()).collect();
    let length = composed.text.chars().count();
    let mut end = 0;
    for line in lines {
        if line.turn_refs.is_empty()
            || !line
                .turn_refs
                .iter()
                .all(|turn| turns.contains(turn) && covers.contains(turn))
        {
            return Err(invalid("an arc line cites a turn its arc does not cover"));
        }
        if line.output_start < end
            || line.output_end <= line.output_start
            || line.output_end > length
        {
            return Err(invalid("an arc line is not in its text"));
        }
        end = line.output_end;
    }
    Ok(())
}
