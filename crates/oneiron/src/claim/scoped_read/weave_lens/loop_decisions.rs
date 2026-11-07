//! A loop decision's weave lens row (OF-499 A2): its decision, time,
//! family, kind, exact outcome and redacted flag, each reason, and each ref
//! it carries, as plain hex cells. No backing handle is minted for its refs
//! and no wrong control is offered (FIX 7598). No cell is cut short: a value
//! past one cell's share of a lens text's bound continues in the next cell
//! under the same label, and no row or reason is ever skipped.
use super::WeaveItem;

/// The bytes one cell's value holds before it continues in the next cell,
/// well inside a lens text's own bound.
const LOOP_CELL_BYTES: usize = 4 * 1024;

/// A loop decision row's lens cells, each a label and its value, in a fixed
/// order; none for any other row.
pub(super) fn loop_decision_cells(item: &WeaveItem) -> Vec<(&'static str, String)> {
    let WeaveItem::LoopDecision {
        decision_id,
        created_at,
        family,
        kind,
        outcome,
        reason_codes,
        redacted,
        claim_ref,
        actor_ref,
        evidence_refs,
    } = item
    else {
        return Vec::new();
    };
    let mut cells = Vec::new();
    let mut push = |label: &'static str, value: &str| {
        cells.extend(split_cell(value).map(|part| (label, part.to_owned())));
    };
    push("decision_ref", &decision_id.to_hex());
    push("created_at", &created_at.to_string());
    push("family", family);
    push("kind", kind);
    push("outcome", outcome);
    push("redacted", &redacted.to_string());
    for reason in reason_codes {
        push("reason_code", reason);
    }
    if let Some(id) = claim_ref {
        push("claim_ref", &id.to_hex());
    }
    if let Some(id) = actor_ref {
        push("actor_ref", &id.to_hex());
    }
    for id in evidence_refs {
        push("evidence_ref", &id.to_hex());
    }
    cells
}

/// `value` in parts of at most [`LOOP_CELL_BYTES`], each cut on a char
/// boundary, every byte kept; an empty value is one empty part.
fn split_cell(value: &str) -> impl Iterator<Item = &str> {
    let mut rest = Some(value);
    std::iter::from_fn(move || {
        let current = rest?;
        if current.len() <= LOOP_CELL_BYTES {
            rest = None;
            return Some(current);
        }
        let (part, tail) = current.split_at(current.floor_char_boundary(LOOP_CELL_BYTES));
        rest = Some(tail);
        Some(part)
    })
}
