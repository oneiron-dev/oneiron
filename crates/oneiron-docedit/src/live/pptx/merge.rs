//! The three-way comparison of a fork's base, the head and its proposal,
//! and the merge preflight over the candidate a landing would make: the
//! fork's operations replayed onto the head, or the candidate the engine
//! joins as its document does (the head with the fork's changes imported),
//! so concurrent table edits merge by identity rather than one replacing
//! the other.

use super::table;
use super::{
    Conflict, DeckDiff, DeckFork, LiveDeck, NodeId, NodeKind, NodeMove, OpaqueChange,
    PreflightReport, sibling_index, slide_of, unit_changed, written,
};
use crate::live::LiveError;
use std::collections::BTreeSet;

/// Compare base, current head and proposal. Text and formatting are
/// reported separately; own geometry separately from moves, and preset and
/// payload on their own.
pub fn diff(base: &LiveDeck, head: &LiveDeck, proposal: &LiveDeck) -> DeckDiff {
    let mut out = DeckDiff {
        base_version: base.version,
        head_version: head.version,
        proposal_version: proposal.version,
        added: Vec::new(),
        removed: Vec::new(),
        moved: Vec::new(),
        text_changed: Vec::new(),
        formatting_changed: Vec::new(),
        geometry_changed: Vec::new(),
        payload_changed: Vec::new(),
        opaque_changed: Vec::new(),
        affected_slides: Vec::new(),
        head_only: Vec::new(),
        conflicts: Vec::new(),
        relationships: Vec::new(),
        renders: None,
    };
    let mut affected: BTreeSet<NodeId> = BTreeSet::new();
    for id in proposal.nodes.keys() {
        if !base.nodes.contains_key(id) {
            out.added.push(*id);
            if let Some(slide) = slide_of(proposal, *id) {
                affected.insert(slide);
            }
        }
    }
    for id in base.nodes.keys() {
        if !proposal.nodes.contains_key(id) {
            out.removed.push(*id);
            if let Some(slide) = slide_of(base, *id) {
                affected.insert(slide);
            }
        }
    }
    for (id, node) in &proposal.nodes {
        let Some(was) = base.nodes.get(id) else {
            continue;
        };
        let moved =
            was.parent != node.parent || sibling_index(base, *id) != sibling_index(proposal, *id);
        if moved {
            out.moved.push(NodeMove {
                node: *id,
                old_parent: was.parent,
                new_parent: node.parent,
                old_index: sibling_index(base, *id),
                new_index: sibling_index(proposal, *id),
                cross_slide: slide_of(base, *id) != slide_of(proposal, *id),
            });
        }
        if was.geometry != node.geometry {
            out.geometry_changed.push(*id);
        }
        let rewritten = written(was) != written(node);
        if rewritten {
            out.payload_changed.push(*id);
        }
        match (base.texts.get(id), proposal.texts.get(id)) {
            (a, b) if a == b => {}
            (Some(a), Some(b)) if a.plain() == b.plain() => out.formatting_changed.push(*id),
            _ => out.text_changed.push(*id),
        }
        if moved
            || rewritten
            || was.geometry != node.geometry
            || base.texts.get(id) != proposal.texts.get(id)
        {
            if let Some(slide) = slide_of(proposal, *id).or_else(|| slide_of(base, *id)) {
                affected.insert(slide);
            }
        }
        // Head-only work: changed on the head, untouched by the proposal.
        if unit_changed(base, head, *id) && !unit_changed(base, proposal, *id) {
            out.head_only.push(*id);
        }
        // Conflicts: both sides changed the same unit incompatibly.
        let head_node = head.nodes.get(id);
        if head_node.is_none() && unit_changed(base, proposal, *id) {
            out.conflicts.push(Conflict::DeletedVsEdited {
                node: *id,
                deleted_by_head: true,
            });
        } else if let Some(head_node) = head_node {
            let head_moved = was.parent != head_node.parent
                || sibling_index(base, *id) != sibling_index(head, *id);
            if moved
                && head_moved
                && (node.parent != head_node.parent
                    || sibling_index(proposal, *id) != sibling_index(head, *id))
            {
                out.conflicts.push(Conflict::BothMoved { node: *id });
            }
            if moved != head_moved
                && ((moved && was.geometry != head_node.geometry)
                    || (head_moved && was.geometry != node.geometry))
            {
                out.conflicts
                    .push(Conflict::GeometryVsReparent { node: *id });
            }
            if base.texts.get(id) != head.texts.get(id)
                && base.texts.get(id) != proposal.texts.get(id)
                && head.texts.get(id) != proposal.texts.get(id)
            {
                out.conflicts.push(Conflict::TextVsText { node: *id });
            }
            // Two tables conflict only in a cell both sides wrote
            // differently; their other units join by identity.
            if written(was) != written(head_node)
                && rewritten
                && written(head_node) != written(node)
            {
                match table::conflicts(was, head_node, node) {
                    Some(cells) => out.conflicts.extend(cells.into_iter().map(|(row, column)| {
                        Conflict::CellVsCell {
                            node: *id,
                            row,
                            column,
                        }
                    })),
                    None => out.conflicts.push(Conflict::PayloadVsPayload { node: *id }),
                }
            }
        }
    }
    for id in base.nodes.keys() {
        if !proposal.nodes.contains_key(id) && unit_changed(base, head, *id) {
            out.conflicts.push(Conflict::DeletedVsEdited {
                node: *id,
                deleted_by_head: false,
            });
        }
    }
    let mut parts: BTreeSet<&str> = BTreeSet::new();
    parts.extend(base.opaque_parts.keys().map(String::as_str));
    parts.extend(proposal.opaque_parts.keys().map(String::as_str));
    for part in parts {
        let (b, h, p) = (
            base.opaque_parts.get(part),
            head.opaque_parts.get(part),
            proposal.opaque_parts.get(part),
        );
        if b != p {
            out.opaque_changed.push(OpaqueChange {
                part: part.to_owned(),
                base: b.copied(),
                proposal: p.copied(),
            });
            // A master, layout or theme replacement can affect every slide.
            affected.extend(
                proposal
                    .nodes
                    .iter()
                    .filter(|(_, node)| node.kind == NodeKind::Slide)
                    .map(|(id, _)| *id),
            );
        }
        if b != h && b != p && h != p {
            out.conflicts.push(Conflict::BothReplacedOpaque {
                part: part.to_owned(),
            });
        }
    }
    out.affected_slides = affected.into_iter().collect();
    out
}

/// The scratch-candidate check before any merge: the fork's actual
/// operations replayed onto the current head. Operations are never
/// cherry-picked and merging is never replaced with a rewrite.
pub fn preflight(head: &LiveDeck, fork: &DeckFork) -> Result<PreflightReport, LiveError> {
    let proposal = fork.candidate()?;
    let comparison = diff(&fork.base, head, &proposal);
    let mut candidate = head.clone();
    let mut refusals = Vec::new();
    for op in &fork.ops {
        if let Err(error) = candidate.apply(op) {
            refusals.push(error.to_string());
        }
    }
    let ok = comparison.conflicts.is_empty() && refusals.is_empty();
    Ok(PreflightReport {
        head_version: head.version,
        candidate,
        diff: comparison,
        replay_refusals: refusals,
        ok,
    })
}

/// [`preflight`] over the candidate the engine joins: the head's document
/// with the fork's own changes imported, read as a deck, or why it does
/// not read as one. The replay still names the operations that no longer
/// apply on the head, but the candidate a review renders and a merge lands
/// is the joined one, so concurrent table edits merge as the document
/// merges them instead of a fork's edits being replayed over the head's.
pub fn preflight_merged(
    head: &LiveDeck,
    fork: &DeckFork,
    merged: Result<LiveDeck, String>,
) -> Result<PreflightReport, LiveError> {
    let mut report = preflight(head, fork)?;
    match merged {
        Ok(candidate) => report.candidate = candidate,
        Err(reason) => {
            report.replay_refusals.push(reason);
            report.ok = false;
        }
    }
    Ok(report)
}
