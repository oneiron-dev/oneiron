//! The three-way comparison of a fork's base, the head and its proposal,
//! and the merge preflight over the candidate a landing would make: the
//! fork's operations replayed onto the head, or the candidate the engine
//! joins as its document does (the head with the fork's changes imported),
//! so concurrent table and chart edits merge by identity rather than one
//! replacing the other.

use super::{
    Conflict, DeckDiff, DeckFork, DeckNode, LiveDeck, NodeId, NodeKind, NodeMove, NodePayload,
    OpaqueChange, PreflightReport, TableBody, sibling_index, slide_of, unit_changed, written,
};
use super::{chart, table};
use crate::live::LiveError;
use std::collections::{BTreeMap, BTreeSet};

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
            // differently, two charts only in a series or chart field both
            // sides wrote; their other units join by identity.
            if written(was) != written(head_node)
                && rewritten
                && written(head_node) != written(node)
            {
                if let Some(cells) = table::conflicts(was, head_node, node) {
                    out.conflicts.extend(cells.into_iter().map(|(row, column)| {
                        Conflict::CellVsCell {
                            node: *id,
                            row,
                            column,
                        }
                    }));
                } else if let Some(found) = chart::conflicts(*id, was, head_node, node) {
                    out.conflicts.extend(found);
                } else {
                    out.conflicts.push(Conflict::PayloadVsPayload { node: *id });
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
    // What a switch to the proposal would take off the head.
    out.head_only = switch_losses(base, head, proposal);
    out
}

/// What a switch to `result` loses of the head's work since `base` (FIX
/// 8592): each node the head added that `result` lacks, each node the head
/// removed that `result` still holds, the head's edits on a node `result`
/// drops, and each node one of whose fields the head changed while `result`
/// holds that field otherwise: its parent, its place among the siblings all
/// three hold, its kind, name, placeholder and preset, each geometry
/// property, its text, and its payload (a table's rows, columns, cells and
/// merges, a chart's series, by identity; a chart's other fields one by
/// one). A head change `result` also holds is no loss, and a field only the
/// proposal changed is not the head's. Bindings are retained-package
/// evidence, never content.
pub(super) fn switch_losses(base: &LiveDeck, head: &LiveDeck, result: &LiveDeck) -> Vec<NodeId> {
    let ids: BTreeSet<NodeId> = base
        .nodes
        .keys()
        .chain(head.nodes.keys())
        .chain(result.nodes.keys())
        .copied()
        .collect();
    ids.into_iter()
        .filter(|id| {
            match (base.nodes.get(id), head.nodes.get(id), result.nodes.get(id)) {
                // The head's addition, gone; the head's removal, undone.
                (None, Some(_), None) | (Some(_), None, Some(_)) => true,
                // The head's edits on a node the switch drops.
                (Some(_), Some(_), None) => unit_changed(base, head, *id),
                // One node both sides hold that no base held: the head's
                // version is what a different result loses.
                (None, Some(_), Some(_)) => unit_changed(head, result, *id),
                (Some(b), Some(h), Some(r)) => {
                    fields_lost(b, h, r)
                        || lost(
                            &base.texts.get(id),
                            &head.texts.get(id),
                            &result.texts.get(id),
                        )
                        || order_lost([base, head, result], *id)
                }
                _ => false,
            }
        })
        .collect()
}

/// The head changed a field from the base, and the result holds it
/// otherwise.
fn lost<T: PartialEq>(base: &T, head: &T, result: &T) -> bool {
    base != head && head != result
}

/// A node's own fields, its payload by identity where it has one.
fn fields_lost(b: &DeckNode, h: &DeckNode, r: &DeckNode) -> bool {
    let (gb, gh, gr) = (&b.geometry, &h.geometry, &r.geometry);
    lost(&b.parent, &h.parent, &r.parent)
        || lost(&b.kind, &h.kind, &r.kind)
        || lost(&b.name, &h.name, &r.name)
        || lost(&b.placeholder, &h.placeholder, &r.placeholder)
        || lost(&b.preset, &h.preset, &r.preset)
        || lost(&gb.offset, &gh.offset, &gr.offset)
        || lost(&gb.extent, &gh.extent, &gr.extent)
        || lost(&gb.rotation, &gh.rotation, &gr.rotation)
        || lost(&gb.flip_h, &gh.flip_h, &gr.flip_h)
        || lost(&gb.flip_v, &gh.flip_v, &gr.flip_v)
        || payload_lost(&b.payload, &h.payload, &r.payload)
}

/// A node's place: the sibling before it among the siblings all three hold
/// under its parent, when all three keep it under one parent.
fn order_lost(decks: [&LiveDeck; 3], id: NodeId) -> bool {
    let parents: Vec<Option<NodeId>> = decks
        .iter()
        .map(|deck| deck.nodes.get(&id).and_then(|node| node.parent))
        .collect();
    let Some(parent) = parents[0].filter(|parent| parents.iter().all(|p| *p == Some(*parent)))
    else {
        return false;
    };
    let lists: Vec<&[NodeId]> = decks
        .iter()
        .map(|deck| {
            deck.nodes
                .get(&parent)
                .map_or(&[][..], |node| node.children.as_slice())
        })
        .collect();
    let [b, h, r] = [lists[0], lists[1], lists[2]].map(|list| before(list, id, &lists));
    lost(&b, &h, &r)
}

/// The id before `id` in `list` among the ids every one of `lists` holds.
fn before(list: &[NodeId], id: NodeId, lists: &[&[NodeId]]) -> Option<NodeId> {
    list.iter()
        .take_while(|at| **at != id)
        .filter(|at| lists.iter().all(|other| other.contains(at)))
        .last()
        .copied()
}

/// An identity list's work: an id the head added the result lacks, one it
/// removed the result holds, or the order of the ids all three hold that
/// the head changed and the result does not keep.
fn listed_lost<K: Ord + Copy>(b: &[K], h: &[K], r: &[K]) -> bool {
    let set = |ids: &[K]| -> BTreeSet<K> { ids.iter().copied().collect() };
    let (sb, sh, sr) = (set(b), set(h), set(r));
    let added = sh.difference(&sb).any(|id| !sr.contains(id));
    let removed = sb.difference(&sh).any(|id| sr.contains(id));
    let common = |ids: &[K]| -> Vec<K> {
        ids.iter()
            .copied()
            .filter(|id| sb.contains(id) && sh.contains(id) && sr.contains(id))
            .collect()
    };
    added || removed || lost(&common(b), &common(h), &common(r))
}

fn payload_lost(b: &Option<NodePayload>, h: &Option<NodePayload>, r: &Option<NodePayload>) -> bool {
    match (b, h, r) {
        (Some(NodePayload::Table(b)), Some(NodePayload::Table(h)), Some(NodePayload::Table(r))) => {
            table_lost(b, h, r)
        }
        (
            Some(NodePayload::Chart {
                family: fb,
                categories: cb,
                series: sb,
                source: ob,
                plots: pb,
                view: vb,
            }),
            Some(NodePayload::Chart {
                family: fh,
                categories: ch,
                series: sh,
                source: oh,
                plots: ph,
                view: vh,
            }),
            Some(NodePayload::Chart {
                family: fr,
                categories: cr,
                series: sr,
                source: or,
                plots: pr,
                view: vr,
            }),
        ) => {
            let ids = |series: &[chart::ChartSeries]| -> Vec<Option<NodeId>> {
                series.iter().map(|one| one.id).collect()
            };
            let by_id =
                |series: &[chart::ChartSeries]| -> BTreeMap<Option<NodeId>, chart::ChartSeries> {
                    series.iter().map(|one| (one.id, one.clone())).collect()
                };
            let (mb, mh, mr) = (by_id(sb), by_id(sh), by_id(sr));
            let keys: BTreeSet<&Option<NodeId>> =
                mb.keys().chain(mh.keys()).chain(mr.keys()).collect();
            lost(fb, fh, fr)
                || lost(cb, ch, cr)
                || lost(ob, oh, or)
                || lost(pb, ph, pr)
                || lost(vb, vh, vr)
                || listed_lost(&ids(sb), &ids(sh), &ids(sr))
                || keys
                    .into_iter()
                    .any(|key| lost(&mb.get(key), &mh.get(key), &mr.get(key)))
        }
        _ => lost(b, h, r),
    }
}

/// A table's rows, columns and merges by identity, and each cell by its row
/// and column.
fn table_lost(b: &TableBody, h: &TableBody, r: &TableBody) -> bool {
    let merges = |table: &TableBody| -> Vec<super::TableMerge> {
        let mut merges = table.merges.clone();
        merges.sort();
        merges
    };
    let mut cells: BTreeSet<(NodeId, NodeId)> = BTreeSet::new();
    for table in [b, h, r] {
        for (row, line) in &table.cells {
            cells.extend(line.keys().map(|column| (*row, *column)));
        }
    }
    listed_lost(&b.rows, &h.rows, &r.rows)
        || listed_lost(&b.columns, &h.columns, &r.columns)
        || {
            let (mb, mh, mr) = (merges(b), merges(h), merges(r));
            let sets = |m: &[super::TableMerge]| -> BTreeSet<super::TableMerge> {
                m.iter().copied().collect()
            };
            let (sb, sh, sr) = (sets(&mb), sets(&mh), sets(&mr));
            sh.difference(&sb).any(|m| !sr.contains(m))
                || sb.difference(&sh).any(|m| sr.contains(m))
        }
        || cells.into_iter().any(|(row, column)| {
            lost(
                &b.cell(row, column),
                &h.cell(row, column),
                &r.cell(row, column),
            )
        })
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
