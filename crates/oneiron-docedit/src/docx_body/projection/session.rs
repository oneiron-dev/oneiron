//! The session: one parse, one tracked transaction for each consecutive
//! actor group, one serialization, and what each group placed.

use super::{apply_built, group_ops};
use crate::docx_body::{DocxAnchor, DocxChange, DocxRevision};
use crate::{ArchiveLimits, DoceditError, Document, preflight_with_limits};
use std::collections::HashMap;
use stemma::view::{BlockRole, BlockView, DocumentView, SegmentView, TrackStatus};

/// What one applied group placed: inserted paragraphs per `Insert` op and
/// move copies per `Move` op, each in `changes` order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocxGroupEvents {
    /// Native ids of the paragraphs each `Insert` op placed, in op order;
    /// each inner vec is in the op's paragraph order.
    pub inserted: Vec<Vec<String>>,
    /// Native id of the copy each `Move` op placed, in op order.
    pub moved: Vec<String>,
}

/// An in-memory multi-revision DOCX projection (FIX 595): parse once, apply
/// one tracked transaction per consecutive actor group with its own
/// [`DocxRevision`], serialize once. Block ids stay stable across groups
/// because nothing re-parses between them (re-parsing renumbers: import
/// mints positional ids, so chaining [`project_docx`] over bytes would
/// misaddress later groups). One group through the session builds and runs
/// exactly what a lone [`project_docx`] call builds and runs.
pub struct DocxProjection {
    doc: Document,
    limits: ArchiveLimits,
    source: Vec<u8>,
    applied: bool,
}

impl DocxProjection {
    /// Parse `source` for a multi-group projection under `limits`.
    pub fn parse(source: &[u8], limits: ArchiveLimits) -> Result<Self, DoceditError> {
        let doc = crate::within(limits, || {
            preflight_with_limits(source, limits)?;
            Document::parse(source)
        })?;
        Ok(Self {
            doc,
            limits,
            source: source.to_vec(),
            applied: false,
        })
    }

    /// Apply one group's changes as one tracked transaction under `revision`,
    /// reading guards from the current in-memory state. `None` when the group
    /// builds no ops (nothing applied, no revision emitted).
    pub fn apply_group(
        &mut self,
        changes: &[DocxChange],
        revision: &DocxRevision,
    ) -> Result<Option<DocxGroupEvents>, DoceditError> {
        crate::within(self.limits, || self.apply_within(changes, revision))
    }

    fn apply_within(
        &mut self,
        changes: &[DocxChange],
        revision: &DocxRevision,
    ) -> Result<Option<DocxGroupEvents>, DoceditError> {
        if changes.is_empty() {
            return Ok(None);
        }
        let view = self.doc.read();
        let (patches, ops) = group_ops(&view, &self.doc.snapshot().canonical, changes)?;
        if patches.is_empty() && ops.is_empty() {
            return Ok(None);
        }
        let edited = apply_built(&self.doc, patches, ops, changes, revision)?;
        let events = group_events(&edited.read(), changes)?;
        self.doc = edited;
        self.applied = true;
        Ok(Some(events))
    }

    /// Top-level block ids in accept-all order: pending deletions and move
    /// sources excluded, inserted paragraphs and move copies included.
    pub fn accepted_id_order(&self) -> Vec<String> {
        crate::within(self.limits, || {
            self.doc
                .read()
                .blocks
                .iter()
                .filter(|block| {
                    let survives = matches!(
                        block.block_status,
                        TrackStatus::Normal | TrackStatus::Inserted(_)
                    );
                    let authored_delete = matches!(
                        &block.paragraph_mark_status,
                        TrackStatus::Deleted(revision) if revision.apply_op_id.is_some()
                    );
                    survives
                        && !(matches!(block.block_status, TrackStatus::Normal)
                            && authored_delete
                            && paragraph_has_no_accepted_segments(block))
                })
                .map(|block| block.id.to_string())
                .collect()
        })
    }

    /// Whether a requested delete left the untracked physical final-mark
    /// carrier. It still has an id, but no longer names a logical paragraph.
    pub fn deleted_final_mark_survives(&self, changes: &[DocxChange]) -> bool {
        crate::within(self.limits, || {
            self.doc.read().blocks.iter().any(|block| {
                matches!(block.block_status, TrackStatus::Normal)
                    && matches!(block.paragraph_mark_status, TrackStatus::Normal)
                    && paragraph_has_no_accepted_segments(block)
                    && changes.iter().any(|change| matches!(change,
                        DocxChange::Delete { block: deleted } if *deleted == block.id.to_string()
                    ))
            })
        })
    }

    /// Match the final carrier of a single delete against the live body.
    /// The caller must also require this to be the terminal actor group.
    pub fn terminal_final_delete_matches(
        &self,
        changes: &[DocxChange],
        accepted_order: &[String],
        expected: &[(String, &str)],
    ) -> bool {
        crate::within(self.limits, || {
            let [DocxChange::Delete { block: deleted }] = changes else {
                return false;
            };
            let Some((last_id, preceding_ids)) = accepted_order.split_last() else {
                return false;
            };
            if last_id != deleted || !preceding_ids.iter().eq(expected.iter().map(|(id, _)| id)) {
                return false;
            }
            let view = self.doc.read();
            let Some((carrier, preceding)) = view.blocks.split_last() else {
                return false;
            };
            if preceding.is_empty()
                || preceding.len() != expected.len()
                || carrier.id.to_string() != *deleted
                || !matches!(carrier.paragraph_mark_status, TrackStatus::Normal)
                || !paragraph_has_no_accepted_segments(carrier)
                || carrier
                    .segments
                    .iter()
                    .any(|segment| !matches!(segment, SegmentView::Text { .. }))
            {
                return false;
            }
            let canonical = &self.doc.snapshot().canonical;
            if canonical.blocks.len() != view.blocks.len() {
                return false;
            }
            for (block, tracked) in view.blocks.iter().zip(&canonical.blocks) {
                let stemma::domain::BlockNode::Paragraph(paragraph) = &tracked.block else {
                    return false;
                };
                if !matches!(block.block_status, TrackStatus::Normal)
                    || tracked.move_id.is_some()
                    || block.literal_prefix.is_some()
                    || paragraph.literal_prefix.is_some()
                    || paragraph.para_split
                {
                    return false;
                }
            }
            for (at, (block, (id, text))) in preceding.iter().zip(expected).enumerate() {
                if block.id.to_string() != *id
                    || if at + 1 == preceding.len() {
                        !matches!(block.paragraph_mark_status, TrackStatus::Deleted(_))
                    } else {
                        !matches!(block.paragraph_mark_status, TrackStatus::Normal)
                    }
                {
                    return false;
                }
                let mut remaining = *text;
                for segment in &block.segments {
                    match segment {
                        SegmentView::Text { text, status, .. } => {
                            if matches!(status, TrackStatus::Normal | TrackStatus::Inserted(_)) {
                                let Some(rest) = remaining.strip_prefix(text.as_str()) else {
                                    return false;
                                };
                                remaining = rest;
                            }
                        }
                        SegmentView::Opaque { .. } => return false,
                    }
                }
                if !remaining.is_empty() {
                    return false;
                }
            }
            true
        })
    }

    /// Serialize the projection through the blocking gate. With no applied
    /// group, the source bytes unchanged (as an empty [`project_docx`]).
    pub fn finish(self) -> Result<Vec<u8>, DoceditError> {
        if !self.applied {
            return Ok(self.source);
        }
        crate::within(self.limits, || {
            crate::export_redline(&self.doc, self.limits)
        })
    }
}

fn paragraph_has_no_accepted_segments(block: &BlockView) -> bool {
    matches!(block.role, BlockRole::Paragraph | BlockRole::Heading { .. })
        && block.segments.iter().all(|segment| match segment {
            SegmentView::Text { status, .. } | SegmentView::Opaque { status, .. } => {
                !matches!(status, TrackStatus::Normal | TrackStatus::Inserted(_))
            }
        })
}

/// Resolve what one applied group placed: each `Insert` op's paragraph ids
/// and each `Move` op's copy id, from the post-apply view. Placements
/// sharing one anchor key form one contiguous run beside it in op order
/// (same-anchor `After` placements chain within a transaction, moves
/// included), so each run slices exactly by its ops' paragraph counts.
fn group_events(
    view: &DocumentView,
    changes: &[DocxChange],
) -> Result<DocxGroupEvents, DoceditError> {
    enum Placement {
        Insert { seq: usize, count: usize },
        Moved { seq: usize },
    }
    let mut order: Vec<(String, bool)> = Vec::new();
    let mut runs: HashMap<(String, bool), Vec<Placement>> = HashMap::new();
    let (mut inserts, mut moves) = (0usize, 0usize);
    for change in changes {
        let (anchor, placement) = match change {
            DocxChange::Insert { anchor, paragraphs } => {
                let seq = inserts;
                inserts += 1;
                (
                    anchor,
                    Placement::Insert {
                        seq,
                        count: paragraphs.len(),
                    },
                )
            }
            DocxChange::Move { anchor: to, .. } => {
                let seq = moves;
                moves += 1;
                (to, Placement::Moved { seq })
            }
            _ => continue,
        };
        let key = match anchor {
            DocxAnchor::After(id) => (id.clone(), true),
            DocxAnchor::Before(id) => (id.clone(), false),
        };
        if !runs.contains_key(&key) {
            order.push(key.clone());
        }
        runs.entry(key).or_default().push(placement);
    }
    let mut inserted: Vec<Vec<String>> = vec![Vec::new(); inserts];
    let mut moved: Vec<String> = vec![String::new(); moves];
    for key in &order {
        let (anchor, after) = key;
        let at = view
            .blocks
            .iter()
            .position(|block| block.id.to_string() == *anchor)
            .ok_or_else(|| DoceditError::InvalidTransaction(format!("unknown block {anchor}")))?;
        let placements = &runs[key];
        let total: usize = placements
            .iter()
            .map(|placement| match placement {
                Placement::Insert { count, .. } => *count,
                Placement::Moved { .. } => 1,
            })
            .sum();
        let span = if *after {
            view.blocks.get(at + 1..at + 1 + total)
        } else {
            at.checked_sub(total)
                .and_then(|start| view.blocks.get(start..at))
        }
        .ok_or_else(|| {
            DoceditError::InvalidTransaction(
                "a group placement did not land beside its anchor".to_owned(),
            )
        })?;
        let mut cursor = 0;
        for placement in placements {
            match placement {
                Placement::Insert { seq, count } => {
                    inserted[*seq] = span[cursor..cursor + *count]
                        .iter()
                        .map(|block| block.id.to_string())
                        .collect();
                    cursor += *count;
                }
                Placement::Moved { seq } => {
                    moved[*seq] = span[cursor].id.to_string();
                    cursor += 1;
                }
            }
        }
    }
    Ok(DocxGroupEvents { inserted, moved })
}
