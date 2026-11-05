//! In-memory multi-revision DOCX projection and its shared op builder.

use crate::{ArchiveLimits, DoceditError, Document, preflight_with_limits};
use serde_json::{Value, json};
use std::collections::HashMap;
use stemma::edit::EditTransaction;
use stemma::view::{BlockView, DocumentView, TrackStatus};

use super::{
    DocxAnchor, DocxChange, DocxParagraph, DocxRevision, inherited, kept_marks, marked_paragraph,
    new_paragraph, paragraph, remark, runs_text,
};

/// The formatting patches and ops one group's changes build against `view`.
/// Shared by [`project_docx`] and [`DocxProjection`]: one group through the
/// session builds exactly what a lone [`project_docx`] call builds.
pub(super) fn group_ops<'v>(
    view: &'v DocumentView,
    changes: &[DocxChange],
) -> Result<(Vec<(&'v BlockView, Vec<(u8, u8)>)>, Vec<Value>), DoceditError> {
    let find = |id: &str| {
        view.blocks
            .iter()
            .find(|block| block.id.to_string() == id)
            .ok_or_else(|| DoceditError::InvalidTransaction(format!("unknown block {id}")))
    };
    let anchor = |anchor: &DocxAnchor| {
        let (id, position) = match anchor {
            DocxAnchor::After(id) => (id, "after"),
            DocxAnchor::Before(id) => (id, "before"),
        };
        find(id).map(|block| json!({"anchor": block.id.to_string(), "position": position}))
    };
    let mut patches = Vec::new();
    let mut ops: Vec<Value> = Vec::with_capacity(changes.len());
    for change in changes {
        match change {
            DocxChange::SetText { block, text } => {
                let block = find(block)?;
                ops.push(json!({
                    "op": "replace",
                    "target": block.id.to_string(),
                    "guard": block.guard,
                    "content": paragraph(block.role_token.as_deref(), text),
                }));
            }
            DocxChange::SetRuns { block, runs } => {
                let block = find(block)?;
                // Formatting goes first, as a pass of its own: the guard pins
                // text, not marks, so the replace after it still reads the
                // block it was read against.
                if let Some(patch) = kept_marks(block, runs)? {
                    patches.push((block, patch));
                }
                if runs_text(runs) != block.text {
                    ops.push(json!({
                        "op": "replace",
                        "target": block.id.to_string(),
                        "guard": block.guard,
                        "content": marked_paragraph(block.role_token.as_deref(), runs),
                    }));
                }
            }
            DocxChange::SetCell {
                block,
                row,
                col,
                text,
            } => ops.push(json!({
                "op": "table_op",
                "target": find(block)?.id.to_string(),
                "table_op": {"kind": "set_cell_text", "row_index": row, "col_index": col, "text": text},
            })),
            DocxChange::Move { block, anchor: to } => ops.push(json!({
                "op": "move",
                "target": find(block)?.id.to_string(),
                "destination": anchor(to)?,
            })),
            DocxChange::Insert {
                anchor: at,
                paragraphs,
            } => {
                let content = paragraphs
                    .iter()
                    .map(new_paragraph)
                    .collect::<Result<Vec<_>, _>>()?;
                ops.push(json!({"op": "insert", "target": anchor(at)?, "content": content}));
            }
            DocxChange::Delete { block } => {
                let block = find(block)?;
                ops.push(json!({
                    "op": "delete",
                    "target": block.id.to_string(),
                    "guard": block.guard,
                    "expect": block.text,
                }));
            }
        }
    }
    Ok((patches, ops))
}

/// Apply one group's built patches and ops as a single tracked transaction
/// under `revision`, with the inherited-marks correction. Shared by
/// [`project_docx`] and [`DocxProjection`]: one group through the session
/// runs exactly what a lone [`project_docx`] call runs. Callers only pass
/// non-empty builds.
pub(super) fn apply_built(
    document: &Document,
    patches: Vec<(&BlockView, Vec<(u8, u8)>)>,
    ops: Vec<Value>,
    changes: &[DocxChange],
    revision: &DocxRevision,
) -> Result<Document, DoceditError> {
    let after_patches = if patches.is_empty() {
        None
    } else {
        Some(remark(document, &patches, revision).ok_or_else(|| {
            DoceditError::InvalidTransaction(
                "a mark change on text its paragraph cannot address".to_owned(),
            )
        })?)
    };
    let after_ops = if ops.is_empty() {
        after_patches
    } else {
        let base = after_patches.as_ref().unwrap_or(document);
        Some(base.apply(&native(ops, revision)?)?)
    };
    let mut edited =
        after_ops.ok_or_else(|| DoceditError::InvalidTransaction("empty projection".to_owned()))?;
    if let Some(remarked) = inherited(&edited, changes, revision) {
        edited = remarked;
    }
    Ok(edited)
}

/// `ops` as one tracked transaction under the projection's revision.
pub(super) fn native(
    ops: Vec<Value>,
    revision: &DocxRevision,
) -> Result<EditTransaction, DoceditError> {
    let transaction = json!({
        "ops": ops,
        "revision": {"author": revision.author, "date": revision.date, "apply_op_id": revision.group},
    });
    crate::parse_native_revision(&transaction.to_string())
}

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
        let (patches, ops) = group_ops(&view, changes)?;
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
                    matches!(
                        block.block_status,
                        TrackStatus::Normal | TrackStatus::Inserted(_)
                    )
                })
                .map(|block| block.id.to_string())
                .collect()
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
