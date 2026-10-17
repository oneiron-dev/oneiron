//! Three-way reads of a fork against the live body (ARCH-0077, "Machine work as
//! fork and diff"): base is the head the fork was opened at, current is the live
//! head, proposal is the fork. Both sides are read against base by block id,
//! and the cases the CRDT would merge silently but a reviewer must see are named.

use super::docx::{BodyBlock, DocxBody, increasing};
use std::collections::{BTreeMap, HashMap};

/// What a side did to one block, relative to base.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Deleted,
    Moved,
    Text,
    Cells,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockChange {
    pub block: String,
    pub kind: ChangeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind {
    /// One side deleted the block the other edited or moved: a lost intent.
    DeleteEdit,
    /// Both sides moved the block.
    CompetingMove,
    /// Both sides edited the same text or cells; the text CRDT interleaves them.
    BothEdited,
    /// Both sides set the same workbook cell or name differently; the later
    /// write would silently replace the other.
    BothSet,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BodyConflict {
    pub block: String,
    pub kind: ConflictKind,
}

/// A fork's proposal against the live body, with the frontiers it was read at.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OfficeBodyDiff {
    pub base: Vec<u8>,
    pub head: Vec<u8>,
    /// The fork's own frontier: a merge names it with the live head, so work
    /// the opener adds after the review never lands on an earlier answer.
    pub fork_head: Vec<u8>,
    pub proposal: Vec<BlockChange>,
    pub current: Vec<BlockChange>,
    pub conflicts: Vec<BodyConflict>,
}

impl OfficeBodyDiff {
    /// Whether a merge must wait: any conflict but a shared text edit, which the
    /// review shows and the CRDT merges.
    #[must_use]
    pub fn blocking(&self) -> bool {
        self.conflicts
            .iter()
            .any(|conflict| conflict.kind != ConflictKind::BothEdited)
    }
}

pub(super) fn diff(
    base: &DocxBody,
    current: &DocxBody,
    proposal: &DocxBody,
    frontiers: (Vec<u8>, Vec<u8>, Vec<u8>),
) -> OfficeBodyDiff {
    let theirs = side(base, current);
    let ours = side(base, proposal);
    let kinds = |changes: &[BlockChange]| {
        let mut by_block: BTreeMap<String, Vec<ChangeKind>> = BTreeMap::new();
        for change in changes {
            by_block
                .entry(change.block.clone())
                .or_default()
                .push(change.kind);
        }
        by_block
    };
    let (current_kinds, proposal_kinds) = (kinds(&theirs), kinds(&ours));
    let mut conflicts = Vec::new();
    for (block, mine) in &proposal_kinds {
        let Some(other) = current_kinds.get(block) else {
            continue;
        };
        let (mine, other) = (mine.as_slice(), other.as_slice());
        let edits = |kinds: &[ChangeKind]| {
            kinds.iter().any(|kind| {
                matches!(
                    kind,
                    ChangeKind::Text | ChangeKind::Cells | ChangeKind::Moved
                )
            })
        };
        let has = |kinds: &[ChangeKind], kind| kinds.contains(&kind);
        let kind = if (has(mine, ChangeKind::Deleted) && edits(other))
            || (has(other, ChangeKind::Deleted) && edits(mine))
        {
            Some(ConflictKind::DeleteEdit)
        } else if has(mine, ChangeKind::Moved) && has(other, ChangeKind::Moved) {
            Some(ConflictKind::CompetingMove)
        } else if (has(mine, ChangeKind::Text) && has(other, ChangeKind::Text))
            || (has(mine, ChangeKind::Cells) && has(other, ChangeKind::Cells))
        {
            Some(ConflictKind::BothEdited)
        } else {
            None
        };
        if let Some(kind) = kind {
            conflicts.push(BodyConflict {
                block: block.clone(),
                kind,
            });
        }
    }
    OfficeBodyDiff {
        base: frontiers.0,
        head: frontiers.1,
        fork_head: frontiers.2,
        proposal: ours,
        current: theirs,
        conflicts,
    }
}

/// What `side` did to each block of `base`.
fn side(base: &DocxBody, side: &DocxBody) -> Vec<BlockChange> {
    let before: HashMap<&str, (usize, &BodyBlock)> = base
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.id.as_str(), (index, block)))
        .collect();
    let after: HashMap<&str, &BodyBlock> = side
        .blocks
        .iter()
        .map(|block| (block.id.as_str(), block))
        .collect();
    let mut changes = Vec::new();
    let common: Vec<(&BodyBlock, usize)> = side
        .blocks
        .iter()
        .filter_map(|block| {
            before
                .get(block.id.as_str())
                .map(|(index, _)| (block, *index))
        })
        .collect();
    let staying = increasing(&common.iter().map(|(_, index)| *index).collect::<Vec<_>>());
    for (position, (block, _)) in common.iter().enumerate() {
        let old = before[block.id.as_str()].1;
        if !staying.contains(&position) {
            changes.push(change(block, ChangeKind::Moved));
        }
        if block.text != old.text {
            changes.push(change(block, ChangeKind::Text));
        }
        if block.cells != old.cells {
            changes.push(change(block, ChangeKind::Cells));
        }
    }
    for block in &side.blocks {
        if !before.contains_key(block.id.as_str()) {
            changes.push(change(block, ChangeKind::Added));
        }
    }
    for block in &base.blocks {
        if !after.contains_key(block.id.as_str()) {
            changes.push(change(block, ChangeKind::Deleted));
        }
    }
    changes
}

fn change(block: &BodyBlock, kind: ChangeKind) -> BlockChange {
    BlockChange {
        block: block.id.clone(),
        kind,
    }
}
