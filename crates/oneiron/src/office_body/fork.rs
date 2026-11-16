//! Three-way reads of a fork against the live body (ARCH-0077, "Machine work as
//! fork and diff"): base is the head the fork was opened at, current is the live
//! head, proposal is the fork. Both sides are read against base by block id,
//! and the cases the CRDT would merge silently but a reviewer must see are named.

use super::docx::{BodyBlock, DocxBody, increasing};
use oneiron_docedit::docx_body::{DocxHeaderFooterBand, DocxStoryScope};
use std::collections::{BTreeMap, HashMap};

#[doc(hidden)]
pub use oneiron_records::office_body::fork::{
    BlockChange, BodyConflict, ChangeKind, ConflictKind, OfficeBodyDiff,
};

pub(super) fn diff(
    base: &DocxBody,
    current: &DocxBody,
    proposal: &DocxBody,
    frontiers: (Vec<u8>, Vec<u8>, Vec<u8>),
) -> OfficeBodyDiff {
    let theirs = side(base, current);
    let ours = side(base, proposal);
    let kinds = |changes: &[BlockChange]| {
        let mut by_block: BTreeMap<UnitKey, (Option<DocxStoryScope>, Vec<ChangeKind>)> =
            BTreeMap::new();
        for change in changes {
            by_block
                .entry(unit_key(change))
                .or_insert_with(|| (change.scope.clone(), Vec::new()))
                .1
                .push(change.kind);
        }
        by_block
    };
    let (current_kinds, proposal_kinds) = (kinds(&theirs), kinds(&ours));
    let mut conflicts = Vec::new();
    for (key, (scope, mine)) in &proposal_kinds {
        let Some((_, other)) = current_kinds.get(key) else {
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
                block: key.1.clone(),
                kind,
                scope: scope.clone(),
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
        // A mark change is a text change: both edit the paragraph's runs.
        if block.text != old.text || block.runs != old.runs {
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
    for story in &side.stories {
        let before = base.stories.iter().find(|other| other.scope == story.scope);
        for paragraph in &story.paragraphs {
            let old = before.and_then(|story| {
                story
                    .paragraphs
                    .iter()
                    .find(|other| other.id == paragraph.id)
            });
            match old {
                None => changes.push(story_change(&story.scope, &paragraph.id, ChangeKind::Added)),
                Some(old) if paragraph.text != old.text || paragraph.runs != old.runs => {
                    changes.push(story_change(&story.scope, &paragraph.id, ChangeKind::Text));
                }
                Some(_) => {}
            }
        }
    }
    for story in &base.stories {
        let after = side.stories.iter().find(|other| other.scope == story.scope);
        for paragraph in &story.paragraphs {
            let gone = after.is_none_or(|story| {
                !story
                    .paragraphs
                    .iter()
                    .any(|other| other.id == paragraph.id)
            });
            if gone {
                changes.push(story_change(
                    &story.scope,
                    &paragraph.id,
                    ChangeKind::Deleted,
                ));
            }
        }
    }
    // Tables retain the existing body-table review granularity. Their exports
    // still address each changed paragraph exactly, within its native cell.
    for story in &side.stories {
        let before = base.stories.iter().find(|other| other.scope == story.scope);
        for table in &story.tables {
            let old = before.and_then(|story| story.tables.iter().find(|old| old.id == table.id));
            match old {
                None => changes.push(story_change(&story.scope, &table.id, ChangeKind::Added)),
                Some(old) if old.cells != table.cells => {
                    changes.push(story_change(&story.scope, &table.id, ChangeKind::Cells));
                }
                Some(_) => {}
            }
        }
    }
    for story in &base.stories {
        let after = side.stories.iter().find(|other| other.scope == story.scope);
        for table in &story.tables {
            if after.is_none_or(|story| !story.tables.iter().any(|now| now.id == table.id)) {
                changes.push(story_change(&story.scope, &table.id, ChangeKind::Deleted));
            }
        }
    }
    changes
}

fn change(block: &BodyBlock, kind: ChangeKind) -> BlockChange {
    BlockChange {
        block: block.id.clone(),
        kind,
        scope: None,
    }
}

fn story_change(scope: &DocxStoryScope, block: &str, kind: ChangeKind) -> BlockChange {
    BlockChange {
        block: block.to_owned(),
        kind,
        scope: Some(scope.clone()),
    }
}

/// Identity of one reviewed unit: a body block (`None`) or one story
/// paragraph. A story keys by its variant, its part or story id, and its
/// band, so two stories' shared local ids never meet.
type UnitKey = (Option<(u8, String, u8)>, String);

fn unit_key(change: &BlockChange) -> UnitKey {
    (change.scope.as_ref().map(scope_key), change.block.clone())
}

fn scope_key(scope: &DocxStoryScope) -> (u8, String, u8) {
    match scope {
        DocxStoryScope::Header { part_name, band } => (0, part_name.clone(), band_index(*band)),
        DocxStoryScope::Footer { part_name, band } => (1, part_name.clone(), band_index(*band)),
        DocxStoryScope::Footnote { id } => (2, id.clone(), 0),
        DocxStoryScope::Endnote { id } => (3, id.clone(), 0),
        DocxStoryScope::Comment { id } => (4, id.clone(), 0),
    }
}

fn band_index(band: DocxHeaderFooterBand) -> u8 {
    match band {
        DocxHeaderFooterBand::Default => 0,
        DocxHeaderFooterBand::First => 1,
        DocxHeaderFooterBand::Even => 2,
    }
}
