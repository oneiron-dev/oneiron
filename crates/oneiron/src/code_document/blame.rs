//! Per-operation blame over tested file states: which operation wrote each
//! surviving character, and which operations changed a range between states.

use std::collections::{BTreeSet, HashMap};

use loro::cursor::Side;
use loro::{ID, LoroDoc};

use super::codec::invalid;
use super::storage::{HeadRow, load_frontier, load_head};
use super::{CodeDocumentFrontier, CodeOpAttribution, CodeRangeChange, CodeSpanBlame};
use crate::Vault;
use crate::error::Result;

/// Birth text is written by reserved peer 0, never by an editing session.
const BIRTH_PEER: u64 = 0;

/// One older/newer range pair; offsets are Unicode scalars in their own state.
pub type CodeRangePair = (Option<(usize, usize)>, Option<(usize, usize)>);

impl Vault {
    /// Splits `[start, end)` of a tested file state into runs, each written by
    /// one operation or by the birth text. Offsets are Unicode scalars.
    pub fn code_document_blame(
        &self,
        tested: &CodeDocumentFrontier,
        start: usize,
        end: usize,
    ) -> Result<Vec<CodeSpanBlame>> {
        let rtxn = self.store.env.read_txn()?;
        let doc = load_frontier(&self.store, &rtxn, tested)?;
        let head = load_head(&self.store, &rtxn, &tested.document_id)?.ok_or_else(invalid)?;
        let mut runs: Vec<(usize, usize, Option<usize>)> = Vec::new();
        for (pos, id) in (start..).zip(char_ids(&doc, start, end)?) {
            let owner = owner(&head, id)?;
            match runs.last_mut() {
                Some(run) if run.1 == pos && run.2 == owner => run.1 = pos + 1,
                _ => runs.push((pos, pos + 1, owner)),
            }
        }
        runs.into_iter()
            .map(|(start, end, owner)| {
                Ok(CodeSpanBlame {
                    start,
                    end,
                    op: owner
                        .map(|index| head.receipts[index].attribution())
                        .transpose()?,
                })
            })
            .collect()
    }

    /// The operations a tested state holds that an older state of the same
    /// document does not, in sequence order. With no older state: every
    /// operation the newer state holds.
    pub fn code_document_ops_between(
        &self,
        before: Option<&CodeDocumentFrontier>,
        after: &CodeDocumentFrontier,
    ) -> Result<Vec<CodeOpAttribution>> {
        if before.is_some_and(|before| before.document_id != after.document_id) {
            return Err(invalid());
        }
        let rtxn = self.store.env.read_txn()?;
        if let Some(before) = before {
            load_frontier(&self.store, &rtxn, before)?;
        }
        load_frontier(&self.store, &rtxn, after)?;
        let head = load_head(&self.store, &rtxn, &after.document_id)?.ok_or_else(invalid)?;
        head.receipts
            .iter()
            .filter(|row| {
                row.within(&after.version)
                    && before.is_none_or(|before| row.after_version(&before.version))
            })
            .map(|row| row.attribution())
            .collect()
    }

    /// For each range pair, the operations made after `before` and held by
    /// `after` that wrote surviving text of the newer range or deleted text of
    /// the older range. Deletions are read from each operation's own observed
    /// state, so a concurrent edit is never blamed for another's removal.
    pub fn code_document_range_changes(
        &self,
        before: &CodeDocumentFrontier,
        after: &CodeDocumentFrontier,
        ranges: &[CodeRangePair],
    ) -> Result<Vec<CodeRangeChange>> {
        if before.document_id != after.document_id {
            return Err(invalid());
        }
        let rtxn = self.store.env.read_txn()?;
        let old = load_frontier(&self.store, &rtxn, before)?;
        let new = load_frontier(&self.store, &rtxn, after)?;
        let head = load_head(&self.store, &rtxn, &after.document_id)?.ok_or_else(invalid)?;
        let between: BTreeSet<usize> = head
            .receipts
            .iter()
            .enumerate()
            .filter(|(_, row)| row.within(&after.version) && row.after_version(&before.version))
            .map(|(index, _)| index)
            .collect();
        let mut deleted: HashMap<ID, BTreeSet<usize>> = HashMap::new();
        for &index in &between {
            let row = &head.receipts[index];
            if row.edit.new_path.is_some() || row.edit.start == row.edit.end {
                continue;
            }
            let seen = load_frontier(&self.store, &rtxn, &row.before)?;
            for id in char_ids(&seen, row.edit.start, row.edit.end)? {
                deleted.entry(id).or_default().insert(index);
            }
        }
        ranges
            .iter()
            .map(|(old_range, new_range)| {
                let mut inserted = BTreeSet::new();
                if let Some((start, end)) = *new_range {
                    for id in char_ids(&new, start, end)? {
                        if let Some(index) = owner(&head, id)?
                            && between.contains(&index)
                        {
                            inserted.insert(index);
                        }
                    }
                }
                let mut removed = BTreeSet::new();
                if let Some((start, end)) = *old_range {
                    for id in char_ids(&old, start, end)? {
                        if let Some(ops) = deleted.get(&id) {
                            removed.extend(ops.iter().copied());
                        }
                    }
                }
                Ok(CodeRangeChange {
                    inserted_by: attributions(&head, &inserted)?,
                    deleted_by: attributions(&head, &removed)?,
                })
            })
            .collect()
    }
}

/// The insertion ID of each character in `[start, end)`.
fn char_ids(doc: &LoroDoc, start: usize, end: usize) -> Result<Vec<ID>> {
    let body = doc.get_text("body");
    if start > end || end > body.len_unicode() {
        return Err(invalid());
    }
    (start..end)
        .map(|pos| {
            body.get_cursor(pos, Side::Middle)
                .and_then(|cursor| cursor.id)
                .ok_or_else(invalid)
        })
        .collect()
}

/// The receipt index of the operation that inserted `id`; `None` for birth text.
fn owner(head: &HeadRow, id: ID) -> Result<Option<usize>> {
    if id.peer == BIRTH_PEER {
        return Ok(None);
    }
    head.receipts
        .iter()
        .position(|row| row.owns(id))
        .map(Some)
        .ok_or_else(invalid)
}

fn attributions(head: &HeadRow, indexes: &BTreeSet<usize>) -> Result<Vec<CodeOpAttribution>> {
    indexes
        .iter()
        .map(|&index| head.receipts[index].attribution())
        .collect()
}
