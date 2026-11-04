//! Per-operation blame over tested file states: which operation wrote each
//! surviving character, and which operations changed a range between states.

use std::collections::{BTreeSet, HashMap};

use heed::RoTxn;
use loro::cursor::Side;
use loro::{ID, LoroDoc};

use super::codec::invalid;
use super::storage::{HeadRow, load_frontier, load_head};
use super::{CodeDocumentFrontier, CodeOpAttribution, CodeRangeChange, CodeSpanBlame};
use crate::Vault;
use crate::error::Result;
use crate::store::Store;

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

/// For each `(start_line, end_line)` of `ranges` (one-based, inclusive), the
/// operations that wrote surviving text of those lines of `document`'s head,
/// in sequence order, read in `txn` (FIX 342). `None` when the document has
/// no head or its head holds another text than `text`: no operation is
/// named for bytes the document does not hold.
///
/// # Errors
/// A corrupt head or a store failure.
pub(crate) fn code_document_line_writers_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    document: &[u8; 32],
    text: &str,
    ranges: &[(u32, u32)],
) -> Result<Option<Vec<Vec<CodeOpAttribution>>>> {
    let Some(head) = load_head(store, txn, document)? else {
        return Ok(None);
    };
    let doc = head.doc()?;
    if doc.get_text("body").to_string() != text {
        return Ok(None);
    }
    let starts = line_starts(text);
    let total = text.chars().count();
    ranges
        .iter()
        .map(|&(start_line, end_line)| {
            let at = |line: u32| {
                usize::try_from(line)
                    .ok()
                    .and_then(|line| starts.get(line.saturating_sub(1)).copied())
            };
            let start = at(start_line).unwrap_or(total);
            let end = at(end_line.saturating_add(1)).unwrap_or(total).max(start);
            let mut writers = BTreeSet::new();
            for id in char_ids(&doc, start, end)? {
                if let Some(index) = owner(&head, id)? {
                    writers.insert(index);
                }
            }
            attributions(&head, &writers)
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

/// The Unicode-scalar offset each line of `text` starts at, first line first.
fn line_starts(text: &str) -> Vec<usize> {
    let mut starts = vec![0];
    for (offset, character) in text.chars().enumerate() {
        if character == '\n' {
            starts.push(offset + 1);
        }
    }
    starts
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
