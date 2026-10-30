//! FIX 2115: an edit to a live body never exported moves no version, so a standing
//! artifact question pins each read artifact's live body when it asks, and an arrival
//! asks again the units an edit to it changed since.

use super::{Asking, Changed, Selection};
use crate::office_body::LivePin;
use crate::{EntityId, Result};

impl Changed {
    /// Adds the units `more` names that this does not.
    pub(super) fn merge(&mut self, more: Changed) {
        match (self, more) {
            (Self::Rows(rows), Self::Rows(more)) => rows.extend(more),
            (Self::Blocks(blocks), Self::Blocks(more)) => {
                for block in more {
                    if !blocks.contains(&block) {
                        blocks.push(block);
                    }
                }
            }
            (Self::Items(items), Self::Items(more)) => {
                for item in more {
                    if !items.contains(&item) {
                        items.push(item);
                    }
                }
            }
            _ => {}
        }
    }
}

impl Asking<'_> {
    /// The units of `selection` an edit to a live body never exported changed since the
    /// `pinned` live bodies the question last asked over (FIX 2115), by the rules
    /// [`Self::changed_units`] keeps: a row whose read cells changed, every row when the
    /// header changed or the sheet was reshaped, a paragraph whose text changed, a folder
    /// item whose file changed. `None` when no live body it reads moved.
    pub(super) fn live_changed_units(
        &self,
        artifact: EntityId,
        selection: &Selection<'_>,
        pinned: &[(EntityId, LivePin)],
    ) -> Result<Option<Changed>> {
        let vault = self.vault;
        let pin = |id: EntityId| {
            pinned
                .iter()
                .find(|(read, _)| *read == id)
                .map(|(_, pin)| pin)
        };
        Ok(match selection {
            Selection::SheetRows {
                sheet,
                rows,
                answer_col,
                header_row,
                ..
            } => {
                let Some(live) = vault.live_sheet(&artifact, pin(artifact), sheet)? else {
                    return Ok(None);
                };
                let cols: Vec<u32> = (rows.start.col..=rows.end.col)
                    .filter(|col| col != answer_col)
                    .collect();
                let moved = |row: u32| cols.iter().any(|col| live.differs(*col, row));
                let all = live.whole().is_some() || header_row.is_some_and(|row| moved(row));
                Some(Changed::Rows(
                    (rows.start.row..=rows.end.row)
                        .filter(|row| all || moved(*row))
                        .collect(),
                ))
            }
            Selection::Paragraphs { blocks, .. } => {
                let Some(live) = vault.live_paragraphs(&artifact, pin(artifact))? else {
                    return Ok(None);
                };
                Some(Changed::Blocks(
                    blocks
                        .iter()
                        .filter(|block| live.change(*block).is_some())
                        .cloned()
                        .collect(),
                ))
            }
            Selection::FolderItems { items, .. } => {
                let mut changed = Vec::new();
                for item in items {
                    if vault.live_body_changed(&item.artifact, pin(item.artifact))? {
                        changed.push(*item);
                    }
                }
                Some(Changed::Items(changed))
            }
        })
    }
}
