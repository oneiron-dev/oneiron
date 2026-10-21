//! A chart reference's cells as the workbook edit reads them: a direct
//! one-row or one-column range on one sheet, and a multi-level category
//! reference's rectangle, one such line per level (FIX 3493).

use super::Key;
use crate::live::conversion::RebuildReason;
use crate::xlsx_body::{a1, parse_a1};

const MAX_COLUMN: u32 = 16_384;
const MAX_ROW: u32 = 1_048_576;

/// A direct one-row or one-column range on one sheet, as a chart's `c:f`
/// names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Line {
    pub(super) sheet: String,
    pub(super) first: (u32, u32),
    pub(super) last: (u32, u32),
}

impl Line {
    /// `Sheet1!$B$2:$B$5`, `'My sheet'!B1`.
    pub(super) fn parse(formula: &str) -> Option<Self> {
        Self::parse_block(formula)
            .filter(|line| line.first.0 == line.last.0 || line.first.1 == line.last.1)
    }

    /// A reference to any rectangle on one sheet, as a multi-level
    /// category reference names its block.
    pub(super) fn parse_block(formula: &str) -> Option<Self> {
        let formula = formula.trim();
        if formula.contains('[') {
            return None;
        }
        let (sheet, area) = formula.rsplit_once('!')?;
        let sheet = match sheet.strip_prefix('\'') {
            Some(quoted) => quoted.strip_suffix('\'')?.replace("''", "'"),
            None => sheet.to_owned(),
        };
        let (from, to) = area.split_once(':').unwrap_or((area, area));
        let (from, to) = (parse_a1(from)?, parse_a1(to)?);
        let first = (from.0.min(to.0), from.1.min(to.1));
        let last = (from.0.max(to.0), from.1.max(to.1));
        (!sheet.is_empty()).then_some(Self { sheet, first, last })
    }

    /// The rectangle `lines` on one sheet cover together.
    pub(super) fn around(lines: &[Self]) -> Option<Self> {
        let (head, rest) = lines.split_first()?;
        let mut out = head.clone();
        for line in rest {
            if line.sheet != out.sheet {
                return None;
            }
            out.first = (out.first.0.min(line.first.0), out.first.1.min(line.first.1));
            out.last = (out.last.0.max(line.last.0), out.last.1.max(line.last.1));
        }
        Some(out)
    }

    /// A block's line of cells for each of its `levels` levels, leaf first,
    /// and the way its points run (down a column, `Some(true)`): the levels
    /// stand side by side, the outermost first, when it is `levels` columns
    /// wide (the way a down-column block is written), else stacked when it
    /// is `levels` rows tall; `None` when neither shape fits. One level is
    /// the block itself, running its own way.
    pub(super) fn levels(&self, levels: usize) -> Option<(Vec<Self>, Option<bool>)> {
        if levels <= 1 {
            return Some((vec![self.clone()], self.down()));
        }
        let span = |first: u32, last: u32| usize::try_from(last - first).ok()?.checked_add(1);
        let (width, height) = (
            span(self.first.0, self.last.0)?,
            span(self.first.1, self.last.1)?,
        );
        let down = if width == levels {
            true
        } else if height == levels {
            false
        } else {
            return None;
        };
        let lines = (0..levels)
            .map(|level| {
                let step = u32::try_from(levels - 1 - level).unwrap_or(u32::MAX);
                if down {
                    let col = self.first.0 + step;
                    Self {
                        sheet: self.sheet.clone(),
                        first: (col, self.first.1),
                        last: (col, self.last.1),
                    }
                } else {
                    let row = self.first.1 + step;
                    Self {
                        sheet: self.sheet.clone(),
                        first: (self.first.0, row),
                        last: (self.last.0, row),
                    }
                }
            })
            .collect();
        Some((lines, Some(down)))
    }

    /// The range's first cell alone.
    pub(super) fn head(&self) -> Self {
        Self {
            sheet: self.sheet.clone(),
            first: self.first,
            last: self.first,
        }
    }

    /// Down a column (`Some(true)`) or along a row; `None` for one cell.
    pub(super) fn down(&self) -> Option<bool> {
        (self.first != self.last).then_some(self.first.0 == self.last.0)
    }

    /// The cells in sequence order.
    pub(super) fn keys(&self) -> impl Iterator<Item = Key> + '_ {
        (self.first.1..=self.last.1).flat_map(move |row| {
            (self.first.0..=self.last.0).map(move |col| (self.sheet.clone(), col, row))
        })
    }

    /// `count` cells from the same first cell, down a column or along a
    /// row: `None` for none, refused past the sheet's edge.
    pub(super) fn fit(&self, count: usize, down: bool) -> Result<Option<Self>, RebuildReason> {
        let Some(more) = count.checked_sub(1) else {
            return Ok(None);
        };
        let more = u32::try_from(more).map_err(|_| RebuildReason::NoRoom)?;
        let (col, row) = self.first;
        let last = if down {
            row.checked_add(more).map(|row| (col, row))
        } else {
            col.checked_add(more).map(|col| (col, row))
        };
        match last {
            Some(last) if last.0 <= MAX_COLUMN && last.1 <= MAX_ROW => Ok(Some(Self {
                sheet: self.sheet.clone(),
                first: self.first,
                last,
            })),
            _ => Err(RebuildReason::NoRoom),
        }
    }

    /// The range `by` columns to the right (for a series down a column) or
    /// rows below (along a row); `None` past the sheet's edge.
    pub(super) fn shifted(&self, by: u32, down: bool) -> Option<Self> {
        let step = |(col, row): (u32, u32)| {
            let at = if down {
                (col.checked_add(by)?, row)
            } else {
                (col, row.checked_add(by)?)
            };
            (at.0 <= MAX_COLUMN && at.1 <= MAX_ROW).then_some(at)
        };
        Some(Self {
            sheet: self.sheet.clone(),
            first: step(self.first)?,
            last: step(self.last)?,
        })
    }

    /// The reference as a chart writes it: `'Sheet1'!$B$2:$B$5`.
    pub(super) fn formula(&self) -> String {
        let anchored = |(col, row): (u32, u32)| {
            let cell = a1(col, row);
            let split = cell
                .find(|c: char| c.is_ascii_digit())
                .unwrap_or(cell.len());
            format!("${}${}", &cell[..split], &cell[split..])
        };
        let sheet = format!("'{}'", self.sheet.replace('\'', "''"));
        if self.first == self.last {
            format!("{sheet}!{}", anchored(self.first))
        } else {
            format!("{sheet}!{}:{}", anchored(self.first), anchored(self.last))
        }
    }
}
