//! A chart reference's cells as the workbook edit reads them: a direct
//! one-row or one-column range on one sheet.

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
        (!sheet.is_empty() && (first.0 == last.0 || first.1 == last.1)).then_some(Self {
            sheet,
            first,
            last,
        })
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
