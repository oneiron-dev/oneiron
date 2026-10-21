//! A rewritten chart's rebuilt workbook (OF-510, FIX 3493): the dataset
//! its one sheet holds, and the references each series writes into it.

use super::SHEET;
use super::layout::{Data, Wanted};
use crate::design_plan::{Cell, Column, ColumnKind, Dataset};

fn letters(mut col: u32) -> String {
    let mut out = Vec::new();
    while col > 0 {
        out.push(b'A' + ((col - 1) % 26) as u8);
        col = (col - 1) / 26;
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

fn formula(col: u32, first: usize, last: usize) -> String {
    let col = letters(col);
    if first == last {
        format!("'{SHEET}'!${col}${first}")
    } else {
        format!("'{SHEET}'!${col}${first}:${col}${last}")
    }
}

/// The references one rewritten series writes: its name, its categories
/// or x values, its values. `None` writes a literal.
#[derive(Debug, Clone, Default)]
pub(super) struct Refs {
    pub(super) name: Option<String>,
    pub(super) first: Option<String>,
    pub(super) values: Option<String>,
}

impl Refs {
    /// A series' references into a rebuilt workbook: its name in row 1 over
    /// its values column, and its x values column (a scatter series') or
    /// the categories in A.
    pub(super) fn rebuilt(line: &Data, categories: usize) -> Self {
        let first = match (&line.x, line.x_col) {
            (Some(x), Some(col)) => Some(formula(col, 2, x.len() + 1)),
            _ if categories > 0 => Some(formula(1, 2, categories + 1)),
            _ => None,
        };
        Self {
            name: Some(formula(line.y_col, 1, 1)),
            first,
            values: Some(formula(line.y_col, 2, line.values.len() + 1)),
        }
    }
}

/// The rebuilt workbook's one sheet: categories in A, then each series' x
/// column (a scatter series') and values column, under a header row.
pub(super) fn workbook_dataset(categories: &[String], wanted: &Wanted) -> Dataset {
    let Wanted {
        numeric_cats,
        category_cells,
        data,
        ..
    } = wanted;
    let mut columns = Vec::new();
    let mut cells: Vec<Vec<Cell>> = Vec::new();
    let column = |name: String, kind| Column {
        name,
        kind,
        unit: None,
        format: None,
    };
    if !categories.is_empty() {
        let kind = if *numeric_cats {
            ColumnKind::Number
        } else {
            ColumnKind::Text
        };
        columns.push(column(String::new(), kind));
        cells.push(category_cells.to_vec());
    }
    for line in data {
        if let Some(x) = &line.x {
            columns.push(column(format!("{} (x)", line.name), ColumnKind::Number));
            cells.push(x.clone());
        }
        columns.push(column(line.name.clone(), ColumnKind::Number));
        cells.push(line.values.clone());
    }
    let height = cells.iter().map(Vec::len).max().unwrap_or(0);
    let rows: Vec<Vec<Cell>> = (0..height)
        .map(|row| {
            cells
                .iter()
                .map(|col| col.get(row).cloned().unwrap_or(Cell::Missing))
                .collect()
        })
        .collect();
    Dataset {
        id: String::new(),
        columns,
        rows,
        missing: None,
        sources: Vec::new(),
        merges: Vec::new(),
    }
}
