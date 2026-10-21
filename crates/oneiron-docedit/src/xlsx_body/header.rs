//! Renaming a worksheet table's column through its header cell (FIX 6399).
//! A header cell is read-only to a body because the table part names its
//! column too; a rename writes both, and the structured references naming
//! the column follow, as Excel's own header edit does. Every other table
//! header or totals cell stays read-only.
use super::{Book, Result, SML, XlsxChange, XlsxLock, XlsxSheet, XlsxTable, XlsxValue, refused};
use crate::edit::xml::{set_attribute, splice};
use crate::ooxml::XmlTree;
use crate::xlsx_shift::rename_table_column;

/// The change that lets a body write `value` into cell `(col, row)` of
/// worksheet `sheet`, when that cell is a worksheet table's header cell:
/// its column renamed to the same text ([`XlsxChange::RenameColumn`]),
/// paired with the cell's own write. `None` for any other cell or text: a
/// cell outside every table's header row, one another read-only range or a
/// formula holds, a query or XML table's header, a value that is not text,
/// or a name [`column_name_free`] refuses.
#[must_use]
pub fn header_rename(
    sheet: &XlsxSheet,
    col: u32,
    row: u32,
    value: &XlsxValue,
) -> Option<XlsxChange> {
    let XlsxValue::Text(name) = value else {
        return None;
    };
    if sheet
        .locked
        .iter()
        .any(|area| area.contains(col, row) && area.lock != XlsxLock::TableRow)
        || sheet.cells.iter().any(|cell| {
            (cell.col, cell.row) == (col, row)
                && (cell.formula.is_some()
                    || cell.locked.is_some_and(|lock| lock != XlsxLock::TableRow))
        })
    {
        return None;
    }
    let table = sheet.tables.iter().find(|table| {
        table.header_row() == Some(row) && (table.first.0..=table.last.0).contains(&col)
    })?;
    let index = usize::try_from(col - table.first.0).ok()?;
    let column = table.columns.get(index)?;
    column_name_free(table, index, name).then(|| XlsxChange::RenameColumn {
        sheet: sheet.name.clone(),
        table: table.name.clone(),
        column: column.clone(),
        name: name.clone(),
    })
}

/// Whether column `index` of `table` may take `name`: a worksheet table
/// whose columns match its range, and a name that is not blank, holds no
/// control character and no other column of the table has (without case).
fn column_name_free(table: &XlsxTable, index: usize, name: &str) -> bool {
    let lower = name.to_lowercase();
    table.worksheet
        && table.columns.len() == (table.last.0 - table.first.0 + 1) as usize
        && !name.trim().is_empty()
        && !name.chars().any(char::is_control)
        && table
            .columns
            .iter()
            .enumerate()
            .all(|(at, held)| at == index || held.to_lowercase() != lower)
}

impl Book {
    /// Rename column `column` of table `table` on worksheet `sheet` to
    /// `name`: the table part's `tableColumn` name, and each structured
    /// reference to the column in the workbook's formulas, an unqualified
    /// one only in the table's own. The header cell's `(column, row)`,
    /// which the paired cell write fills.
    pub(super) fn rename_column(
        &mut self,
        sheet: &str,
        table: &str,
        column: &str,
        name: &str,
    ) -> Result<(u32, u32)> {
        let part = self
            .worksheets
            .get(sheet)
            .ok_or(refused("no such worksheet"))?
            .clone();
        let lower = table.to_lowercase();
        let held = self
            .tables(&part)?
            .into_iter()
            .find(|held| held.name.to_lowercase() == lower)
            .ok_or(refused("no such table"))?;
        let index = held
            .columns
            .iter()
            .position(|other| other.to_lowercase() == column.to_lowercase())
            .ok_or(refused("no such table column"))?;
        let row = held
            .header_row()
            .ok_or(refused("the table has no header row"))?;
        if !column_name_free(&held, index, name) {
            return Err(refused("not a name the table's column can take"));
        }
        let old = held.columns[index].clone();
        let col =
            held.first.0 + u32::try_from(index).map_err(|_| refused("no such table column"))?;
        for rel in self.package.relationships(&part)? {
            if rel.external || !rel.kind.ends_with("/table") {
                continue;
            }
            let bytes = self
                .package
                .part(&rel.target)?
                .ok_or(refused("a workbook part is missing"))?;
            let tree = XmlTree::parse(&bytes, self.package.limits().xml)?;
            let root = &tree.nodes[0];
            if root
                .attr("displayName")
                .or_else(|| root.attr("name"))
                .is_none_or(|own| own.to_lowercase() != lower)
            {
                continue;
            }
            let (list, _) = tree
                .child(0, SML, "tableColumns")?
                .ok_or(refused("a table has no columns"))?;
            let node = tree
                .children(list)
                .filter(|(_, node)| node.is(SML, "tableColumn"))
                .nth(index)
                .map(|(_, node)| node)
                .ok_or(refused("no such table column"))?;
            let value = splice(&bytes, vec![set_attribute(&bytes, node, "name", name)])
                .map_err(|_| refused("a table could not be rewritten"))?;
            self.package.replace_xml_part(&rel.target, value)?;
            break;
        }
        for home in self.formula_homes()? {
            self.rewrite_formulas(&home.part, &|text: &str, at| {
                let own = home
                    .owner(at)
                    .is_some_and(|own| own.to_lowercase() == lower);
                rename_table_column(text, &held.name, &old, name, own)
            })?;
        }
        Ok((col, row))
    }
}
