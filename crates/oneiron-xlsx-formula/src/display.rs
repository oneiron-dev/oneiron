//! A cell as a person sees it in Excel: its stored value (a formula's cached
//! result) under its number format, rendered as `TEXT` renders it in en-US,
//! the fork's documented contract. Every host renders a cell the same way.

use formualizer_common::DateSystem;
use oneiron_docedit::xlsx_body::{XlsxBook, XlsxCell, XlsxValue};

/// The format of a cell with no style, or one Excel cannot read.
const GENERAL: &str = "General";

/// The text `cell` shows in `book`. A number shows under its style's format
/// code: the workbook's own, else the code en-US Excel reads for the
/// style's id, else General; a code Excel cannot read shows it as General.
/// Text shows under the code's text section, a boolean as `TRUE` or `FALSE`,
/// an error as its code.
#[must_use]
pub fn cell_display_text(book: &XlsxBook, cell: &XlsxCell) -> String {
    let code = cell
        .style
        .and_then(|index| book.styles.get(usize::try_from(index).ok()?))
        .map_or(GENERAL, |style| {
            style.format.as_deref().unwrap_or_else(|| {
                u16::try_from(style.num_fmt)
                    .ok()
                    .and_then(formualizer_workbook::number_format_code)
                    .unwrap_or(GENERAL)
            })
        });
    let system = if book.date1904 {
        DateSystem::Excel1904
    } else {
        DateSystem::Excel1900
    };
    match &cell.value {
        XlsxValue::Blank => String::new(),
        XlsxValue::Bool(true) => "TRUE".to_owned(),
        XlsxValue::Bool(false) => "FALSE".to_owned(),
        XlsxValue::Error(error) => error.clone(),
        XlsxValue::Text(text) => {
            formualizer_eval::format_text(text, code).unwrap_or_else(|_| text.clone())
        }
        XlsxValue::Number(number) => formualizer_eval::format_number(*number, code, system)
            .or_else(|_| formualizer_eval::format_number(*number, GENERAL, system))
            .unwrap_or_else(|_| number.to_string()),
    }
}
