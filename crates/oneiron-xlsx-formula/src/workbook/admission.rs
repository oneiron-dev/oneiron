//! Admitting a workbook's formulas for native recalculation
//! (`Formulas::admit`): what the engine must not evaluate itself is refused
//! before it runs. Also the location Excel last saved in the workbook's
//! CELL("filename") caches (`Formulas::saved_location`).

use std::collections::BTreeSet;

use super::Formulas;
use crate::Result;
use crate::links::LinkedBooks;
use crate::location::DocumentLocation;
use crate::xml::unsupported;

impl Formulas {
    /// The location Excel last calculated the workbook in, from its cached
    /// CELL("filename") values (`C:\Reports\[Budget.xlsx]Sheet1`): `None`
    /// unless there is one, each names a folder, a file and one of the
    /// workbook's sheets, and they agree. Called once `admit` has bounded
    /// every formula.
    pub(super) fn saved_location(&self) -> Result<Option<DocumentLocation>> {
        let mut found = None;
        for (formula, texts) in &self.filename_caches {
            if !crate::context::cell_filename(&crate::context::parse_bounded(formula)?) {
                continue;
            }
            for text in texts {
                let Some(location) = text
                    .as_deref()
                    .and_then(|text| saved_filename(text, &self.sheet_names))
                else {
                    return Ok(None);
                };
                if found.as_ref().is_some_and(|found| *found != location) {
                    return Ok(None);
                }
                found = Some(location);
            }
        }
        Ok(found)
    }

    /// Whether the workbook names `name`: a defined name or a table.
    fn defines(&self, name: &str) -> bool {
        self.names
            .iter()
            .any(|defined| defined.name.eq_ignore_ascii_case(name))
            || self.tables.contains(&name.to_lowercase())
    }

    /// Refuse what the engine must not evaluate natively, before it runs, and
    /// say why a formula reads the file's location, if one does.
    pub(super) fn admit(&self, links: &LinkedBooks) -> Result<Option<&'static str>> {
        if let Some(reason) = &self.refusal {
            return Err(unsupported(reason.clone()));
        }
        let cells = self
            .sheets
            .values()
            .flatten()
            .map(|formula| (formula, None));
        let names = self
            .names
            .iter()
            .map(|name| (&name.formula, Some(name.name.as_str())));
        let mut reads_location = None;
        // The engine reads `[0]!Rate` as `Rate`: on a sheet with its own
        // `Rate` that is the sheet's, where Excel reads the workbook's.
        let sheet_level: BTreeSet<String> = self
            .names
            .iter()
            .filter(|name| name.sheet_level)
            .map(|name| name.name.to_lowercase())
            .collect();
        for (formula, defined) in cells.chain(names) {
            let inspection = crate::context::inspect_formula(formula)?;
            if let Some(name) = crate::links::workbook_qualified_names(formula)
                .into_iter()
                .find(|name| sheet_level.contains(&name.to_lowercase()))
            {
                return Err(unsupported(format!(
                    "workbook-qualified name with a sheet-level definition ([0]!{name})"
                )));
            }
            if let Some(need) = inspection.host_context {
                return Err(unsupported(format!("formula needs host context: {need}")));
            }
            reads_location = reads_location.or(inspection.location);
            // The engine does not resolve a workbook name to its LAMBDA yet:
            // MAP over one, or a call of one, would cache #NAME?.
            if let Some(name) = defined
                && inspection.lambda
            {
                return Err(unsupported(format!("defined name holds a LAMBDA: {name}")));
            }
            // The engine evaluates a call it does not resolve to #NAME?, and
            // so does Excel for a name outside its function list as the file
            // spells it (IMAGE without `_xlfn.`, EOM, a Google Sheets export's
            // __xludf.DUMMYFUNCTION): an undefined name. Such a call stays
            // native unless something Excel would call defines the name: the
            // workbook (a defined name or a table) or a linked workbook
            // (`[1]!Fn`), Excel itself, an XLL add-in or the workbook's VBA
            // project.
            let unknown = &inspection.unknown_functions;
            let defined = unknown
                .iter()
                .find(|function| self.defines(function) || function.contains('!'));
            if let Some(name) = inspection
                .callable_name
                .as_deref()
                .or(defined.map(String::as_str))
            {
                return Err(unsupported(format!("name used as a function: {name}")));
            }
            if let Some(name) = unknown.iter().find(|function| excel_function(function)) {
                return Err(unsupported(format!(
                    "function the engine does not implement: {name}"
                )));
            }
            if let Some(name) = unknown.iter().find(|function| prefixed(function, "_xll.")) {
                return Err(unsupported(format!("XLL add-in function: {name}")));
            }
            if self.vba_project
                && let Some(name) = unknown.first()
            {
                return Err(unsupported(format!(
                    "function the workbook's VBA project may define: {name}"
                )));
            }
        }
        // Every formula is bounded now. A linked workbook is written `[1]`, a
        // file name `[Book.xlsx]` and a linked name `[1]!Rate`, so only a
        // formula with `[`, or one using a workbook name that reads such a
        // reference (itself or through another name), reads another workbook.
        let mut parsed = Vec::new();
        for name in &self.names {
            parsed.push((
                name.name.as_str(),
                crate::context::parse_bounded(&name.formula)?,
            ));
        }
        let linked = links.names(parsed.iter().map(|(name, formula)| (*name, formula)));
        let reads_a_link = |formula: &str| {
            formula.contains('[') || {
                let upper = formula.to_ascii_uppercase();
                linked.keys().any(|name| upper.contains(name.as_str()))
            }
        };
        for formula in self.sheets.values().flatten() {
            if reads_a_link(formula) {
                links.admit(&crate::context::parse_bounded(formula)?, &linked)?;
            }
        }
        for name in &self.names {
            if reads_a_link(&name.formula) {
                links.admit_name(&crate::context::parse_bounded(&name.formula)?, &linked)?;
            }
        }
        Ok(reads_location)
    }
}

/// Whether `name`, as the file spells it, is one of Excel's functions: a bare
/// name of the Excel 2007 file format, one written `_xlfn.` or `_xlws.`, one
/// passed by name (Excel writes `_xleta.` only for its own functions), or an
/// Excel 4.0 macro function, which a defined name may call
/// (`GET.WORKBOOK(1)`, `EVALUATE(...)`; Excel runs them as macros).
fn excel_function(name: &str) -> bool {
    formualizer_workbook::is_excel_function(name)
        || prefixed(name, "_xleta.")
        || prefixed(name, "GET.")
        || EXCEL_BARE
            .iter()
            .any(|known| known.eq_ignore_ascii_case(name))
}

/// Excel's functions a file names without a prefix that the fork's Excel 2007
/// list (`is_excel_function`) lacks, from the BIFF function tables of
/// LibreOffice's OOXML filter and Apache POI: DBCS (the stored name of JIS),
/// USDOLLAR and YEN (older names of DOLLAR), DATESTRING and NUMBERSTRING, the
/// Thai functions and the Euro tool's EUROCONVERT, then the Excel 4.0 macro
/// functions besides the `GET.` ones.
const EXCEL_BARE: &[&str] = &[
    "DATESTRING",
    "DBCS",
    "EUROCONVERT",
    "ISTHAIDIGIT",
    "NUMBERSTRING",
    "ROUNDBAHTDOWN",
    "ROUNDBAHTUP",
    "THAIDAYOFWEEK",
    "THAIDIGIT",
    "THAIMONTHOFYEAR",
    "THAINUMSOUND",
    "THAINUMSTRING",
    "THAISTRINGLENGTH",
    "THAIYEAR",
    "USDOLLAR",
    "YEN",
    "ABSREF",
    "ACTIVE.CELL",
    "APP.TITLE",
    "ARGUMENT",
    "CALL",
    "CALLER",
    "DEREF",
    "DIRECTORY",
    "DOCUMENTS",
    "ENABLE.TOOL",
    "END.IF",
    "ERROR",
    "EVALUATE",
    "EXEC",
    "FILES",
    "FORMULA.CONVERT",
    "GOTO",
    "LAST.ERROR",
    "LINKS",
    "NAMES",
    "PRESS.TOOL",
    "REFTEXT",
    "REGISTER",
    "REGISTER.ID",
    "RELREF",
    "RETURN",
    "SAVE.TOOLBAR",
    "SELECTION",
    "STEP",
    "TEXTREF",
    "WINDOW.TITLE",
    "WINDOWS",
];

fn prefixed(name: &str, prefix: &str) -> bool {
    crate::context::strip_prefix(name, prefix).is_some()
}

/// The location a cached CELL("filename") text names, `folder[file]sheet`
/// with `sheet` one of `sheets`: a sheet's and a file's name hold no bracket,
/// though a folder may.
fn saved_filename(text: &str, sheets: &[String]) -> Option<DocumentLocation> {
    let close = text.rfind(']')?;
    let open = text[..close].rfind('[')?;
    let sheet = &text[close + 1..];
    if !sheets.iter().any(|name| name == sheet) {
        return None;
    }
    DocumentLocation::new(&text[..open], &text[open + 1..close])
}
