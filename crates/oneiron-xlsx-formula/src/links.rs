//! Linked workbooks: the external references the engine reads exactly as
//! Excel for Windows reads them with the linked workbook closed.
//!
//! A formula names a linked workbook by its place in the workbook's
//! `<externalReferences>` list (`[1]Sheet!A1`), and that link's part
//! (`xl/externalLinks/externalLinkN.xml`) keeps the values Excel last read
//! from it. With the linked workbook closed, Excel computes from those saved
//! values, and so does the fork (0.9.3-oneiron.9): a saved cell is its value,
//! a cell not saved is blank, a sheet the link does not name is `#REF!`, and
//! on a sheet Excel could not read at its last refresh (`refreshError`), or
//! saved nothing for, every cell not saved is `#REF!`. Since 0.9.3-oneiron.12
//! a linked range a function returns (INDEX at a computed row) intersects a
//! legacy formula's cell as a written one does, and `[0]` is the workbook
//! itself (`[0]!Rate` is its own `Rate`), which the fork reads as the local
//! name or reference. Probes 1 to 5 of the fork's
//! `ops/excel-extlinks-probe-20261006.md`, the links2 probe of
//! `ops/excel-links2-probe-20261008.md` (Excel for Windows 16.0.20430) and
//! the SpreadsheetBench workbooks with links are the evidence. Recalculating
//! natively keeps every link part and relationship byte for byte.
//!
//! What the fork cannot compute as Excel does keeps the fallback, each with its
//! own reason: a DDE or OLE link, a link part the check cannot read, an
//! external relationship other than a hyperlink, a link's path or a pivot
//! cache's source, a link list or link content type the edit gate cannot
//! join, link markup the fork's reader would read where Excel reads none, an
//! escape in a link's sheet names or saved values, a reference by file name
//! or to a link the list does not hold, a defined name of a linked workbook
//! (`[1]!Rate`), a 3D linked reference, a linked reference in a reference
//! operator, a multi-cell linked range passed on as a reference
//! (`reads_a_range`), one INDEX position into what another function or a
//! name hands on (`hands_on_a_link`), a linked reference reaching a criteria
//! function through
//! another function or a name, or reaching a function that reads references
//! through one that passes it on as values (`passed_on`), one bound to a LET
//! or LAMBDA name, and an open or very large linked range unless the function
//! reading it gives Excel's result from the cells up to the last saved one
//! (`reads_past_saved_values`). A workbook name over a linked workbook is
//! checked where each formula uses it, as if written there; one with a
//! relative linked reference anywhere in its formula falls back wherever it
//! is used, as the fork reads every name's formula at A1 where Excel moves
//! the reference with the cell using it. `[0]!Rate` falls back where the
//! workbook defines `Rate` for a sheet too (`workbook_qualified_names`): the
//! fork reads it as `Rate`, the sheet's own, where Excel reads the
//! workbook's. A link part that is not XML is
//! malformed workbook content, refused outright (`InvalidWorkbook`).

use std::collections::{BTreeMap, BTreeSet};

use formualizer_parse::parser::{
    ASTNode, ASTNodeType, ExternalRefKind, ExternalReference, ReferenceType,
};

use crate::Result;
use crate::xml::unsupported;

pub(crate) use parts::external_targets;

mod admission;
mod parts;

/// The fork reads at most this many cells of a linked range, and crops a
/// larger one at the last saved cell (`external_book_rows`).
const MAX_LINKED_CELLS: u64 = 4_000_000;

/// The workbook's links, in `<externalReferences>` order (`[1]` first).
#[derive(Debug, Default)]
pub(crate) struct LinkedBooks {
    books: Vec<LinkedBook>,
}

#[derive(Debug)]
struct LinkedBook {
    /// Sheet names, lowercased, with whether a cell the link did not save is
    /// `#REF!` (a refresh error, or no saved values for the sheet).
    sheets: Vec<(String, bool)>,
}

/// A name of a linked workbook written with its book: `[1]!Rate` is the
/// linked workbook's `Rate`. The fork reads `[0]!Rate`, the workbook's own,
/// as `Rate`.
fn linked_workbook_name(name: &str) -> Result<()> {
    if linked_name(name) {
        Err(unsupported(
            "external reference to a defined name of a linked workbook",
        ))
    } else {
        Ok(())
    }
}

/// What a workbook name that reads a linked workbook holds.
#[derive(Debug)]
pub(crate) enum LinkedName {
    /// One absolute linked reference, read as that reference.
    Reference(ExternalReference),
    /// Any other formula over a linked workbook, its linked references all
    /// absolute. It may return a linked reference (`IF(TRUE,[1]S!$A$3)`), so
    /// each use is checked as if the formula were written there.
    Expression(ASTNode),
    /// A formula with a relative linked reference anywhere in it
    /// (`IF(TRUE,[1]S!$A3)`), which Excel moves with the cell using the name
    /// and the fork reads at A1, or a name defined more than once.
    Unclear,
}

/// Whether every bound a linked reference writes is absolute (`$A$1:$B$9`,
/// `$A:$A`).
fn absolute(kind: ExternalRefKind) -> bool {
    match kind {
        ExternalRefKind::Cell {
            row_abs, col_abs, ..
        } => row_abs && col_abs,
        ExternalRefKind::Range {
            start_row,
            start_col,
            end_row,
            end_col,
            start_row_abs,
            start_col_abs,
            end_row_abs,
            end_col_abs,
        } => {
            (start_row.is_none() || start_row_abs)
                && (start_col.is_none() || start_col_abs)
                && (end_row.is_none() || end_row_abs)
                && (end_col.is_none() || end_col_abs)
        }
    }
}

/// Whether `node` holds a linked reference with a relative bound.
fn relative_link(node: &ASTNode) -> bool {
    match &node.node_type {
        ASTNodeType::Reference {
            reference: ReferenceType::External(external),
            ..
        } => !absolute(external.kind),
        ASTNodeType::Reference { .. } | ASTNodeType::Literal(_) | ASTNodeType::Omitted => false,
        ASTNodeType::UnaryOp { expr, .. } => relative_link(expr),
        ASTNodeType::BinaryOp { left, right, .. } => relative_link(left) || relative_link(right),
        ASTNodeType::Function { args, .. } => args.iter().any(relative_link),
        ASTNodeType::Call { callee, args } => {
            relative_link(callee) || args.iter().any(relative_link)
        }
        ASTNodeType::Array(rows) => rows.iter().flatten().any(relative_link),
    }
}

/// Whether `node` reads a linked workbook: an external reference, or a name
/// of `names`.
fn mentions_link(node: &ASTNode, names: &BTreeMap<String, LinkedName>) -> bool {
    match &node.node_type {
        ASTNodeType::Reference { reference, .. } => match reference {
            ReferenceType::External(_) => true,
            ReferenceType::NamedRange(name) => {
                linked_name(name) || names.contains_key(&name_key(name))
            }
            _ => false,
        },
        ASTNodeType::Literal(_) | ASTNodeType::Omitted => false,
        ASTNodeType::UnaryOp { expr, .. } => mentions_link(expr, names),
        ASTNodeType::BinaryOp { left, right, .. } => {
            mentions_link(left, names) || mentions_link(right, names)
        }
        ASTNodeType::Function { args, .. } => args.iter().any(|arg| mentions_link(arg, names)),
        ASTNodeType::Call { callee, args } => {
            mentions_link(callee, names) || args.iter().any(|arg| mentions_link(arg, names))
        }
        ASTNodeType::Array(rows) => rows.iter().flatten().any(|arg| mentions_link(arg, names)),
    }
}

/// Collect the workbook names `node` uses, as `names` keys them.
fn used_names(node: &ASTNode, used: &mut BTreeSet<String>) {
    match &node.node_type {
        ASTNodeType::Reference {
            reference: ReferenceType::NamedRange(name),
            ..
        } if !linked_name(name) => {
            used.insert(name_key(name));
        }
        ASTNodeType::Reference { .. } | ASTNodeType::Literal(_) | ASTNodeType::Omitted => {}
        ASTNodeType::UnaryOp { expr, .. } => used_names(expr, used),
        ASTNodeType::BinaryOp { left, right, .. } => {
            used_names(left, used);
            used_names(right, used);
        }
        ASTNodeType::Function { args, .. } => args.iter().for_each(|arg| used_names(arg, used)),
        ASTNodeType::Call { callee, args } => {
            used_names(callee, used);
            args.iter().for_each(|arg| used_names(arg, used));
        }
        ASTNodeType::Array(rows) => rows.iter().flatten().for_each(|arg| used_names(arg, used)),
    }
}

/// A workbook name as `names` keys it: upper case, without the sheet a
/// formula may qualify it with (`Sheet1!Rate`).
fn name_key(name: &str) -> String {
    name.rsplit_once('!')
        .map_or(name, |(_, name)| name)
        .to_ascii_uppercase()
}

/// A function's name without its storage prefixes (`_xlfn.RANK.EQ` is
/// `RANK.EQ`), upper case.
fn bare_name(name: &str) -> String {
    let mut name = name;
    while let Some((prefix, rest)) = name.split_once('.')
        && prefix.starts_with('_')
    {
        name = rest;
    }
    name.to_ascii_uppercase()
}

/// Where a reference sits in its formula.
enum Parent<'a> {
    Root,
    /// An operand of an operator (`""` for a unary one, a call or an array).
    Operator(&'a str),
    /// An argument of a function, by its bare upper-case name. `reference`:
    /// a function that reads references reads it (`reads_reference`),
    /// directly or through the range of an INDEX it is given.
    Argument {
        function: String,
        index: usize,
        args: &'a [ASTNode],
        reference: bool,
    },
}

/// Whether `parent` reads a range of a closed linked workbook as Excel does:
/// as a value (an operand, or an argument the function reads as values),
/// never as a reference passed on. The fork holds a linked range as values,
/// so a function that returns references (IF, CHOOSE, IFS, XLOOKUP, OFFSET,
/// INDIRECT, LET) would pass on what Excel passes on as a reference; and a
/// range as the whole formula, or where Excel needs a reference (AREAS, RANK,
/// GETPIVOTDATA), is left to the fallback too. INDEX hands on the reference
/// it selects, which a legacy formula intersects with its cell as Excel does
/// (probe links2: `INDEX([1]S!A1:A5,SMALL({0,1},1))*2` in row 3 is 2*A3), at
/// any row or column it computes in a range the fork reads whole; in one
/// read only up to its last saved cell, or one INDEX turns into such a range
/// by selecting all of its rows or columns (`opens`), only a position that is
/// never 0 keeps it to one cell. With one position, the range must be one
/// row or column: `INDEX([1]S!A1:B5,3)` is #REF! in Excel, its third row in
/// the fork.
fn reads_a_range(parent: &Parent<'_>, kind: ExternalRefKind) -> bool {
    match parent {
        Parent::Root => false,
        // `""` is a call or an array literal.
        Parent::Operator(op) => !op.is_empty(),
        Parent::Argument {
            function,
            index,
            args,
            ..
        } => match (function.as_str(), *index) {
            // One position selects within a single column or row only.
            ("INDEX", 0) => match args.len() {
                2 => one_line(kind) && (!opens(kind) || row_or_column(&args[1])),
                3 => !opens(kind) || (row_or_column(&args[1]) && row_or_column(&args[2])),
                _ => false,
            },
            ("AREAS" | "RANK" | "RANK.EQ" | "RANK.AVG" | "GETPIVOTDATA" | "LET" | "LAMBDA", _) => {
                false
            }
            (name, _) => !returns_reference(name),
        },
    }
}

/// Whether the function reading a range at `parent` gives Excel's result
/// although only the cells up to the last saved one are read, plus one
/// `#REF!` on a sheet whose unsaved cells are `#REF!` (`unsaved_is_error`).
/// Excel reads every cell of the range. INDEX at a row it is told (one cell),
/// ROWS and COLUMNS go by the range as written, exact MATCH, VLOOKUP and
/// HLOOKUP skip errors and blanks, the sums and extremes return the first
/// error, COUNT ignores errors and blanks, and the criteria functions refuse
/// any closed linked range (`#VALUE!`). Where the unsaved cells are blank,
/// COUNTA gives the same count too. An approximate VLOOKUP, HLOOKUP or MATCH
/// (match type 1) bisects the range as written, 1,048,576 rows for `A:A`,
/// skipping blanks and errors, so the unsaved cells past the last saved one
/// lead its probes as they do the fork's (probe links2: on unsorted data
/// `VLOOKUP(165,[1]S!$A:$B,2,TRUE)` is the last row, and so is the
/// SpreadsheetBench `VLOOKUP(A173,[1]Sort!$C:$Z,11,TRUE)`, saved or refresh
/// error). Anything that counts the unsaved cells (ISBLANK or ISERROR over
/// the range), pairs the range with another of another length, returns its
/// rows (ROW over an open range), reads a result past the saved cells
/// (LOOKUP, blank in the fork where a refresh-error sheet is #REF!), or
/// searches descending (`MATCH(3,[1]S!A:A,-1)` over 1 to 5 is #N/A in Excel,
/// 5 in the fork, as for a local range) stays the fallback's.
fn reads_past_saved_values(parent: &Parent<'_>, unsaved_is_error: bool) -> bool {
    let Parent::Argument {
        function,
        index,
        args,
        ..
    } = parent
    else {
        return false;
    };
    let arg = |at: usize| args.get(at);
    match (function.as_str(), *index) {
        ("INDEX", 0) | ("ROWS" | "COLUMNS", 0) => true,
        // Exact (0) or approximate (1, the default).
        ("MATCH", 1) => {
            literal(arg(2)).is_none_or(|mode| mode.is_none_or(|mode| matches!(mode, 0.0 | 1.0)))
        }
        // Exact or approximate, whatever the range_lookup.
        ("VLOOKUP" | "HLOOKUP", 1) => true,
        ("COUNTA", _) => !unsaved_is_error,
        ("SUM" | "AVERAGE" | "MIN" | "MAX" | "PRODUCT" | "COUNT" | "CONCAT", _) => true,
        _ => criteria_range(parent),
    }
}

/// A range parameter of a criteria function (SUMIF, COUNTIFS, ...), which
/// Excel refuses for a closed linked workbook (`#VALUE!`).
fn criteria_range(parent: &Parent<'_>) -> bool {
    let Parent::Argument {
        function, index, ..
    } = parent
    else {
        return false;
    };
    match (function.as_str(), *index) {
        ("SUMIF" | "AVERAGEIF", 0 | 2) | ("COUNTIF" | "COUNTBLANK", 0) => true,
        ("COUNTIFS", at) => at % 2 == 0,
        ("SUMIFS" | "AVERAGEIFS" | "MAXIFS" | "MINIFS", at) => at % 2 == 1 || at == 0,
        _ => false,
    }
}

/// Refuse a linked reference that reaches a parameter Excel reads as a
/// reference through what the fork passes on as values. A criteria function
/// is #VALUE! for a closed linked range however it arrives, through INDEX,
/// IF, CHOOSE or a name (probes: `SUMIF(INDEX([1]Ok!A1:A5,0),">0")`), and
/// for one cell too, where the fork computes all but the one written in it
/// (`SUMIF(INDEX([1]S!A1:A5,3),">0")` is 3). A function that reads references
/// (`reads_reference`) sees the reference INDEX selects in the fork, but what
/// IF, CHOOSE or another function passes on only as values: ROW of
/// `IF(TRUE,[1]S!A3)`, or of a name holding it, is #VALUE! where Excel gives 3.
fn passed_on(
    node: &ASTNode,
    parent: &Parent<'_>,
    names: &BTreeMap<String, LinkedName>,
) -> Result<()> {
    let Parent::Argument { reference, .. } = parent else {
        return Ok(());
    };
    if matches!(node.node_type, ASTNodeType::Reference { .. }) || !mentions_link(node, names) {
        return Ok(());
    }
    if reads_linked_location(parent) {
        return Err(unsupported(LINKED_LOCATION));
    }
    if criteria_range(parent) {
        return Err(unsupported(
            "external reference reaching a criteria function through another function",
        ));
    }
    if *reference && passes_on_values(node) {
        return Err(unsupported(
            "external reference passed on by a function to one that reads references",
        ));
    }
    Ok(())
}

/// CELL("filename") and CELL("address") of a linked workbook's cell name that
/// workbook's file, whose location the engine does not read.
const LINKED_LOCATION: &str = "CELL(\"filename\") or CELL(\"address\") of a linked workbook's cell reads that workbook's location";

/// Whether `parent` is the reference of CELL("filename") or CELL("address").
fn reads_linked_location(parent: &Parent<'_>) -> bool {
    matches!(
        parent,
        Parent::Argument { function, index: 1, args, .. }
            if function == "CELL"
                && matches!(
                    &args[0].node_type,
                    ASTNodeType::Literal(formualizer_common::LiteralValue::Text(info))
                        if info.eq_ignore_ascii_case("filename")
                            || info.eq_ignore_ascii_case("address")
                )
    )
}

/// The fork binds a LET name or LAMBDA parameter to a linked reference's
/// values, where Excel binds the reference: `LET(x,[1]S!A3,ROW(x))` is
/// #VALUE! in the fork and 3 in Excel.
const BOUND: &str = "external reference bound to a LET or LAMBDA name";

/// Whether `function` binds a linked reference of `args` to a name: a LET
/// value, or an array MAP, REDUCE, SCAN, BYROW or BYCOL hands its LAMBDA.
fn binds_a_link(function: &str, args: &[ASTNode], names: &BTreeMap<String, LinkedName>) -> bool {
    let lambda = |arg: &ASTNode| matches!(&arg.node_type, ASTNodeType::Function { name, .. } if bare_name(name) == "LAMBDA");
    match function {
        "LET" => args
            .iter()
            .enumerate()
            .any(|(at, arg)| at % 2 == 1 && at + 1 < args.len() && mentions_link(arg, names)),
        "MAP" | "REDUCE" | "SCAN" | "BYROW" | "BYCOL" => args
            .iter()
            .any(|arg| !lambda(arg) && mentions_link(arg, names)),
        _ => false,
    }
}

/// The functions that read an argument as a reference, not its values.
fn reads_reference(function: &str) -> bool {
    matches!(
        function,
        "ROW"
            | "COLUMN"
            | "ROWS"
            | "COLUMNS"
            | "ISREF"
            | "AREAS"
            | "ISFORMULA"
            | "FORMULATEXT"
            | "SHEET"
            | "SHEETS"
    )
}

/// Whether `node` may hand on a linked reference without being one: a call
/// that may return a reference over a linked workbook, or a name holding an
/// expression over one.
fn hands_on_a_link(node: &ASTNode, names: &BTreeMap<String, LinkedName>) -> bool {
    match &node.node_type {
        ASTNodeType::Function { name, .. } => returns_reference(name) && mentions_link(node, names),
        ASTNodeType::Reference {
            reference: ReferenceType::NamedRange(name),
            ..
        } => matches!(
            names.get(&name_key(name)),
            Some(LinkedName::Expression(_) | LinkedName::Unclear)
        ),
        _ => false,
    }
}

/// The names a formula qualifies with the workbook itself (`[0]!Rate`, or
/// `'[0]'!Rate`, which Excel saves back as `[0]!Rate`), outside its strings
/// and quoted sheet names. The fork reads `[0]!Rate` as `Rate`, which a
/// formula on a sheet with its own `Rate` reads as that one, where Excel reads
/// the workbook's (and, with none, one sheet's).
pub(crate) fn workbook_qualified_names(formula: &str) -> Vec<&str> {
    let bytes = formula.as_bytes();
    let mut found = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if let Some(qualifier) = ["[0]!", "'[0]'!"]
            .into_iter()
            .find(|qualifier| bytes[at..].starts_with(qualifier.as_bytes()))
        {
            let start = at + qualifier.len();
            let end = formula[start..]
                .find(|c: char| !(c.is_alphanumeric() || matches!(c, '_' | '.' | '\\' | '?')))
                .map_or(formula.len(), |length| start + length);
            found.push(&formula[start..end]);
            at = end.max(start);
            continue;
        }
        match bytes[at] {
            quote @ (b'"' | b'\'') => {
                // A doubled quote stands for one inside the quotes.
                at += 1;
                while at < bytes.len() {
                    if bytes[at] == quote {
                        if bytes.get(at + 1) == Some(&quote) {
                            at += 2;
                            continue;
                        }
                        break;
                    }
                    at += 1;
                }
                at += 1;
            }
            _ => at += 1,
        }
    }
    found
}

/// A call other than INDEX (which selects a linked reference itself) that
/// may return a reference, and returns a linked one as values in the fork.
fn passes_on_values(node: &ASTNode) -> bool {
    match &node.node_type {
        ASTNodeType::Function { name, .. } => bare_name(name) != "INDEX" && returns_reference(name),
        _ => false,
    }
}

/// Whether the engine's function `name` may return a reference (IF, CHOOSE,
/// IFS, INDEX, XLOOKUP, OFFSET, INDIRECT), after its storage prefix.
fn returns_reference(name: &str) -> bool {
    formualizer_workbook::ensure_builtins_loaded();
    formualizer_eval::function_registry::get("", name).is_some_and(|function| {
        function
            .caps()
            .contains(formualizer_eval::function::FnCaps::RETURNS_REFERENCE)
    })
}

/// An INDEX row or column that is a position, never 0 (a whole column or
/// row): a literal of at least 1, or a MATCH or XMATCH.
fn row_or_column(node: &ASTNode) -> bool {
    match &node.node_type {
        ASTNodeType::Function { name, .. } => {
            matches!(bare_name(name).as_str(), "MATCH" | "XMATCH")
        }
        _ => number(node).is_some_and(|value| value >= 1.0),
    }
}

/// The number a literal argument holds (`FALSE` is 0, `TRUE` 1, `-1` a
/// negated literal): `None` when the argument is absent, `Some(None)` when
/// omitted, and `Some(Some(NaN))` for anything computed, which matches no
/// allowed mode.
fn literal(node: Option<&ASTNode>) -> Option<Option<f64>> {
    let node = node?;
    Some(match &node.node_type {
        ASTNodeType::Omitted => None,
        _ => Some(number(node).unwrap_or(f64::NAN)),
    })
}

fn number(node: &ASTNode) -> Option<f64> {
    use formualizer_common::LiteralValue;
    match &node.node_type {
        ASTNodeType::Literal(LiteralValue::Number(value)) => Some(*value),
        ASTNodeType::Literal(LiteralValue::Int(value)) => Some(*value as f64),
        ASTNodeType::Literal(LiteralValue::Boolean(value)) => Some(f64::from(u8::from(*value))),
        ASTNodeType::UnaryOp { op, expr } if op == "-" => number(expr).map(|value| -value),
        ASTNodeType::UnaryOp { op, expr } if op == "+" => number(expr),
        _ => None,
    }
}

/// A range the fork reads only up to the last saved cell: an open end (`A:A`,
/// `1:1`) or more cells than it reads whole.
fn cropped(kind: ExternalRefKind) -> bool {
    match kind {
        ExternalRefKind::Cell { .. } => false,
        ExternalRefKind::Range {
            start_row,
            start_col,
            end_row,
            end_col,
            ..
        } => match (start_row, start_col, end_row, end_col) {
            (Some(sr), Some(sc), Some(er), Some(ec)) => {
                u64::from(sr.abs_diff(er) + 1) * u64::from(sc.abs_diff(ec) + 1) > MAX_LINKED_CELLS
            }
            _ => true,
        },
    }
}

/// A range the fork reads only up to its last saved cell (`cropped`), or one
/// whose rows or columns reach both edges of the sheet (`$A$1:$A$1048576`),
/// which INDEX hands on as the whole column or row (`A:A`) when it selects
/// them all: `COUNTA(INDEX([1]S!$A$1:$A$1048576,0,1))` is 1048576 in Excel
/// on a sheet Excel could not refresh, and counts the saved cells in the
/// fork.
fn opens(kind: ExternalRefKind) -> bool {
    const ROWS: u32 = 1_048_576;
    const COLUMNS: u32 = 16_384;
    let whole = |start: Option<u32>, end: Option<u32>, last: u32| match (start, end) {
        (Some(a), Some(b)) => a.min(b) == 1 && a.max(b) == last,
        _ => false,
    };
    cropped(kind)
        || matches!(kind, ExternalRefKind::Range {
            start_row,
            start_col,
            end_row,
            end_col,
            ..
        } if whole(start_row, end_row, ROWS) || whole(start_col, end_col, COLUMNS))
}

/// A range of one column or one row (`A:A`, `A1:A9`, `1:1`).
fn one_line(kind: ExternalRefKind) -> bool {
    match kind {
        ExternalRefKind::Cell { .. } => true,
        ExternalRefKind::Range {
            start_row,
            start_col,
            end_row,
            end_col,
            ..
        } => {
            (start_col.is_some() && start_col == end_col)
                || (start_row.is_some() && start_row == end_row)
        }
    }
}

/// A reference to one cell (`A1`, or a range of one cell such as `A1:A1`).
fn one_cell(kind: ExternalRefKind) -> bool {
    match kind {
        ExternalRefKind::Cell { .. } => true,
        ExternalRefKind::Range {
            start_row,
            start_col,
            end_row,
            end_col,
            ..
        } => {
            start_row.is_some()
                && start_row == end_row
                && start_col.is_some()
                && start_col == end_col
        }
    }
}

/// `[n]`, the 1-based place of a link in the workbook's list (the fork reads
/// `[0]`, the workbook itself, as a local reference).
fn link_index(token: &str) -> Option<usize> {
    token
        .trim()
        .strip_prefix('[')?
        .strip_suffix(']')
        .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))?
        .parse()
        .ok()
}

/// `[1]!Rate` or `[1]Sheet1!Rate`: a name defined in a linked workbook (no
/// sheet name holds `[`).
fn linked_name(name: &str) -> bool {
    name.rsplit_once('!')
        .is_some_and(|(book, _)| book.contains('['))
}
