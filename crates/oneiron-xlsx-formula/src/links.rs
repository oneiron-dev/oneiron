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
//! saved nothing for, every cell not saved is `#REF!`. Probes 1 to 5 of the
//! fork's `ops/excel-extlinks-probe-20261006.md` (Excel for Windows
//! 16.0.20430) and the SpreadsheetBench workbooks with links are the
//! evidence. Recalculating natively keeps every link part and relationship
//! byte for byte.
//!
//! What the fork cannot compute as Excel does keeps the fallback, each with its
//! own reason: a DDE or OLE link, a link part the check cannot read, an
//! external relationship other than a hyperlink, a link's path or a pivot
//! cache's source, a link list or link content type the edit gate cannot
//! join, a reference by file name, to `[0]` or to a link the list does not
//! hold, a defined name of a linked workbook (`[1]!Rate`), a 3D linked
//! reference, a linked reference in a reference operator, a multi-cell linked
//! range passed on as a reference (`reads_a_range`) or reaching a criteria
//! function through a name, and an open or very large linked range unless the
//! function reading it gives Excel's result from the cells up to the last
//! saved one (`reads_past_saved_values`).

use std::collections::BTreeMap;

use formualizer_parse::parser::{
    ASTNode, ASTNodeType, ExternalRefKind, ExternalReference, ReferenceType,
};
use oneiron_docedit::retained_opc::Package;

use crate::Result;
use crate::xml::{DOC_REL, MAIN, REL, Xml, unsupported};

/// The fork reads at most this many cells of a linked range, and crops a
/// larger one at the last saved cell (`external_book_rows`).
const MAX_LINKED_CELLS: u64 = 4_000_000;

/// The content type the edit gate requires of a link part.
const LINK_CONTENT_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.spreadsheetml.externalLink+xml";

/// `[0]` is the workbook itself (`[0]!Rate` is its own `Rate`), which the fork
/// does not resolve that way.
const WORKBOOK_ITSELF: &str = "external reference to the workbook itself ([0])";

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

impl LinkedBooks {
    /// Read the workbook's links and its external relationship targets. A
    /// link or target the engine cannot read as Excel does is the fallback's.
    pub(crate) fn read(package: &Package) -> Result<Self> {
        let limits = package.limits().xml;
        for name in package.names().filter(|name| name.ends_with(".rels")) {
            let Some(bytes) = package.part(name)? else {
                continue;
            };
            let xml = Xml::parse(&bytes, limits)
                .map_err(|_| unsupported("relationship part the link check cannot read"))?;
            // A link's path, and a pivot cache's external source, which only
            // a pivot refresh reads, never a recalculation.
            let link_paths = name.starts_with("xl/externalLinks/_rels/")
                || name.starts_with("xl/pivotCache/_rels/");
            for node in xml
                .nodes
                .iter()
                .filter(|node| node.attr("TargetMode") == Some("External"))
            {
                let kind = node
                    .attr("Type")
                    .and_then(|kind| kind.rsplit('/').next())
                    .unwrap_or_default();
                let allowed = kind == "hyperlink"
                    || (link_paths
                        && matches!(
                            kind,
                            "externalLinkPath" | "xlPathMissing" | "externalLinkLongPath"
                        ));
                if !allowed {
                    return Err(unsupported(format!(
                        "external relationship target ({kind})"
                    )));
                }
            }
        }
        let Some(workbook) = package.part("xl/workbook.xml")? else {
            return Ok(Self::default());
        };
        let workbook = Xml::parse(&workbook, limits)
            .map_err(|_| unsupported("external link list the check cannot read"))?;
        let ids: Vec<&str> = workbook
            .nodes
            .iter()
            .filter(|node| node.is(MAIN, "externalReference"))
            .map(|node| node.attr_ns(DOC_REL, "id").unwrap_or_default())
            .collect();
        let rels = match package.part("xl/_rels/workbook.xml.rels")? {
            Some(bytes) => Xml::parse(&bytes, limits)
                .map_err(|_| unsupported("external link list the check cannot read"))?,
            None if ids.is_empty() => return Ok(Self::default()),
            None => return Err(unsupported("external link list the edit gate cannot join")),
        };
        let links = link_relationships(&rels);
        // The edit gate joins every reference to one internal link part.
        if links.len() != ids.len() {
            return Err(unsupported("external link list the edit gate cannot join"));
        }
        let types = ContentTypes::read(package)?;
        let mut books = Vec::with_capacity(ids.len());
        for id in ids {
            let target = links
                .get(id)
                .and_then(|target| target.as_deref())
                .ok_or_else(|| unsupported("external link list the edit gate cannot join"))?;
            let part = package
                .part(target)?
                .ok_or_else(|| unsupported("external link list the edit gate cannot join"))?;
            if types.content_type(target).as_deref() != Some(LINK_CONTENT_TYPE) {
                return Err(unsupported("external link list the edit gate cannot join"));
            }
            books.push(LinkedBook::read(&part, package)?);
        }
        Ok(Self { books })
    }

    /// The defined names (upper case) whose formula reads a linked workbook:
    /// one linked reference, or an expression over linked values.
    pub(crate) fn names<'a>(
        &self,
        names: impl IntoIterator<Item = (&'a str, &'a ASTNode)>,
    ) -> BTreeMap<String, LinkedName> {
        let mut linked = BTreeMap::new();
        for (name, formula) in names {
            if !mentions_link(formula, &BTreeMap::new()) {
                continue;
            }
            let shape = match &formula.node_type {
                // A relative reference in a name moves with the cell using it.
                ASTNodeType::Reference {
                    reference: ReferenceType::External(external),
                    ..
                } if absolute(external.kind) => LinkedName::Reference(external.clone()),
                ASTNodeType::Reference {
                    reference: ReferenceType::External(_),
                    ..
                } => LinkedName::Unclear,
                _ => LinkedName::Expression,
            };
            // A name defined in several scopes may hold any of its formulas.
            linked
                .entry(name.to_ascii_uppercase())
                .and_modify(|known| *known = LinkedName::Unclear)
                .or_insert(shape);
        }
        linked
    }

    /// Admit one formula's external references, or name why they are the
    /// fallback's. `names` are the workbook names that read a linked workbook.
    pub(crate) fn admit(
        &self,
        formula: &ASTNode,
        names: &BTreeMap<String, LinkedName>,
    ) -> Result<()> {
        let mut pending = vec![(formula, Parent::Root)];
        while let Some((node, parent)) = pending.pop() {
            match &node.node_type {
                ASTNodeType::Reference { reference, .. } => {
                    self.reference(reference, &parent, names)?;
                }
                ASTNodeType::Literal(_) | ASTNodeType::Omitted => {}
                ASTNodeType::UnaryOp { op, expr } => pending.push((expr, Parent::Operator(op))),
                ASTNodeType::BinaryOp { op, left, right } => {
                    // The fork has no intersection, union or range of linked
                    // references, however they are reached (`INDEX(...) INDEX(...)`).
                    if matches!(op.as_str(), ":" | " " | ",")
                        && (mentions_link(left, names) || mentions_link(right, names))
                    {
                        return Err(unsupported("external reference in a reference operator"));
                    }
                    pending.push((left, Parent::Operator(op)));
                    pending.push((right, Parent::Operator(op)));
                }
                ASTNodeType::Function { name, args } => {
                    let bare = name.rsplit('.').next().unwrap_or(name).to_ascii_uppercase();
                    // A function that reads its argument as a reference sees a
                    // linked reference that IF, CHOOSE or another function
                    // passed on as values in the fork (`ROW(IF(1,[1]S!A3))`).
                    if reads_reference(&bare) && args.iter().any(|arg| passes_on_a_link(arg, names))
                    {
                        return Err(unsupported(
                            "external reference passed on by a function to one that reads references",
                        ));
                    }
                    for (index, arg) in args.iter().enumerate() {
                        pending.push((
                            arg,
                            Parent::Argument {
                                function: bare.clone(),
                                index,
                                args,
                            },
                        ));
                    }
                }
                ASTNodeType::Call { callee, args } => {
                    pending.push((callee, Parent::Operator("")));
                    pending.extend(args.iter().map(|arg| (arg, Parent::Operator(""))));
                }
                ASTNodeType::Array(rows) => {
                    pending.extend(rows.iter().flatten().map(|arg| (arg, Parent::Operator(""))));
                }
            }
        }
        Ok(())
    }

    fn reference(
        &self,
        reference: &ReferenceType,
        parent: &Parent<'_>,
        names: &BTreeMap<String, LinkedName>,
    ) -> Result<()> {
        match reference {
            ReferenceType::External(external) => self.external(external, parent),
            // A workbook name for a linked reference reads as that reference;
            // one for an expression over linked values is a value.
            ReferenceType::NamedRange(name) => match names.get(&name.to_ascii_uppercase()) {
                Some(LinkedName::Reference(external)) => {
                    // A criteria function refuses a closed linked range written
                    // in it (#VALUE!), which the fork does too, and one a
                    // name holds as well, which the fork computes.
                    if criteria_range(parent) {
                        return Err(unsupported(
                            "external range reaching a criteria function through a name",
                        ));
                    }
                    self.external(external, parent)
                }
                Some(LinkedName::Expression) => Ok(()),
                Some(LinkedName::Unclear) => Err(unsupported(
                    "workbook name holding a relative or repeated linked reference",
                )),
                None => linked_workbook_name(name),
            },
            // A table of a closed linked workbook is #REF! for both.
            _ => Ok(()),
        }
    }

    /// Admit a workbook name's formula. A name that is one linked reference is
    /// read where the formulas using it put it, which `admit` checks there;
    /// here only its link is.
    pub(crate) fn admit_name(
        &self,
        formula: &ASTNode,
        names: &BTreeMap<String, LinkedName>,
    ) -> Result<()> {
        match &formula.node_type {
            ASTNodeType::Reference {
                reference: ReferenceType::External(external),
                ..
            } => self.book(external).map(|_| ()),
            _ => self.admit(formula, names),
        }
    }

    /// The link a reference reads, or why the engine cannot read it.
    fn book(&self, external: &ExternalReference) -> Result<&LinkedBook> {
        if link_index(external.book.token()) == Some(0) {
            return Err(unsupported(WORKBOOK_ITSELF));
        }
        let book = link_index(external.book.token())
            .filter(|&index| index > 0)
            .and_then(|index| self.books.get(index - 1))
            .ok_or_else(|| unsupported("external reference outside the workbook's links"))?;
        // `[1]Jan:Dec!A1`: no sheet name holds a colon.
        if external.sheet.contains(':') {
            return Err(unsupported("external 3D reference"));
        }
        Ok(book)
    }

    fn external(&self, external: &ExternalReference, parent: &Parent<'_>) -> Result<()> {
        let book = self.book(external)?;
        if !one_cell(external.kind) && !reads_a_range(parent, external.kind) {
            return Err(unsupported(
                "external range returned or passed on as a reference",
            ));
        }
        let sheet = external.sheet.to_lowercase();
        // A sheet the link does not name is #REF! for both.
        let unsaved_is_error = book
            .sheets
            .iter()
            .find(|(name, _)| *name == sheet)
            .is_some_and(|(_, unsaved_is_error)| *unsaved_is_error);
        if cropped(external.kind) && !reads_past_saved_values(parent, unsaved_is_error) {
            return Err(unsupported(if unsaved_is_error {
                "external range past the saved values of a sheet Excel could not refresh"
            } else {
                "external range past the saved values of a linked sheet"
            }));
        }
        Ok(())
    }
}

/// A name of this or a linked workbook written with its book: `[0]!Rate` is
/// this workbook's own `Rate`, `[1]!Rate` the linked workbook's.
fn linked_workbook_name(name: &str) -> Result<()> {
    if name.starts_with("[0]!") {
        Err(unsupported(WORKBOOK_ITSELF))
    } else if linked_name(name) {
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
    /// An expression over linked values: a value.
    Expression,
    /// A relative linked reference, or a name defined more than once.
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

/// Whether `node` reads a linked workbook: an external reference, or a name
/// of `names`.
fn mentions_link(node: &ASTNode, names: &BTreeMap<String, LinkedName>) -> bool {
    match &node.node_type {
        ASTNodeType::Reference { reference, .. } => match reference {
            ReferenceType::External(_) => true,
            ReferenceType::NamedRange(name) => {
                linked_name(name) || names.contains_key(&name.to_ascii_uppercase())
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

impl LinkedBook {
    fn read(part: &[u8], package: &Package) -> Result<Self> {
        let unreadable = || unsupported("external link part the check cannot read");
        let xml = Xml::parse(part, package.limits().xml).map_err(|_| unreadable())?;
        xml.root(MAIN, "externalLink").map_err(|_| unreadable())?;
        if xml
            .child(0, MAIN, "ddeLink")
            .map_err(|_| unreadable())?
            .is_some()
        {
            return Err(unsupported("DDE link"));
        }
        if xml
            .child(0, MAIN, "oleLink")
            .map_err(|_| unreadable())?
            .is_some()
        {
            return Err(unsupported("OLE link"));
        }
        let (book, _) = xml
            .child(0, MAIN, "externalBook")
            .map_err(|_| unreadable())?
            .ok_or_else(|| unsupported("unknown external link"))?;
        let names: Vec<String> = match xml
            .child(book, MAIN, "sheetNames")
            .map_err(|_| unreadable())?
        {
            Some((list, _)) => xml
                .children(list)
                .filter(|(_, node)| node.is(MAIN, "sheetName"))
                .map(|(_, node)| node.attr("val").unwrap_or_default().to_lowercase())
                .collect(),
            None => Vec::new(),
        };
        // Saved values by sheet position: whether Excel could not refresh it.
        let mut saved = BTreeMap::new();
        if let Some((set, _)) = xml
            .child(book, MAIN, "sheetDataSet")
            .map_err(|_| unreadable())?
        {
            for (_, data) in xml
                .children(set)
                .filter(|(_, node)| node.is(MAIN, "sheetData"))
            {
                if let Some(index) = data.attr("sheetId").and_then(|id| id.parse::<usize>().ok()) {
                    let refresh_error = matches!(data.attr("refreshError"), Some("1" | "true"));
                    saved.insert(index, refresh_error);
                }
            }
        }
        let sheets = names
            .into_iter()
            .enumerate()
            .map(|(index, name)| (name, saved.get(&index).copied().unwrap_or(true)))
            .collect();
        Ok(Self { sheets })
    }
}

/// The package's content types: `Override` by part name, `Default` by
/// extension, both case-insensitive as OPC compares them.
struct ContentTypes {
    overrides: BTreeMap<String, String>,
    defaults: BTreeMap<String, String>,
}

impl ContentTypes {
    fn read(package: &Package) -> Result<Self> {
        let unreadable = || unsupported("external link list the edit gate cannot join");
        let bytes = package
            .part("[Content_Types].xml")?
            .ok_or_else(unreadable)?;
        let xml = Xml::parse(&bytes, package.limits().xml).map_err(|_| unreadable())?;
        let mut types = Self {
            overrides: BTreeMap::new(),
            defaults: BTreeMap::new(),
        };
        for node in &xml.nodes {
            let content_type = node.attr("ContentType").unwrap_or_default().to_owned();
            match node.name.as_str() {
                "Override" => {
                    let part = node.attr("PartName").unwrap_or_default();
                    types
                        .overrides
                        .insert(part.to_ascii_lowercase(), content_type);
                }
                "Default" => {
                    let extension = node.attr("Extension").unwrap_or_default();
                    types
                        .defaults
                        .insert(extension.to_ascii_lowercase(), content_type);
                }
                _ => {}
            }
        }
        Ok(types)
    }

    fn content_type(&self, part: &str) -> Option<String> {
        let name = format!("/{part}").to_ascii_lowercase();
        self.overrides.get(&name).cloned().or_else(|| {
            let extension = name.rsplit_once('.')?.1;
            self.defaults.get(extension).cloned()
        })
    }
}

/// Where a reference sits in its formula.
enum Parent<'a> {
    Root,
    /// An operand of an operator (`""` for a unary one, a call or an array).
    Operator(&'a str),
    /// An argument of a function, by its bare upper-case name.
    Argument {
        function: String,
        index: usize,
        args: &'a [ASTNode],
    },
}

/// Whether `parent` reads a range of a closed linked workbook as Excel does:
/// as a value (an operand, or an argument the function reads as values),
/// never as a reference passed on. The fork returns a linked range as values
/// with no position, so a function that returns references (IF, CHOOSE,
/// IFS, XLOOKUP, OFFSET, INDIRECT, LET) would pass on what Excel passes on as
/// a reference, INDEX only when it narrows the range to one cell; and a range
/// as the whole formula, or where Excel needs a reference (AREAS, RANK,
/// GETPIVOTDATA), is left to the fallback too.
fn reads_a_range(parent: &Parent<'_>, kind: ExternalRefKind) -> bool {
    match parent {
        Parent::Root => false,
        // `""` is a call or an array literal.
        Parent::Operator(op) => !op.is_empty(),
        Parent::Argument {
            function,
            index,
            args,
        } => match (function.as_str(), *index) {
            // One position selects a cell of a single column or row only.
            ("INDEX", 0) => match args.len() {
                2 => one_line(kind) && row_or_column(&args[1]),
                3 => row_or_column(&args[1]) && row_or_column(&args[2]),
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
/// COUNTA gives the same count too. Anything that counts the unsaved cells
/// (ISBLANK or ISERROR over the range), pairs the range with another of
/// another length, returns its rows (ROW over an open range) or searches it
/// by halves (an approximate MATCH: `MATCH(3,[1]S!A:A,-1)` over 1 to 5 is
/// #N/A in Excel) stays the fallback's.
fn reads_past_saved_values(parent: &Parent<'_>, unsaved_is_error: bool) -> bool {
    let Parent::Argument {
        function,
        index,
        args,
    } = parent
    else {
        return false;
    };
    let arg = |at: usize| args.get(at);
    match (function.as_str(), *index) {
        ("INDEX", 0) | ("ROWS" | "COLUMNS", 0) => true,
        ("MATCH", 1) => literal(arg(2)) == Some(Some(0.0)),
        ("VLOOKUP" | "HLOOKUP", 1) => literal(arg(3)) == Some(Some(0.0)),
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

/// A call other than INDEX (which selects a linked reference itself) that
/// may return a reference and reads a linked workbook.
fn passes_on_a_link(node: &ASTNode, names: &BTreeMap<String, LinkedName>) -> bool {
    match &node.node_type {
        ASTNodeType::Function { name, .. } => {
            let bare = name.rsplit('.').next().unwrap_or(name).to_ascii_uppercase();
            bare != "INDEX" && returns_reference(name) && mentions_link(node, names)
        }
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
        ASTNodeType::Function { name, .. } => matches!(
            name.rsplit('.')
                .next()
                .unwrap_or(name)
                .to_ascii_uppercase()
                .as_str(),
            "MATCH" | "XMATCH"
        ),
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

/// `[n]`, the 1-based place of a link in the workbook's list (`[0]` is the
/// workbook itself).
fn link_index(token: &str) -> Option<usize> {
    token
        .trim()
        .strip_prefix('[')?
        .strip_suffix(']')
        .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))?
        .parse()
        .ok()
}

/// `[1]!Rate`: a name defined in a linked workbook.
fn linked_name(name: &str) -> bool {
    name.starts_with('[') && name.contains("]!")
}

/// The workbook's link relationships by id: the internal part each targets,
/// `None` when it targets none (an external or unresolvable target).
fn link_relationships(rels: &Xml) -> BTreeMap<String, Option<String>> {
    let mut links = BTreeMap::new();
    for node in rels
        .nodes
        .iter()
        .filter(|node| node.is(REL, "Relationship"))
        .filter(|node| {
            node.attr("Type")
                .is_some_and(|kind| kind.rsplit('/').next() == Some("externalLink"))
        })
    {
        let target = match node.attr("TargetMode") {
            None | Some("Internal") => node.attr("Target").and_then(resolve_under_xl),
            Some(_) => None,
        };
        links.insert(node.attr("Id").unwrap_or_default().to_owned(), target);
    }
    links
}

/// The part a workbook relationship target names (relative to `xl/`).
fn resolve_under_xl(target: &str) -> Option<String> {
    let path = target
        .strip_prefix('/')
        .map_or_else(|| format!("xl/{target}"), str::to_owned);
    let mut segments = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop()?;
            }
            segment if segment.contains(['\\', ':', '#', '?', '%']) => return None,
            segment => segments.push(segment),
        }
    }
    Some(segments.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(formula: &str) -> ASTNode {
        formualizer_parse::parse(formula).unwrap_or_else(|error| panic!("{formula}: {error:?}"))
    }

    fn books() -> LinkedBooks {
        LinkedBooks {
            books: vec![LinkedBook {
                sheets: vec![("data".into(), false), ("failed".into(), true)],
            }],
        }
    }

    /// `Rates` names `[1]Data!$A$1:$A$5`, `Twice` an expression over a link.
    fn names() -> BTreeMap<String, LinkedName> {
        let rates = parse("=[1]Data!$A$1:$A$5");
        let twice = parse("=[1]Data!$A$1*2");
        let moving = parse("=[1]Data!A1");
        books().names([("Rates", &rates), ("Twice", &twice), ("Moving", &moving)])
    }

    fn reason(formula: &str) -> Option<String> {
        match books().admit(&parse(formula), &names()) {
            Ok(()) => None,
            Err(crate::FormulaError::UnsupportedWorkbook(reason)) => Some(reason.into_owned()),
            Err(other) => panic!("{formula}: {other:?}"),
        }
    }

    #[test]
    fn saved_values_and_their_lookups_are_admitted() {
        for formula in [
            "=[1]Data!A1+[1]Failed!A1",
            "=[1]Data!A1:A1",
            "=SUM([1]Data!A:A)",
            "=COUNTA([1]Data!A:A)",
            "=VLOOKUP(1,[1]Data!A1:B9,2)",
            "=MATCH(4,[1]Data!A1:A9)",
            "=SUM([1]Data!A1:A5*2)",
            "=SUMPRODUCT([1]Data!A1:A5,[1]Data!B1:B5)",
            "=INDEX([1]Failed!B:B,MATCH(4,[1]Failed!A:A,0))",
            "=INDEX([1]Data!A1:C9,2,MATCH(\"x\",[1]Data!A1:C1,0))",
            "=VLOOKUP(\"x\",[1]Failed!A:Z,13,FALSE)",
            "=SUM([1]Failed!A:A)+ROWS([1]Failed!A:A)",
            "=SUMIF([1]Failed!A:A,\">1\",[1]Failed!B:B)",
            "=COUNTA([1]Failed!A1:A999)",
            "=ROW([1]Data!A2:A9)",
            "=[1]Missing!A1",
            "=VLOOKUP(1,[1]!Prices[#Data],2,FALSE)",
            "=SUM(Rates)+Twice",
            "=IF(Twice>1,Twice)",
        ] {
            assert_eq!(reason(formula), None, "{formula}");
        }
    }

    #[test]
    fn forms_excel_reads_differently_fall_back() {
        let outside = Some("external reference outside the workbook's links".to_owned());
        assert_eq!(reason("=[2]Data!A1"), outside);
        assert_eq!(reason("='[other.xlsx]Data'!A1"), outside);
        assert_eq!(
            reason("=[1]!Rate*2"),
            Some("external reference to a defined name of a linked workbook".to_owned())
        );
        let itself = Some(WORKBOOK_ITSELF.to_owned());
        assert_eq!(reason("=[0]!PeriodInActual*2"), itself);
        assert_eq!(reason("=[0]Data!A1"), itself);
        assert_eq!(
            reason("=SUM('[1]Jan:Dec'!A1)"),
            Some("external 3D reference".to_owned())
        );
        let operator = Some("external reference in a reference operator".to_owned());
        for formula in [
            "=[1]Data!A1:A5 [1]Data!A3:B3",
            "=SUM(INDEX([1]Data!A1:A5,2) INDEX([1]Data!A1:A5,2))",
        ] {
            assert_eq!(reason(formula), operator, "{formula}");
        }
        assert_eq!(
            reason("=Moving+1"),
            Some("workbook name holding a relative or repeated linked reference".to_owned())
        );
        assert_eq!(
            reason("=SUMIF(Rates,\">0\")"),
            Some("external range reaching a criteria function through a name".to_owned())
        );
        assert_eq!(
            reason("=ROW(IF(TRUE,[1]Data!A3))"),
            Some(
                "external reference passed on by a function to one that reads references"
                    .to_owned()
            )
        );
        assert_eq!(reason("=ROW(INDEX([1]Data!A1:A5,3))"), None);
        // The fork returns a linked range as values with no position.
        let passed = Some("external range returned or passed on as a reference".to_owned());
        for formula in [
            "=[1]Data!A1:A5",
            "=SUMIF(INDEX([1]Data!A1:A5,0),\">0\")",
            "=SUM(INDEX([1]Data!A2:A5,0)*2)",
            "=SUM(INDEX([1]Data!A1:B5,3))",
            "=SUMIF(CHOOSE(1,[1]Data!A1:A5),\">0\")",
            "=SUM(IF(TRUE,[1]Data!A1:A5))",
            "=MAX(IF([1]Failed!A:A>2,[1]Failed!A:A))",
            "=RANK(3,[1]Data!A1:A5)",
            "=INDEX(Rates,0)",
        ] {
            assert_eq!(reason(formula), passed, "{formula}");
        }
        let failed = Some(
            "external range past the saved values of a sheet Excel could not refresh".to_owned(),
        );
        for formula in [
            "=COUNTA([1]Failed!A:A)",
            "=SUMPRODUCT(--ISERROR([1]Failed!A:A))",
            "=MATCH(3,[1]Failed!A:A,-1)",
            "=VLOOKUP(3,[1]Failed!A:B,2)",
            "=LOOKUP(2,[1]Failed!A:A)",
            "=XMATCH(3,[1]Failed!A:A,0,2)",
            "=COUNTA([1]Failed!A1:Z1000000)",
        ] {
            assert_eq!(reason(formula), failed, "{formula}");
        }
        let past = Some("external range past the saved values of a linked sheet".to_owned());
        for formula in [
            "=SUMPRODUCT(--ISBLANK([1]Data!A:A))",
            "=SUMPRODUCT([1]Data!A:A,[1]Data!A1:A5)",
            "=SUMPRODUCT(ROW([1]Data!A:A))",
            "=MATCH(3,[1]Data!A:A,-1)",
            "=VLOOKUP(1,[1]Data!A:B,2)",
            "=LOOKUP(2.5,[1]Data!A:A)",
        ] {
            assert_eq!(reason(formula), past, "{formula}");
        }
    }
}
