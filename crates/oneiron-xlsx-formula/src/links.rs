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
//! join, link markup the fork's reader would read where Excel reads none, an
//! escape in a link's sheet names or saved values, a reference by file name,
//! to `[0]` or to a link the list does not hold, a defined name of a linked
//! workbook (`[1]!Rate`), a 3D linked reference, a linked reference in a
//! reference operator, a multi-cell linked range passed on as a reference
//! (`reads_a_range`), a linked reference reaching a criteria function through
//! another function or a name, or reaching a function that reads references
//! through one that passes it on as values (`passed_on`), one bound to a LET
//! or LAMBDA name, and an open or very large linked range unless the function
//! reading it gives Excel's result from the cells up to the last saved one
//! (`reads_past_saved_values`). A workbook name over a linked workbook is
//! checked where each formula uses it, as if written there; one with a
//! relative linked reference anywhere in its formula falls back wherever it
//! is used, as the fork reads every name's formula at A1 where Excel moves
//! the reference with the cell using it. A link part that is not XML is
//! malformed workbook content, refused outright (`InvalidWorkbook`).

use std::collections::{BTreeMap, BTreeSet};

use formualizer_common::parse_a1_1based;
use formualizer_parse::parser::{
    ASTNode, ASTNodeType, ExternalRefKind, ExternalReference, ReferenceType,
};
use oneiron_docedit::ooxml::Node;
use oneiron_docedit::retained_opc::Package;

use crate::Result;
use crate::workbook::{ESCAPED_TEXT, escaped};
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

const UNJOINED: &str = "external link list the edit gate cannot join";

/// The fork's link reader (`formualizer_workbook`'s `external_links.rs`)
/// matches `externalReference`, `Relationship`, `externalBook`, `sheetName`,
/// `sheetData`, `cell` and `v` by local name anywhere in their part, and takes
/// the first attribute of each name it reads whatever its namespace. An
/// element outside its SpreadsheetML place, or an attribute of that name in
/// another namespace, is read where Excel reads none (a vendor extension's
/// `u:cell` would replace a saved value).
const OUT_OF_PLACE: &str = "external link markup outside its SpreadsheetML place";

/// The most workbook names one formula's check reads through, nested or
/// repeated; a name may use another, or itself.
const MAX_NAME_EXPANSIONS: usize = 256;

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

/// Refuse an external relationship target the engine cannot keep as Excel
/// does: anything other than a hyperlink, a link's path or a pivot cache's
/// external source. A relationship part the check cannot read fails closed to
/// the fallback, as it did before linked workbooks were read natively.
pub(crate) fn external_targets(package: &Package) -> Result<()> {
    let limits = package.limits().xml;
    for name in package.names().filter(|name| name.ends_with(".rels")) {
        let Some(bytes) = package.part(name)? else {
            continue;
        };
        let xml = Xml::parse(&bytes, limits)
            .map_err(|_| unsupported("relationship part the link check cannot read"))?;
        // A link's path, and a pivot cache's external source, which only
        // a pivot refresh reads, never a recalculation.
        let link_paths =
            name.starts_with("xl/externalLinks/_rels/") || name.starts_with("xl/pivotCache/_rels/");
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
    Ok(())
}

impl LinkedBooks {
    /// Read the workbook's links, after `external_targets` and the formula
    /// reader have checked the package. A link the engine cannot read as
    /// Excel does is the fallback's; malformed XML in the workbook or a link
    /// part stays an outright refusal (`InvalidWorkbook`).
    pub(crate) fn read(package: &Package) -> Result<Self> {
        let limits = package.limits().xml;
        let Some(workbook) = package.part("xl/workbook.xml")? else {
            return Ok(Self::default());
        };
        let ids = link_ids(&Xml::parse(&workbook, limits)?)?;
        let rels = match package.part("xl/_rels/workbook.xml.rels")? {
            Some(bytes) => Xml::parse(&bytes, limits)?,
            None if ids.is_empty() => return Ok(Self::default()),
            None => return Err(unsupported(UNJOINED)),
        };
        let targets = link_parts(&rels, &ids)?;
        if targets.is_empty() {
            return Ok(Self::default());
        }
        let types = ContentTypes::read(package)?;
        let mut books = Vec::with_capacity(targets.len());
        for target in targets {
            let part = package
                .part(&target)?
                .ok_or_else(|| unsupported(UNJOINED))?;
            if types.content_type(&target).as_deref() != Some(LINK_CONTENT_TYPE) {
                return Err(unsupported(UNJOINED));
            }
            books.push(LinkedBook::read(&part, package)?);
        }
        Ok(Self { books })
    }

    /// The defined names (upper case) that read a linked workbook: through a
    /// linked reference in their formula, or through another such name.
    pub(crate) fn names<'a>(
        &self,
        names: impl IntoIterator<Item = (&'a str, &'a ASTNode)>,
    ) -> BTreeMap<String, LinkedName> {
        let names: Vec<(String, &ASTNode)> = names
            .into_iter()
            .map(|(name, formula)| (name.to_ascii_uppercase(), formula))
            .collect();
        // The definitions that use each name, so a name that reads a linked
        // workbook marks every definition using it in turn.
        let mut users: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (index, (_, formula)) in names.iter().enumerate() {
            let mut used = BTreeSet::new();
            used_names(formula, &mut used);
            for name in used {
                users.entry(name).or_default().push(index);
            }
        }
        let mut reads = vec![false; names.len()];
        let mut pending: Vec<usize> = (0..names.len())
            .filter(|&index| mentions_link(names[index].1, &BTreeMap::new()))
            .collect();
        while let Some(index) = pending.pop() {
            if std::mem::replace(&mut reads[index], true) {
                continue;
            }
            pending.extend(users.get(&names[index].0).into_iter().flatten());
        }
        let mut linked = BTreeMap::new();
        for ((name, formula), _) in names.iter().zip(&reads).filter(|(_, reads)| **reads) {
            let shape = match &formula.node_type {
                ASTNodeType::Reference {
                    reference: ReferenceType::External(external),
                    ..
                } if absolute(external.kind) => LinkedName::Reference(external.clone()),
                // A relative reference in a name moves with the cell using
                // it, bare or inside an expression; the fork reads every
                // name's formula at A1 (`evaluate_named_formula`).
                _ if relative_link(formula) => LinkedName::Unclear,
                _ => LinkedName::Expression((*formula).clone()),
            };
            // A name defined in several scopes may hold any of its formulas.
            linked
                .entry(name.clone())
                .and_modify(|known| *known = LinkedName::Unclear)
                .or_insert(shape);
        }
        linked
    }

    /// Admit one formula's external references, or name why they are the
    /// fallback's. `names` are the workbook names that read a linked workbook.
    pub(crate) fn admit<'a>(
        &self,
        formula: &'a ASTNode,
        names: &'a BTreeMap<String, LinkedName>,
    ) -> Result<()> {
        let mut pending = vec![(formula, Parent::Root)];
        let mut expansions = 0;
        while let Some((node, parent)) = pending.pop() {
            passed_on(node, &parent, names)?;
            match &node.node_type {
                // `[0]` is the workbook itself: the fork reads `[0]Sheet1!A1`
                // as Sheet1!A1 and `[0]!Rate` as its own Rate, so the written
                // reference tells such a formula, which goes to the fallback.
                ASTNodeType::Reference { original, .. } if workbook_itself(original) => {
                    return Err(unsupported(WORKBOOK_ITSELF));
                }
                ASTNodeType::Reference { reference, .. } => {
                    // A name holding an expression over linked values is
                    // checked as if its formula were written here.
                    if let Some(expression) = self.reference(reference, &parent, names)? {
                        expansions += 1;
                        if expansions > MAX_NAME_EXPANSIONS {
                            return Err(unsupported(
                                "workbook names over linked workbooks nested past the check's limit",
                            ));
                        }
                        pending.push((expression, parent));
                    }
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
                    let bare = bare_name(name);
                    if binds_a_link(&bare, args, names) {
                        return Err(unsupported(BOUND));
                    }
                    // INDEX hands on the reference it selects, so its range
                    // is read as a reference wherever the INDEX is.
                    let through = bare == "INDEX"
                        && matches!(
                            parent,
                            Parent::Argument {
                                reference: true,
                                ..
                            }
                        );
                    for (index, arg) in args.iter().enumerate() {
                        pending.push((
                            arg,
                            Parent::Argument {
                                reference: reads_reference(&bare) || (through && index == 0),
                                function: bare.clone(),
                                index,
                                args,
                            },
                        ));
                    }
                }
                ASTNodeType::Call { callee, args } => {
                    // A LAMBDA's parameters hold its arguments as the fork's
                    // LET names do.
                    if args.iter().any(|arg| mentions_link(arg, names)) {
                        return Err(unsupported(BOUND));
                    }
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

    /// Check one reference, and return the expression of a workbook name
    /// that holds one over linked values, to check where it is used.
    fn reference<'a>(
        &self,
        reference: &ReferenceType,
        parent: &Parent<'_>,
        names: &'a BTreeMap<String, LinkedName>,
    ) -> Result<Option<&'a ASTNode>> {
        match reference {
            ReferenceType::External(external) => self.external(external, parent).map(|()| None),
            // A workbook name for a linked reference reads as that reference.
            ReferenceType::NamedRange(name) if !linked_name(name) => {
                match names.get(&name_key(name)) {
                    Some(LinkedName::Reference(external)) => {
                        // A criteria function refuses a closed linked range
                        // written in it (#VALUE!), which the fork does too, and
                        // one a name holds as well, which the fork computes.
                        if criteria_range(parent) {
                            return Err(unsupported(
                                "external range reaching a criteria function through a name",
                            ));
                        }
                        self.external(external, parent).map(|()| None)
                    }
                    Some(LinkedName::Expression(expression)) => Ok(Some(expression)),
                    Some(LinkedName::Unclear) => Err(unsupported(
                        "workbook name holding a relative or repeated linked reference",
                    )),
                    None => Ok(None),
                }
            }
            ReferenceType::NamedRange(name) => linked_workbook_name(name).map(|()| None),
            // A table of a closed linked workbook is #REF! for both.
            _ => Ok(None),
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

impl LinkedBook {
    /// Read one link part as Excel reads it: its sheet names and which sheets
    /// Excel could not refresh. The fork's reader takes the same values only
    /// from markup in its SpreadsheetML place (`OUT_OF_PLACE`), and decodes no
    /// `_xHHHH_` escape in a sheet name or saved value, where Excel reads each
    /// as one UTF-16 unit (`a_x0001_b` is three characters). A part that is
    /// not XML, or over the host's XML limits, is malformed workbook content
    /// as in any part the writer reads; well-formed content the check cannot
    /// read is the fallback's.
    fn read(part: &[u8], package: &Package) -> Result<Self> {
        let unreadable = || unsupported("external link part the check cannot read");
        let out_of_place = || unsupported(OUT_OF_PLACE);
        let xml = Xml::parse(part, package.limits().xml)?;
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
        let child = |name| {
            xml.child(book, MAIN, name)
                .map(|found| found.map(|(index, _)| index))
                .map_err(|_| unreadable())
        };
        let (list, set) = (child("sheetNames")?, child("sheetDataSet")?);
        // A saved row: a row of a sheet's saved values.
        let saved_row = |row: usize| {
            let row = &xml.nodes[row];
            row.is(MAIN, "row")
                && row.parent.is_some_and(|data| {
                    xml.nodes[data].is(MAIN, "sheetData")
                        && set.is_some()
                        && xml.nodes[data].parent == set
                })
        };
        let saved_cell = |cell: usize| {
            let cell = &xml.nodes[cell];
            cell.is(MAIN, "cell") && cell.parent.is_some_and(saved_row)
        };
        let mut names = Vec::new();
        // Saved values by sheet position: whether Excel could not refresh it.
        let mut saved = BTreeMap::new();
        for (index, node) in xml.nodes.iter().enumerate() {
            let parent = node.parent;
            // Other markup, such as Excel's own `xxl21:alternateUrls`, the
            // fork's reader passes over.
            let placed = match node.name.as_str() {
                "externalBook" => index == book,
                "sheetName" => parent.is_some() && parent == list,
                "sheetData" => parent.is_some() && parent == set,
                "cell" => parent.is_some_and(saved_row),
                "v" => node.children.is_empty() && parent.is_some_and(saved_cell),
                _ => continue,
            };
            if !placed || node.namespace != MAIN {
                return Err(out_of_place());
            }
            let attr = |local| sole_attr(node, "", local).ok_or_else(out_of_place);
            match node.name.as_str() {
                "sheetName" => {
                    let name = attr("val")?.ok_or_else(unreadable)?;
                    if escaped(name) {
                        return Err(unsupported(ESCAPED_TEXT));
                    }
                    names.push(name.to_lowercase());
                }
                "sheetData" => {
                    let refresh_error = matches!(attr("refreshError")?, Some("1" | "true"));
                    if let Some(index) = attr("sheetId")?.and_then(|id| id.parse::<usize>().ok()) {
                        saved.insert(index, refresh_error);
                    }
                }
                "cell" => {
                    let address = attr("r")?.ok_or_else(unreadable)?;
                    parse_a1_1based(address).map_err(|_| unreadable())?;
                    let kind = attr("t")?;
                    if let Some((_, value)) =
                        xml.child(index, MAIN, "v").map_err(|_| unreadable())?
                    {
                        saved_value(kind, &value.text)?;
                    }
                }
                _ => {}
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

/// A saved value the fork reads as Excel does: a number, text, a boolean or
/// an error, with no `_xHHHH_` escape.
fn saved_value(kind: Option<&str>, value: &str) -> Result<()> {
    if escaped(value) {
        return Err(unsupported(ESCAPED_TEXT));
    }
    let readable = match kind {
        None | Some("n") => value.trim().parse::<f64>().is_ok_and(f64::is_finite),
        Some("b") => matches!(value, "0" | "1"),
        Some("str" | "e") => true,
        _ => false,
    };
    if readable {
        Ok(())
    } else {
        Err(unsupported(
            "external link saved value the check cannot read",
        ))
    }
}

/// The value of `node`'s one attribute named `local`, when it is in namespace
/// `ns` (`""` for none): `Some(None)` when there is none, and `None` when the
/// fork's reader, which takes the first attribute of that local name in any
/// namespace (a declaration `xmlns:r` included), could read another.
fn sole_attr<'a>(node: &'a Node, ns: &str, local: &str) -> Option<Option<&'a str>> {
    let mut named = node
        .attrs
        .keys()
        .filter(|key| key.rsplit(':').next() == Some(local));
    let Some(key) = named.next() else {
        return Some(None);
    };
    if named.next().is_some() {
        return None;
    }
    if ns.is_empty() {
        (key == local).then(|| node.attr(local))
    } else {
        node.attr_ns(ns, local).map(Some)
    }
}

/// The relationship ids of the workbook's links, in `<externalReferences>`
/// order.
fn link_ids(workbook: &Xml) -> Result<Vec<String>> {
    let mut ids = Vec::new();
    for node in workbook
        .nodes
        .iter()
        .filter(|node| node.name == "externalReference")
    {
        let placed = node.namespace == MAIN
            && node.parent.is_some_and(|list| {
                workbook.nodes[list].is(MAIN, "externalReferences")
                    && workbook.nodes[list].parent == Some(0)
            });
        let id = sole_attr(node, DOC_REL, "id")
            .filter(|_| placed)
            .ok_or_else(|| unsupported(OUT_OF_PLACE))?;
        ids.push(id.unwrap_or_default().to_owned());
    }
    Ok(ids)
}

/// The link part each id of `ids` names. The edit gate joins every reference
/// to one internal link relationship; the fork's reader takes the
/// relationship by its first `Id` attribute whatever its namespace, type or
/// target mode, so the id must name that one relationship alone.
fn link_parts(rels: &Xml, ids: &[String]) -> Result<Vec<String>> {
    let link = |node: &Node| {
        node.is(REL, "Relationship")
            && node.parent == Some(0)
            && node
                .attr("Type")
                .is_some_and(|kind| kind.rsplit('/').next() == Some("externalLink"))
    };
    if rels.nodes.iter().filter(|node| link(node)).count() != ids.len() {
        return Err(unsupported(UNJOINED));
    }
    let mut parts = Vec::with_capacity(ids.len());
    for id in ids {
        let named: Vec<&Node> = rels
            .nodes
            .iter()
            .filter(|node| {
                node.name == "Relationship"
                    && node
                        .attrs
                        .iter()
                        .any(|(key, value)| key.rsplit(':').next() == Some("Id") && value == id)
            })
            .collect();
        if named
            .iter()
            .any(|node| !node.is(REL, "Relationship") || node.parent != Some(0))
        {
            return Err(unsupported(OUT_OF_PLACE));
        }
        let [node] = named[..] else {
            return Err(unsupported(UNJOINED));
        };
        if !link(node) {
            return Err(unsupported(UNJOINED));
        }
        let (Some(Some(_)), Some(Some(target)), Some(None | Some("Internal"))) = (
            sole_attr(node, "", "Id"),
            sole_attr(node, "", "Target"),
            sole_attr(node, "", "TargetMode"),
        ) else {
            return Err(unsupported(UNJOINED));
        };
        parts.push(resolve_under_xl(target).ok_or_else(|| unsupported(UNJOINED))?);
    }
    Ok(parts)
}

/// The package's content types: `Override` by part name, `Default` by
/// extension, both case-insensitive as OPC compares them.
struct ContentTypes {
    overrides: BTreeMap<String, String>,
    defaults: BTreeMap<String, String>,
}

impl ContentTypes {
    fn read(package: &Package) -> Result<Self> {
        let unreadable = || unsupported(UNJOINED);
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
            ..
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
        ..
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

/// A reference written with the workbook itself as its book (`[0]Sheet1!A1`,
/// `'[0]My Sheet'!A1`, `[0]!Rate`).
fn workbook_itself(original: &str) -> bool {
    original.trim_start_matches('\'').starts_with("[0]")
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

/// `[1]!Rate` or `[1]Sheet1!Rate`: a name defined in a linked workbook (no
/// sheet name holds `[`).
fn linked_name(name: &str) -> bool {
    name.rsplit_once('!')
        .is_some_and(|(book, _)| book.contains('['))
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
