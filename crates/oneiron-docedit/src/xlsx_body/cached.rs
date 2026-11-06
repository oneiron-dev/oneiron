//! A recalculated copy's formula values, written into the original workbook
//! (FIX 2462).
//! Entry: `write_cached_values`.
//!
//! The precision fallback (LibreOffice headless, ARCH-0075) recalculates a
//! copy of a workbook the native formula engine refuses. The application that
//! saves the copy writes its own package, so the copy is never the output:
//! only the values it cached for the formula cells come back, each into the
//! original's matching cell, where only the value (`v`) and its type (`t`)
//! change. Sheets match by name, never by part, since the copy names its
//! parts its own way. A part with no change keeps its bytes, and a changed
//! worksheet keeps every other element and attribute in place
//! (docengine:fidelity).

use super::{
    Book, Result, SML, XlsxArea, XlsxLock, cell_ref, drop_attribute, encode_escapes, parse,
    refused, string_item,
};
use crate::edit::xml::{Splice, insert_end, replace_text, set_attribute, splice};
use crate::ooxml::{Node, XmlTree, escape_text};
use crate::retained_opc::Limits;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// The formula kinds whose `ref` spans cells that hold its results without
/// a formula of their own: an array formula (a dynamic array's spill
/// included) and a data table, whose results the engine's live reads count
/// as computed too. Taking a data table's is an engine call (CALLS, FIX
/// 2462).
const RANGED_FORMULAS: &[&str] = &["array", "dataTable"];

/// The functions whose result reads where the file is opened from. Under
/// the fallback that is the run's private scratch, so a formula that calls
/// one keeps the value it cached rather than take a host path into the
/// file. An engine call (CALLS, FIX 2462).
const LOCATION_FUNCTIONS: &[&str] = &["CELL", "INFO"];

/// The original workbook with the recalculated values in its formula cells.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedValuesWritten {
    pub bytes: Vec<u8>,
    /// The formula cells the recalculated copy gave a value for.
    pub formula_count: usize,
}

/// One value the recalculated copy cached, as the original's cell takes it:
/// its type (`None` for a number) and its `v` text, `_xHHHH_` escaped and
/// not yet XML escaped.
struct Cached {
    kind: Option<&'static str>,
    text: String,
}

/// Write the values `computed`, a recalculated copy of `original`, caches for
/// its formula cells into `original` in place. A formula cell is one with a
/// formula, or one inside an array formula's or data table's range. Only a
/// cell's `v` text and `t` change: a number has no `t`, a string `str`, a
/// boolean `b`, an error `e`. A cell the copy gives no value for, a sheet
/// either side does not hold by name, a rich value's cell and a formula that
/// reads the file's location keep what they hold.
pub fn write_cached_values(
    original: &[u8],
    computed: &[u8],
    limits: Limits,
    resources: &crate::resource::Resources,
) -> Result<CachedValuesWritten> {
    let mut book = Book::open(original, limits, resources)?;
    let copy = Book::open(computed, limits, resources)?;
    let sheets: Vec<(String, String)> = book
        .worksheets
        .iter()
        .map(|(name, part)| (name.clone(), part.clone()))
        .collect();
    // Names match as the application reads them: a `_xHHHH_` escape one
    // side writes and the other spells out are the same name (review #6434).
    let copied_sheets: BTreeMap<String, &String> = copy
        .worksheets
        .iter()
        .map(|(name, part)| (sheet_name_key(name), part))
        .collect();
    let mut formula_count = 0;
    for (name, part) in sheets {
        let Some(copied) = copied_sheets.get(&sheet_name_key(&name)).copied() else {
            continue;
        };
        let bytes = book
            .package
            .part(&part)?
            .ok_or(refused("a worksheet part is missing"))?;
        let tree = XmlTree::parse(&bytes, book.package.resources())?;
        let cells = formula_cells(&tree)?;
        if cells.is_empty() {
            continue;
        }
        // An array whose results grew or shrank in the copy would leave
        // stale or missing cells under a stamp that says the workbook was
        // recalculated, so the whole fallback stands down instead and the
        // workbook keeps today's fullCalcOnLoad mark (review #6434).
        let extents = array_extents(&tree)?;
        let copy_tree = parse(&copy.package, copied)?;
        if extents != array_extents(&copy_tree)? {
            return Err(refused(
                "an array formula's result range changed in the recalculated copy",
            ));
        }
        // A result the copy holds inside an array's range where the original
        // has no cell element would be lost the same way; this patch writes
        // values into cells that exist and inserts none, so it stands down.
        if copy.unplaced_array_result(&copy_tree, &extents, &cell_addresses(&tree)?) {
            return Err(refused(
                "an array formula's result has no cell in the original worksheet",
            ));
        }
        let values = copy.cached_values(copied, &cells)?;
        let mut edits = Vec::new();
        for (at, cell) in &cells {
            let Some(value) = values.get(at) else {
                continue;
            };
            formula_count += 1;
            edits.extend(write_value(&bytes, &tree, *cell, value)?);
        }
        if edits.is_empty() {
            continue;
        }
        let value =
            splice(&bytes, edits).map_err(|_| refused("a worksheet could not be rewritten"))?;
        book.package.replace_xml_part(&part, value)?;
    }
    Ok(CachedValuesWritten {
        bytes: book.package.export()?,
        formula_count,
    })
}

/// Whether formula cell `cell`, whose formula text is `formula` (a shared
/// member's is its group's), takes the value the recalculated copy holds.
/// Not a rich value's cell (`vm`), whose metadata describes the value it
/// holds and which the fallback does not compute, and not one whose formula
/// reads the file's location ([`LOCATION_FUNCTIONS`]): each keeps the value
/// it holds. An engine call (CALLS, FIX 2462).
fn takes_value(cell: &Node, formula: Option<&str>) -> bool {
    cell.attr("vm").is_none() && !formula.is_some_and(reads_location)
}

/// Whether `formula` calls one of [`LOCATION_FUNCTIONS`]. A string literal
/// (`"..."`) and a quoted sheet name (`'...'`) are text, never a call, so
/// they are blanked before the names are looked for (review #6434).
fn reads_location(formula: &str) -> bool {
    let upper = unquoted(formula).to_ascii_uppercase();
    LOCATION_FUNCTIONS.iter().any(|name| {
        upper.match_indices(name).any(|(at, _)| {
            let called = upper[at + name.len()..].trim_start().starts_with('(');
            let joined = upper[..at].chars().next_back().is_some_and(|before| {
                before.is_ascii_alphanumeric() || matches!(before, '_' | '.')
            });
            called && !joined
        })
    })
}

/// A sheet name as the application reads it, for matching names across two
/// packages: each `_xHHHH_` escape is one UTF-16 code unit, so an escaped
/// surrogate pair decodes to its one character (review #6434). A name whose
/// units do not form valid UTF-16 matches by its own text.
fn sheet_name_key(name: &str) -> String {
    let bytes = name.as_bytes();
    let mut units: Vec<u16> = Vec::with_capacity(name.len());
    let mut at = 0;
    while at < name.len() {
        let escape = bytes.get(at..at + 7).filter(|run| {
            run[0] == b'_'
                && run[1] == b'x'
                && run[6] == b'_'
                && run[2..6].iter().all(u8::is_ascii_hexdigit)
        });
        if let Some(run) = escape
            && let Ok(unit) =
                u16::from_str_radix(std::str::from_utf8(&run[2..6]).unwrap_or("0"), 16)
        {
            units.push(unit);
            at += 7;
            continue;
        }
        let Some(c) = name[at..].chars().next() else {
            break;
        };
        let mut buffer = [0u16; 2];
        units.extend_from_slice(c.encode_utf16(&mut buffer));
        at += c.len_utf8();
    }
    String::from_utf16(&units).unwrap_or_else(|_| name.to_owned())
}

/// The address (column, row) of every cell element of worksheet `tree`.
fn cell_addresses(tree: &XmlTree) -> Result<BTreeSet<(u32, u32)>> {
    let mut present = BTreeSet::new();
    let Some((data, _)) = tree.child(0, SML, "sheetData")? else {
        return Ok(present);
    };
    for (row, _) in tree.children(data).filter(|(_, node)| node.is(SML, "row")) {
        for (_, cell) in tree.children(row).filter(|(_, node)| node.is(SML, "c")) {
            if let Some(at) = cell.attr("r").and_then(cell_ref) {
                present.insert(at);
            }
        }
    }
    Ok(present)
}

/// `formula` with the inside of each string literal and quoted name replaced
/// by spaces: a doubled quote inside one is its own quote character, and an
/// unclosed one runs to the end.
fn unquoted(formula: &str) -> String {
    let mut out = String::with_capacity(formula.len());
    let mut open: Option<char> = None;
    let mut chars = formula.chars().peekable();
    while let Some(c) = chars.next() {
        match open {
            None => {
                if matches!(c, '"' | '\'') {
                    open = Some(c);
                }
                out.push(c);
            }
            Some(quote) if c == quote => {
                if chars.peek() == Some(&quote) {
                    chars.next();
                    out.push_str("  ");
                } else {
                    open = None;
                    out.push(c);
                }
            }
            Some(_) => out.push(' '),
        }
    }
    out
}

/// Each array formula of worksheet `tree` by its anchor cell (column, row),
/// with the range its results fill: the `ref` it names, or its own cell when
/// it names none or one that does not parse.
fn array_extents(tree: &XmlTree) -> Result<BTreeMap<(u32, u32), ((u32, u32), (u32, u32))>> {
    let mut extents = BTreeMap::new();
    let Some((data, _)) = tree.child(0, SML, "sheetData")? else {
        return Ok(extents);
    };
    for (row, _) in tree.children(data).filter(|(_, node)| node.is(SML, "row")) {
        for (index, cell) in tree.children(row).filter(|(_, node)| node.is(SML, "c")) {
            let Some(at) = cell.attr("r").and_then(cell_ref) else {
                continue;
            };
            let Some((_, f)) = tree
                .children(index)
                .find(|(_, child)| child.is(SML, "f") && child.attr("t") == Some("array"))
            else {
                continue;
            };
            let extent = f
                .attr("ref")
                .and_then(|reference| XlsxArea::parse(reference, XlsxLock::ArrayFormula))
                .map_or((at, at), |area| (area.first, area.last));
            extents.insert(at, extent);
        }
    }
    Ok(extents)
}

/// The cells of worksheet `tree` that take a recalculated value, each its
/// `c` element's index by (column, row): every cell with a formula, and
/// every cell inside a range of [`RANGED_FORMULAS`], as [`takes_value`]
/// admits them. A cell without a readable reference is left.
fn formula_cells(tree: &XmlTree) -> Result<BTreeMap<(u32, u32), usize>> {
    let mut taken = BTreeMap::new();
    let Some((data, _)) = tree.child(0, SML, "sheetData")? else {
        return Ok(taken);
    };
    // Each cell with its address and formula, the ranges results fill
    // without a formula, and each shared group's text by `si`.
    let mut cells: Vec<((u32, u32), usize, Option<&Node>)> = Vec::new();
    let mut ranges: Vec<XlsxArea> = Vec::new();
    let mut anchors: HashMap<&str, &str> = HashMap::new();
    for (row, _) in tree.children(data).filter(|(_, node)| node.is(SML, "row")) {
        for (index, cell) in tree.children(row).filter(|(_, node)| node.is(SML, "c")) {
            let Some(at) = cell.attr("r").and_then(cell_ref) else {
                continue;
            };
            let formula = tree
                .children(index)
                .map(|(_, child)| child)
                .find(|child| child.is(SML, "f"));
            if let Some(f) = formula {
                let kind = f.attr("t").unwrap_or("normal");
                // A one-cell range holds its own formula's cell alone.
                if RANGED_FORMULAS.contains(&kind)
                    && let Some(area) = f
                        .attr("ref")
                        .and_then(|reference| XlsxArea::parse(reference, XlsxLock::ArrayFormula))
                        .filter(|area| area.first != area.last)
                {
                    ranges.push(area);
                }
                if kind == "shared"
                    && !f.text.trim().is_empty()
                    && let Some(si) = f.attr("si")
                {
                    anchors.insert(si.trim(), f.text.as_str());
                }
            }
            cells.push((at, index, formula));
        }
    }
    for (at, index, formula) in cells {
        let text = formula.map(|f| match f.attr("si") {
            Some(si) if f.text.trim().is_empty() => {
                anchors.get(si.trim()).copied().unwrap_or_default()
            }
            _ => f.text.as_str(),
        });
        let computed = formula.is_some() || ranges.iter().any(|area| area.contains(at.0, at.1));
        if computed && takes_value(&tree.nodes[index], text) {
            taken.insert(at, index);
        }
    }
    Ok(taken)
}

impl Book {
    /// Whether this recalculated copy's worksheet `tree` caches a value inside
    /// one of the original's array ranges `extents` at an address `present`
    /// does not hold: a result the original has no cell element for.
    fn unplaced_array_result(
        &self,
        tree: &XmlTree,
        extents: &BTreeMap<(u32, u32), ((u32, u32), (u32, u32))>,
        present: &BTreeSet<(u32, u32)>,
    ) -> bool {
        let Ok(Some((data, _))) = tree.child(0, SML, "sheetData") else {
            return false;
        };
        let inside = |at: (u32, u32)| {
            extents.values().any(|(first, last)| {
                (first.0..=last.0).contains(&at.0) && (first.1..=last.1).contains(&at.1)
            })
        };
        tree.children(data)
            .filter(|(_, node)| node.is(SML, "row"))
            .flat_map(|(row, _)| tree.children(row).filter(|(_, node)| node.is(SML, "c")))
            .any(|(index, cell)| {
                cell.attr("r")
                    .and_then(cell_ref)
                    .is_some_and(|at| inside(at) && !present.contains(&at))
                    && self.cached(tree, index).is_some()
            })
    }

    /// The values this recalculated copy's worksheet `part` caches at the
    /// cells `wanted` names, by (column, row). A cell with no value, or one
    /// of a type the original's cell cannot take, has none.
    fn cached_values(
        &self,
        part: &str,
        wanted: &BTreeMap<(u32, u32), usize>,
    ) -> Result<BTreeMap<(u32, u32), Cached>> {
        let tree = parse(&self.package, part)?;
        let mut values = BTreeMap::new();
        let Some((data, _)) = tree.child(0, SML, "sheetData")? else {
            return Ok(values);
        };
        for (row, _) in tree.children(data).filter(|(_, node)| node.is(SML, "row")) {
            for (index, cell) in tree.children(row).filter(|(_, node)| node.is(SML, "c")) {
                let Some(at) = cell.attr("r").and_then(cell_ref) else {
                    continue;
                };
                if !wanted.contains_key(&at) {
                    continue;
                }
                if let Some(value) = self.cached(&tree, index) {
                    values.insert(at, value);
                }
            }
        }
        Ok(values)
    }

    /// The value cell `cell` of this copy's worksheet `tree` caches, as the
    /// original's cell takes it. A shared or inline string is escaped again
    /// as the original writes text; a formula string (`str`) keeps the text
    /// the copy wrote. A date (`d`), an unknown type and an unreadable value
    /// give none.
    fn cached(&self, tree: &XmlTree, cell: usize) -> Option<Cached> {
        let child = |name: &str| tree.children(cell).find(|(_, child)| child.is(SML, name));
        let stored = child("v").map(|(_, value)| value.text.as_str());
        let (kind, text) = match tree.nodes[cell].attr("t").unwrap_or("n") {
            "n" => {
                let text = stored?.trim();
                text.parse::<f64>()
                    .ok()
                    .filter(|number| number.is_finite())?;
                (None, text.to_owned())
            }
            "str" => (Some("str"), stored?.to_owned()),
            "s" => {
                let at = stored?.trim().parse::<usize>().ok()?;
                (Some("str"), encode_escapes(self.shared.get(at)?))
            }
            "inlineStr" => {
                let (item, _) = child("is")?;
                (Some("str"), encode_escapes(&string_item(tree, item)))
            }
            "b" => {
                let flag = match stored?.trim() {
                    "1" | "true" => "1",
                    "0" | "false" => "0",
                    _ => return None,
                };
                (Some("b"), flag.to_owned())
            }
            "e" => {
                let text = stored?.trim();
                if text.is_empty() {
                    return None;
                }
                (Some("e"), text.to_owned())
            }
            _ => return None,
        };
        Some(Cached { kind, text })
    }
}

/// The splices that write `value` into the original's formula cell `cell`
/// (its index in `tree`): its `t`, and its `v` text, each where it differs.
/// A number leaves a `t` of `n` and drops any other. A missing `v` goes in
/// after the cell's formula, else before its first child, else at its end;
/// an inline string the cell held goes, since its `v` now holds the value.
/// Every other attribute and child, and the bytes between them, stay.
fn write_value(bytes: &[u8], tree: &XmlTree, cell: usize, value: &Cached) -> Result<Vec<Splice>> {
    let node = &tree.nodes[cell];
    let mut edits: Vec<Splice> = Vec::new();
    match (value.kind, node.attr("t")) {
        (None, None | Some("n")) => {}
        (None, Some(_)) => edits.extend(drop_attribute(bytes, node, "t")),
        (Some(kind), Some(held)) if held == kind => {}
        (Some(kind), _) => edits.push(set_attribute(bytes, node, "t", kind)),
    }
    let children: Vec<&Node> = tree.children(cell).map(|(_, child)| child).collect();
    match children.iter().find(|child| child.is(SML, "v")) {
        Some(stored) if stored.text == value.text => {}
        Some(stored) => edits.extend(
            replace_text(bytes, stored, &value.text)
                .ok_or(refused("a worksheet cell could not be rewritten"))?,
        ),
        None => {
            let name = node.child_name("v");
            let element = format!("<{name}>{}</{name}>", escape_text(&value.text)).into_bytes();
            let point = children
                .iter()
                .find(|child| child.is(SML, "f"))
                .map(|formula| formula.span.end)
                .or_else(|| children.first().map(|child| child.span.start));
            edits.push(match point {
                Some(at) => (at..at, element),
                None => insert_end(bytes, node, &element),
            });
        }
    }
    for item in children.iter().filter(|child| child.is(SML, "is")) {
        edits.push((item.span.clone(), Vec::new()));
    }
    Ok(edits)
}
