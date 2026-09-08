//! Workbook inspect scanners.

use super::opc::{self, OpcPackage, PartClass};
use super::{EditWarning, MutationMode, OfficeFormat, WarningCode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};

/// One sheet in workbook order (1-based `index`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SheetSummary {
    pub name: String,
    pub index: u32,
}

/// A best-effort cross-sheet formula dependency edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossSheetDep {
    pub from_sheet: String,
    pub to_sheet: String,
}

/// The inspect-first structure summary produced before any edit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructureSummary {
    pub format: OfficeFormat,
    pub sheets: Vec<SheetSummary>,
    pub defined_names: Vec<String>,
    pub has_pivots: bool,
    pub has_charts: bool,
    pub has_macros: bool,
    pub cross_sheet_dependencies: Vec<CrossSheetDep>,
    /// Parts classified unknown/unsupported — the passthrough set.
    pub unknown_parts: Vec<String>,
}

/// Runs the mandatory inspect-first stage over an already-parsed package.
#[must_use]
pub(super) fn inspect(package: &OpcPackage, format: OfficeFormat) -> StructureSummary {
    let has_pivots = package
        .names()
        .any(|n| n.starts_with("xl/pivotTables/") || n.starts_with("xl/pivotCache/"));
    let has_charts = package.names().any(|n| n.starts_with("xl/charts/"));
    let has_macros = package.contains("xl/vbaProject.bin");

    let sheets = scan_sheets(package);
    let defined_names = scan_defined_names(package);
    let cross_sheet_dependencies = scan_cross_sheet_deps(package, &sheets);
    let unknown_parts = package
        .names()
        .filter(|n| opc::classify(n) == PartClass::Unknown)
        .map(str::to_owned)
        .collect();

    StructureSummary {
        format,
        sheets,
        defined_names,
        has_pivots,
        has_charts,
        has_macros,
        cross_sheet_dependencies,
        unknown_parts,
    }
}

pub(super) fn mutation_mode_for(summary: &StructureSummary) -> (MutationMode, Vec<EditWarning>) {
    let mut warnings = Vec::new();
    if summary.has_pivots {
        warnings.push(EditWarning::new(
            WarningCode::HeavyPivotMinimalMutation,
            "workbook contains pivot tables; limiting to minimal-mutation passthrough",
        ));
    }
    if summary.has_charts {
        warnings.push(EditWarning::new(
            WarningCode::ChartsPresentMinimalMutation,
            "workbook contains charts; limiting to minimal-mutation passthrough",
        ));
    }
    if summary.has_macros {
        warnings.push(EditWarning::new(
            WarningCode::MacrosPresentMinimalMutation,
            "workbook contains VBA macros; limiting to minimal-mutation passthrough",
        ));
    }
    let mode = if warnings.is_empty() {
        MutationMode::Full
    } else {
        MutationMode::Minimal
    };
    (mode, warnings)
}

fn scan_sheets(package: &OpcPackage) -> Vec<SheetSummary> {
    let Some(workbook) = package.part("xl/workbook.xml") else {
        return Vec::new();
    };
    let xml = String::from_utf8_lossy(workbook);
    scan_tag_attr(&xml, "<sheet", "name")
        .into_iter()
        .enumerate()
        .map(|(i, name)| SheetSummary {
            name,
            index: (i as u32) + 1,
        })
        .collect()
}

fn scan_defined_names(package: &OpcPackage) -> Vec<String> {
    let Some(workbook) = package.part("xl/workbook.xml") else {
        return Vec::new();
    };
    let xml = String::from_utf8_lossy(workbook);
    scan_tag_attr(&xml, "<definedName", "name")
}

fn scan_cross_sheet_deps(package: &OpcPackage, sheets: &[SheetSummary]) -> Vec<CrossSheetDep> {
    let name_by_part = worksheet_name_by_part(package);
    // BTreeSet dedupes (replacing the O(n) `Vec::contains`) and yields a stable
    // ordering regardless of part iteration order.
    let mut deps: BTreeSet<(String, String)> = BTreeSet::new();
    for part in package.parts() {
        // Resolve this worksheet part to its sheet name via the workbook
        // relationships; fall back to the positional `sheetN.xml == Nth sheet`
        // heuristic only when the rels join did not cover it (e.g. rels absent).
        let Some(from_name) = name_by_part
            .get(&part.name)
            .map(String::as_str)
            .or_else(|| {
                worksheet_ordinal(&part.name)
                    .and_then(|ordinal| sheets.iter().find(|sheet| sheet.index == ordinal))
                    .map(|sheet| sheet.name.as_str())
            })
        else {
            continue;
        };
        let xml = String::from_utf8_lossy(&part.data);
        for formula in extract_formulas(&xml) {
            // A cross-sheet reference always contains '!'; skip the common
            // same-sheet formula before the O(sheets) comparison.
            if !formula.contains('!') {
                continue;
            }
            for other in sheets {
                if other.name == from_name {
                    continue;
                }
                if formula_references_sheet(&formula, &other.name) {
                    deps.insert((from_name.to_owned(), other.name.clone()));
                }
            }
        }
    }
    deps.into_iter()
        .map(|(from_sheet, to_sheet)| CrossSheetDep {
            from_sheet,
            to_sheet,
        })
        .collect()
}

/// Maps each worksheet part path to its workbook sheet name by joining
/// `xl/_rels/workbook.xml.rels` (relationship id -> Target) with
/// `xl/workbook.xml`'s `<sheet name=.. r:id=..>` entries — the authoritative
/// binding, since sheet part names need not match workbook order. Empty when
/// either part is absent, so the caller falls back to the positional heuristic.
fn worksheet_name_by_part(package: &OpcPackage) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let (Some(workbook), Some(rels)) = (
        package.part("xl/workbook.xml"),
        package.part("xl/_rels/workbook.xml.rels"),
    ) else {
        return out;
    };
    let rels_xml = String::from_utf8_lossy(rels);
    let id_to_target: HashMap<String, String> =
        scan_tag_attr_pairs(&rels_xml, "<Relationship", "Id", "Target")
            .into_iter()
            .collect();
    let workbook_xml = String::from_utf8_lossy(workbook);
    for (name, rid) in scan_tag_attr_pairs(&workbook_xml, "<sheet", "name", "r:id") {
        if let Some(target) = id_to_target.get(&rid) {
            out.insert(join_xl_target(target), name);
        }
    }
    out
}

/// Resolves a `xl/_rels/workbook.xml.rels` Target (relative to `xl/`, or
/// absolute from the package root) to a full part path.
fn join_xl_target(target: &str) -> String {
    target
        .strip_prefix('/')
        .map_or_else(|| format!("xl/{target}"), str::to_owned)
}

fn worksheet_ordinal(name: &str) -> Option<u32> {
    let stem = name
        .strip_prefix("xl/worksheets/sheet")?
        .strip_suffix(".xml")?;
    stem.parse().ok()
}

fn formula_references_sheet(formula: &str, sheet: &str) -> bool {
    formula.contains(&format!("{sheet}!")) || formula.contains(&format!("'{sheet}'!"))
}

/// Extracts the inline expression from every `<f>` / `<f ...attrs>` element.
/// Shared and array formulas carry attributes (`<f t="shared" si="0">`), so we
/// match the tag prefix, skip to the end of the open tag, then read to `</f>`.
/// A self-closing `<f .../>` (a shared-formula reference with no inline text)
/// yields nothing.
fn extract_formulas(xml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(idx) = rest.find("<f") {
        let after = &rest[idx + 2..];
        // The char after "<f" must end the tag name, so `<font>`/`<fill>` and
        // similar are not mistaken for a formula element.
        let is_f_element = after
            .chars()
            .next()
            .is_none_or(|c| c == '>' || c == '/' || c.is_ascii_whitespace());
        if !is_f_element {
            rest = after;
            continue;
        }
        let Some(open_end) = after.find('>') else {
            break;
        };
        if after[..open_end].ends_with('/') {
            rest = &after[open_end + 1..];
            continue;
        }
        let content = &after[open_end + 1..];
        let Some(close) = content.find("</f>") else {
            break;
        };
        out.push(content[..close].to_owned());
        rest = &content[close + "</f>".len()..];
    }
    out
}

pub(super) fn scan_tag_attr(xml: &str, tag: &str, attr: &str) -> Vec<String> {
    let needle = format!("{attr}=\"");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(pos) = rest.find(tag) {
        let after_tag = &rest[pos + tag.len()..];
        let tag_end = after_tag.find('>').unwrap_or(after_tag.len());
        let body = &after_tag[..tag_end];
        if let Some(value) = attr_value(body, &needle) {
            out.push(value);
        }
        rest = &after_tag[tag_end..];
    }
    out
}

/// Like [`scan_tag_attr`] but reads two attributes from the same tag, keeping
/// only tags that carry both (order-independent).
fn scan_tag_attr_pairs(xml: &str, tag: &str, attr1: &str, attr2: &str) -> Vec<(String, String)> {
    let needle1 = format!("{attr1}=\"");
    let needle2 = format!("{attr2}=\"");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(pos) = rest.find(tag) {
        let after_tag = &rest[pos + tag.len()..];
        let tag_end = after_tag.find('>').unwrap_or(after_tag.len());
        let body = &after_tag[..tag_end];
        if let (Some(v1), Some(v2)) = (attr_value(body, &needle1), attr_value(body, &needle2)) {
            out.push((v1, v2));
        }
        rest = &after_tag[tag_end..];
    }
    out
}

/// Reads a double-quoted attribute value from a tag body given the search
/// needle `name="` (already including the opening quote).
pub(super) fn attr_value(tag_body: &str, needle: &str) -> Option<String> {
    let start = tag_body.find(needle)? + needle.len();
    let end = tag_body[start..].find('"')?;
    Some(tag_body[start..start + end].to_owned())
}
