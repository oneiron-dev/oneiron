//! Reading the package for its links: the external relationship targets the
//! engine keeps, the workbook's link list joined to its relationships and
//! content types, and each link part's sheet names and saved values.

use std::collections::BTreeMap;

use formualizer_common::parse_a1_1based;
use oneiron_docedit::ooxml::Node;
use oneiron_docedit::retained_opc::Package;

use super::{LinkedBook, LinkedBooks};
use crate::Result;
use crate::workbook::{ESCAPED_TEXT, escaped};
use crate::xml::{DOC_REL, MAIN, REL, Xml, unsupported};

/// The content type the edit gate requires of a link part.
const LINK_CONTENT_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.spreadsheetml.externalLink+xml";

const UNJOINED: &str = "external link list the edit gate cannot join";

/// The fork's link reader (`formualizer_workbook`'s `external_links.rs`)
/// matches `externalReference`, `Relationship`, `externalBook`, `sheetName`,
/// `sheetData`, `cell` and `v` by local name anywhere in their part, and takes
/// the first attribute of each name it reads whatever its namespace. An
/// element outside its SpreadsheetML place, or an attribute of that name in
/// another namespace, is read where Excel reads none (a vendor extension's
/// `u:cell` would replace a saved value).
const OUT_OF_PLACE: &str = "external link markup outside its SpreadsheetML place";

/// Refuse an external relationship target the engine cannot keep as Excel
/// does: anything other than a hyperlink, a link's path or a pivot cache's
/// external source. A relationship part the check cannot read fails closed to
/// the fallback, as it did before linked workbooks were read natively.
pub(crate) fn external_targets(package: &Package) -> Result<()> {
    let limits = package.resources();
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
        let limits = package.resources();
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
        let xml = Xml::parse(part, package.resources())?;
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
        let xml = Xml::parse(&bytes, package.resources()).map_err(|_| unreadable())?;
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
