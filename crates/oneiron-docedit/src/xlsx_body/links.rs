//! The workbook's links to itself (FIX 9080). An external link
//! (`xl/externalLinks/externalLinkN.xml`) whose path names the file the
//! workbook is opened from reads this workbook's own sheets, as `[0]` does,
//! so a sheet layout carries the formulas through it and the link's sheet
//! list as it carries the workbook's own references.
use super::read::decode_escapes;
use super::{Book, REL, Result, SML, encode_escapes, parse, refused};
use crate::edit::xml::{set_attribute, splice};
use crate::ooxml::XmlTree;
use crate::xlsx_shift::{SheetFate, retarget_sheets};
use std::collections::BTreeSet;

/// Where Excel records the folder it last saved the workbook in
/// (`x15ac:absPath`).
const ABSOLUTE_PATH: &str = "http://schemas.microsoft.com/office/spreadsheetml/2010/11/ac";

/// The links a formula names this workbook through.
pub(super) struct OwnLinks {
    /// Each link's bracketed text in a formula: `0` always, `1` for the
    /// first link of the workbook's `externalReferences`.
    pub(super) names: BTreeSet<String>,
    /// The link parts among them.
    pub(super) parts: Vec<String>,
}

impl Book {
    /// The links to this workbook: `[0]`, and each external link whose path
    /// names `location`, the file the workbook is opened from
    /// (`C:\Reports\Budget.xlsx`). A bare file name (`Budget.xlsx`) is in
    /// the folder Excel last saved the workbook in, when it recorded one.
    /// Without a location, `[0]` alone.
    pub(super) fn own_links(&self, location: Option<&str>) -> Result<OwnLinks> {
        let mut own = OwnLinks {
            names: BTreeSet::from(["0".to_owned()]),
            parts: Vec::new(),
        };
        let Some(location) = location else {
            return Ok(own);
        };
        let tree = parse(&self.package, &self.part)?;
        let Some((list, _)) = tree.child(0, SML, "externalReferences")? else {
            return Ok(own);
        };
        let saved = tree
            .nodes
            .iter()
            .find(|node| node.is(ABSOLUTE_PATH, "absPath"))
            .and_then(|node| node.attr("url"))
            .filter(|folder| folder.ends_with(['\\', '/']));
        let location = match saved {
            Some(folder) if !location.contains(['\\', '/']) => format!("{folder}{location}"),
            _ => location.to_owned(),
        };
        let rels = self.package.relationships(&self.part)?;
        for (index, (_, reference)) in tree
            .children(list)
            .filter(|(_, node)| node.is(SML, "externalReference"))
            .enumerate()
        {
            let Some(part) = reference.attr_ns(REL, "id").and_then(|id| {
                rels.iter()
                    .find(|rel| {
                        rel.id == id && !rel.external && rel.kind.ends_with("/externalLink")
                    })
                    .map(|rel| rel.target.clone())
            }) else {
                continue;
            };
            if self
                .link_path(&part)?
                .is_some_and(|path| names_location(&path, &location))
            {
                own.names.insert((index + 1).to_string());
                own.parts.push(part);
            }
        }
        Ok(own)
    }

    /// The path link part `part` reads its workbook from, as its
    /// relationship writes it; `None` for a DDE or OLE link or one without.
    fn link_path(&self, part: &str) -> Result<Option<String>> {
        let tree = parse(&self.package, part)?;
        let Some((_, book)) = tree.child(0, SML, "externalBook")? else {
            return Ok(None);
        };
        let Some(id) = book.attr_ns(REL, "id") else {
            return Ok(None);
        };
        Ok(self
            .package
            .relationships(part)?
            .into_iter()
            .find(|rel| rel.id == id && rel.external)
            .map(|rel| rel.target))
    }

    /// Carry a sheet layout into each of the workbook's links to itself:
    /// a renamed sheet's name in the link's sheet list and in its names'
    /// formulas. A deleted sheet keeps its place in the list, by which the
    /// link's saved values are numbered.
    pub(super) fn retarget_own_links(
        &mut self,
        parts: &[String],
        fate: &dyn Fn(&str) -> SheetFate,
    ) -> Result<()> {
        let order = self.order.clone();
        for part in parts {
            let Some(bytes) = self.package.part(part)? else {
                continue;
            };
            let tree = XmlTree::parse(&bytes, self.package.resources())?;
            let mut edits = Vec::new();
            for node in &tree.nodes {
                if node.is(SML, "sheetName")
                    && let Some(name) = node.attr("val")
                    && let SheetFate::Rename(to) = fate(&decode_escapes(name))
                {
                    edits.push(set_attribute(&bytes, node, "val", &encode_escapes(&to)));
                } else if node.is(SML, "definedName")
                    && let Some(text) = node
                        .attr("refersTo")
                        .and_then(|formula| retarget_sheets(formula, &order, fate))
                {
                    edits.push(set_attribute(&bytes, node, "refersTo", &text));
                }
            }
            if edits.is_empty() {
                continue;
            }
            let value =
                splice(&bytes, edits).map_err(|_| refused("a link part could not be rewritten"))?;
            self.package.replace_xml_part(part, value)?;
        }
        Ok(())
    }
}

/// Whether link path `target`, as a relationship writes it
/// (`file:///C:\Reports\Budget.xlsx`, `Budget.xlsx`, `../Reports/Budget.xlsx`,
/// a web address), names the file at `location`, a relative path read from
/// its folder; a location with no folder is named by its bare file name
/// alone. Separators, percent escapes and case aside, as Windows and Excel
/// compare paths.
fn names_location(target: &str, location: &str) -> bool {
    let (target, location) = (normalized(target), normalized(location));
    // A drive, a scheme or a leading separator makes a path absolute.
    let absolute = target.starts_with('/')
        || target
            .split('/')
            .next()
            .is_some_and(|first| first.contains(':'));
    let joined = match location.rsplit_once('/') {
        Some((folder, _)) if !absolute => format!("{folder}/{target}"),
        _ => target,
    };
    resolved(&joined) == resolved(&location)
}

/// `path` percent-decoded, with `/` for each separator, in lower case, and
/// a `file:` address as the path it names (`file:///C:/x` is `c:/x`,
/// `file://server/share` is `//server/share`).
fn normalized(path: &str) -> String {
    let path = percent_decoded(path).replace('\\', "/").to_lowercase();
    let Some(rest) = path.strip_prefix("file:") else {
        return path;
    };
    let bare = rest.trim_start_matches('/');
    let drive = bare.as_bytes().get(1) == Some(&b':');
    match rest.len() - bare.len() {
        _ if drive => bare.to_owned(),
        0 | 1 => rest.to_owned(),
        2 => format!("//{bare}"),
        3 => format!("/{bare}"),
        _ => format!("//{bare}"),
    }
}

/// `path` with each `%XX` escape decoded.
fn percent_decoded(path: &str) -> String {
    if !path.contains('%') {
        return path.to_owned();
    }
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes
            .get(i + 1..i + 3)
            .filter(|pair| pair.iter().all(u8::is_ascii_hexdigit))
            .and_then(|pair| std::str::from_utf8(pair).ok())
            .and_then(|pair| u8::from_str_radix(pair, 16).ok());
        match (bytes[i], hex) {
            (b'%', Some(byte)) => {
                out.push(byte);
                i += 3;
            }
            (byte, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `path` with its `.` and `..` segments resolved; a `..` stops at the
/// root, a drive or a scheme.
fn resolved(path: &str) -> String {
    let mut kept: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "." => {}
            ".." if kept
                .last()
                .is_some_and(|last| !last.is_empty() && !last.ends_with(':')) =>
            {
                kept.pop();
            }
            ".." => {}
            _ => kept.push(segment),
        }
    }
    kept.join("/")
}
