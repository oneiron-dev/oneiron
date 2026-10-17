//! The add-part and remove-part doors. A new part, the content type that
//! declares it and the relationship that reaches it are written as checked
//! metadata edits under the package budgets, each call all-or-nothing; a
//! removed part leaves with its relationship part and its content type
//! override. `changed_parts` is the write set an export would actually carry,
//! for a caller's independent comparison with the parts its operation was
//! allowed to touch.
use super::{Added, Editability, Error, Limits, Package, Result, as_u32, check_limits};
use crate::ooxml::{CONTENT_TYPES, PACKAGE_RELATIONSHIPS, XmlTree, escape_text};
use crate::retained_opc::xml;
use flate2::{Compression, write::DeflateEncoder};
use std::collections::BTreeSet;
use std::io::Write;

const TYPES: &str = "[Content_Types].xml";
const RELS_TYPE: &str = "application/vnd.openxmlformats-package.relationships+xml";
const SEED_TYPES: &[u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/></Types>";
const SEED_RELS: &[u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"></Relationships>";
/// 1980-01-01 00:00, the earliest ZIP time: an added record carries no clock.
const DOS_DATE: u16 = 0x0021;
/// General-purpose flag bit 11: the name is UTF-8.
const UTF8: u16 = 0x0800;

/// One relationship of a source part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relationship {
    pub id: String,
    pub kind: String,
    /// The package part name of an internal target; the literal target of an
    /// external one.
    pub target: String,
    pub external: bool,
}

impl Added {
    fn new(name: &str, data: Vec<u8>) -> Result<Self> {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&data)
            .map_err(|_| Error::Edit("compression failed"))?;
        let deflated = encoder
            .finish()
            .map_err(|_| Error::Edit("compression failed"))?;
        Ok(Self {
            name: name.to_owned(),
            data,
            deflated,
        })
    }

    /// The local header, or with an `offset` the central record, that
    /// precedes this part's name.
    pub(super) fn header(&self, signature: u32, offset: Option<u32>) -> Result<Vec<u8>> {
        let name = self.name.as_bytes();
        let mut out = Vec::with_capacity(46 + name.len());
        out.extend_from_slice(&signature.to_le_bytes());
        if offset.is_some() {
            out.extend_from_slice(&20u16.to_le_bytes());
        }
        for field in [20u16, UTF8, 8, 0, DOS_DATE] {
            out.extend_from_slice(&field.to_le_bytes());
        }
        for field in [
            crc32fast::hash(&self.data),
            as_u32(self.deflated.len())?,
            as_u32(self.data.len())?,
        ] {
            out.extend_from_slice(&field.to_le_bytes());
        }
        let length = u16::try_from(name.len()).map_err(|_| Error::Edit("part name too long"))?;
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        if let Some(offset) = offset {
            out.extend_from_slice(&[0; 10]);
            out.extend_from_slice(&offset.to_le_bytes());
        }
        out.extend_from_slice(name);
        Ok(out)
    }

    fn archive_bytes(&self) -> usize {
        30 + 46 + 2 * self.name.len() + self.deflated.len()
    }
}

impl Package {
    /// A new, empty package holding only `[Content_Types].xml` (with the
    /// `rels` and `xml` defaults), under the same limits as an opened one.
    pub fn create(limits: Limits) -> Result<Self> {
        check_limits(limits)?;
        let mut eocd = vec![0; 22];
        eocd[..4].copy_from_slice(&super::EOCD.to_le_bytes());
        let package = Self {
            source: eocd.into(),
            entries: Vec::new(),
            cd_offset: 0,
            eocd: 0,
            limits,
            editability: Editability::Unsigned,
            added: vec![Added::new(TYPES, SEED_TYPES.to_vec())?],
        };
        package.check_budgets()?;
        Ok(package)
    }

    /// Add one new part and declare its content type, by override unless the
    /// extension's default already names it. XML parts must validate. A
    /// relationship part is written only by [`Package::relate`].
    pub fn add_part(&mut self, name: &str, content_type: &str, value: Vec<u8>) -> Result<()> {
        if name.to_ascii_lowercase().ends_with(".rels") || name == TYPES {
            return Err(Error::Edit("package metadata is written by its own door"));
        }
        self.transact(|package| package.insert(name, content_type, value))
    }

    /// Add a relationship of `kind` from `source` (`""` is the package) to
    /// the part `target`, creating the source's relationship part when it
    /// has none. Returns the new id, one past the highest `rId<n>` in use.
    pub fn relate(&mut self, source: &str, kind: &str, target: &str) -> Result<String> {
        self.add_relationship(source, kind, &relative(source, target), false)
    }

    /// Add an external relationship of `kind` from `source` to `target` (a
    /// URL, written as given with `TargetMode="External"`), as
    /// [`Package::relate`] does an internal one. Returns the new id.
    pub fn relate_external(&mut self, source: &str, kind: &str, target: &str) -> Result<String> {
        if target.is_empty() {
            return Err(Error::Edit("an external relationship without a target"));
        }
        self.add_relationship(source, kind, target, true)
    }

    fn add_relationship(
        &mut self,
        source: &str,
        kind: &str,
        target: &str,
        external: bool,
    ) -> Result<String> {
        let rels = rels_name(source);
        let current = self.part(&rels)?;
        let bytes = current.clone().unwrap_or_else(|| SEED_RELS.to_vec());
        let tree = XmlTree::parse(&bytes, self.limits.xml)
            .map_err(|_| Error::Edit("relationship part unreadable"))?;
        tree.root(PACKAGE_RELATIONSHIPS, "Relationships")
            .map_err(|_| Error::Edit("relationship part unreadable"))?;
        let next = tree
            .children(0)
            .filter_map(|(_, node)| node.attr("Id")?.strip_prefix("rId")?.parse::<u32>().ok())
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(Error::Edit("relationship id overflow"))?;
        let id = format!("rId{next}");
        let element = format!(
            "<{} Id=\"{id}\" Type=\"{}\" Target=\"{}\"{}/>",
            tree.nodes[0].child_name("Relationship"),
            escape_text(kind),
            escape_text(target),
            if external {
                " TargetMode=\"External\""
            } else {
                ""
            },
        );
        let value = splice_last_child(&tree, &bytes, &element)?;
        self.transact(|package| match current {
            Some(_) => package.write_metadata(&rels, value),
            None => package.insert(&rels, RELS_TYPE, value),
        })?;
        Ok(id)
    }

    /// Remove the part `name` from the archive with its relationship part and
    /// its content type override; an export carries none of their records.
    /// The caller first removes every relationship that reaches it.
    pub fn remove_part(&mut self, name: &str) -> Result<()> {
        if name.to_ascii_lowercase().ends_with(".rels") || name == TYPES {
            return Err(Error::Edit("package metadata is written by its own door"));
        }
        self.transact(|package| {
            package.drop_record(name)?;
            let rels = rels_name(name);
            if package.names().any(|held| held == rels) {
                package.drop_record(&rels)?;
            }
            package.undeclare(name)
        })
    }

    /// Drop each content type default whose extension no part has any more
    /// (after a removal took the last part that had it).
    pub fn prune_defaults(&mut self) -> Result<()> {
        self.transact(|package| {
            let bytes = package
                .part(TYPES)?
                .ok_or(Error::Edit("content types missing"))?;
            let tree = XmlTree::parse(&bytes, package.limits.xml)
                .map_err(|_| Error::Edit("content types unreadable"))?;
            tree.root(CONTENT_TYPES, "Types")
                .map_err(|_| Error::Edit("content types unreadable"))?;
            let used: BTreeSet<String> = package
                .names()
                .filter_map(|name| name.rsplit('/').next()?.rsplit_once('.'))
                .map(|(_, extension)| extension.to_ascii_lowercase())
                .collect();
            let unused: Vec<_> = tree
                .children(0)
                .filter(|(_, node)| {
                    node.is(CONTENT_TYPES, "Default")
                        && node.attr("Extension").is_some_and(|extension| {
                            !used.contains(&extension.to_ascii_lowercase())
                        })
                })
                .map(|(_, node)| node.span.clone())
                .collect();
            if unused.is_empty() {
                return Ok(());
            }
            let mut value = Vec::with_capacity(bytes.len());
            let mut at = 0;
            for span in unused {
                value.extend_from_slice(&bytes[at..span.start]);
                at = span.end;
            }
            value.extend_from_slice(&bytes[at..]);
            package.write_metadata(TYPES, value)
        })
    }

    /// Every part name reachable from `source` (`""` is the package) through
    /// internal relationships, `source` itself included when it is a part. A
    /// target the archive does not hold is named but leads nowhere.
    pub fn reachable(&self, source: &str) -> Result<BTreeSet<String>> {
        let mut seen = BTreeSet::new();
        if !source.is_empty() {
            seen.insert(source.to_owned());
        }
        let mut queue = vec![source.to_owned()];
        while let Some(part) = queue.pop() {
            for rel in self.relationships(&part)? {
                if !rel.external && seen.insert(rel.target.clone()) {
                    queue.push(rel.target);
                }
            }
        }
        Ok(seen)
    }

    /// Remove `source`'s relationship `id`. Its target stays in the archive,
    /// unreachable, until [`Self::remove_part`] takes it out.
    pub fn unrelate(&mut self, source: &str, id: &str) -> Result<()> {
        let rels = rels_name(source);
        let bytes = self
            .part(&rels)?
            .ok_or(Error::Edit("relationship part missing"))?;
        let tree = XmlTree::parse(&bytes, self.limits.xml)
            .map_err(|_| Error::Edit("relationship part unreadable"))?;
        tree.root(PACKAGE_RELATIONSHIPS, "Relationships")
            .map_err(|_| Error::Edit("relationship part unreadable"))?;
        let span = tree
            .children(0)
            .find(|(_, node)| {
                node.is(PACKAGE_RELATIONSHIPS, "Relationship") && node.attr("Id") == Some(id)
            })
            .ok_or(Error::Edit("no such relationship"))?
            .1
            .span
            .clone();
        let value = [&bytes[..span.start], &bytes[span.end..]].concat();
        self.transact(|package| package.write_metadata(&rels, value))
    }

    /// Add the relationship part of `source`, which has none, as written: a
    /// cloned part keeps its relationship ids, which [`Package::relate`]
    /// would mint afresh.
    pub(crate) fn add_relationship_part(&mut self, source: &str, value: Vec<u8>) -> Result<()> {
        let tree = XmlTree::parse(&value, self.limits.xml)
            .map_err(|_| Error::Edit("relationship part unreadable"))?;
        tree.root(PACKAGE_RELATIONSHIPS, "Relationships")
            .map_err(|_| Error::Edit("relationship part unreadable"))?;
        let rels = rels_name(source);
        self.transact(|package| package.insert(&rels, RELS_TYPE, value))
    }

    /// The relationships `source` declares, internal targets resolved to part
    /// names. A source without a relationship part has none.
    pub fn relationships(&self, source: &str) -> Result<Vec<Relationship>> {
        let Some(bytes) = self.part(&rels_name(source))? else {
            return Ok(Vec::new());
        };
        let tree = XmlTree::parse(&bytes, self.limits.xml)
            .map_err(|_| Error::Invalid("relationship part unreadable"))?;
        tree.root(PACKAGE_RELATIONSHIPS, "Relationships")
            .map_err(|_| Error::Invalid("relationship part unreadable"))?;
        tree.children(0)
            .filter(|(_, node)| node.is(PACKAGE_RELATIONSHIPS, "Relationship"))
            .map(|(_, node)| {
                let (Some(id), Some(kind), Some(target)) =
                    (node.attr("Id"), node.attr("Type"), node.attr("Target"))
                else {
                    return Err(Error::Invalid("incomplete relationship"));
                };
                let external = node.attr("TargetMode") == Some("External");
                Ok(Relationship {
                    id: id.to_owned(),
                    kind: kind.to_owned(),
                    target: if external {
                        target.to_owned()
                    } else {
                        resolve(source, target)?
                    },
                    external,
                })
            })
            .collect()
    }

    /// Replace a part that is itself an OPC package (an embedded workbook).
    /// The new bytes must open under this package's limits.
    pub fn replace_nested_package(&mut self, name: &str, value: Vec<u8>) -> Result<()> {
        Package::open(&value, self.limits)?;
        self.transact(|package| package.write_metadata(name, value))
    }

    /// Parts an export would write differently from the source: edited and
    /// removed retained parts, then added parts, in archive order.
    pub fn changed_parts(&self) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|entry| entry.replacement.is_some() || entry.removed)
            .map(|entry| entry.name.as_str())
            .chain(self.added.iter().map(|part| part.name.as_str()))
            .collect()
    }

    pub(super) fn added_bytes(&self) -> usize {
        self.added
            .iter()
            .fold(0usize, |sum, part| sum.saturating_add(part.data.len()))
    }

    pub(super) fn added_archive_bytes(&self) -> Result<usize> {
        self.added.iter().try_fold(0usize, |sum, part| {
            sum.checked_add(part.archive_bytes())
                .ok_or(Error::Edit("edited ZIP size overflow"))
        })
    }

    pub(super) fn rewrite_added(&mut self, name: &str, value: Vec<u8>) -> Result<()> {
        xml::ValidatedXmlPart::parse(&value, self.limits.xml)?;
        self.transact(|package| package.write_metadata(name, value))
    }

    /// Run `edit` on a copy and keep it only when every budget still holds;
    /// the retained source is shared, so a copy costs only the edits.
    fn transact<T>(&mut self, edit: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        if self.editability != Editability::Unsigned {
            return Err(Error::Edit("signed or unsupported metadata is read-only"));
        }
        let mut next = self.clone();
        let value = edit(&mut next)?;
        next.check_budgets()?;
        *self = next;
        Ok(value)
    }

    fn insert(&mut self, name: &str, content_type: &str, value: Vec<u8>) -> Result<()> {
        let lower = name.to_ascii_lowercase();
        if name.is_empty()
            || name.starts_with('/')
            || name.contains(['\\', '\0'])
            || name.split('/').any(|part| matches!(part, "" | "." | ".."))
            || lower.starts_with("_xmlsignatures/")
            || self
                .entries
                .iter()
                .filter(|entry| !entry.removed)
                .map(|entry| (entry.name.trim_end_matches('/'), entry.is_directory()))
                .chain(self.added.iter().map(|part| (part.name.as_str(), false)))
                .any(|(existing, directory)| {
                    let existing = existing.to_ascii_lowercase();
                    // A directory record may hold parts; a part may not.
                    existing == lower
                        || (!directory && lower.starts_with(&format!("{existing}/")))
                        || existing.starts_with(&format!("{lower}/"))
                })
        {
            return Err(Error::Edit("unsafe or duplicate part name"));
        }
        if lower.ends_with(".xml") || lower.ends_with(".rels") {
            xml::ValidatedXmlPart::parse(&value, self.limits.xml)?;
        }
        self.declare(name, content_type)?;
        self.added.push(Added::new(name, value)?);
        Ok(())
    }

    /// Declare `name`'s content type unless an override or its extension's
    /// default already does; a conflicting override refuses.
    fn declare(&mut self, name: &str, content_type: &str) -> Result<()> {
        let bytes = self
            .part(TYPES)?
            .ok_or(Error::Edit("content types missing"))?;
        let tree = XmlTree::parse(&bytes, self.limits.xml)
            .map_err(|_| Error::Edit("content types unreadable"))?;
        tree.root(CONTENT_TYPES, "Types")
            .map_err(|_| Error::Edit("content types unreadable"))?;
        let part_name = format!("/{name}");
        let file = name.rsplit('/').next().unwrap_or(name);
        let extension = file.rsplit_once('.').map(|(_, extension)| extension);
        let mut default = None;
        for (_, node) in tree.children(0) {
            if node.is(CONTENT_TYPES, "Override")
                && node
                    .attr("PartName")
                    .is_some_and(|declared| declared.eq_ignore_ascii_case(&part_name))
            {
                return if node.attr("ContentType") == Some(content_type) {
                    Ok(())
                } else {
                    Err(Error::Edit("conflicting content type override"))
                };
            }
            if node.is(CONTENT_TYPES, "Default")
                && extension.is_some_and(|extension| {
                    node.attr("Extension")
                        .is_some_and(|declared| declared.eq_ignore_ascii_case(extension))
                })
            {
                default = node.attr("ContentType");
            }
        }
        if default == Some(content_type) {
            return Ok(());
        }
        let element = format!(
            "<{} PartName=\"{}\" ContentType=\"{}\"/>",
            tree.nodes[0].child_name("Override"),
            escape_text(&part_name),
            escape_text(content_type),
        );
        let value = splice_last_child(&tree, &bytes, &element)?;
        self.write_metadata(TYPES, value)
    }

    /// Install bytes for an existing retained or added part.
    fn write_metadata(&mut self, name: &str, value: Vec<u8>) -> Result<()> {
        if name.to_ascii_lowercase().ends_with(".xml") || name.ends_with(".rels") {
            xml::ValidatedXmlPart::parse(&value, self.limits.xml)?;
        }
        if let Some(part) = self.added.iter_mut().find(|part| part.name == name) {
            *part = Added::new(name, value)?;
            return Ok(());
        }
        let index = self
            .entries
            .iter()
            .position(|entry| entry.name == name && !entry.removed)
            .ok_or(Error::Edit("part missing"))?;
        let old = self.expanded(&self.entries[index])?;
        self.commit_replacement(index, old, value)
    }

    /// Take one part's record out: an added part is dropped, a retained one
    /// is marked removed.
    fn drop_record(&mut self, name: &str) -> Result<()> {
        if let Some(at) = self.added.iter().position(|part| part.name == name) {
            self.added.remove(at);
            return Ok(());
        }
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.name == name && !entry.is_directory() && !entry.removed)
            .ok_or(Error::Edit("part missing"))?;
        entry.removed = true;
        entry.replacement = None;
        Ok(())
    }

    /// Drop `name`'s content type override, when it has one; an extension
    /// default stays, other parts may still use it.
    fn undeclare(&mut self, name: &str) -> Result<()> {
        let bytes = self
            .part(TYPES)?
            .ok_or(Error::Edit("content types missing"))?;
        let tree = XmlTree::parse(&bytes, self.limits.xml)
            .map_err(|_| Error::Edit("content types unreadable"))?;
        tree.root(CONTENT_TYPES, "Types")
            .map_err(|_| Error::Edit("content types unreadable"))?;
        let part_name = format!("/{name}");
        let Some(span) = tree
            .children(0)
            .find(|(_, node)| {
                node.is(CONTENT_TYPES, "Override")
                    && node
                        .attr("PartName")
                        .is_some_and(|declared| declared.eq_ignore_ascii_case(&part_name))
            })
            .map(|(_, node)| node.span.clone())
        else {
            return Ok(());
        };
        let value = [&bytes[..span.start], &bytes[span.end..]].concat();
        self.write_metadata(TYPES, value)
    }

    fn check_budgets(&self) -> Result<()> {
        let count = self.entries.iter().filter(|entry| !entry.removed).count() + self.added.len();
        if count > self.limits.entries || count >= usize::from(u16::MAX) {
            return Err(Error::Edit("entry limit"));
        }
        if self
            .added
            .iter()
            .any(|part| part.data.len() > self.limits.part_bytes)
        {
            return Err(Error::Edit("edited part size limit"));
        }
        let total = self
            .entries
            .iter()
            .filter(|entry| !entry.removed)
            .try_fold(self.added_bytes(), |sum, entry| {
                sum.checked_add(
                    entry
                        .replacement
                        .as_ref()
                        .map_or(entry.uncompressed, Vec::len),
                )
                .ok_or(Error::Edit("edited package size overflow"))
            })?;
        if total > self.limits.expanded_bytes {
            return Err(Error::Edit("edited package size limit"));
        }
        self.check_export_size(usize::MAX, None)
    }
}

/// Insert `element` as the root's last child; a self-closing root is opened.
fn splice_last_child(tree: &XmlTree, bytes: &[u8], element: &str) -> Result<Vec<u8>> {
    let root = &tree.nodes[0];
    if root.empty {
        let close = root.span.end - 2;
        if bytes.get(close..root.span.end) != Some(&b"/>"[..]) {
            return Err(Error::Edit("unreadable package metadata root"));
        }
        let mut out = bytes[..close].to_vec();
        out.extend_from_slice(format!(">{element}</{}>", root.qualified).as_bytes());
        out.extend_from_slice(&bytes[root.span.end..]);
        return Ok(out);
    }
    let at = root.content.end;
    let mut out = Vec::with_capacity(bytes.len() + element.len());
    out.extend_from_slice(&bytes[..at]);
    out.extend_from_slice(element.as_bytes());
    out.extend_from_slice(&bytes[at..]);
    Ok(out)
}

/// `ppt/slides/slide1.xml` → `ppt/slides/_rels/slide1.xml.rels`; the
/// package itself (`""`) → `_rels/.rels`.
pub fn rels_name(source: &str) -> String {
    match source.rsplit_once('/') {
        Some((folder, file)) => format!("{folder}/_rels/{file}.rels"),
        None if source.is_empty() => "_rels/.rels".to_owned(),
        None => format!("_rels/{source}.rels"),
    }
}

fn folder(source: &str) -> &str {
    source.rsplit_once('/').map_or("", |(folder, _)| folder)
}

/// The relative reference from `source`'s folder to the part `target`.
fn relative(source: &str, target: &str) -> String {
    let from: Vec<&str> = folder(source)
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let to: Vec<&str> = target.split('/').collect();
    let shared = from
        .iter()
        .zip(&to)
        .take_while(|(left, right)| left == right)
        .count()
        .min(to.len().saturating_sub(1));
    let mut out = "../".repeat(from.len() - shared);
    out.push_str(&to[shared..].join("/"));
    out
}

/// Resolve a relationship target against `source`'s folder.
fn resolve(source: &str, target: &str) -> Result<String> {
    let base = match target.strip_prefix('/') {
        Some(_) => "",
        None => folder(source),
    };
    let mut parts: Vec<&str> = base.split('/').filter(|s| !s.is_empty()).collect();
    for segment in target.trim_start_matches('/').split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                parts
                    .pop()
                    .ok_or(Error::Invalid("relationship target escapes the package"))?;
            }
            name => parts.push(name),
        }
    }
    Ok(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::{relative, resolve};
    use crate::deck::fixture::limits;
    use crate::retained_opc::Package;
    use std::io::Write;

    #[test]
    fn directory_records_hold_new_parts_and_empty_relationship_roots_open() {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        writer.add_directory("doc/", options).unwrap();
        for (name, body) in [
            (
                "[Content_Types].xml",
                r#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/></Types>"#,
            ),
            ("doc/a.xml", "<a/>"),
            (
                "doc/_rels/a.xml.rels",
                r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships" />"#,
            ),
        ] {
            writer.start_file(name, options).unwrap();
            writer.write_all(body.as_bytes()).unwrap();
        }
        let bytes = writer.finish().unwrap().into_inner();
        let mut package = Package::open(&bytes, limits()).unwrap();
        package
            .add_part("doc/b.xml", "application/xml", b"<b/>".to_vec())
            .unwrap();
        assert!(
            package
                .add_part("doc/a.xml/c.xml", "application/xml", b"<c/>".to_vec())
                .is_err()
        );
        let id = package
            .relate("doc/a.xml", "urn:test", "doc/b.xml")
            .unwrap();
        assert_eq!(id, "rId1");
        let reopened = Package::open(&package.export().unwrap(), limits()).unwrap();
        let rels = reopened.relationships("doc/a.xml").unwrap();
        assert_eq!(
            (rels[0].id.as_str(), rels[0].target.as_str()),
            ("rId1", "doc/b.xml")
        );
    }

    #[test]
    fn relative_targets_round_trip_through_resolution() {
        for (source, target, href) in [
            (
                "ppt/slides/slide1.xml",
                "ppt/charts/chart1.xml",
                "../charts/chart1.xml",
            ),
            (
                "ppt/charts/chart1.xml",
                "ppt/embeddings/book1.xlsx",
                "../embeddings/book1.xlsx",
            ),
            ("", "ppt/presentation.xml", "ppt/presentation.xml"),
            (
                "xl/workbook.xml",
                "xl/worksheets/sheet1.xml",
                "worksheets/sheet1.xml",
            ),
        ] {
            assert_eq!(relative(source, target), href);
            assert_eq!(resolve(source, href).unwrap(), target);
        }
        assert!(resolve("a.xml", "../b.xml").is_err());
    }
}
