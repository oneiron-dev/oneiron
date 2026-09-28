//! OPC link additions and modern-comment part discovery; retained XML insertion only.

use super::identities::{relationships, rels_path, resolve_target, text};
use super::limits::PptxOperationalLimits;
use super::package::*;
use super::xml::{Xml, escape};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const CONTENT_TYPES: &str = "[Content_Types].xml";
pub(super) const COMMENTS_TYPE: &str = "application/vnd.ms-powerpoint.comments+xml";
pub(super) const AUTHORS_TYPE: &str = "application/vnd.ms-powerpoint.authors+xml";
pub(super) type Parts = BTreeMap<String, Vec<u8>>;

pub(super) fn put(parts: &mut Parts, allowed: &mut BTreeSet<String>, name: &str, xml: String) {
    allowed.insert(name.to_owned());
    parts.insert(name.to_owned(), xml.into_bytes());
}
pub(super) fn append_extension(
    parts: &mut Parts,
    allowed: &mut BTreeSet<String>,
    part: &str,
    common: bool,
    fragment: &str,
    limits: &PptxOperationalLimits,
) -> PatchResult<()> {
    let xml = Xml::parse_with_limits(text(parts, part)?, limits)?;
    let root = xml.root(P, "sld")?;
    let parent = if common {
        xml.child(root, P, "cSld")?.ok_or(PptxError::InvalidXml)?
    } else {
        root
    };
    let output = if let Some(list) = xml.child(parent, P, "extLst")? {
        xml.append(list, fragment)
    } else {
        xml.append(
            parent,
            &format!("<p:extLst xmlns:p=\"{P}\">{fragment}</p:extLst>"),
        )
    };
    put(parts, allowed, part, output);
    Ok(())
}
pub(super) fn add_relationship(
    parts: &mut Parts,
    allowed: &mut BTreeSet<String>,
    name: &str,
    kind: &str,
    target: &str,
    limits: &PptxOperationalLimits,
) -> PatchResult<String> {
    let rels = relationships(parts, name, limits)?;
    let matches: Vec<_> = rels.iter().filter(|r| r.kind == kind).collect();
    match matches.as_slice() {
        [existing] if !existing.external && existing.target == target => {
            return Ok(existing.id.clone());
        }
        [] => {}
        _ => return Err(PptxError::InvalidReference),
    }
    let id = (1u64..)
        .map(|i| format!("rId{i}"))
        .find(|id| rels.iter().all(|r| r.id != *id))
        .ok_or(PptxError::InvalidReference)?;
    let empty = format!("<Relationships xmlns=\"{REL}\"/>");
    let original = if parts.contains_key(name) {
        text(parts, name)?
    } else {
        &empty
    };
    let xml = Xml::parse_with_limits(original, limits)?;
    let root = xml.root(REL, "Relationships")?;
    let fragment = format!(
        "<Relationship xmlns=\"{REL}\" Id=\"{}\" Type=\"{}\" Target=\"{}\"/>",
        escape(&id)?,
        escape(kind)?,
        escape(target)?
    );
    let output = xml.append(root, &fragment);
    put(parts, allowed, name, output);
    Ok(id)
}
pub(super) fn content_type(
    parts: &mut Parts,
    allowed: &mut BTreeSet<String>,
    part: &str,
    kind: &str,
    limits: &PptxOperationalLimits,
) -> PatchResult<()> {
    let xml = Xml::parse_with_limits(text(parts, CONTENT_TYPES)?, limits)?;
    let root = xml.root(CT, "Types")?;
    let name = format!("/{part}");
    let matching: Vec<_> = xml
        .children(root, CT, "Override")
        .into_iter()
        .filter(|i| xml.nodes[*i].attr("PartName") == Some(&name))
        .collect();
    match matching.as_slice() {
        [n] if xml.nodes[*n].attr("ContentType") == Some(kind) => return Ok(()),
        [] => {}
        _ => return Err(PptxError::InvalidReference),
    }
    let output = xml.append(
        root,
        &format!(
            "<Override xmlns=\"{CT}\" PartName=\"{}\" ContentType=\"{}\"/>",
            escape(&name)?,
            escape(kind)?
        ),
    );
    put(parts, allowed, CONTENT_TYPES, output);
    Ok(())
}
pub(super) fn comment_part(
    parts: &Parts,
    slide: &PptxSlideIdentity,
    limits: &PptxOperationalLimits,
) -> PatchResult<Option<String>> {
    let xml = Xml::parse_with_limits(text(parts, &slide.part)?, limits)?;
    let root = xml.root(P, "sld")?;
    let mut rid = None;
    if let Some(list) = xml.child(root, P, "extLst")? {
        for ext in xml.children(list, P, "ext") {
            if xml.nodes[ext].attr("uri") != Some(COMMENT_EXT) {
                continue;
            }
            let child = xml
                .child(ext, P188, "commentRel")?
                .ok_or(PptxError::InvalidReference)?;
            let id = xml.nodes[child]
                .attr_ns(R, "id")
                .ok_or(PptxError::InvalidReference)?;
            if rid.replace(id).is_some() {
                return Err(PptxError::InvalidReference);
            }
        }
    }
    let rels = relationships(parts, &rels_path(&slide.part)?, limits)?;
    let comments: Vec<_> = rels.iter().filter(|r| r.kind == COMMENT_REL).collect();
    match (rid, comments.as_slice()) {
        (None, []) => Ok(None),
        (Some(id), [rel]) if rel.id == id && !rel.external => {
            let target = resolve_target(&slide.part, &rel.target)?;
            // A comment transaction cannot use a hostile relationship to widen
            // the write set to a theme, slide, or arbitrary XML part.
            if !target.starts_with("ppt/comments/") || !target.ends_with(".xml") {
                return Err(PptxError::InvalidReference);
            }
            let comments = Xml::parse_with_limits(text(parts, &target)?, limits)?;
            comments.root(P188, "cmLst")?;
            Ok(Some(target))
        }
        _ => Err(PptxError::InvalidReference),
    }
}
pub(super) fn ensure_comment_part(
    parts: &mut Parts,
    allowed: &mut BTreeSet<String>,
    slide: &PptxSlideIdentity,
    thread: crate::EntityId,
    limits: &PptxOperationalLimits,
) -> PatchResult<String> {
    if let Some(part) = comment_part(parts, slide, limits)? {
        return Ok(part);
    }
    let file = format!(
        "modernComment_{}.xml",
        guid(thread).trim_matches(['{', '}'])
    );
    let part = format!("ppt/comments/{file}");
    if parts.contains_key(&part) {
        return Err(PptxError::InvalidReference);
    }
    put(
        parts,
        allowed,
        &part,
        format!("<p188:cmLst xmlns:p188=\"{P188}\"/>"),
    );
    let rid = add_relationship(
        parts,
        allowed,
        &rels_path(&slide.part)?,
        COMMENT_REL,
        &format!("../comments/{file}"),
        limits,
    )?;
    append_extension(
        parts,
        allowed,
        &slide.part,
        false,
        &format!(
            "<p:ext xmlns:p=\"{P}\" uri=\"{COMMENT_EXT}\"><p188:commentRel xmlns:p188=\"{P188}\" xmlns:r=\"{R}\" r:id=\"{rid}\"/></p:ext>"
        ),
        limits,
    )?;
    content_type(parts, allowed, &part, COMMENTS_TYPE, limits)?;
    Ok(part)
}
pub(super) fn ensure_author(
    parts: &mut Parts,
    allowed: &mut BTreeSet<String>,
    author: &PptxAuthor,
    limits: &PptxOperationalLimits,
) -> PatchResult<()> {
    let id = canonical_guid(&author.guid)?;
    if author.name.trim().is_empty() || author.name.len() > limits.max_author_name_bytes {
        return Err(PptxError::InvalidPatch);
    }
    let rels = relationships(parts, PRESENTATION_RELS, limits)?;
    let authors: Vec<_> = rels.iter().filter(|r| r.kind == AUTHOR_REL).collect();
    match authors.as_slice() {
        [] if !parts.contains_key(AUTHORS) => {
            add_relationship(
                parts,
                allowed,
                PRESENTATION_RELS,
                AUTHOR_REL,
                "authors.xml",
                limits,
            )?;
            put(
                parts,
                allowed,
                AUTHORS,
                format!("<p188:authorLst xmlns:p188=\"{P188}\"/>"),
            );
        }
        [rel]
            if !rel.external && resolve_target("ppt/presentation.xml", &rel.target)? == AUTHORS => {
        }
        _ => return Err(PptxError::InvalidReference),
    }
    let xml = Xml::parse_with_limits(text(parts, AUTHORS)?, limits)?;
    let root = xml.root(P188, "authorLst")?;
    let mut ids = BTreeSet::new();
    let mut exists = false;
    for n in xml.children(root, P188, "author") {
        let n = &xml.nodes[n];
        let existing =
            canonical_guid(n.required("id")?).map_err(|_| PptxError::InvalidReference)?;
        n.required("userId")?;
        n.required("providerId")?;
        if !ids.insert(existing.clone()) {
            return Err(PptxError::AuthorConflict);
        }
        if existing == id {
            if n.required("name")? != author.name {
                return Err(PptxError::AuthorConflict);
            }
            exists = true;
        }
    }
    if !exists {
        // A neutral stable identity, not an invented email/provider account.
        let output=xml.append(root,&format!("<p188:author xmlns:p188=\"{P188}\" id=\"{id}\" name=\"{}\" userId=\"{id}\" providerId=\"\"/>",escape(&author.name)?));
        put(parts, allowed, AUTHORS, output);
    }
    content_type(parts, allowed, AUTHORS, AUTHORS_TYPE, limits)
}
/// Resolve all internal links without fetching external relationships.
pub(super) fn validate_links(parts: &Parts, limits: &PptxOperationalLimits) -> PatchResult<()> {
    let types = Xml::parse_with_limits(text(parts, CONTENT_TYPES)?, limits)?;
    let root = types.root(CT, "Types")?;
    let mut names = BTreeSet::new();
    for n in types.children(root, CT, "Override") {
        let name = types.nodes[n]
            .required("PartName")?
            .strip_prefix('/')
            .ok_or(PptxError::InvalidReference)?;
        if !parts.contains_key(name) || !names.insert(name) {
            return Err(PptxError::InvalidReference);
        }
    }
    for name in parts.keys().filter(|n| n.ends_with(".rels")) {
        let source = if name == "_rels/.rels" {
            String::new()
        } else {
            let (dir, file) = name
                .rsplit_once("/_rels/")
                .ok_or(PptxError::InvalidReference)?;
            format!(
                "{dir}/{}",
                file.strip_suffix(".rels")
                    .ok_or(PptxError::InvalidReference)?
            )
        };
        for rel in relationships(parts, name, limits)? {
            if !rel.external && !parts.contains_key(&resolve_target(&source, &rel.target)?) {
                return Err(PptxError::InvalidReference);
            }
        }
    }
    Ok(())
}

pub(super) fn require_content_type(
    parts: &Parts,
    part: &str,
    kind: &str,
    limits: &PptxOperationalLimits,
) -> PatchResult<()> {
    let xml = Xml::parse_with_limits(text(parts, CONTENT_TYPES)?, limits)?;
    let root = xml.root(CT, "Types")?;
    let name = format!("/{part}");
    let matches: Vec<_> = xml
        .children(root, CT, "Override")
        .into_iter()
        .filter(|i| xml.nodes[*i].attr("PartName") == Some(&name))
        .collect();
    match matches.as_slice() {
        [n] if xml.nodes[*n].attr("ContentType") == Some(kind) => Ok(()),
        _ => Err(PptxError::InvalidReference),
    }
}
