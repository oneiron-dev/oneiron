//! Modern PPTX comment topology and patch seam.
//! Entry: `comment_patch`.
//! patch owns mutations; this module owns topology, indexing and allowed parts.
//!
//! Modern threaded comments using retained XML surgery and a derived part allowlist.

mod patch;

use super::archive::{Archive, enforce_allowlist};
use super::identities::{inspect_parts, resolve_anchor, resolve_positions, text};
use super::links::{self, Parts, comment_part, put};
use super::model::*;
use super::xml::{Xml, escape, replace};
use crate::resource::Resources;
use std::collections::{BTreeMap, BTreeSet};

pub use patch::comment_patch;

const PC: &str = "http://schemas.microsoft.com/office/powerpoint/2013/main/command";

struct CommentIndex {
    threads: BTreeMap<String, (String, String)>,
    ids: BTreeSet<String>,
}
fn comment_index(
    parts: &Parts,
    inspection: &PptxInspection,
    limits: &Codec<'_>,
) -> PatchResult<CommentIndex> {
    let mut index = CommentIndex {
        threads: BTreeMap::new(),
        ids: BTreeSet::new(),
    };
    let mut used_parts = BTreeSet::new();
    let mut authors = BTreeSet::new();
    if parts.contains_key(AUTHORS) {
        let rels = super::identities::relationships(parts, PRESENTATION_RELS, limits)?;
        let author_rels: Vec<_> = rels.iter().filter(|r| r.kind == AUTHOR_REL).collect();
        if !matches!(author_rels.as_slice(), [rel] if !rel.external && super::identities::resolve_target("ppt/presentation.xml", &rel.target)? == AUTHORS)
        {
            return Err(PptxError::InvalidReference);
        }
        links::require_content_type(parts, AUTHORS, links::AUTHORS_TYPE, limits)?;
        let xml = Xml::parse_with_limits(text(parts, AUTHORS)?, limits)?;
        let root = xml.root(P188, "authorLst")?;
        for author in xml.children(root, P188, "author") {
            let author = &xml.nodes[author];
            author.required("name")?;
            author.required("userId")?;
            author.required("providerId")?;
            if !authors.insert(canonical_guid(author.required("id")?)?) {
                return Err(PptxError::AuthorConflict);
            }
        }
    }
    for slide in &inspection.slides {
        let Some(part) = comment_part(parts, slide, limits)? else {
            continue;
        };
        if !used_parts.insert(part.clone()) {
            return Err(PptxError::InvalidReference);
        }
        links::require_content_type(parts, &part, links::COMMENTS_TYPE, limits)?;
        let xml = Xml::parse_with_limits(text(parts, &part)?, limits)?;
        let root = xml.root(P188, "cmLst")?;
        for node in xml.children(root, P188, "cm") {
            let cm = &xml.nodes[node];
            cm.required("created")?;
            if cm
                .attr("status")
                .is_some_and(|s| !matches!(s, "active" | "resolved" | "closed"))
            {
                return Err(PptxError::InvalidXml);
            }
            let id = canonical_guid(cm.required("id")?)?;
            let author = canonical_guid(cm.required("authorId")?)?;
            if !authors.contains(&author) {
                return Err(PptxError::InvalidReference);
            }
            if !index.ids.insert(id.clone()) {
                return Err(PptxError::DuplicateComment);
            }
            index.threads.insert(id, (part.clone(), author));
            for reply in xml.descendants(node, P188, "reply") {
                let reply = &xml.nodes[reply];
                if !authors.contains(&canonical_guid(reply.required("authorId")?)?) {
                    return Err(PptxError::InvalidReference);
                }
                if !index.ids.insert(canonical_guid(reply.required("id")?)?) {
                    return Err(PptxError::DuplicateComment);
                }
            }
        }
    }
    Ok(index)
}

/// GUIDs of exported root comments that explicitly have no resolved anchor,
/// as their sixteen bytes. The annotation sweep uses this actual-byte
/// evidence to pin those threads.
pub fn unknown_anchor_threads(
    bytes: &[u8],
    limits: &PptxCommentLimits,
    resources: &Resources,
) -> Result<BTreeSet<[u8; 16]>, PptxError> {
    if !limits.valid() {
        return Err(PptxError::InvalidPatch);
    }
    let limits = &Codec { limits, resources };
    let archive = Archive::read(bytes, limits)?;
    let inspection = inspect_parts(&archive.parts, limits)?;
    let mut result = BTreeSet::new();
    for slide in &inspection.slides {
        let Some(part) = comment_part(&archive.parts, slide, limits)? else {
            continue;
        };
        let xml = Xml::parse_with_limits(archive.text(&part)?, limits)?;
        for node in xml.children(0, P188, "cm") {
            if xml.child(node, P188, "unknownAnchor")?.is_some() {
                let id =
                    guid_bytes(xml.nodes[node].required("id")?).ok_or(PptxError::InvalidXml)?;
                result.insert(id);
            }
        }
    }
    Ok(result)
}

/// Independent format policy: derive permitted parts from the immutable base
/// topology and requested operations, not from the writer's observed writes.
fn derive_allowed_parts(
    parts: &Parts,
    inspection: &PptxInspection,
    patches: &[PptxCommentEdit],
    limits: &Codec<'_>,
) -> PatchResult<BTreeSet<String>> {
    let mut allowed = BTreeSet::new();
    let mut threads = comment_index(parts, inspection, limits)?.threads;
    let mut slides: BTreeMap<String, String> = BTreeMap::new();
    for slide in &inspection.slides {
        if let Some(part) = comment_part(parts, slide, limits)? {
            slides.insert(slide.part.clone(), part);
        }
    }
    for patch in patches {
        let thread = canonical_guid(&patch.thread_id)?;
        let part = match &patch.action {
            PptxCommentAction::Add { target, .. } => {
                let slide = if let Some(id) = target.slide_creation_id {
                    inspection.slides.iter().find(|s| s.creation_id == Some(id))
                } else {
                    inspection.slides.iter().find(|s| s.slide == target.slide)
                }
                .ok_or(PptxError::SlideNotFound)?;
                allowed.insert(slide.part.clone());
                allowed.insert(super::identities::rels_path(&slide.part)?);
                let part = slides
                    .entry(slide.part.clone())
                    .or_insert_with(|| {
                        format!(
                            "ppt/comments/modernComment_{}.xml",
                            thread.trim_matches(['{', '}'])
                        )
                    })
                    .clone();
                threads.insert(thread, (part.clone(), canonical_guid(&patch.author.guid)?));
                part
            }
            PptxCommentAction::Reply { .. } | PptxCommentAction::Resolve { .. } => threads
                .get(&thread)
                .ok_or(PptxError::ThreadNotFound)?
                .0
                .clone(),
        };
        allowed.insert(part);
        if !matches!(patch.action, PptxCommentAction::Resolve { .. }) {
            allowed.extend([
                AUTHORS.to_owned(),
                PRESENTATION_RELS.to_owned(),
                links::CONTENT_TYPES.to_owned(),
            ]);
        }
    }
    Ok(allowed)
}
