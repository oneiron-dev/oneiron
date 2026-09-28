//! Modern threaded comments using retained XML surgery and a derived part allowlist.

use super::archive::{Archive, enforce_allowlist};
use super::identities::{inspect_parts, resolve_anchor, text};
use super::limits::PptxOperationalLimits;
use super::links::{self, Parts, comment_part, put};
use super::package::*;
use super::xml::{Xml, escape, replace};
use crate::entity_id::EntityId;
use std::collections::{BTreeMap, BTreeSet};

const PC: &str = "http://schemas.microsoft.com/office/powerpoint/2013/main/command";

/// Applies only modern-comment operations. It never edits slide content, repairs
/// identities, fetches relationships, or claims application-level validation.
/// An empty batch returns the exact original archive, including signatures.
pub fn comment_patch(
    base: &[u8],
    patches: &[PptxCommentPatch],
) -> Result<PptxCommentEffects, PptxError> {
    comment_patch_with_limits(base, patches, &PptxOperationalLimits::default())
}

pub(super) fn comment_patch_with_limits(
    base: &[u8],
    patches: &[PptxCommentPatch],
    limits: &PptxOperationalLimits,
) -> Result<PptxCommentEffects, PptxError> {
    patch_with_mints(base, patches, None, limits)
}

pub(super) fn patch_with_mints(
    base: &[u8],
    patches: &[PptxCommentPatch],
    mints: Option<&[(u64, u32)]>,
    limits: &PptxOperationalLimits,
) -> PatchResult<PptxCommentEffects> {
    if !limits.valid() || patches.len() > limits.max_patches {
        return Err(PptxError::InvalidPatch);
    }
    let archive = Archive::read(base)?;
    let mut inspection = inspect_parts(&archive.parts, limits)?;
    let mut parts = archive.parts.clone();
    let mut allowed = BTreeSet::new();
    let mut minted = Vec::new();
    let mut anchors = Vec::new();
    if patches.is_empty() {
        if mints.is_some_and(|m| !m.is_empty()) {
            return Err(PptxError::InvalidPatch);
        }
        return Ok(PptxCommentEffects {
            new_bytes: base.to_vec(),
            touched_parts: allowed,
            minted_slide_creation_ids: minted,
            anchors,
        });
    }
    links::validate_links(&parts, limits)?;
    let derived_allowed = derive_allowed_parts(&parts, &inspection, patches, limits)?;
    for patch in patches {
        let author = canonical_guid(&patch.author.guid)?;
        let thread = guid(patch.thread_id);
        let comment = guid(patch.comment_id);
        let index = comment_index(&parts, &inspection, limits)?;
        match &patch.action {
            PptxCommentAction::Add { target, text: body } => {
                if patch.comment_id != patch.thread_id
                    || target.slide == 0
                    || target.shape_fingerprint.is_some() && target.shape_creation_id.is_none()
                {
                    return Err(PptxError::InvalidPatch);
                }
                if index.ids.contains(&comment) {
                    return Err(PptxError::DuplicateComment);
                }
                let slide_index = if let Some(id) = target.slide_creation_id {
                    inspection
                        .slides
                        .iter()
                        .position(|s| s.creation_id == Some(id))
                } else {
                    inspection
                        .slides
                        .iter()
                        .position(|s| s.slide == target.slide)
                }
                .ok_or(PptxError::SlideNotFound)?;
                if inspection.slides[slide_index].creation_id.is_none() {
                    let slide = &inspection.slides[slide_index];
                    let id = if let Some(mints) = mints {
                        let matches: Vec<_> =
                            mints.iter().filter(|(s, _)| *s == slide.slide).collect();
                        let [(_, id)] = matches.as_slice() else {
                            return Err(PptxError::InvalidPatch);
                        };
                        *id
                    } else {
                        // Draw UUID entropy; never increment the largest surviving id.
                        (0..128)
                            .find_map(|_| {
                                let hash = blake3::hash(EntityId::now().as_bytes());
                                let id = u32::from_le_bytes(hash.as_bytes()[..4].try_into().ok()?);
                                (!inspection.slides.iter().any(|s| s.creation_id == Some(id)))
                                    .then_some(id)
                            })
                            .ok_or(PptxError::AmbiguousAnchor)?
                    };
                    if inspection.slides.iter().any(|s| s.creation_id == Some(id)) {
                        return Err(PptxError::AmbiguousAnchor);
                    }
                    links::append_extension(
                        &mut parts,
                        &mut allowed,
                        &slide.part,
                        true,
                        &format!(
                            "<p:ext xmlns:p=\"{P}\" uri=\"{SLIDE_ID_EXT}\"><p14:creationId xmlns:p14=\"{P14}\" val=\"{id}\"/></p:ext>"
                        ),
                        limits,
                    )?;
                    minted.push((slide.slide, id));
                    inspection.slides[slide_index].creation_id = Some(id);
                }
                let slide = &inspection.slides[slide_index];
                let outcome = resolve_anchor(slide, target)?;
                links::ensure_author(&mut parts, &mut allowed, &patch.author, limits)?;
                let part = links::ensure_comment_part(
                    &mut parts,
                    &mut allowed,
                    slide,
                    patch.thread_id,
                    limits,
                )?;
                let fragment = format!(
                    "<p188:cm xmlns:p188=\"{P188}\" id=\"{comment}\" authorId=\"{author}\" created=\"{}\">{}{}</p188:cm>",
                    timestamp(patch.at)?,
                    anchor_xml(&outcome),
                    text_body(body)?
                );
                let xml = Xml::parse_with_limits(text(&parts, &part)?, limits)?;
                let root = xml.root(P188, "cmLst")?;
                let output = xml.append(root, &fragment);
                put(&mut parts, &mut allowed, &part, output);
                anchors.push((patch.thread_id, outcome));
            }
            PptxCommentAction::Reply { text: body } => {
                if index.ids.contains(&comment) {
                    return Err(PptxError::DuplicateComment);
                }
                let (part, _) = index
                    .threads
                    .get(&thread)
                    .ok_or(PptxError::ThreadNotFound)?;
                links::ensure_author(&mut parts, &mut allowed, &patch.author, limits)?;
                let fragment = format!(
                    "<p188:reply xmlns:p188=\"{P188}\" id=\"{comment}\" authorId=\"{author}\" created=\"{}\">{}</p188:reply>",
                    timestamp(patch.at)?,
                    text_body(body)?
                );
                let xml = Xml::parse_with_limits(text(&parts, part)?, limits)?;
                let node = find_thread(&xml, &thread)?;
                let output = if let Some(list) = xml.child(node, P188, "replyLst")? {
                    xml.append(list, &fragment)
                } else {
                    let fragment =
                        format!("<p188:replyLst xmlns:p188=\"{P188}\">{fragment}</p188:replyLst>");
                    // replyLst precedes txBody/extLst in CT_Comment's sequence.
                    let at = xml
                        .nodes
                        .iter()
                        .find(|n| {
                            n.parent == Some(node)
                                && n.ns == P188
                                && matches!(n.name.as_str(), "txBody" | "extLst")
                        })
                        .map(|n| n.start);
                    if let Some(at) = at {
                        replace(xml.text, at..at, &fragment)
                    } else {
                        xml.append(node, &fragment)
                    }
                };
                put(&mut parts, &mut allowed, part, output);
            }
            PptxCommentAction::Resolve { resolved } => {
                if patch.comment_id != patch.thread_id {
                    return Err(PptxError::InvalidPatch);
                }
                let (part, owner) = index
                    .threads
                    .get(&thread)
                    .ok_or(PptxError::ThreadNotFound)?;
                if owner != &author {
                    return Err(PptxError::NotAuthor);
                }
                // Verify the selected display name against the imported author
                // before the receipt may persist it. This is read-only for an
                // existing GUID: Resolve never creates an author-part write.
                links::ensure_author(&mut parts, &mut allowed, &patch.author, limits)?;
                let xml = Xml::parse_with_limits(text(&parts, part)?, limits)?;
                let node = find_thread(&xml, &thread)?;
                let status = if *resolved { "resolved" } else { "active" };
                if xml.nodes[node].attr("status").unwrap_or("active") != status {
                    let output = xml.set_attr(node, "status", status)?;
                    put(&mut parts, &mut allowed, part, output);
                }
            }
        }
    }
    if mints.is_some_and(|expected| expected != minted.as_slice()) {
        return Err(PptxError::InvalidPatch);
    }
    let touched = enforce_allowlist(&archive.parts, &parts, &derived_allowed)?;
    if !touched.is_empty() && !inspection.signature_parts.is_empty() {
        return Err(PptxError::SignedPackage);
    }
    links::validate_links(&parts, limits)?;
    comment_index(&parts, &inspection, limits)?;
    for part in &touched {
        Xml::parse_with_limits(text(&parts, part)?, limits)?;
    }
    let new_bytes = archive.write(&parts)?;
    let actual = Archive::read(&new_bytes)?;
    if actual.parts != parts {
        return Err(PptxError::PartDiffOutsideTransaction);
    }
    Ok(PptxCommentEffects {
        new_bytes,
        touched_parts: touched,
        minted_slide_creation_ids: minted,
        anchors,
    })
}

struct CommentIndex {
    threads: BTreeMap<String, (String, String)>,
    ids: BTreeSet<String>,
}
fn comment_index(
    parts: &Parts,
    inspection: &PptxInspection,
    limits: &PptxOperationalLimits,
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
fn find_thread(xml: &Xml<'_>, id: &str) -> PatchResult<usize> {
    for node in xml.children(0, P188, "cm") {
        if canonical_guid(xml.nodes[node].required("id")?)? == id {
            return Ok(node);
        }
    }
    Err(PptxError::ThreadNotFound)
}
fn timestamp(at: u64) -> PatchResult<String> {
    let value = i64::try_from(at)
        .ok()
        .and_then(chrono::DateTime::from_timestamp_millis)
        .ok_or(PptxError::InvalidPatch)?;
    // Keep the schema's four-digit Gregorian year profile.
    if at > 253_402_300_799_999 {
        return Err(PptxError::InvalidPatch);
    }
    Ok(value.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
}
fn text_body(text: &str) -> PatchResult<String> {
    if text.trim().is_empty()
        || text.len() > crate::anchored_annotation::ANNOTATION_COMMENT_TEXT_MAX_BYTES
    {
        return Err(PptxError::InvalidPatch);
    }
    Ok(format!(
        "<p188:txBody xmlns:p188=\"{P188}\" xmlns:a=\"{A}\"><a:bodyPr/><a:lstStyle/><a:p><a:r><a:t xml:space=\"preserve\">{}</a:t></a:r></a:p></p188:txBody>",
        escape(text)?
    ))
}
fn anchor_xml(anchor: &PptxAnchorOutcome) -> String {
    let (sld_id, id, pos) = match anchor {
        PptxAnchorOutcome::UnknownAnchor { .. } => return "<p188:unknownAnchor/>".into(),
        PptxAnchorOutcome::Slide {
            sld_id,
            creation_id,
            ..
        } => (*sld_id, *creation_id, None),
        PptxAnchorOutcome::Shape {
            sld_id,
            creation_id,
            x,
            y,
            ..
        } => (*sld_id, *creation_id, Some((*x, *y))),
    };
    let mut xml = format!(
        "<pc:sldMkLst xmlns:pc=\"{PC}\"><pc:docMk/><pc:sldMk cId=\"{id}\" sldId=\"{sld_id}\"/></pc:sldMkLst>"
    );
    if let Some((x, y)) = pos {
        xml.push_str(&format!("<p188:pos x=\"{x}\" y=\"{y}\"/>"));
    }
    xml
}

/// IDs of exported root comments that explicitly have no resolved anchor.
/// The annotation sweep uses this actual-byte evidence to pin those threads.
#[cfg(test)]
pub(crate) fn unknown_anchor_threads(bytes: &[u8]) -> Result<BTreeSet<EntityId>, PptxError> {
    unknown_anchor_threads_with_limits(bytes, &PptxOperationalLimits::default())
}

pub(crate) fn unknown_anchor_threads_with_limits(
    bytes: &[u8],
    limits: &PptxOperationalLimits,
) -> Result<BTreeSet<EntityId>, PptxError> {
    let archive = Archive::read(bytes)?;
    let inspection = inspect_parts(&archive.parts, limits)?;
    let mut result = BTreeSet::new();
    for slide in &inspection.slides {
        let Some(part) = comment_part(&archive.parts, slide, limits)? else {
            continue;
        };
        let xml = Xml::parse_with_limits(archive.text(&part)?, limits)?;
        for node in xml.children(0, P188, "cm") {
            if xml.child(node, P188, "unknownAnchor")?.is_some() {
                let id = uuid::Uuid::parse_str(xml.nodes[node].required("id")?)
                    .map_err(|_| PptxError::InvalidXml)?;
                if let Ok(id) = EntityId::from_bytes(*id.as_bytes()) {
                    result.insert(id);
                }
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
    patches: &[PptxCommentPatch],
    limits: &PptxOperationalLimits,
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
        let thread = guid(patch.thread_id);
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
