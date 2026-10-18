//! Modern threaded comments using retained XML surgery and a derived part allowlist.

use super::archive::{Archive, enforce_allowlist};
use super::identities::{inspect_parts, resolve_anchor, resolve_positions, text};
use super::links::{self, Parts, comment_part, put};
use super::model::*;
use super::xml::{Xml, escape, replace};
use std::collections::{BTreeMap, BTreeSet};

const PC: &str = "http://schemas.microsoft.com/office/powerpoint/2013/main/command";

/// Applies only modern-comment operations, in order. It never edits slide
/// content, repairs identities, fetches relationships, or claims
/// application-level validation. An empty batch returns the exact original
/// archive, including signatures. A comment's text is written whole: no
/// storage budget of the caller's bounds it here.
pub fn comment_patch(
    base: &[u8],
    edits: &[PptxCommentEdit],
    mints: SlideMints<'_>,
    limits: &PptxCommentLimits,
) -> Result<PptxCommentEffects, PptxError> {
    if !limits.valid() {
        return Err(PptxError::InvalidPatch);
    }
    let archive = Archive::read(base, limits)?;
    let mut inspection = inspect_parts(&archive.parts, limits)?;
    resolve_positions(base, &archive.parts, &mut inspection, limits);
    let mut parts = archive.parts.clone();
    let mut allowed = BTreeSet::new();
    let mut minted = Vec::new();
    let mut anchors = Vec::new();
    // Each new thread's part, id, target and resolved anchor, read back
    // after the write.
    let mut written = Vec::new();
    if edits.is_empty() {
        if matches!(mints, SlideMints::Replay(m) if !m.is_empty()) {
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
    let derived_allowed = derive_allowed_parts(&parts, &inspection, edits, limits)?;
    for patch in edits {
        let author = canonical_guid(&patch.author.guid)?;
        let thread = canonical_guid(&patch.thread_id)?;
        let comment = canonical_guid(&patch.comment_id)?;
        let index = comment_index(&parts, &inspection, limits)?;
        match &patch.action {
            PptxCommentAction::Add { target, text: body } => {
                if comment != thread
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
                    let id = match mints {
                        SlideMints::Replay(mints) => {
                            let matches: Vec<_> =
                                mints.iter().filter(|(s, _)| *s == slide.slide).collect();
                            let [(_, id)] = matches.as_slice() else {
                                return Err(PptxError::InvalidPatch);
                            };
                            *id
                        }
                        // Draw from the caller's entropy; never increment the
                        // largest surviving id.
                        SlideMints::Draw(entropy) => (0..128u32)
                            .find_map(|draw| {
                                let mut hash = blake3::Hasher::new();
                                hash.update(entropy);
                                hash.update(&slide.slide.to_le_bytes());
                                hash.update(&draw.to_le_bytes());
                                let hash = hash.finalize();
                                let id = u32::from_le_bytes(hash.as_bytes()[..4].try_into().ok()?);
                                (!inspection.slides.iter().any(|s| s.creation_id == Some(id)))
                                    .then_some(id)
                            })
                            .ok_or(PptxError::AmbiguousAnchor)?,
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
                let part =
                    links::ensure_comment_part(&mut parts, &mut allowed, slide, &thread, limits)?;
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
                written.push((part, comment, target, outcome.clone()));
                anchors.push((thread.clone(), outcome));
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
                if comment != thread {
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
    if matches!(mints, SlideMints::Replay(expected) if expected != minted.as_slice()) {
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
    let actual = Archive::read(&new_bytes, limits)?;
    if actual.parts != parts {
        return Err(PptxError::PartDiffOutsideTransaction);
    }
    // Each anchor written reads back from the new bytes as the resolver
    // chose it, and its target, resolved again over them, chooses it again.
    if !written.is_empty() {
        let mut after = inspect_parts(&actual.parts, limits)?;
        resolve_positions(&new_bytes, &actual.parts, &mut after, limits);
        for (part, comment, target, outcome) in &written {
            let xml = Xml::parse_with_limits(actual.text(part)?, limits)?;
            let node = find_thread(&xml, comment)?;
            let slide = match target.slide_creation_id {
                Some(id) => after.slides.iter().find(|s| s.creation_id == Some(id)),
                None => after.slides.iter().find(|s| s.slide == target.slide),
            }
            .ok_or(PptxError::SlideNotFound)?;
            if !reads_back(&xml, node, outcome)? || resolve_anchor(slide, target)? != *outcome {
                return Err(PptxError::AnchorReadBack);
            }
        }
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
    limits: &PptxCommentLimits,
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
    // Keep the schema's four-digit Gregorian year profile.
    if at > 253_402_300_799_999 {
        return Err(PptxError::InvalidPatch);
    }
    let (days, millis) = (at / 86_400_000, at % 86_400_000);
    // Civil date from days since 1970-01-01 (proleptic Gregorian).
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    let (secs, ms) = (millis / 1_000, millis % 1_000);
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{ms:03}Z",
        secs / 3_600,
        secs / 60 % 60,
        secs % 60
    ))
}
fn text_body(text: &str) -> PatchResult<String> {
    if text.trim().is_empty() {
        return Err(PptxError::InvalidPatch);
    }
    Ok(format!(
        "<p188:txBody xmlns:p188=\"{P188}\" xmlns:a=\"{A}\"><a:bodyPr/><a:lstStyle/><a:p><a:r><a:t xml:space=\"preserve\">{}</a:t></a:r></a:p></p188:txBody>",
        escape(text)?
    ))
}
/// Whether a written root comment's anchor reads back as `outcome`: its
/// slide marker and point, or its unknown anchor.
fn reads_back(xml: &Xml<'_>, node: usize, outcome: &PptxAnchorOutcome) -> PatchResult<bool> {
    let unknown = xml.child(node, P188, "unknownAnchor")?.is_some();
    let (sld_id, creation_id, point) = match outcome {
        PptxAnchorOutcome::UnknownAnchor { .. } => return Ok(unknown),
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
    let Some(list) = xml.child(node, PC, "sldMkLst")? else {
        return Ok(false);
    };
    let Some(mark) = xml.child(list, PC, "sldMk")? else {
        return Ok(false);
    };
    let mark = &xml.nodes[mark];
    let number = |value: Option<&str>| value.and_then(|value| value.parse::<i64>().ok());
    if unknown
        || number(mark.attr("cId")) != Some(i64::from(creation_id))
        || number(mark.attr("sldId")) != Some(i64::from(sld_id))
    {
        return Ok(false);
    }
    Ok(match (point, xml.child(node, P188, "pos")?) {
        (None, None) => true,
        (Some((x, y)), Some(pos)) => {
            let pos = &xml.nodes[pos];
            number(pos.attr("x")) == Some(x) && number(pos.attr("y")) == Some(y)
        }
        _ => false,
    })
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

/// GUIDs of exported root comments that explicitly have no resolved anchor,
/// as their sixteen bytes. The annotation sweep uses this actual-byte
/// evidence to pin those threads.
pub fn unknown_anchor_threads(
    bytes: &[u8],
    limits: &PptxCommentLimits,
) -> Result<BTreeSet<[u8; 16]>, PptxError> {
    if !limits.valid() {
        return Err(PptxError::InvalidPatch);
    }
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
    limits: &PptxCommentLimits,
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
