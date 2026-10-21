//! Modern PPTX comment edits over retained XML.
//! Entry: `comment_patch`.
//! Definitions live here; comments forwards the original entry name.

use super::*;

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

pub(super) fn find_thread(xml: &Xml<'_>, id: &str) -> PatchResult<usize> {
    for node in xml.children(0, P188, "cm") {
        if canonical_guid(xml.nodes[node].required("id")?)? == id {
            return Ok(node);
        }
    }
    Err(PptxError::ThreadNotFound)
}

pub(super) fn timestamp(at: u64) -> PatchResult<String> {
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

pub(super) fn text_body(text: &str) -> PatchResult<String> {
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
pub(super) fn reads_back(
    xml: &Xml<'_>,
    node: usize,
    outcome: &PptxAnchorOutcome,
) -> PatchResult<bool> {
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

pub(super) fn anchor_xml(anchor: &PptxAnchorOutcome) -> String {
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
