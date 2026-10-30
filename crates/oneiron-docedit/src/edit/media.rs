//! `set_picture`, `set_notes` and `release_media`: verbs whose write sets
//! reach beyond the slide part. A picture gets a new media part and
//! relationship (existing media is never rewritten); notes are written in
//! the notes slide, which is created over the notes master when the slide
//! has none; media the slide no longer references is released on its own
//! step.
use super::check::{Added, Declared};
use super::text::{self, BREAK};
use super::xml::{self, A, P, R};
use super::{EditRefusal, Effect, Picture, Written};
use crate::deck::{ShapeKind, ShapeView};
use crate::design_plan::{AssetBinding, MediaType, Rect};
use crate::graphic::{GraphicInput, Output, compile_graphic};
use crate::ooxml::{CONTENT_TYPES, XmlTree};
use crate::retained_opc::{Package, rels_name};
use std::collections::BTreeSet;

const TYPES: &str = "[Content_Types].xml";
/// Office's SVG blip namespace (`asvg:svgBlip`).
pub(super) const ASVG: &str = "http://schemas.microsoft.com/office/drawing/2016/SVG/main";
const NOTES_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.presentationml.notesSlide+xml";

pub(super) fn set_picture(
    next: &mut Package,
    slide: &str,
    shape: &ShapeView,
    picture: &Picture<'_>,
) -> Result<Written, EditRefusal> {
    if shape.kind != ShapeKind::Picture {
        return Err(EditRefusal::Invalid("set_picture targets a picture"));
    }
    if picture.record.media == MediaType::Svg {
        return Err(EditRefusal::Invalid("set_picture takes a PNG or JPEG"));
    }
    let (bytes, tree) = xml::read(next, slide)?;
    let blip_at = xml::path(&tree, shape.node.index, &[(P, "blipFill"), (A, "blip")])
        .ok_or(EditRefusal::Missing("picture fill"))?;
    let blip = &tree.nodes[blip_at];
    if blip.attr_ns(R, "link").is_some() {
        return Err(EditRefusal::Invalid("a linked picture"));
    }
    let previous = blip
        .attr_ns(R, "embed")
        .ok_or(EditRefusal::Missing("picture relationship"))?
        .to_owned();
    let embed = blip
        .attr_spans
        .keys()
        .find(|name| name.ends_with(":embed") && blip.attrs.get(*name) == Some(&previous))
        .ok_or(EditRefusal::Missing("picture relationship"))?
        .clone();
    let record = picture.record;
    let (Some((x, y)), Some((cx, cy))) = (shape.geometry.offset.value, shape.geometry.extent.value)
    else {
        return Err(EditRefusal::Missing("picture bounds"));
    };
    let (extension, content_type, _) = admit(picture, Rect { x, y, cx, cy }, next.resources())?;
    let media = xml::next_part(next, "ppt/media/image", &format!(".{extension}"))?;
    let mut allowed = vec![slide.to_owned(), rels_name(slide), media.clone()];
    if !default_names(next, extension, content_type)? {
        allowed.push(TYPES.to_owned());
    }
    next.add_part(&media, content_type, picture.bytes.to_vec())?;
    let id = next.relate(slide, &format!("{R}/image"), &media)?;
    let c_nv_pr =
        xml::c_nv_pr(&tree, shape.node.index).ok_or(EditRefusal::Missing("shape properties"))?;
    let mut edits = vec![
        (
            blip.attr_spans[&embed].clone(),
            format!(r#"{embed}="{id}""#).into_bytes(),
        ),
        xml::set_attribute(&bytes, &tree.nodes[c_nv_pr], "descr", &record.description),
    ];
    let shape_id = shape.id.ok_or(EditRefusal::Missing("shape id"))?;
    let mut declared = vec![
        Declared::attribute(
            slide,
            shape_id,
            &[(P, "nvPicPr"), (P, "cNvPr")],
            ("", "descr"),
        ),
        Declared::attribute(
            slide,
            shape_id,
            &[(P, "blipFill"), (A, "blip")],
            (R, "embed"),
        ),
    ];
    let mut effects = vec![Effect::PreviousMedia {
        relationship: previous,
    }];
    // PowerPoint draws a blip's Office SVG extension over its raster, so
    // the extension goes with the old media (FIX 6306): its `a:ext`, and
    // the `a:extLst` with it when it held nothing else. Every other
    // extension keeps its bytes; the SVG's relationship stays, unreferenced.
    if let Some((gone, svg)) = svg_extension(&tree, blip_at) {
        edits.push((tree.nodes[gone].span.clone(), Vec::new()));
        declared.push(Declared::element(
            slide,
            Some(shape_id),
            &[(P, "blipFill"), (A, "blip"), (A, "extLst")],
        ));
        if let Some(relationship) = tree.nodes[svg].attr_ns(R, "embed") {
            effects.push(Effect::PreviousMedia {
                relationship: relationship.to_owned(),
            });
        }
    }
    next.replace_xml_part(slide, xml::splice(&bytes, edits)?)?;
    Ok(Written {
        allowed,
        declared,
        relationships: vec![Added::new(slide, "image", &media)],
        created: vec![(media, content_type)],
        effects,
        fit: None,
    })
}

/// `release_media` (FIX 10387): each relationship of `slide` that
/// `relationships` names and no element of the slide references (a
/// picture's previous media, [`Effect::PreviousMedia`], or a deleted
/// shape's, [`Effect::Unreferenced`]) leaves the slide's relationship part,
/// and the part it reached leaves the archive with each part only it
/// reached, once no relationship of a part the archive keeps reaches it. A
/// relationship the slide still references stays ([`Effect::MediaKept`]);
/// one the slide no longer holds is not there to release. The user's own
/// act: `set_picture` itself keeps the old media. Returns the parts it
/// changed and what it did.
pub(super) fn release_media(
    next: &mut Package,
    slide: &str,
    relationships: &[String],
) -> Result<(Vec<String>, Vec<Effect>), EditRefusal> {
    let (_, tree) = xml::read(next, slide)?;
    let used: BTreeSet<&str> = tree
        .nodes
        .iter()
        .flat_map(|node| node.attrs_ns.iter())
        .filter(|((ns, _), _)| ns == R)
        .map(|(_, value)| value.as_str())
        .collect();
    let held = next.relationships(slide)?;
    let types = next.part(TYPES)?;
    let names: BTreeSet<String> = next.names().map(str::to_owned).collect();
    let mut asked: Vec<&String> = Vec::new();
    for id in relationships {
        if !asked.contains(&id) {
            asked.push(id);
        }
    }
    let mut effects = Vec::new();
    let mut released: Vec<(String, Option<String>)> = Vec::new();
    for id in asked {
        let Some(rel) = held.iter().find(|rel| rel.id == *id) else {
            continue;
        };
        if used.contains(id.as_str()) {
            effects.push(Effect::MediaKept {
                relationship: id.clone(),
            });
            continue;
        }
        next.unrelate(slide, id)?;
        released.push((id.clone(), (!rel.external).then(|| rel.target.clone())));
    }
    // The parts only the released relationships reached, less each one a
    // part the archive keeps still relates to.
    let root = next.reachable("")?;
    let mut gone: BTreeSet<String> = BTreeSet::new();
    for target in released.iter().filter_map(|(_, target)| target.as_ref()) {
        for part in next.reachable(target)? {
            if !root.contains(&part) && names.contains(&part) {
                gone.insert(part);
            }
        }
    }
    loop {
        let mut referenced = None;
        for name in names.iter().filter(|name| !gone.contains(*name)) {
            if let Some(rel) = next
                .relationships(name)?
                .into_iter()
                .find(|rel| !rel.external && gone.contains(&rel.target))
            {
                referenced = Some(rel.target);
                break;
            }
        }
        match referenced {
            Some(part) => {
                gone.remove(&part);
            }
            None => break,
        }
    }
    for part in &gone {
        next.remove_part(part)?;
    }
    if !gone.is_empty() {
        next.prune_defaults()?;
    }
    let mut changed: Vec<String> = Vec::new();
    if !released.is_empty() {
        changed.push(rels_name(slide));
    }
    for part in &gone {
        changed.push(part.clone());
        let rels = rels_name(part);
        if names.contains(&rels) {
            changed.push(rels);
        }
    }
    if next.part(TYPES)? != types {
        changed.push(TYPES.to_owned());
    }
    for (relationship, target) in released {
        effects.push(Effect::MediaReleased {
            relationship,
            part: target.filter(|target| gone.contains(target)),
        });
    }
    Ok((changed, effects))
}

/// The blip's Office SVG extension: the element dropping it removes (its
/// `a:ext`, or its `a:extLst` when that holds nothing else) and its
/// `asvg:svgBlip`.
pub(super) fn svg_extension(tree: &XmlTree, blip: usize) -> Option<(usize, usize)> {
    let list = xml::child(tree, blip, A, "extLst")?;
    let (ext, svg) = tree.nodes[list].children.iter().find_map(|&ext| {
        if !tree.nodes[ext].is(A, "ext") {
            return None;
        }
        xml::child(tree, ext, ASVG, "svgBlip").map(|svg| (ext, svg))
    })?;
    let gone = if tree.nodes[list].children.len() == 1 {
        list
    } else {
        ext
    };
    Some((gone, svg))
}

/// The admitted raster's extension and content type, and where it sits
/// inside `bounds` at its own aspect ratio: the ONE-2534 asset checks over
/// its record and stored bytes.
pub(super) fn admit(
    picture: &Picture<'_>,
    bounds: Rect,
    resources: &crate::resource::Resources,
) -> Result<(&'static str, &'static str, Rect), EditRefusal> {
    let record = picture.record;
    let compiled = compile_graphic(
        &GraphicInput {
            binding: &AssetBinding {
                handle: record.artifact.clone(),
                media: record.media,
            },
            requested: picture.requested,
            record,
            bytes: Some(picture.bytes),
            bounds,
            limits: picture.limits,
        },
        resources,
    )
    .map_err(EditRefusal::Picture)?;
    let (extension, content_type) = match compiled.output {
        Output::Image(image) if image.media == MediaType::Png => ("png", "image/png"),
        Output::Image(image) if image.media == MediaType::Jpeg => ("jpeg", "image/jpeg"),
        _ => return Err(EditRefusal::Invalid("set_picture takes a PNG or JPEG")),
    };
    Ok((extension, content_type, compiled.record.placed))
}

/// Whether `[Content_Types].xml` already maps the extension to this type, so
/// a new part needs no override.
fn default_names(
    package: &Package,
    extension: &str,
    content_type: &str,
) -> Result<bool, EditRefusal> {
    let (_, tree) = xml::read(package, TYPES)?;
    Ok(tree.children(0).any(|(_, node)| {
        node.is(CONTENT_TYPES, "Default")
            && node
                .attr("Extension")
                .is_some_and(|ext| ext.eq_ignore_ascii_case(extension))
            && node.attr("ContentType") == Some(content_type)
    }))
}

/// The notes slide's one body placeholder.
pub(super) fn notes_body(tree: &XmlTree) -> Result<(usize, usize), EditRefusal> {
    let mut found = tree.nodes.iter().enumerate().filter(|(at, node)| {
        node.is(P, "sp")
            && xml::path(tree, *at, &[(P, "nvSpPr"), (P, "nvPr"), (P, "ph")])
                .is_some_and(|ph| tree.nodes[ph].attr("type") == Some("body"))
    });
    let (shape, _) = found
        .next()
        .ok_or(EditRefusal::Missing("notes body placeholder"))?;
    if found.next().is_some() {
        return Err(EditRefusal::AmbiguousAnchor(
            "several notes body placeholders",
        ));
    }
    let body =
        xml::child(tree, shape, P, "txBody").ok_or(EditRefusal::Missing("notes text body"))?;
    Ok((shape, body))
}

/// The notes text as `set_notes` takes it.
pub(super) fn notes_text(tree: &XmlTree, body: usize) -> String {
    text::paragraphs(tree, body)
        .iter()
        .map(|p| p.text.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}

/// The one internal relationship of `kind` from `source`, if any.
pub(super) fn related(
    package: &Package,
    source: &str,
    kind: &str,
) -> Result<Option<String>, EditRefusal> {
    let kind = format!("{R}/{kind}");
    let mut found = package
        .relationships(source)?
        .into_iter()
        .filter(|rel| rel.kind == kind && !rel.external);
    let first = found.next().map(|rel| rel.target);
    if found.next().is_some() {
        return Err(EditRefusal::AmbiguousAnchor(
            "several relationships of one kind",
        ));
    }
    Ok(first)
}

pub(super) fn set_notes(
    next: &mut Package,
    slide: &str,
    expected: Option<&str>,
    text: &str,
) -> Result<Written, EditRefusal> {
    let new = text::split(text)?;
    let Some(notes) = related(next, slide, "notesSlide")? else {
        if expected.is_some() {
            return Err(EditRefusal::TargetChanged);
        }
        return create_notes(next, slide, &new);
    };
    let (bytes, tree) = xml::read(next, &notes)?;
    let (shape, body) = notes_body(&tree)?;
    if expected != Some(notes_text(&tree, body).as_str()) {
        return Err(EditRefusal::TargetChanged);
    }
    let id = xml::c_nv_pr(&tree, shape)
        .and_then(|at| tree.nodes[at].attr("id"))
        .and_then(|id| id.parse().ok())
        .ok_or(EditRefusal::Missing("notes placeholder id"))?;
    let (edits, _) = text::rewrite_body(&bytes, &tree, body, &new)?;
    if !edits.is_empty() {
        next.replace_xml_part(&notes, xml::splice(&bytes, edits)?)?;
    }
    Ok(Written {
        allowed: vec![notes.clone()],
        declared: vec![Declared::element(&notes, Some(id), &[(P, "txBody")])],
        relationships: Vec::new(),
        created: Vec::new(),
        effects: Vec::new(),
        fit: None,
    })
}

/// A notes slide over the notes master: its slide-image placeholder (when
/// the master has one) and its body placeholder, named as the master names
/// them, with the text; the slide and the notes slide relate both ways.
fn create_notes(
    next: &mut Package,
    slide: &str,
    new: &[Vec<char>],
) -> Result<Written, EditRefusal> {
    let presentation =
        related(next, "", "officeDocument")?.ok_or(EditRefusal::Missing("presentation"))?;
    let master =
        related(next, &presentation, "notesMaster")?.ok_or(EditRefusal::Missing("notes master"))?;
    let (_, master_tree) = xml::read(next, &master)?;
    let placeholder = |kind: &str| -> Option<(String, String)> {
        master_tree.nodes.iter().enumerate().find_map(|(at, node)| {
            let ph = xml::path(&master_tree, at, &[(P, "nvSpPr"), (P, "nvPr"), (P, "ph")])?;
            let ph = &master_tree.nodes[ph];
            if !node.is(P, "sp") || ph.attr("type") != Some(kind) {
                return None;
            }
            let name = xml::c_nv_pr(&master_tree, at)
                .and_then(|c| master_tree.nodes[c].attr("name"))
                .unwrap_or_default();
            let idx = ph.attr("idx").map_or_else(String::new, |idx| {
                format!(r#" idx="{}""#, xml::escape_attribute(idx))
            });
            Some((xml::escape_attribute(name), idx))
        })
    };
    let (body_name, body_idx) =
        placeholder("body").ok_or(EditRefusal::Missing("notes master body placeholder"))?;
    let image = placeholder("sldImg").map_or_else(String::new, |(name, idx)| {
        format!(
            r#"<p:sp><p:nvSpPr><p:cNvPr id="2" name="{name}"/><p:cNvSpPr><a:spLocks noGrp="1" noRot="1" noChangeAspect="1"/></p:cNvSpPr><p:nvPr><p:ph type="sldImg"{idx}/></p:nvPr></p:nvSpPr><p:spPr/></p:sp>"#
        )
    });
    let paragraphs: String = new
        .iter()
        .map(|p| {
            let value: String = p.iter().collect();
            let lines: Vec<String> = value
                .split(BREAK)
                .map(|line| text::bare_runs("a", line))
                .collect();
            format!("<a:p>{}</a:p>", lines.join("<a:br/>"))
        })
        .collect();
    let notes_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:notes xmlns:a="{A}" xmlns:r="{R}" xmlns:p="{P}"><p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/>{image}<p:sp><p:nvSpPr><p:cNvPr id="3" name="{body_name}"/><p:cNvSpPr><a:spLocks noGrp="1"/></p:cNvSpPr><p:nvPr><p:ph type="body"{body_idx}/></p:nvPr></p:nvSpPr><p:spPr/><p:txBody><a:bodyPr/><a:lstStyle/>{paragraphs}</p:txBody></p:sp></p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:notes>"#
    );
    let notes = xml::next_part(next, "ppt/notesSlides/notesSlide", ".xml")?;
    next.add_part(&notes, NOTES_TYPE, notes_xml.into_bytes())?;
    next.relate(&notes, &format!("{R}/notesMaster"), &master)?;
    next.relate(&notes, &format!("{R}/slide"), slide)?;
    next.relate(slide, &format!("{R}/notesSlide"), &notes)?;
    Ok(Written {
        allowed: vec![
            notes.clone(),
            rels_name(&notes),
            rels_name(slide),
            TYPES.to_owned(),
        ],
        declared: Vec::new(),
        relationships: vec![
            Added::new(&notes, "notesMaster", &master),
            Added::new(&notes, "slide", slide),
            Added::new(slide, "notesSlide", &notes),
        ],
        created: vec![(notes.clone(), NOTES_TYPE)],
        effects: vec![Effect::NotesCreated { part: notes }],
        fit: None,
    })
}
