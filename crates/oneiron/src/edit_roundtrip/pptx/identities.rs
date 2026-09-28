//! Imported slide/shape identities and conservative creation-ID re-binding.

use super::archive::Archive;
use super::limits::PptxOperationalLimits;
use super::package::*;
use super::xml::Xml;
use crate::anchored_annotation::{Locator, ReanchorOutcome};
use std::collections::{BTreeMap, BTreeSet};

/// Reads identities without creating missing ones or changing any package byte.
pub fn inspect_pptx(bytes: &[u8]) -> Result<PptxInspection, PptxError> {
    inspect_pptx_with_limits(bytes, &PptxOperationalLimits::default())
}
pub(crate) fn inspect_pptx_with_limits(
    bytes: &[u8],
    limits: &PptxOperationalLimits,
) -> Result<PptxInspection, PptxError> {
    inspect_parts(&Archive::read(bytes)?.parts, limits)
}
pub(super) fn text<'a>(parts: &'a BTreeMap<String, Vec<u8>>, name: &str) -> PatchResult<&'a str> {
    std::str::from_utf8(parts.get(name).ok_or(PptxError::InvalidReference)?)
        .map_err(|_| PptxError::InvalidXml)
}
pub(super) fn inspect_parts(
    parts: &BTreeMap<String, Vec<u8>>,
    limits: &PptxOperationalLimits,
) -> PatchResult<PptxInspection> {
    let presentation = Xml::parse_with_limits(text(parts, "ppt/presentation.xml")?, limits)?;
    let root = presentation.root(P, "presentation")?;
    let list = presentation
        .child(root, P, "sldIdLst")?
        .ok_or(PptxError::InvalidXml)?;
    let slide_relationships = relationships(parts, PRESENTATION_RELS, limits)?;
    let mut slides = Vec::new();
    let mut ids = BTreeSet::new();
    let mut native_ids = BTreeSet::new();
    let mut used_parts = BTreeSet::new();
    for (ordinal, index) in presentation
        .children(list, P, "sldId")
        .into_iter()
        .enumerate()
    {
        let node = &presentation.nodes[index];
        let sld_id = node
            .required("id")?
            .parse::<u32>()
            .map_err(|_| PptxError::InvalidXml)?;
        if !(256..2_147_483_648).contains(&sld_id) {
            return Err(PptxError::InvalidXml);
        }
        let rid = node.attr_ns(R, "id").ok_or(PptxError::InvalidReference)?;
        let rel = slide_relationships
            .iter()
            .find(|r| r.id == rid && r.kind == format!("{R}/slide") && !r.external)
            .ok_or(PptxError::InvalidReference)?;
        let part = resolve_target("ppt/presentation.xml", &rel.target)?;
        if !used_parts.insert(part.clone()) || !native_ids.insert(sld_id) {
            return Err(PptxError::AmbiguousAnchor);
        }
        let xml = Xml::parse_with_limits(text(parts, &part)?, limits)?;
        let slide_root = xml.root(P, "sld")?;
        let common = xml
            .child(slide_root, P, "cSld")?
            .ok_or(PptxError::InvalidXml)?;
        let creation_id = slide_creation_id(&xml, common)?;
        if creation_id.is_some_and(|id| !ids.insert(id)) {
            return Err(PptxError::AmbiguousAnchor);
        }
        let tree = xml
            .child(common, P, "spTree")?
            .ok_or(PptxError::InvalidXml)?;
        let mut shapes = Vec::new();
        for property in xml.descendants(tree, P, "cNvPr") {
            let node = &xml.nodes[property];
            let Some(nonvisual) = node.parent else {
                continue;
            };
            let Some(shape) = xml.nodes[nonvisual].parent else {
                continue;
            };
            let shape_node = &xml.nodes[shape];
            if shape_node.ns != P
                || !matches!(
                    shape_node.name.as_str(),
                    "sp" | "pic" | "graphicFrame" | "cxnSp" | "grpSp"
                )
            {
                continue;
            }
            let shape_id = node
                .required("id")?
                .parse::<u32>()
                .map_err(|_| PptxError::InvalidXml)?;
            let creation_nodes = xml.descendants(property, A16, "creationId");
            let creation_id = match creation_nodes.as_slice() {
                [] => None,
                [n] => Some(
                    canonical_guid(xml.nodes[*n].required("id")?)
                        .map_err(|_| PptxError::InvalidXml)?,
                ),
                _ => return Err(PptxError::AmbiguousAnchor),
            };
            shapes.push(PptxShapeIdentity {
                shape_id,
                creation_id,
                fingerprint: xml.fingerprint(shape),
                position: position(&xml, shape, tree)?,
            });
        }
        slides.push(PptxSlideIdentity {
            slide: ordinal as u64 + 1,
            part,
            sld_id,
            creation_id,
            fingerprint: xml.slide_content_fingerprint(slide_root),
            shapes,
        });
    }
    let mut signature_parts: BTreeSet<String> = parts
        .keys()
        .filter(|n| n.starts_with("_xmlsignatures/"))
        .cloned()
        .collect();
    for part in parts.keys().filter(|p| p.ends_with(".rels")) {
        for relation in relationships(parts, part, limits)? {
            if relation.kind.starts_with(
                "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/",
            ) {
                signature_parts.insert(part.clone());
            }
        }
    }
    let signature_parts = signature_parts.into_iter().collect();
    Ok(PptxInspection {
        slides,
        signature_parts,
    })
}
fn slide_creation_id(xml: &Xml<'_>, common: usize) -> PatchResult<Option<u32>> {
    let Some(list) = xml.child(common, P, "extLst")? else {
        return Ok(None);
    };
    let mut result = None;
    for ext in xml.children(list, P, "ext") {
        if xml.nodes[ext].attr("uri") != Some(SLIDE_ID_EXT) {
            continue;
        }
        let id = xml
            .child(ext, P14, "creationId")?
            .ok_or(PptxError::InvalidXml)?;
        let id = xml.nodes[id]
            .required("val")?
            .parse()
            .map_err(|_| PptxError::InvalidXml)?;
        if result.replace(id).is_some() {
            return Err(PptxError::AmbiguousAnchor);
        }
    }
    Ok(result)
}
fn position(xml: &Xml<'_>, shape: usize, tree: usize) -> PatchResult<Option<(i64, i64)>> {
    let node = &xml.nodes[shape];
    if node.parent != Some(tree) || node.name == "grpSp" {
        return Ok(None);
    }
    let transform = if node.name == "graphicFrame" {
        xml.child(shape, P, "xfrm")?
    } else {
        match xml.child(shape, P, "spPr")? {
            Some(p) => xml.child(p, A, "xfrm")?,
            None => None,
        }
    };
    let Some(transform) = transform else {
        return Ok(None);
    };
    let xfrm = &xml.nodes[transform];
    if xfrm.attr("rot").is_some_and(|r| r != "0")
        || ["flipH", "flipV"]
            .iter()
            .any(|a| xfrm.attr(a).is_some_and(|v| v != "0" && v != "false"))
    {
        return Ok(None);
    }
    let Some(off) = xml.child(transform, A, "off")? else {
        return Ok(None);
    };
    let Some(ext) = xml.child(transform, A, "ext")? else {
        return Ok(None);
    };
    let x = xml.nodes[off]
        .required("x")?
        .parse::<i64>()
        .map_err(|_| PptxError::InvalidXml)?;
    let y = xml.nodes[off]
        .required("y")?
        .parse::<i64>()
        .map_err(|_| PptxError::InvalidXml)?;
    let cx = xml.nodes[ext]
        .required("cx")?
        .parse::<i64>()
        .map_err(|_| PptxError::InvalidXml)?;
    let cy = xml.nodes[ext]
        .required("cy")?
        .parse::<i64>()
        .map_err(|_| PptxError::InvalidXml)?;
    if cx < 0 || cy < 0 || x.abs_diff(0) > 27_273_042_316_900 || y.abs_diff(0) > 27_273_042_316_900
    {
        return Ok(None);
    }
    Ok(Some((x, y)))
}

pub(super) fn resolve_anchor(
    slide: &PptxSlideIdentity,
    target: &PptxCommentTarget,
) -> PatchResult<PptxAnchorOutcome> {
    let Some(creation_id) = slide.creation_id else {
        return Ok(PptxAnchorOutcome::UnknownAnchor {
            reason: PptxDriftReason::MissingSlideIdentity,
        });
    };
    let Some(id) = &target.shape_creation_id else {
        return Ok(PptxAnchorOutcome::Slide {
            slide: slide.slide,
            sld_id: slide.sld_id,
            creation_id,
        });
    };
    let id = canonical_guid(id)?;
    let matching: Vec<_> = slide
        .shapes
        .iter()
        .filter(|s| s.creation_id.as_ref() == Some(&id))
        .collect();
    let shape = match matching.as_slice() {
        [] => {
            return Ok(PptxAnchorOutcome::UnknownAnchor {
                reason: PptxDriftReason::MissingShape,
            });
        }
        [shape] => *shape,
        _ => {
            return Ok(PptxAnchorOutcome::UnknownAnchor {
                reason: PptxDriftReason::AmbiguousShape,
            });
        }
    };
    if target
        .shape_fingerprint
        .is_some_and(|f| f != shape.fingerprint)
    {
        return Ok(PptxAnchorOutcome::UnknownAnchor {
            reason: PptxDriftReason::TargetChanged,
        });
    }
    let (x, y) = shape.position.ok_or(PptxError::UnverifiedGeometry)?;
    Ok(PptxAnchorOutcome::Shape {
        slide: slide.slide,
        sld_id: slide.sld_id,
        creation_id,
        shape_creation_id: id,
        x,
        y,
    })
}

/// Rebinds by imported creation identities, never by a nearby shape or its name.
/// `shape_id = "slide"` denotes a whole-slide locator. Numeric legacy shape IDs
/// are resolved in the old version first; only their creation GUID may follow.
/// Missing, duplicate, or changed shape evidence drifts instead of guessing.
pub fn rebind_locator(
    locator: &Locator,
    before: &PptxInspection,
    after: &PptxInspection,
) -> ReanchorOutcome {
    let Locator::Pptx { slide, shape_id } = locator else {
        return ReanchorOutcome::Drifted;
    };
    let Some(old) = before.slides.iter().find(|s| s.slide == *slide) else {
        return ReanchorOutcome::Drifted;
    };
    let Some(id) = old.creation_id else {
        return ReanchorOutcome::Drifted;
    };
    let found: Vec<_> = after
        .slides
        .iter()
        .filter(|s| s.creation_id == Some(id))
        .collect();
    let [new] = found.as_slice() else {
        return ReanchorOutcome::Drifted;
    };
    if old.sld_id != new.sld_id {
        return ReanchorOutcome::Drifted;
    }
    if shape_id == "slide" {
        if old.fingerprint != new.fingerprint {
            return ReanchorOutcome::Drifted;
        }
        return ReanchorOutcome::Mapped(Locator::Pptx {
            slide: new.slide,
            shape_id: shape_id.clone(),
        });
    }
    let guid = canonical_guid(shape_id).ok();
    let number = shape_id.parse::<u32>().ok();
    let old_shapes: Vec<_> = old
        .shapes
        .iter()
        .filter(|s| {
            guid.as_ref()
                .is_some_and(|g| s.creation_id.as_ref() == Some(g))
                || number == Some(s.shape_id)
        })
        .collect();
    let [old_shape] = old_shapes.as_slice() else {
        return ReanchorOutcome::Drifted;
    };
    let Some(guid) = &old_shape.creation_id else {
        return ReanchorOutcome::Drifted;
    };
    if old
        .shapes
        .iter()
        .filter(|s| s.creation_id.as_ref() == Some(guid))
        .count()
        != 1
    {
        return ReanchorOutcome::Drifted;
    }
    let new_shapes: Vec<_> = new
        .shapes
        .iter()
        .filter(|s| s.creation_id.as_ref() == Some(guid))
        .collect();
    let [new_shape] = new_shapes.as_slice() else {
        return ReanchorOutcome::Drifted;
    };
    if old_shape.fingerprint != new_shape.fingerprint {
        return ReanchorOutcome::Drifted;
    }
    ReanchorOutcome::Mapped(Locator::Pptx {
        slide: new.slide,
        shape_id: guid.clone(),
    })
}

pub(super) struct Relationship {
    pub id: String,
    pub kind: String,
    pub target: String,
    pub external: bool,
}
pub(super) fn relationships(
    parts: &BTreeMap<String, Vec<u8>>,
    name: &str,
    limits: &PptxOperationalLimits,
) -> PatchResult<Vec<Relationship>> {
    if !parts.contains_key(name) {
        return Ok(Vec::new());
    }
    let xml = Xml::parse_with_limits(text(parts, name)?, limits)?;
    let root = xml.root(REL, "Relationships")?;
    let mut ids = BTreeSet::new();
    let mut result = Vec::new();
    for n in xml.children(root, REL, "Relationship") {
        let n = &xml.nodes[n];
        let id = n.required("Id")?.to_owned();
        if !ids.insert(id.clone()) {
            return Err(PptxError::InvalidReference);
        }
        let external = match n.attr("TargetMode") {
            None | Some("Internal") => false,
            Some("External") => true,
            _ => return Err(PptxError::InvalidReference),
        };
        result.push(Relationship {
            id,
            kind: n.required("Type")?.to_owned(),
            target: n.required("Target")?.to_owned(),
            external,
        });
    }
    Ok(result)
}
pub(super) fn resolve_target(source: &str, target: &str) -> PatchResult<String> {
    if target.contains(['\\', ':', '%', '?', '#', '\0']) {
        return Err(PptxError::InvalidReference);
    }
    let mut path: Vec<&str> = if target.starts_with('/') {
        Vec::new()
    } else {
        source
            .rsplit_once('/')
            .map(|(dir, _)| dir.split('/').collect())
            .unwrap_or_default()
    };
    for segment in target.trim_start_matches('/').split('/') {
        match segment {
            ".." => {
                path.pop().ok_or(PptxError::InvalidReference)?;
            }
            "." => {}
            "" => return Err(PptxError::InvalidReference),
            s => path.push(s),
        }
    }
    if path.is_empty() {
        return Err(PptxError::InvalidReference);
    }
    Ok(path.join("/"))
}
pub(super) fn rels_path(part: &str) -> PatchResult<String> {
    let (dir, name) = part.rsplit_once('/').ok_or(PptxError::InvalidReference)?;
    Ok(format!("{dir}/_rels/{name}.rels"))
}
