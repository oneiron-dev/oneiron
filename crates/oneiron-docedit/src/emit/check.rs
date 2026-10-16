//! The candidate checks, run on the exported bytes and independent of the
//! writer's bookkeeping: the write set read by comparing every part with the
//! template, the plan's relationships and nothing else, package closure,
//! content types, id scopes and cross-references, no written autofit
//! metrics, and a re-import through the deck view that finds every unit
//! where the plan put it.
use super::slide::PML;
use super::{CheckFault, EmitError, EmittedSlide, FitTrace, REL};
use crate::deck::{DeckView, ShapeKind, ShapeView};
use crate::design_plan::{Content, DesignPlan, Destination, Rect};
use crate::ooxml::{CONTENT_TYPES, XmlTree};
use crate::retained_opc::{Package, rels_name};
use std::collections::BTreeSet;

const TYPES: &str = "[Content_Types].xml";

/// Check the candidate `bytes` against the plan and template; returns the
/// write set, in archive order.
pub(super) fn verify(
    plan: &DesignPlan,
    template: &Package,
    bytes: &[u8],
    slides: &[EmittedSlide],
) -> Result<Vec<String>, EmitError> {
    let candidate = Package::open(bytes, template.limits())?;
    let row = plan.package();

    // The write set: what differs from the template, against the row.
    let allowed: BTreeSet<String> = row
        .new_parts
        .iter()
        .map(|part| part.part.clone())
        .chain(row.changed_parts.iter().cloned())
        .chain(row.relationships.iter().map(|rel| rels_name(&rel.source)))
        .collect();
    let mut written = Vec::new();
    for name in candidate.names() {
        if template.part(name)? != candidate.part(name)? {
            if !allowed.contains(name) {
                return fault(name, CheckFault::OutsideWriteSet);
            }
            written.push(name.to_owned());
        }
    }
    for name in template.names() {
        if candidate.part(name)?.is_none() {
            return fault(name, CheckFault::OutsideWriteSet);
        }
    }

    // Content types of the new parts.
    let types = candidate
        .part(TYPES)?
        .ok_or(crate::retained_opc::Error::Invalid("content types missing"))?;
    let types = XmlTree::parse(&types, candidate.limits().xml)?;
    types.root(CONTENT_TYPES, "Types")?;
    for new in &row.new_parts {
        if candidate.part(&new.part)?.is_none() {
            return fault(&new.part, CheckFault::MissingPlanned);
        }
        if declared(&types, &new.part) != Some(new.content_type) {
            return fault(&new.part, CheckFault::ContentType);
        }
    }

    // Relationships: the template's stay, the new ones are the plan's, and
    // every internal target is a part.
    let sources: BTreeSet<&str> = row
        .relationships
        .iter()
        .map(|rel| rel.source.as_str())
        .collect();
    for source in sources {
        let before = template.relationships(source)?;
        let after = candidate.relationships(source)?;
        let at = rels_name(source);
        if before.iter().any(|rel| !after.contains(rel)) {
            return fault(&at, CheckFault::UnplannedRelationship);
        }
        let mut planned: Vec<(&str, &str)> = row
            .relationships
            .iter()
            .filter(|rel| rel.source == source)
            .map(|rel| (rel.kind, rel.target.as_str()))
            .collect();
        for rel in after.iter().filter(|rel| !before.contains(rel)) {
            let kind = rel
                .kind
                .strip_prefix(REL)
                .and_then(|kind| kind.strip_prefix('/'));
            let Some(found) = planned.iter().position(|&(want, target)| {
                !rel.external && Some(want) == kind && target == rel.target
            }) else {
                return fault(&at, CheckFault::UnplannedRelationship);
            };
            planned.swap_remove(found);
            if candidate.part(&rel.target)?.is_none() {
                return fault(&at, CheckFault::DanglingTarget);
            }
        }
        if !planned.is_empty() {
            return fault(&at, CheckFault::MissingPlanned);
        }
    }

    // Id scopes: shape ids once per slide, every `r:` reference resolves.
    for slide in plan.slides() {
        let bytes = candidate
            .part(&slide.part)?
            .ok_or(crate::retained_opc::Error::Invalid("slide missing"))?;
        let tree = XmlTree::parse(&bytes, candidate.limits().xml)?;
        let links: BTreeSet<String> = candidate
            .relationships(&slide.part)?
            .into_iter()
            .map(|rel| rel.id)
            .collect();
        let mut ids = BTreeSet::new();
        for node in &tree.nodes {
            if node.is(PML, "cNvPr") && !ids.insert(node.attr("id")) {
                return fault(&slide.part, CheckFault::IdScope);
            }
            if node
                .attrs_ns
                .iter()
                .any(|((ns, _), value)| ns == REL && !links.contains(value))
            {
                return fault(&slide.part, CheckFault::IdScope);
            }
        }
    }

    // Nothing written restates or requests autofit metrics.
    for name in &written {
        let bytes = candidate.part(name)?.unwrap_or_default();
        if [&b"fontScale"[..], b"lnSpcReduction"]
            .iter()
            .any(|word| bytes.windows(word.len()).any(|window| window == *word))
        {
            return fault(name, CheckFault::AutofitMetrics);
        }
    }

    reimport(plan, &candidate, slides)?;
    Ok(written)
}

/// Read the candidate back as a deck: the slide list in plan order, each
/// slide over its layout, and each unit as the shape the plan placed.
fn reimport(
    plan: &DesignPlan,
    candidate: &Package,
    slides: &[EmittedSlide],
) -> Result<(), EmitError> {
    let view = DeckView::read(candidate)?;
    let parts: Vec<&str> = view.slides.iter().map(|s| s.part.as_str()).collect();
    let planned: Vec<&str> = plan.slides().iter().map(|s| s.part.as_str()).collect();
    if parts != planned || !view.ambiguities.is_empty() || slides.len() != planned.len() {
        return fault("ppt/presentation.xml", CheckFault::Reimport);
    }
    for ((planned, emitted), read) in plan.slides().iter().zip(slides).zip(&view.slides) {
        let top: Vec<&ShapeView> = read
            .shapes
            .iter()
            .filter(|shape| shape.group_path.is_empty())
            .collect();
        let held = read.layout.as_deref() == Some(planned.layout.as_str())
            && read.sld_id == emitted.sld_id
            && top.len() == planned.placements.len()
            && emitted.units.len() == planned.placements.len()
            && planned.placements.iter().zip(&emitted.units).zip(&top).all(
                |((placement, unit), shape)| {
                    unit.block == placement.block
                        && unit.content == placement.content
                        && unit.destination == placement.destination
                        && reads_as(
                            shape,
                            unit.shape,
                            &unit.content,
                            &unit.destination,
                            &unit.fit,
                        )
                },
            );
        if !held {
            return fault(&planned.part, CheckFault::Reimport);
        }
    }
    Ok(())
}

/// One unit as read back: its id, kind, placeholder, text and geometry.
fn reads_as(
    shape: &ShapeView,
    id: u32,
    content: &Content,
    destination: &Destination,
    fit: &FitTrace,
) -> bool {
    let (placeholder, bounds) = match destination {
        Destination::Placeholder {
            placeholder,
            bounds,
            ..
        } => (Some(placeholder), *bounds),
        Destination::Shape { bounds } => (None, *bounds),
    };
    let (kind, text) = match content {
        Content::Title(text) => (ShapeKind::Shape, Some(vec![text.clone()])),
        Content::Text(paragraphs) => (ShapeKind::Shape, Some(paragraphs.clone())),
        Content::Picture(_) => (ShapeKind::Picture, None),
        Content::Figure(_) => (ShapeKind::Group, None),
        Content::Table(_) | Content::Chart(_) => (ShapeKind::GraphicFrame, None),
    };
    let expected = match fit {
        FitTrace::Exact { placed } if within(*placed, bounds) => *placed,
        FitTrace::Exact { .. } => return false,
        FitTrace::Unverified { .. } => bounds,
    };
    let lines = |paragraphs: &[String]| -> Vec<String> {
        paragraphs
            .iter()
            .flat_map(|paragraph| paragraph.split('\n'))
            .map(str::to_owned)
            .collect()
    };
    let read_text = shape.text.as_ref().map(|body| {
        body.paragraphs
            .iter()
            .map(|paragraph| paragraph.runs.iter().map(|run| run.text.as_str()).collect())
            .collect::<Vec<String>>()
    });
    // A group cannot be a placeholder: a figure fills one as ordinary
    // shapes at its bounds.
    let placeholder = placeholder.filter(|_| kind != ShapeKind::Group);
    shape.id == Some(id)
        && shape.kind == kind
        && shape.placeholder.as_ref() == placeholder
        && text.is_none_or(|text| read_text == Some(lines(&text)))
        && shape.geometry.offset.value == Some((expected.x, expected.y))
        && shape.geometry.extent.value == Some((expected.cx, expected.cy))
}

fn within(inner: Rect, outer: Rect) -> bool {
    inner.x >= outer.x
        && inner.y >= outer.y
        && inner.x + inner.cx <= outer.x + outer.cx
        && inner.y + inner.cy <= outer.y + outer.cy
}

/// The content type `[Content_Types].xml` gives `part`: its override, else
/// its extension's default.
fn declared<'t>(types: &'t XmlTree, part: &str) -> Option<&'t str> {
    let name = format!("/{part}");
    let extension = part
        .rsplit('/')
        .next()
        .and_then(|file| file.rsplit_once('.'))
        .map(|(_, extension)| extension);
    let mut default = None;
    for (_, node) in types.children(0) {
        if node.is(CONTENT_TYPES, "Override")
            && node
                .attr("PartName")
                .is_some_and(|declared| declared.eq_ignore_ascii_case(&name))
        {
            return node.attr("ContentType");
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
    default
}

fn fault<T>(part: &str, fault: CheckFault) -> Result<T, EmitError> {
    Err(EmitError::Check {
        part: part.to_owned(),
        fault,
    })
}
