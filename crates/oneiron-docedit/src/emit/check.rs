//! The candidate checks, run on the exported bytes and independent of the
//! writer's bookkeeping: the write set read by comparing every part with the
//! template, the plan's relationships and nothing else, package closure,
//! content types, id scopes and cross-references, no written autofit
//! metrics, and a re-import through the deck view that finds every unit
//! where the plan put it.
use super::slide::PML;
use super::{CheckFault, EmitError, EmittedSlide, FitTrace, REL, Unit};
use crate::deck::{Ambiguity, DeckView, ShapeKind, ShapeView};
use crate::design_plan::{Cell, Content, DesignPlan, Destination, Rect};
use crate::native_patch::{Sequence, TableLayout, chart_data, header, number, serial};
use crate::ooxml::{CONTENT_TYPES, Node, XmlTree};
use crate::retained_opc::{Package, rels_name};
use std::collections::BTreeSet;

const TYPES: &str = "[Content_Types].xml";
const DML: &str = "http://schemas.openxmlformats.org/drawingml/2006/main";
const TABLE: &str = "http://schemas.openxmlformats.org/drawingml/2006/table";
/// The chart graphic-data URI, which is also the chart namespace.
const CHART: &str = "http://schemas.openxmlformats.org/drawingml/2006/chart";

/// Check the candidate `bytes` against the plan and template; returns the
/// write set, in archive order.
pub(super) fn verify(
    plan: &DesignPlan,
    template: &Package,
    bytes: &[u8],
    slides: &[EmittedSlide],
) -> Result<Vec<String>, EmitError> {
    let candidate = Package::open(bytes, template.limits(), template.resources())?;
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
    let types = XmlTree::parse(&types, candidate.resources())?;
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
        let tree = XmlTree::parse(&bytes, candidate.resources())?;
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

    // Nothing written restates or requests autofit metrics (FIX 8586): the
    // solver attributes on a DrawingML `a:normAutofit`, read as XML, not as
    // bytes; a metric the template's same part already holds is kept.
    for name in &written {
        if introduced_metrics(&types, template, &candidate, name)? {
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
    // A repeated native slide id is reported, never refused (FIX 7986).
    let ambiguous = view
        .ambiguities
        .iter()
        .any(|found| !matches!(found, Ambiguity::DuplicateSlideId { .. }));
    if parts != planned || ambiguous || slides.len() != planned.len() {
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
        for unit in &emitted.units {
            if !native_data(plan, candidate, &planned.part, unit)? {
                return fault(&planned.part, CheckFault::Reimport);
            }
        }
    }
    Ok(())
}

/// A table's cells, or a chart's caches and workbook cells, as the candidate
/// holds them, against the planned dataset.
fn native_data(
    plan: &DesignPlan,
    candidate: &Package,
    slide: &str,
    unit: &Unit,
) -> Result<bool, EmitError> {
    let (Content::Table(dataset) | Content::Chart(dataset) | Content::Share(dataset)) =
        &unit.content
    else {
        return Ok(true);
    };
    let Some(dataset) = plan.data().iter().find(|data| data.id == *dataset) else {
        return Ok(false);
    };
    let bytes = candidate.part(slide)?.unwrap_or_default();
    let tree = XmlTree::parse(&bytes, candidate.resources())?;
    let id = unit.shape.to_string();
    let Some(frame) = (0..tree.nodes.len()).find(|&at| {
        tree.nodes[at].is(PML, "graphicFrame")
            && inside(&tree, at)
                .any(|(_, node)| node.is(PML, "cNvPr") && node.attr("id") == Some(id.as_str()))
    }) else {
        return Ok(false);
    };
    let uri = inside(&tree, frame)
        .find(|(_, node)| node.is(DML, "graphicData"))
        .and_then(|(_, node)| node.attr("uri"));
    let column = |at: usize| -> Vec<Cell> {
        dataset
            .rows
            .iter()
            .map(|row| row.get(at).cloned().unwrap_or(Cell::Missing))
            .collect()
    };
    if matches!(unit.content, Content::Table(_)) {
        // Every cell, a covered one too, holds its own displayed text or the
        // dataset's missing meaning (FIX 8585): the planned values, read
        // against the candidate's own `a:tr`/`a:tc`/`a:p`/`a:t`.
        let Ok(planned) = TableLayout::of(dataset, &dataset.merges) else {
            return Ok(false);
        };
        let expected = planned.text;
        let read: Vec<Vec<String>> = inside(&tree, frame)
            .filter(|(_, node)| node.is(DML, "tr"))
            .map(|(row, _)| {
                inside(&tree, row)
                    .filter(|(_, node)| node.is(DML, "tc"))
                    .map(|(cell, _)| {
                        inside(&tree, cell)
                            .filter(|(_, node)| node.is(DML, "p"))
                            .map(|(paragraph, _)| {
                                inside(&tree, paragraph)
                                    .filter(|(_, node)| node.is(DML, "t"))
                                    .map(|(_, node)| node.text.as_str())
                                    .collect::<String>()
                            })
                            .collect::<Vec<_>>()
                            .join("\n")
                    })
                    .collect()
            })
            .collect();
        return Ok(uri == Some(TABLE) && read == expected);
    }
    let link = inside(&tree, frame)
        .find(|(_, node)| node.is(CHART, "chart"))
        .and_then(|(_, node)| node.attr_ns(REL, "id"));
    let target = candidate
        .relationships(slide)?
        .into_iter()
        .find(|rel| Some(rel.id.as_str()) == link)
        .map(|rel| rel.target);
    let Some(data) = target.and_then(|target| chart_data(candidate, &target).ok()) else {
        return Ok(false);
    };
    let categories: Vec<Cell> = column(0)
        .into_iter()
        .map(|cell| match cell {
            Cell::Number(value) => Cell::Text(number(value)),
            // Creation refused a date without a serial.
            Cell::Date(date) => serial(&date, false).map_or(Cell::Missing, Cell::Number),
            cell => cell,
        })
        .collect();
    let held = |sequence: &Option<Sequence>, want: &[Cell]| {
        sequence
            .as_ref()
            .is_some_and(|sequence| sequence.cache == want && sequence.workbook == want)
    };
    Ok(uri == Some(CHART)
        && data.series.len() + 1 == dataset.columns.len()
        && data.series.iter().enumerate().all(|(at, series)| {
            held(
                &series.name,
                &[Cell::Text(header(&dataset.columns[at + 1]))],
            ) && held(&series.categories, &categories)
                && held(&series.values, &column(at + 1))
        }))
}

/// Whether a written part holds an autofit solver metric its template part
/// does not (FIX 8586): `fontScale` or `lnSpcReduction` on a DrawingML
/// `a:normAutofit`, each with its value, its shape and its path there. Only
/// parts whose content type is XML are read; text, binary media and another
/// namespace's attribute of the same spelling are no metric. A new part has
/// no template, so every metric in it is new.
fn introduced_metrics(
    types: &XmlTree,
    template: &Package,
    candidate: &Package,
    name: &str,
) -> Result<bool, EmitError> {
    if !declared(types, name).is_some_and(|kind| kind.ends_with("xml")) {
        return Ok(false);
    }
    let Some(bytes) = candidate.part(name)? else {
        return Ok(false);
    };
    let mut found = metrics(&XmlTree::parse(&bytes, candidate.resources())?);
    if found.is_empty() {
        return Ok(false);
    }
    if let Some(before) = template.part(name)? {
        for held in metrics(&XmlTree::parse(&before, template.resources())?) {
            if let Some(at) = found.iter().position(|metric| *metric == held) {
                found.swap_remove(at);
            }
        }
    }
    Ok(!found.is_empty())
}

/// One `a:normAutofit` holding solver metrics: the id of the shape holding
/// it, its expanded-name path from there (or the root), and its
/// `fontScale` and `lnSpcReduction`.
type Metric = (Option<String>, String, Option<String>, Option<String>);

fn metrics(tree: &XmlTree) -> Vec<Metric> {
    (0..tree.nodes.len())
        .filter(|&at| tree.nodes[at].is(DML, "normAutofit"))
        .filter_map(|at| {
            let node = &tree.nodes[at];
            let scale = node.attr_ns("", "fontScale").map(str::to_owned);
            let reduction = node.attr_ns("", "lnSpcReduction").map(str::to_owned);
            if scale.is_none() && reduction.is_none() {
                return None;
            }
            let (shape, path) = anchor(tree, at);
            Some((shape, path, scale, reduction))
        })
        .collect()
}

/// The `p:cNvPr/@id` of the nearest shape holding `at`, and the expanded
/// names from below it down to `at`.
fn anchor(tree: &XmlTree, at: usize) -> (Option<String>, String) {
    let mut path = Vec::new();
    let mut shape = None;
    let mut cursor = Some(at);
    while let Some(index) = cursor {
        if index != at
            && let Some(id) = shape_id(tree, index)
        {
            shape = Some(id);
            break;
        }
        let node = &tree.nodes[index];
        path.push(format!("{{{}}}{}", node.namespace, node.name));
        cursor = node.parent;
    }
    path.reverse();
    (shape, path.join("/"))
}

/// A PresentationML shape element's `p:cNvPr/@id`.
fn shape_id(tree: &XmlTree, at: usize) -> Option<String> {
    let node = &tree.nodes[at];
    if node.namespace != PML {
        return None;
    }
    let nv = node.children.iter().copied().find(|&child| {
        tree.nodes[child].namespace == PML && tree.nodes[child].name.starts_with("nv")
    })?;
    tree.nodes[nv]
        .children
        .iter()
        .copied()
        .find(|&child| tree.nodes[child].is(PML, "cNvPr"))
        .and_then(|child| tree.nodes[child].attr("id"))
        .map(str::to_owned)
}

/// The elements inside `index`, in document order.
fn inside(tree: &XmlTree, index: usize) -> impl Iterator<Item = (usize, &Node)> {
    let end = tree.nodes[index].span.end;
    tree.nodes
        .iter()
        .enumerate()
        .skip(index + 1)
        .take_while(move |(_, node)| node.span.start < end)
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
        Content::Table(_) | Content::Chart(_) | Content::Share(_) => {
            (ShapeKind::GraphicFrame, None)
        }
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
