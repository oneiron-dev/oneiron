//! The independent passthrough check (ARCH-0077, "Transactions and allowed
//! part changes"). It reads the exported candidate, not the writer's
//! bookkeeping: the actual part diff must sit inside the verb's allowed set;
//! in each changed part every byte outside the declared elements must be
//! unchanged; relationship parts may only gain the declared relationships;
//! new parts carry their declared content types; and a fresh [`DeckView`]
//! must read the same slides, identities and animation index, plus the
//! written values.
use super::media::{notes_body, notes_text, related};
use super::text::{paragraphs, split};
use super::xml::{self, A, P, R};
use super::{EditRefusal, ValueEdit, Written};
use crate::deck::{AnimationIndex, DeckView, ShapeView};
use crate::ooxml::{CONTENT_TYPES, XmlTree};
use crate::retained_opc::{Package, rels_name};

const TYPES: &str = "[Content_Types].xml";

type Path = &'static [(&'static str, &'static str)];

/// An element (and everything in it), or one attribute of an element, that
/// an edit may write. The path runs from the shape element, or from the part
/// root when `shape` is `None`.
#[derive(Debug, Clone)]
pub(super) struct Declared {
    part: String,
    shape: Option<u32>,
    path: Path,
    attribute: Option<(&'static str, &'static str)>,
}

impl Declared {
    pub(super) fn element(part: &str, shape: Option<u32>, path: Path) -> Self {
        Self {
            part: part.to_owned(),
            shape,
            path,
            attribute: None,
        }
    }
    pub(super) fn attribute(
        part: &str,
        shape: u32,
        path: Path,
        attribute: (&'static str, &'static str),
    ) -> Self {
        Self {
            part: part.to_owned(),
            shape: Some(shape),
            path,
            attribute: Some(attribute),
        }
    }
}

/// A relationship the edit declares it adds.
#[derive(Debug, Clone)]
pub(super) struct Added {
    source: String,
    kind: String,
    target: String,
}

impl Added {
    pub(super) fn new(source: &str, kind: &str, target: &str) -> Self {
        Self {
            source: source.to_owned(),
            kind: format!("{R}/{kind}"),
            target: target.to_owned(),
        }
    }
}

pub(super) fn outside(part: &str, why: &'static str) -> EditRefusal {
    EditRefusal::WriteOutsideTarget {
        part: part.to_owned(),
        why,
    }
}

/// Check `next` against `input`; returns the actual changed parts.
pub(super) fn verify(
    input: &Package,
    next: &Package,
    before: &DeckView,
    op: &ValueEdit<'_>,
    written: &Written,
) -> Result<Vec<String>, EditRefusal> {
    let candidate = Package::open(&next.export()?, input.limits())?;
    let mut changed = Vec::new();
    for part in candidate.names() {
        if input.part(part)? != candidate.part(part)? {
            changed.push(part.to_owned());
        }
    }
    if input
        .names()
        .any(|part| candidate.names().all(|name| name != part))
    {
        return Err(EditRefusal::PartDiffOutsideTransaction(
            "a part was removed".to_owned(),
        ));
    }
    if let Some(part) = changed.iter().find(|part| !written.allowed.contains(part)) {
        return Err(EditRefusal::PartDiffOutsideTransaction(part.clone()));
    }
    for part in &changed {
        let created = written.created.iter().any(|(name, _)| name == part);
        if created {
            continue;
        }
        let declared: Vec<&Declared> = written
            .declared
            .iter()
            .filter(|d| &d.part == part)
            .collect();
        // Relationship parts are checked below, with every declared source.
        let relationship_part = written
            .relationships
            .iter()
            .any(|added| &rels_name(&added.source) == part);
        if part == TYPES {
            let created: Vec<String> = written.created.iter().map(|(p, _)| p.clone()).collect();
            content_types(input, &candidate, &created)?;
        } else if !relationship_part {
            if declared.is_empty() {
                return Err(outside(part, "the edit declares nothing in this part"));
            }
            confine(input, &candidate, part, &declared)?;
        }
    }
    relationships(input, &candidate, &written.relationships)?;
    for (part, content_type) in &written.created {
        if declared_type(&candidate, part)?.as_deref() != Some(*content_type) {
            return Err(outside(part, "new part without its content type"));
        }
    }
    let after = DeckView::read(&candidate)?;
    same_deck(before, &after)?;
    reads_back(&candidate, before, &after, op)?;
    Ok(changed)
}

/// Every byte outside the declared elements is unchanged.
fn confine(
    input: &Package,
    candidate: &Package,
    part: &str,
    declared: &[&Declared],
) -> Result<(), EditRefusal> {
    let (old, old_tree) = xml::read(input, part)?;
    let (new, new_tree) = xml::read(candidate, part)?;
    let shape = declared[0].shape;
    if declared.iter().any(|d| d.shape != shape) {
        return Err(EditRefusal::Invalid("one edit declares one shape"));
    }
    let (at_old, at_new) = match shape {
        Some(id) => (
            find_shape(&old_tree, id).ok_or(outside(part, "the target is gone"))?,
            find_shape(&new_tree, id).ok_or(outside(part, "the target is gone"))?,
        ),
        None => (0, 0),
    };
    let (span_old, span_new) = (&old_tree.nodes[at_old].span, &new_tree.nodes[at_new].span);
    if old[..span_old.start] != new[..span_new.start] || old[span_old.end..] != new[span_new.end..]
    {
        return Err(outside(part, "bytes outside the target changed"));
    }
    let paths: Vec<Allowance<'_>> = declared.iter().map(|d| (d.path, d.attribute)).collect();
    same_except((&old_tree, &old, at_old), (&new_tree, &new, at_new), &paths)
        .map_err(|why| outside(part, why))
}

pub(super) type Side<'a> = (&'a XmlTree, &'a [u8], usize);

/// A declared path below an element, and the attribute it ends in, if any.
pub(super) type Allowance<'a> = (&'a [(&'a str, &'a str)], Option<(&'a str, &'a str)>);

/// The two elements are equal except where `paths` allow.
pub(super) fn same_except(
    (old_tree, old, at_old): Side<'_>,
    (new_tree, new, at_new): Side<'_>,
    paths: &[Allowance<'_>],
) -> Result<(), &'static str> {
    let (a, b) = (&old_tree.nodes[at_old], &new_tree.nodes[at_new]);
    if a.namespace != b.namespace || a.name != b.name {
        return Err("an element changed");
    }
    let skipped: Vec<(&str, &str)> = paths
        .iter()
        .filter(|(path, _)| path.is_empty())
        .filter_map(|(_, attribute)| *attribute)
        .collect();
    let attributes = |node: &crate::ooxml::Node| -> Vec<(String, String, String)> {
        node.attrs_ns
            .iter()
            .filter(|((ns, local), _)| !skipped.contains(&(ns.as_str(), local.as_str())))
            .map(|((ns, local), value)| (ns.clone(), local.clone(), value.clone()))
            .collect()
    };
    if attributes(a) != attributes(b) {
        return Err("an attribute outside the declared ones changed");
    }
    let open = |tree: &XmlTree, at: usize| -> Vec<usize> {
        tree.nodes[at]
            .children
            .iter()
            .copied()
            .filter(|&child| {
                !paths.iter().any(|(path, attribute)| {
                    path.len() == 1
                        && attribute.is_none()
                        && tree.nodes[child].is(path[0].0, path[0].1)
                })
            })
            .collect()
    };
    let (kids_old, kids_new) = (open(old_tree, at_old), open(new_tree, at_new));
    if kids_old.len() != kids_new.len() {
        return Err("children outside the declared elements changed");
    }
    for (&k_old, &k_new) in kids_old.iter().zip(&kids_new) {
        let deeper: Vec<Allowance<'_>> = paths
            .iter()
            .filter(|(path, _)| {
                path.first()
                    .is_some_and(|&(ns, name)| old_tree.nodes[k_old].is(ns, name))
            })
            .map(|(path, attribute)| (&path[1..], *attribute))
            .collect();
        if deeper.is_empty() {
            if old[old_tree.nodes[k_old].span.clone()] != new[new_tree.nodes[k_new].span.clone()] {
                return Err("content outside the declared elements changed");
            }
        } else {
            same_except((old_tree, old, k_old), (new_tree, new, k_new), &deeper)?;
        }
    }
    Ok(())
}

/// The one shape element whose `p:cNvPr/@id` is `id`, outside opaque
/// content.
pub(crate) fn find_shape(tree: &XmlTree, id: u32) -> Option<usize> {
    const SHAPES: [&str; 5] = ["sp", "pic", "grpSp", "graphicFrame", "cxnSp"];
    let id = id.to_string();
    let mut found = (0..tree.nodes.len()).filter(|&at| {
        let node = &tree.nodes[at];
        node.namespace == P
            && SHAPES.contains(&node.name.as_str())
            && std::iter::successors(node.parent, |&up| tree.nodes[up].parent)
                .all(|up| tree.nodes[up].namespace == P)
            && xml::c_nv_pr(tree, at).is_some_and(|c| tree.nodes[c].attr("id") == Some(id.as_str()))
    });
    let first = found.next();
    found.next().is_none().then_some(first).flatten()
}

/// Relationship parts gain exactly the declared relationships and keep
/// every other one as it was.
/// Each declared source's relationship part only gains the declared
/// relationships, under fresh ids.
pub(super) fn relationships(
    input: &Package,
    candidate: &Package,
    declared: &[Added],
) -> Result<(), EditRefusal> {
    let mut sources: Vec<&str> = declared.iter().map(|a| a.source.as_str()).collect();
    sources.sort_unstable();
    sources.dedup();
    for source in sources {
        let old = input.relationships(source)?;
        let new = candidate.relationships(source)?;
        let mut added: Vec<(&str, &str)> = declared
            .iter()
            .filter(|a| a.source == source)
            .map(|a| (a.kind.as_str(), a.target.as_str()))
            .collect();
        let part = rels_name(source);
        for rel in &new {
            if old.contains(rel) {
                continue;
            }
            let at = added
                .iter()
                .position(|&(kind, target)| {
                    rel.kind == kind && rel.target == target && !rel.external
                })
                .ok_or(outside(&part, "an undeclared relationship"))?;
            if old.iter().any(|o| o.id == rel.id) {
                return Err(outside(&part, "a relationship id was reused"));
            }
            added.remove(at);
        }
        if !added.is_empty() || old.iter().any(|rel| !new.contains(rel)) {
            return Err(outside(
                &part,
                "relationships other than the declared ones changed",
            ));
        }
    }
    Ok(())
}

/// `[Content_Types].xml` only gains overrides for the created parts.
/// `[Content_Types].xml` only gains overrides for the created parts.
pub(super) fn content_types(
    input: &Package,
    candidate: &Package,
    created: &[String],
) -> Result<(), EditRefusal> {
    let (old, old_tree) = xml::read(input, TYPES)?;
    let (new, new_tree) = xml::read(candidate, TYPES)?;
    let entries = |tree: &XmlTree, bytes: &[u8]| -> Vec<Vec<u8>> {
        tree.children(0)
            .map(|(_, node)| bytes[node.span.clone()].to_vec())
            .collect()
    };
    let (old_entries, new_entries) = (entries(&old_tree, &old), entries(&new_tree, &new));
    let mut extra = new_tree
        .children(0)
        .zip(&new_entries)
        .filter(|(_, bytes)| !old_entries.contains(bytes));
    let fault = || outside(TYPES, "content types other than the created parts' changed");
    if old_entries.iter().any(|entry| !new_entries.contains(entry)) {
        return Err(fault());
    }
    extra.try_for_each(|((_, node), _)| {
        let name = node
            .attr("PartName")
            .unwrap_or_default()
            .trim_start_matches('/');
        let ours = node.is(CONTENT_TYPES, "Override")
            && created.iter().any(|part| part.eq_ignore_ascii_case(name));
        if ours { Ok(()) } else { Err(fault()) }
    })
}

/// The content type the package declares for `part`.
pub(super) fn declared_type(package: &Package, part: &str) -> Result<Option<String>, EditRefusal> {
    let (_, tree) = xml::read(package, TYPES)?;
    let entry = |kind: &str, key: &str, value: &str| {
        tree.children(0)
            .find(|(_, node)| {
                node.is(CONTENT_TYPES, kind)
                    && node
                        .attr(key)
                        .is_some_and(|v| v.eq_ignore_ascii_case(value))
            })
            .and_then(|(_, node)| node.attr("ContentType").map(str::to_owned))
    };
    let extension = part.rsplit_once('.').map_or("", |(_, ext)| ext);
    Ok(entry("Override", "PartName", &format!("/{part}"))
        .or_else(|| entry("Default", "Extension", extension)))
}

/// The same slides, identities, ambiguities and animation index.
fn same_deck(before: &DeckView, after: &DeckView) -> Result<(), EditRefusal> {
    let fault = |why| Err(EditRefusal::ReadBack(why));
    if before.slides.len() != after.slides.len() || before.ambiguities != after.ambiguities {
        return fault("the slide list or its ambiguities changed");
    }
    for (old, new) in before.slides.iter().zip(&after.slides) {
        if (&old.part, old.sld_id, old.creation_id, &old.layout)
            != (&new.part, new.sld_id, new.creation_id, &new.layout)
        {
            return fault("a slide's identity changed");
        }
        if old.shapes.len() != new.shapes.len()
            || old
                .shapes
                .iter()
                .zip(&new.shapes)
                .any(|(a, b)| identity(a) != identity(b))
        {
            return fault("a shape's identity changed");
        }
        if timing(&old.animation) != timing(&new.animation) {
            return fault("the animation index changed");
        }
    }
    Ok(())
}

type Identity<'a> = (
    Option<u32>,
    crate::deck::ShapeKind,
    Option<&'a str>,
    Option<&'a str>,
    &'a [usize],
    Option<&'a crate::deck::Placeholder>,
);

fn identity(shape: &ShapeView) -> Identity<'_> {
    (
        shape.id,
        shape.kind,
        shape.name.as_deref(),
        shape.creation_id.as_deref(),
        &shape.group_path,
        shape.placeholder.as_ref(),
    )
}

/// The index without retained node positions, which a longer text body
/// shifts.
pub(super) fn timing(index: &AnimationIndex) -> impl PartialEq + '_ {
    let targets: Vec<_> = index
        .targets
        .iter()
        .map(|t| (t.shape, t.role, t.text, t.timing_id))
        .collect();
    (
        targets,
        &index.timing_ids,
        &index.morph_names,
        &index.connections,
    )
}

/// A declared property reads as written; an undeclared one as before or,
/// where the shape had no transform to read it from, as the default a new
/// own transform gives it.
fn kept<T: PartialEq>(declared: Option<T>, old: Option<T>, new: Option<T>, default: T) -> bool {
    match declared {
        Some(value) => new == Some(value),
        None => new == old || (old.is_none() && new == Some(default)),
    }
}

fn shape_in<'v>(view: &'v DeckView, slide: &str, id: u32) -> Result<&'v ShapeView, EditRefusal> {
    view.slides
        .iter()
        .find(|s| s.part == slide)
        .and_then(|s| s.shapes.iter().find(|shape| shape.id == Some(id)))
        .ok_or(EditRefusal::ReadBack("the target is gone"))
}

/// The written values read back from the candidate.
fn reads_back(
    candidate: &Package,
    before: &DeckView,
    after: &DeckView,
    op: &ValueEdit<'_>,
) -> Result<(), EditRefusal> {
    let fault = |why| Err(EditRefusal::ReadBack(why));
    match *op {
        ValueEdit::SetText { target, text } => {
            let (_, tree) = xml::read(candidate, target.slide)?;
            let at = find_shape(&tree, target.shape)
                .ok_or(EditRefusal::ReadBack("the target is gone"))?;
            let body =
                xml::child(&tree, at, P, "txBody").ok_or(EditRefusal::ReadBack("no text body"))?;
            let read: Vec<Vec<char>> = paragraphs(&tree, body)
                .into_iter()
                .map(|p| p.text)
                .collect();
            if read != split(text)? {
                return fault("the text body does not read as written");
            }
        }
        ValueEdit::ReplaceRunText {
            target,
            paragraph,
            run,
            text,
            ..
        } => {
            let runs = |view: &DeckView| -> Result<Vec<Vec<String>>, EditRefusal> {
                let shape = shape_in(view, target.slide, target.shape)?;
                Ok(shape.text.as_ref().map_or_else(Vec::new, |body| {
                    body.paragraphs
                        .iter()
                        .map(|p| p.runs.iter().map(|r| r.text.clone()).collect())
                        .collect()
                }))
            };
            let mut expected = runs(before)?;
            if let Some(slot) = expected.get_mut(paragraph).and_then(|p| p.get_mut(run)) {
                text.clone_into(slot);
            }
            if runs(after)? != expected {
                return fault("the runs do not read as written");
            }
        }
        ValueEdit::SetRunProps {
            target,
            paragraph,
            range: (start, end),
            expected,
            props,
        } => {
            type Marks = (Option<u32>, Option<bool>, Option<bool>, Option<String>);
            let chars = |view: &DeckView| -> Result<Vec<(char, Marks)>, EditRefusal> {
                let shape = shape_in(view, target.slide, target.shape)?;
                let held = shape
                    .text
                    .as_ref()
                    .and_then(|body| body.paragraphs.get(paragraph))
                    .ok_or(EditRefusal::ReadBack("the paragraph is gone"))?;
                Ok(held
                    .runs
                    .iter()
                    .flat_map(|run| {
                        let marks = (
                            run.size.value,
                            run.bold.value,
                            run.italic.value,
                            run.latin.value.as_ref().map(|font| font.typeface.clone()),
                        );
                        run.text.chars().map(move |c| (c, marks.clone()))
                    })
                    .collect())
            };
            let (old, new) = (chars(before)?, chars(after)?);
            let text: String = new.iter().map(|(c, _)| c).collect();
            let good = text == expected
                && old.len() == new.len()
                && old
                    .iter()
                    .zip(&new)
                    .enumerate()
                    .all(|(at, ((_, was), (_, now)))| {
                        if at < start || at >= end {
                            return was == now;
                        }
                        now.0 == props.size.or(was.0)
                            && now.1 == props.bold.or(was.1)
                            && now.2 == props.italic.or(was.2)
                            && now.3 == props.latin.map(str::to_owned).or_else(|| was.3.clone())
                    });
            if !good {
                return fault("the run properties do not read as written");
            }
        }
        ValueEdit::SetXfrm { target, xfrm } => {
            let (old, new) = (
                &shape_in(before, target.slide, target.shape)?.geometry,
                &shape_in(after, target.slide, target.shape)?.geometry,
            );
            let own = |declared: bool, inherited: bool| !declared || !inherited;
            let good = (xfrm.offset.map_or(old.offset.value, Some) == new.offset.value)
                && (xfrm.extent.map_or(old.extent.value, Some) == new.extent.value)
                && kept(xfrm.rotation, old.rotation.value, new.rotation.value, 0)
                && kept(xfrm.flip_h, old.flip_h.value, new.flip_h.value, false)
                && kept(xfrm.flip_v, old.flip_v.value, new.flip_v.value, false)
                && own(xfrm.offset.is_some(), new.offset.inherited)
                && own(xfrm.extent.is_some(), new.extent.inherited);
            if !good {
                return fault("the transform does not read as written");
            }
        }
        ValueEdit::MoveInSlideSpace { target, by } => {
            let (old, new) = (
                &shape_in(before, target.slide, target.shape)?.geometry,
                &shape_in(after, target.slide, target.shape)?.geometry,
            );
            let (Some(m), Some(from), Some(to)) = (
                old.parent_transform.value,
                old.offset.value,
                new.offset.value,
            ) else {
                return fault("the move does not read back");
            };
            let (dx, dy) = (to.0 as f64 - from.0 as f64, to.1 as f64 - from.1 as f64);
            let moved = (m.a * dx + m.c * dy, m.b * dx + m.d * dy);
            let slack = (
                0.5 * (m.a.abs() + m.c.abs()) + 1e-6,
                0.5 * (m.b.abs() + m.d.abs()) + 1e-6,
            );
            let unchanged = (
                old.extent.value,
                old.rotation.value,
                old.flip_h.value,
                old.flip_v.value,
            ) == (
                new.extent.value,
                new.rotation.value,
                new.flip_h.value,
                new.flip_v.value,
            );
            if (moved.0 - by.0 as f64).abs() > slack.0
                || (moved.1 - by.1 as f64).abs() > slack.1
                || !unchanged
            {
                return fault("the move does not land where asked");
            }
        }
        ValueEdit::SetPicture { target, picture } => {
            let (_, tree) = xml::read(candidate, target.slide)?;
            let at = find_shape(&tree, target.shape)
                .ok_or(EditRefusal::ReadBack("the target is gone"))?;
            let embed = xml::path(&tree, at, &[(P, "blipFill"), (A, "blip")])
                .and_then(|blip| tree.nodes[blip].attr_ns(R, "embed"))
                .ok_or(EditRefusal::ReadBack("the picture has no media"))?;
            let rel = candidate
                .relationships(target.slide)?
                .into_iter()
                .find(|rel| rel.id == embed && !rel.external && rel.kind == format!("{R}/image"))
                .ok_or(EditRefusal::ReadBack("the picture relationship"))?;
            let descr = xml::c_nv_pr(&tree, at).and_then(|c| tree.nodes[c].attr("descr"));
            if candidate.part(&rel.target)?.as_deref() != Some(picture.bytes)
                || descr != Some(picture.record.description.as_str())
            {
                return fault("the picture does not read as written");
            }
        }
        ValueEdit::SetNotes { slide, text, .. } => {
            let notes = related(candidate, slide, "notesSlide")?
                .ok_or(EditRefusal::ReadBack("no notes slide"))?;
            let (_, tree) = xml::read(candidate, &notes)?;
            let (_, body) = notes_body(&tree)?;
            if notes_text(&tree, body) != text
                || related(candidate, &notes, "slide")?.as_deref() != Some(slide)
                || related(candidate, &notes, "notesMaster")?.is_none()
            {
                return fault("the notes do not read as written");
            }
        }
    }
    Ok(())
}
