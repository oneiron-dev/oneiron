//! The independent check for slide-level edits. It reads the exported
//! candidate, not the writer's reasoning.
//!
//! A copy may change only the presentation (the input's bytes plus the
//! copy's entries, right after its source's in the slide list and in its
//! section), the presentation's relationships (one new slide relationship),
//! the content types (overrides for created parts), the app properties (one
//! slide more) and the parts it creates.
//! Each created part is its original byte for byte, but the copy slide,
//! whose bytes differ only in creation id values and the dropped comment
//! extension. Each copy keeps its original's relationship ids and kinds,
//! with the policy's targets: notes, charts and a chart's closure cloned,
//! a link to the source repointed at the copy, comments gone, the rest
//! shared. A fresh [`DeckView`] reads the copy after its source with its
//! source's shapes and animation, a slide id above the marks and fresh
//! creation ids.
//!
//! A reorder may change only the presentation, and only the order of the
//! slide list and the section lists, which must follow the requested order
//! with each section whole and in place.
use super::super::super::check::{
    Added, content_types, declared_type, outside, relationships, timing as index,
};
use super::super::super::media::related;
use super::super::super::xml::{self, R};
use super::super::StructureEdit;
use super::super::check::diff;
use super::app_props::slide_count;
use super::{
    A16, CHART_COLORS, CHART_STYLE, Duplicate, Lists, MODERN_COMMENTS, comment_ext, slide_creation,
};
use crate::deck::{DeckView, Placeholder, ShapeKind, SlideView};
use crate::edit::EditRefusal;
use crate::ooxml::XmlTree;
use crate::retained_opc::{Package, Relationship, rels_name};

const TYPES: &str = "[Content_Types].xml";

/// Kinds a copy must own a clone of: its notes, its charts and their
/// closure.
fn must_clone(rel: &Relationship) -> bool {
    let kind = rel.kind.as_str();
    let suffix = kind.strip_prefix(R).and_then(|rest| rest.strip_prefix('/'));
    !rel.external
        && (kind == CHART_STYLE
            || kind == CHART_COLORS
            || matches!(
                suffix,
                Some("notesSlide" | "chart" | "package" | "themeOverride")
            ))
}

fn comments(rel: &Relationship) -> bool {
    rel.kind == MODERN_COMMENTS || rel.kind == format!("{R}/comments")
}

type Shape<'a> = (
    Option<u32>,
    ShapeKind,
    Option<&'a str>,
    Option<&'a Placeholder>,
    &'a [usize],
);

fn shape(slide: &SlideView, k: usize) -> Shape<'_> {
    let x = &slide.shapes[k];
    (
        x.id,
        x.kind,
        x.name.as_deref(),
        x.placeholder.as_ref(),
        &x.group_path,
    )
}

fn guid(slide: &SlideView, k: usize) -> Option<&str> {
    slide.shapes[k].creation_id.as_deref()
}

fn ids(list: &[(usize, u32)]) -> Vec<u32> {
    list.iter().map(|&(_, id)| id).collect()
}

/// `bytes` without the elements at `nodes`.
fn cut(lists: &Lists, nodes: &[usize]) -> Result<Vec<u8>, EditRefusal> {
    let edits = nodes
        .iter()
        .map(|&at| (lists.tree.nodes[at].span.clone(), Vec::new()))
        .collect();
    xml::splice(&lists.bytes, edits)
}

pub(in crate::edit::structure) fn duplicated(
    input: &Package,
    next: &Package,
    before: &DeckView,
    op: &StructureEdit<'_>,
    copy: &Duplicate,
) -> Result<Vec<String>, EditRefusal> {
    let StructureEdit::DuplicateSlide {
        slide, high_water, ..
    } = *op
    else {
        return Err(EditRefusal::Invalid("the plan does not match the verb"));
    };
    let candidate = Package::open(&next.export()?, input.limits())?;
    let changed = diff(input, &candidate)?;
    let old = Lists::read(input)?;
    let presentation = old.part.as_str();
    // Every created part, with the part it copies.
    let pairs: Vec<(&str, &str)> = std::iter::once((slide, copy.clone.as_str()))
        .chain(
            copy.cloned
                .iter()
                .map(|(from, to)| (from.as_str(), to.as_str())),
        )
        .collect();
    let mut created = Vec::new();
    for &(from, to) in &pairs {
        created.push(to.to_owned());
        if input.part(&rels_name(from))?.is_some() {
            created.push(rels_name(to));
        }
    }
    let mut edited = vec![
        presentation.to_owned(),
        rels_name(presentation),
        TYPES.to_owned(),
    ];
    // The app properties count one slide more when they changed.
    if let Some(props) = related(input, "", "extended-properties")?
        && changed.contains(&props)
    {
        if slide_count(&candidate)? != slide_count(input)?.map(|count| count.saturating_add(1)) {
            return Err(EditRefusal::ReadBack(
                "the app properties do not count the copy in",
            ));
        }
        edited.push(props);
    }
    for part in &changed {
        let allowed = match input.part(part)? {
            Some(_) => edited.contains(part),
            None => created.contains(part),
        };
        if !allowed {
            return Err(EditRefusal::PartDiffOutsideTransaction(part.clone()));
        }
    }
    if created.iter().any(|part| !changed.contains(part)) {
        return Err(EditRefusal::ReadBack("a cloned part is missing"));
    }
    content_types(input, &candidate, &created)?;
    let link = Added::new(presentation, "slide", &copy.clone);
    relationships(input, &candidate, std::slice::from_ref(&link))?;
    for &(from, to) in &pairs {
        if declared_type(&candidate, to)? != declared_type(input, from)? {
            return Err(outside(to, "a copy without its original's content type"));
        }
        if from != slide && candidate.part(to)? != input.part(from)? {
            return Err(outside(to, "a cloned part differs from its original"));
        }
    }
    cloned_relationships(input, &candidate, slide, &copy.clone, &pairs)?;
    same_slide(input, &candidate, slide, &copy.clone)?;
    let source = before
        .slides
        .iter()
        .find(|s| s.part == slide)
        .ok_or(EditRefusal::Missing("slide"))?;
    entries(&old, &Lists::read(&candidate)?, source.sld_id, copy.sld_id)?;
    read_back(
        before,
        &DeckView::read(&candidate)?,
        slide,
        high_water,
        copy,
    )?;
    Ok(changed)
}

/// Each copy's relationships are its original's ids and kinds, each target
/// shared, repointed at the copy (a link to the source slide) or cloned as
/// the policy says, the source slide's comments left out; every clone is
/// reached by one.
fn cloned_relationships(
    input: &Package,
    candidate: &Package,
    slide: &str,
    clone: &str,
    pairs: &[(&str, &str)],
) -> Result<(), EditRefusal> {
    let mut reached = vec![clone.to_owned()];
    for &(from, to) in pairs {
        let part = rels_name(to);
        let (old, new) = (input.relationships(from)?, candidate.relationships(to)?);
        let mut kept = 0;
        for rel in &old {
            let found = new.iter().find(|now| now.id == rel.id);
            if from == slide && comments(rel) {
                if found.is_some() {
                    return Err(outside(&part, "the copy carries its source's comments"));
                }
                continue;
            }
            let now =
                found.ok_or_else(|| outside(&part, "a relationship of the original is missing"))?;
            kept += 1;
            let target = if rel.external {
                now.target == rel.target
            } else if rel.target == slide {
                now.target == clone
            } else if must_clone(rel) {
                pairs
                    .iter()
                    .any(|&(f, t)| f == rel.target && t == now.target && f != t)
            } else {
                now.target == rel.target
            };
            if now.kind != rel.kind || now.external != rel.external || !target {
                return Err(outside(
                    &part,
                    "a relationship is not shared, cloned or repointed as the policy says",
                ));
            }
            if must_clone(rel) {
                reached.push(now.target.clone());
            }
        }
        if new.len() != kept {
            return Err(outside(&part, "the copy gained a relationship"));
        }
    }
    match pairs
        .iter()
        .find(|(_, to)| !reached.iter().any(|r| r == to))
    {
        Some((_, to)) => Err(outside(to, "no copied relationship reaches this clone")),
        None => Ok(()),
    }
}

/// The copy's bytes are its source's but for the creation id values and the
/// comment extension, and every relationship reference in it resolves.
fn same_slide(
    input: &Package,
    candidate: &Package,
    slide: &str,
    clone: &str,
) -> Result<(), EditRefusal> {
    let (old, old_tree) = xml::read(input, slide)?;
    let (new, new_tree) = xml::read(candidate, clone)?;
    if blank(&old, &old_tree)? != blank(&new, &new_tree)? {
        return Err(outside(
            clone,
            "the copy differs from its source beyond creation ids and comments",
        ));
    }
    let ids: Vec<String> = candidate
        .relationships(clone)?
        .into_iter()
        .map(|rel| rel.id)
        .collect();
    let dangling = new_tree
        .nodes
        .iter()
        .flat_map(|node| node.attrs_ns.iter())
        .any(|((ns, _), value)| ns == R && !ids.contains(value));
    if dangling {
        return Err(outside(clone, "a relationship reference dangles"));
    }
    Ok(())
}

/// The slide with every creation id value emptied and no comment extension.
fn blank(bytes: &[u8], tree: &XmlTree) -> Result<Vec<u8>, EditRefusal> {
    let mut edits: Vec<xml::Splice> = tree
        .nodes
        .iter()
        .filter(|node| node.is(A16, "creationId"))
        .map(|node| xml::set_attribute(bytes, node, "id", ""))
        .collect();
    if let Some(at) = slide_creation(tree) {
        edits.push(xml::set_attribute(bytes, &tree.nodes[at], "val", ""));
    }
    if let Some(at) = comment_ext(tree) {
        edits.push((tree.nodes[at].span.clone(), Vec::new()));
    }
    xml::splice(bytes, edits)
}

/// The presentation is its input plus the copy's entries: right after the
/// source's in the slide list, and in its section when it has one.
fn entries(old: &Lists, new: &Lists, source: u32, sld_id: u32) -> Result<(), EditRefusal> {
    let fault = |why| Err(outside(&new.part, why));
    let inserted: Vec<usize> = new
        .slides
        .iter()
        .chain(new.sections.iter().flatten())
        .filter(|&&(_, id)| id == sld_id)
        .map(|&(at, _)| at)
        .collect();
    if cut(new, &inserted)? != old.bytes {
        return fault("bytes other than the copy's list entries changed");
    }
    let after = |list: &[(usize, u32)]| {
        let mut ids = ids(list);
        if let Some(at) = ids.iter().position(|&id| id == source) {
            ids.insert(at + 1, sld_id);
        }
        ids
    };
    if ids(&new.slides) != after(&old.slides)
        || new.sections.len() != old.sections.len()
        || old
            .sections
            .iter()
            .zip(&new.sections)
            .any(|(was, now)| ids(now) != after(was))
    {
        return fault("the copy is not right after its source in the slide list and its section");
    }
    Ok(())
}

/// A fresh view reads the input's slides with the copy after its source:
/// its id above the marks, fresh creation ids, its source's layout, shapes
/// and animation index.
fn read_back(
    before: &DeckView,
    after: &DeckView,
    slide: &str,
    high_water: u32,
    copy: &Duplicate,
) -> Result<(), EditRefusal> {
    let fault = Err(EditRefusal::ReadBack(
        "the copy does not read as its source",
    ));
    let at = before
        .slides
        .iter()
        .position(|s| s.part == slide)
        .ok_or(EditRefusal::Missing("slide"))?;
    let (source, Some(read)) = (&before.slides[at], after.slides.get(at + 1)) else {
        return fault;
    };
    let identity = |s: &SlideView| (s.part.clone(), s.sld_id, s.creation_id, s.layout.clone());
    let mut expected: Vec<_> = before.slides.iter().map(identity).collect();
    expected.insert(at + 1, identity(read));
    let fresh_slide = match (source.creation_id, read.creation_id) {
        (None, None) => true,
        (Some(_), Some(id)) => before.slides.iter().all(|s| s.creation_id != Some(id)),
        _ => false,
    };
    let count = source.shapes.len();
    let same_shapes =
        read.shapes.len() == count && (0..count).all(|k| shape(source, k) == shape(read, k));
    let taken: Vec<&str> = before
        .slides
        .iter()
        .flat_map(|s| s.shapes.iter().filter_map(|x| x.creation_id.as_deref()))
        .collect();
    // Fresh where the source had one, absent where it had none, and paired
    // where the source repeated one.
    let fresh_shapes = same_shapes
        && (0..count).all(|k| match (guid(source, k), guid(read, k)) {
            (None, None) => true,
            (Some(_), Some(new)) => {
                !taken.contains(&new)
                    && (0..count).all(|j| {
                        (guid(source, j) == guid(source, k)) == (guid(read, j) == Some(new))
                    })
            }
            _ => false,
        });
    let good = after.slides.iter().map(identity).eq(expected)
        && read.part == copy.clone
        && read.sld_id == copy.sld_id
        && before.slides.iter().all(|s| s.sld_id < read.sld_id)
        && high_water < read.sld_id
        && read.layout == source.layout
        && fresh_slide
        && fresh_shapes
        && index(&source.animation) == index(&read.animation);
    if good { Ok(()) } else { fault }
}

pub(in crate::edit::structure) fn reordered(
    input: &Package,
    next: &Package,
    before: &DeckView,
    order: &[u32],
) -> Result<Vec<String>, EditRefusal> {
    let candidate = Package::open(&next.export()?, input.limits())?;
    let changed = diff(input, &candidate)?;
    let (old, new) = (Lists::read(input)?, Lists::read(&candidate)?);
    if let Some(part) = changed.iter().find(|part| **part != old.part) {
        return Err(EditRefusal::PartDiffOutsideTransaction(part.clone()));
    }
    let fault = |why| Err(outside(&old.part, why));
    let all = |lists: &Lists| -> Vec<usize> {
        lists
            .slides
            .iter()
            .chain(lists.sections.iter().flatten())
            .map(|&(at, _)| at)
            .collect()
    };
    if cut(&old, &all(&old))? != cut(&new, &all(&new))? {
        return fault("bytes other than the slide list entries changed");
    }
    let sorted = |lists: &Lists, list: &[(usize, u32)]| {
        let mut entries: Vec<&[u8]> = list
            .iter()
            .map(|&(at, _)| &lists.bytes[lists.tree.nodes[at].span.clone()])
            .collect();
        entries.sort_unstable();
        entries.into_iter().map(<[u8]>::to_vec).collect::<Vec<_>>()
    };
    if sorted(&old, &old.slides) != sorted(&new, &new.slides) || ids(&new.slides) != order {
        return fault("the slide list is not its entries in the requested order");
    }
    let section_of = |id: &u32| new.sections.iter().position(|s| ids(s).contains(id));
    let walk: Vec<Option<usize>> = order.iter().map(section_of).collect();
    let split = !new.sections.is_empty()
        && (walk.contains(&None) || walk.windows(2).any(|pair| pair[0] > pair[1]));
    let moved = old.sections.len() != new.sections.len()
        || old.sections.iter().zip(&new.sections).any(|(was, now)| {
            let members = ids(was);
            let want: Vec<u32> = order
                .iter()
                .copied()
                .filter(|id| members.contains(id))
                .collect();
            sorted(&old, was) != sorted(&new, now) || ids(now) != want
        });
    if split || moved {
        return fault("a section's slides changed, split or left the slide order");
    }
    let after = DeckView::read(&candidate)?;
    let identity = |s: &SlideView| {
        (
            s.part.clone(),
            s.sld_id,
            s.creation_id,
            s.layout.clone(),
            s.content_fingerprint,
        )
    };
    let expected: Option<Vec<_>> = order
        .iter()
        .map(|&id| before.slides.iter().find(|s| s.sld_id == id).map(identity))
        .collect();
    if expected != Some(after.slides.iter().map(identity).collect()) {
        return Err(EditRefusal::ReadBack(
            "the slides do not read in the requested order",
        ));
    }
    Ok(changed)
}
