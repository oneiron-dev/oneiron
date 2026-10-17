//! The independent check for structural edits. It reads the exported
//! candidate, not the writer's reasoning: only the slide part may change; its
//! bytes are the input's with exactly the verb's change (one inserted shape
//! element; whole elements removed, each the shape or an element whose every
//! named shape is deleted; or one moved element whose own transform alone
//! differs); and a fresh [`DeckView`] reads every surviving identity, parent
//! and animation entry as before, the new shape as asked and the moved shape
//! where it was in slide space.
use super::super::check::{outside, same_except, timing as index};
use super::super::xfrm::own_path;
use super::super::xml::{self, A, P};
use super::{Plan, StructureEdit, members, timing};
use crate::deck::{DeckView, Placeholder, ShapeKind, ShapeView, SlideView, State};
use crate::edit::EditRefusal;
pub(super) use crate::edit::check::find_shape;
use crate::ooxml::XmlTree;
use crate::retained_opc::Package;

pub(super) fn verify(
    input: &Package,
    next: &Package,
    before: &DeckView,
    op: &StructureEdit<'_>,
    plan: &Plan,
) -> Result<Vec<String>, EditRefusal> {
    let candidate = Package::open(&next.export()?, input.limits())?;
    let slide = op
        .slide()
        .ok_or(EditRefusal::Invalid("the plan does not match the verb"))?;
    let changed = diff(input, &candidate)?;
    if let Some(part) = changed.iter().find(|part| part.as_str() != slide) {
        return Err(EditRefusal::PartDiffOutsideTransaction(part.clone()));
    }
    let after = DeckView::read(&candidate)?;
    let slides = |view: &DeckView| -> Vec<_> {
        view.slides
            .iter()
            .map(|s| (s.part.clone(), s.sld_id, s.creation_id, s.layout.clone()))
            .collect()
    };
    if slides(before) != slides(&after) {
        return Err(EditRefusal::ReadBack("the slide list changed"));
    }
    let at = before
        .slides
        .iter()
        .position(|s| s.part == slide)
        .ok_or(EditRefusal::Missing("slide"))?;
    let (old_view, new_view) = (&before.slides[at], &after.slides[at]);
    let (old, old_tree) = xml::read(input, slide)?;
    let (new, new_tree) = xml::read(&candidate, slide)?;
    let sides = Sides {
        part: slide,
        old: (&old, &old_tree, old_view),
        new: (&new, &new_tree, new_view),
    };
    match (*op, plan) {
        (StructureEdit::AddShape { shape, .. }, &Plan::Added(id)) => sides.added(&shape, id)?,
        (StructureEdit::DeleteShape { target, cascade }, Plan::Removed(removed)) => {
            sides.removed(target.shape, cascade, removed)?;
        }
        (StructureEdit::Reparent { target, parent }, Plan::Moved) => {
            sides.moved(target.shape, parent)?;
        }
        _ => return Err(EditRefusal::Invalid("the plan does not match the verb")),
    }
    Ok(changed)
}

/// The parts whose exported bytes differ from the input's; a removed part
/// refuses.
pub(super) fn diff(input: &Package, candidate: &Package) -> Result<Vec<String>, EditRefusal> {
    diff_removing(input, candidate, &[])
}

/// The parts whose exported bytes differ from the input's, with the declared
/// `removed` parts among them: each must be gone from the candidate, and any
/// other removed part refuses.
pub(super) fn diff_removing(
    input: &Package,
    candidate: &Package,
    removed: &[String],
) -> Result<Vec<String>, EditRefusal> {
    let mut changed = Vec::new();
    for part in candidate.names() {
        if removed.iter().any(|gone| gone == part) {
            return Err(EditRefusal::ReadBack(
                "a released part is still in the archive",
            ));
        }
        if input.part(part)? != candidate.part(part)? {
            changed.push(part.to_owned());
        }
    }
    for part in input.names() {
        if candidate.names().all(|name| name != part) {
            if !removed.iter().any(|gone| gone == part) {
                return Err(EditRefusal::PartDiffOutsideTransaction(
                    "a part was removed".to_owned(),
                ));
            }
            changed.push(part.to_owned());
        }
    }
    Ok(changed)
}

type Side<'a> = (&'a [u8], &'a XmlTree, &'a SlideView);

struct Sides<'a> {
    part: &'a str,
    old: Side<'a>,
    new: Side<'a>,
}

/// Identity evidence with the parent chain as ids: view indices shift when
/// shapes go or move.
type Who<'a> = (
    Option<u32>,
    ShapeKind,
    Option<&'a str>,
    Option<&'a str>,
    Option<&'a Placeholder>,
    Vec<Option<u32>>,
);

fn who(slide: &SlideView, at: usize) -> Who<'_> {
    let shape = &slide.shapes[at];
    (
        shape.id,
        shape.kind,
        shape.name.as_deref(),
        shape.creation_id.as_deref(),
        shape.placeholder.as_ref(),
        shape
            .group_path
            .iter()
            .map(|&g| slide.shapes[g].id)
            .collect(),
    )
}

/// `bytes` without `span`.
fn without(bytes: &[u8], span: std::ops::Range<usize>) -> Vec<u8> {
    [&bytes[..span.start], &bytes[span.end..]].concat()
}

fn view_index(slide: &SlideView, node: usize) -> Option<usize> {
    slide
        .shapes
        .iter()
        .position(|shape| shape.node.index == node)
}

impl Sides<'_> {
    fn fault(&self, why: &'static str) -> EditRefusal {
        outside(self.part, why)
    }

    fn added(&self, shape: &super::NewShape<'_>, id: u32) -> Result<(), EditRefusal> {
        let ((old, old_tree, old_view), (new, new_tree, new_view)) = (self.old, self.new);
        let at =
            find_shape(new_tree, id).ok_or(EditRefusal::ReadBack("the new shape is missing"))?;
        let node = &new_tree.nodes[at];
        if !node.is(P, "sp") || node.parent != xml::path(new_tree, 0, &[(P, "cSld"), (P, "spTree")])
        {
            return Err(self.fault("the new shape is not a member of the shape tree"));
        }
        if without(new, node.span.clone()) != old {
            return Err(self.fault("bytes other than the new shape changed"));
        }
        if id <= super::highest_id(old_tree).max(shape.high_water) {
            return Err(EditRefusal::ReadBack(
                "the id is not above the high-water mark",
            ));
        }
        let Some((last, kept)) = new_view.shapes.split_last() else {
            return Err(EditRefusal::ReadBack("the new shape is missing"));
        };
        let same = kept.len() == old_view.shapes.len()
            && (0..kept.len()).all(|k| who(old_view, k) == who(new_view, k));
        let prst = xml::path(new_tree, at, &[(P, "spPr"), (A, "prstGeom")])
            .and_then(|g| new_tree.nodes[g].attr("prst"));
        let explicit = |value: &crate::deck::Value<(i64, i64)>, want| {
            value.state == State::Explicit && !value.inherited && value.value == Some(want)
        };
        let creation = last.creation_id.as_deref();
        let good = last.id == Some(id)
            && last.kind == ShapeKind::Shape
            && last.name.as_deref() == Some(shape.name)
            && last.group_path.is_empty()
            && explicit(&last.geometry.offset, shape.offset)
            && explicit(&last.geometry.extent, shape.extent)
            && prst == Some(shape.preset.name())
            && creation.is_some()
            && kept.iter().all(|s| s.creation_id.as_deref() != creation);
        if !same || !good || index(&old_view.animation) != index(&new_view.animation) {
            return Err(EditRefusal::ReadBack(
                "the new shape does not read as asked",
            ));
        }
        Ok(())
    }

    fn removed(&self, id: u32, cascade: bool, removed: &[usize]) -> Result<(), EditRefusal> {
        let ((old, old_tree, old_view), (new, new_tree, new_view)) = (self.old, self.new);
        let shape = find_shape(old_tree, id).ok_or(EditRefusal::Missing("shape"))?;
        let index_of = view_index(old_view, shape).ok_or(EditRefusal::Missing("shape"))?;
        let gone: Vec<usize> = members(old_view, index_of).collect();
        let deleted = super::shape_ids(old_tree, shape);
        let expected = xml::splice(
            old,
            removed
                .iter()
                .map(|&at| (old_tree.nodes[at].span.clone(), Vec::new()))
                .collect(),
        )
        .map_err(|_| self.fault("overlapping removals"))?;
        if expected != new {
            return Err(self.fault("the slide is not the input less the removed elements"));
        }
        if removed.iter().filter(|&&at| at == shape).count() != 1 {
            return Err(self.fault("the shape itself was not removed"));
        }
        let timing_root = xml::child(old_tree, 0, P, "timing");
        for &at in removed.iter().filter(|&&at| at != shape) {
            let node = &old_tree.nodes[at];
            let glue = (node.is(A, "stCxn") || node.is(A, "endCxn"))
                && node
                    .parent
                    .is_some_and(|up| old_tree.nodes[up].is(P, "cNvCxnSpPr"))
                && node
                    .attr("id")
                    .and_then(|v| v.parse().ok())
                    .is_some_and(|v| deleted.contains(&v));
            let timed = timing_root.is_some_and(|root| {
                at == root
                    || std::iter::successors(node.parent, |&up| old_tree.nodes[up].parent)
                        .any(|up| up == root)
            }) && timing::gone(old_tree, at, &deleted)
                && timing::only_effects(old_tree, at);
            if !cascade || !(glue || timed) {
                return Err(self
                    .fault("a removed element is neither the shape nor one of its dependencies"));
            }
        }
        let survivors: Vec<Who<'_>> = (0..old_view.shapes.len())
            .filter(|k| !gone.contains(k))
            .map(|k| who(old_view, k))
            .collect();
        let read: Vec<Who<'_>> = (0..new_view.shapes.len())
            .map(|k| who(new_view, k))
            .collect();
        let dangling = new_view
            .animation
            .targets
            .iter()
            .any(|t| deleted.contains(&t.shape))
            || new_view.animation.connections.iter().any(|c| {
                [c.start, c.end]
                    .iter()
                    .any(|end| end.is_some_and(|v| deleted.contains(&v)))
            });
        let entries = |view: &SlideView| -> Vec<_> {
            view.animation
                .targets
                .iter()
                .filter(|t| !deleted.contains(&t.shape))
                .map(|t| (t.shape, t.role, t.text, t.timing_id))
                .collect()
        };
        let before = timing::dangling(old_tree);
        let unlinked = timing::dangling(new_tree)
            .iter()
            .any(|val| !before.contains(val));
        if survivors != read || dangling || unlinked || entries(old_view) != entries(new_view) {
            return Err(EditRefusal::ReadBack(
                "the surviving shapes or their animation entries changed",
            ));
        }
        Ok(())
    }

    fn moved(&self, id: u32, parent: Option<u32>) -> Result<(), EditRefusal> {
        let ((old, old_tree, old_view), (new, new_tree, new_view)) = (self.old, self.new);
        let (a, b) = (
            find_shape(old_tree, id).ok_or(EditRefusal::Missing("shape"))?,
            find_shape(new_tree, id).ok_or(EditRefusal::ReadBack("the moved shape is gone"))?,
        );
        if without(old, old_tree.nodes[a].span.clone())
            != without(new, new_tree.nodes[b].span.clone())
        {
            return Err(self.fault("bytes other than the moved shape changed"));
        }
        let index_of = view_index(old_view, a).ok_or(EditRefusal::Missing("shape"))?;
        let kind = old_view.shapes[index_of].kind;
        same_except(
            (old_tree, old, a),
            (new_tree, new, b),
            &[(own_path(kind), None)],
        )
        .map_err(|why| self.fault(why))?;
        let container = match parent {
            None => xml::path(new_tree, 0, &[(P, "cSld"), (P, "spTree")]),
            Some(group) => find_shape(new_tree, group),
        };
        if container.is_none() || new_tree.nodes[b].parent != container {
            return Err(self.fault("the shape is not under the new parent"));
        }
        // Expected identities: the moved subtree's chains start at the new
        // parent's chain; every other shape is as it was.
        let moving: Vec<usize> = members(old_view, index_of).collect();
        let depth = old_view.shapes[index_of].group_path.len();
        let base: Vec<Option<u32>> = match parent {
            None => Vec::new(),
            Some(group) => {
                let g = old_view
                    .shapes
                    .iter()
                    .position(|s| s.id == Some(group))
                    .ok_or(EditRefusal::Missing("parent group"))?;
                let mut chain = who(old_view, g).5;
                chain.push(Some(group));
                chain
            }
        };
        let mut expected: Vec<Who<'_>> = (0..old_view.shapes.len())
            .map(|k| {
                let mut entry = who(old_view, k);
                if moving.contains(&k) {
                    entry.5 = [base.clone(), entry.5[depth..].to_vec()].concat();
                }
                entry
            })
            .collect();
        for k in 0..new_view.shapes.len() {
            let entry = who(new_view, k);
            let found = expected
                .iter()
                .position(|e| *e == entry)
                .ok_or(EditRefusal::ReadBack(
                    "a shape's identity or parent changed",
                ))?;
            expected.remove(found);
        }
        if !expected.is_empty() || index(&old_view.animation) != index(&new_view.animation) {
            return Err(EditRefusal::ReadBack(
                "a shape's identity or parent changed",
            ));
        }
        self.kept_in_place(id, &moving)
    }

    /// The moved shape and its members keep their slide-space corners, to
    /// rounding: two EMU through the new parent's scale, plus 10 ppm of the
    /// frame's reach for the angle and member-scale rounding.
    fn kept_in_place(&self, id: u32, moving: &[usize]) -> Result<(), EditRefusal> {
        let (old_view, new_view) = (self.old.2, self.new.2);
        let fault = EditRefusal::ReadBack("the moved shape left its place in slide space");
        let moved = new_view
            .shapes
            .iter()
            .find(|s| s.id == Some(id))
            .ok_or(fault.clone())?;
        let matrix = moved.geometry.parent_transform.value.ok_or(fault.clone())?;
        let scale = (matrix.a.abs() + matrix.c.abs()).max(matrix.b.abs() + matrix.d.abs());
        let mut pairs = Vec::new();
        for &k in moving {
            let shape = &old_view.shapes[k];
            let Some(now) = new_view
                .shapes
                .iter()
                .find(|s| s.id.is_some() && s.id == shape.id && s.name == shape.name)
            else {
                return Err(fault);
            };
            match (corners(shape), corners(now)) {
                (Some(was), Some(is)) => pairs.push((was, is)),
                (None, None) => {}
                _ => return Err(fault),
            }
        }
        let reach = pairs
            .iter()
            .flat_map(|(was, _)| was.iter())
            .flat_map(|p| {
                pairs
                    .iter()
                    .flat_map(|(w, _)| w.iter())
                    .map(move |q| (p.0 - q.0).abs() + (p.1 - q.1).abs())
            })
            .fold(0.0, f64::max);
        let slack = 2.0 * scale + 1e-5 * reach + 1e-6;
        let off = pairs.iter().any(|(was, is)| {
            was.iter()
                .zip(is)
                .any(|(p, q)| (p.0 - q.0).abs() > slack || (p.1 - q.1).abs() > slack)
        });
        if off { Err(fault) } else { Ok(()) }
    }
}

/// The frame's four corners in slide space.
pub(super) fn corners(shape: &ShapeView) -> Option<[(f64, f64); 4]> {
    let geometry = &shape.geometry;
    let (off, ext) = (geometry.offset.value?, geometry.extent.value?);
    let matrix = geometry.parent_transform.value?;
    let rot = geometry.rotation.value.unwrap_or(0) as f64;
    let sign = |flip: Option<bool>| if flip == Some(true) { -1.0 } else { 1.0 };
    let (fx, fy) = (sign(geometry.flip_h.value), sign(geometry.flip_v.value));
    let (sin, cos) = (rot / 60_000.0).to_radians().sin_cos();
    let (hx, hy) = (ext.0 as f64 / 2.0, ext.1 as f64 / 2.0);
    let centre = (off.0 as f64 + hx, off.1 as f64 + hy);
    Some(
        [(-1.0, -1.0), (1.0, -1.0), (-1.0, 1.0), (1.0, 1.0)].map(|(u, v)| {
            let (x, y) = (u * hx * fx, v * hy * fy);
            matrix.apply(centre.0 + cos * x - sin * y, centre.1 + sin * x + cos * y)
        }),
    )
}
