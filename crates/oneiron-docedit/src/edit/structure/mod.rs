//! Structural edits (ONE-2529; ARCH-0077, "Edit in place with
//! passthrough"): `add_shape` from a preset, `delete_shape` under the
//! animation and connector dependency rules, a legal `reparent` within one
//! slide, and the slide-level `duplicate_slide` and `reorder_slides`
//! (`slides/`). The live-deck projector's verbs ride the same door
//! (`arrange.rs`, `slides/lifecycle.rs`): a blank `add_slide` over a layout,
//! `delete_slide`, a sibling `reorder_shape`, an empty `add_group` and a
//! cross-slide `copy_to_slide`.
//!
//! Like a value edit, one structural edit is one checked operation on a copy
//! of the package (`check.rs`, `slides/check.rs`): surviving shapes keep
//! their ids, names, creation ids and animation entries, and a refusal
//! leaves the package as it was. New native and slide ids come from the
//! caller's high-water mark (managed history), never from the surviving
//! shapes or slides alone.
mod arrange;
mod check;
mod slides;
#[cfg(test)]
mod tests;
mod timing;

use super::xfrm::{self as transform, TURN};
use super::xml::{self, A, P, R};
use super::{EditRefusal, Effect, Target, Xfrm, locate};
use crate::deck::{
    Affine, DeckView, Geometry, Refusal, ShapeKind, ShapeView, SlideView, State, Value,
    group_matrix,
};
use crate::ooxml::XmlTree;
use crate::retained_opc::Package;

const A16: &str = "http://schemas.microsoft.com/office/drawing/2014/main";
/// The `a:ext` that holds a shape's `a16:creationId`.
const SHAPE_CREATION_EXT: &str = "{FF2B5EF4-FFF2-40B4-BE49-F238E27FC236}";
/// PowerPoint's default shape style: theme references, no literal colour.
const STYLE: &str = r#"<p:style><a:lnRef idx="2"><a:schemeClr val="accent1"><a:shade val="50000"/></a:schemeClr></a:lnRef><a:fillRef idx="1"><a:schemeClr val="accent1"/></a:fillRef><a:effectRef idx="0"><a:schemeClr val="accent1"/></a:effectRef><a:fontRef idx="minor"><a:schemeClr val="lt1"/></a:fontRef></p:style>"#;

/// The structural verbs.
#[derive(Debug, Clone, Copy)]
pub enum StructureEdit<'a> {
    /// A preset shape appended to the slide's shape tree (topmost).
    AddShape { slide: &'a str, shape: NewShape<'a> },
    /// The shape, with its group members. Animation effects that name it,
    /// and connector glue to it, refuse unless `cascade` is set; the cascade
    /// covers the tested timing subset in `timing.rs` and nothing else.
    DeleteShape { target: Target<'a>, cascade: bool },
    /// Move the shape (and its members) under the group `parent`, or the
    /// slide's shape tree for `None`, keeping its identity and its place in
    /// slide space. It becomes the new parent's last (topmost) member.
    Reparent {
        target: Target<'a>,
        parent: Option<u32>,
    },
    /// A copy of the slide after it in the slide list (and its section),
    /// cloning, sharing or leaving out each dependency by the tested policy
    /// in `slides/`. `expected` is the slide's render fingerprint as read.
    DuplicateSlide {
        slide: &'a str,
        expected: [u8; 32],
        /// The deck's slide-id high-water mark in managed history: the
        /// copy's id is above it and above every id in the slide list.
        high_water: u32,
        /// Derives the copy's creation ids, re-drawn on a collision.
        seed: &'a [u8],
    },
    /// Every slide id, in the new order.
    ReorderSlides { order: &'a [u32] },
    /// A blank slide over the slide layout `layout`, after the slide part
    /// `after` in the slide list and its section (first for `None`).
    AddSlide {
        after: Option<&'a str>,
        layout: &'a str,
        /// The deck's slide-id high-water mark in managed history.
        high_water: u32,
        /// Derives the slide's `p14:creationId`.
        seed: &'a [u8],
    },
    /// The slide leaves the slide list, its section and the presentation's
    /// relationships, and the archive drops every part it leaves unreachable
    /// from the package root: the slide, its notes and comments, and media or
    /// charts no other part reaches. A custom show that lists it, or another
    /// slide that links to it, refuses.
    /// `expected` is the slide's render fingerprint as read.
    DeleteSlide { slide: &'a str, expected: [u8; 32] },
    /// The shape (and its members) to sibling position `index` among the
    /// direct members of its own container: z-order, nothing else.
    ReorderShape { target: Target<'a>, index: usize },
    /// An empty group appended to the slide's shape tree, framed so its child
    /// space is slide space.
    AddGroup { slide: &'a str, group: NewGroup<'a> },
    /// A copy of the shape (and its members) appended to the shape tree of
    /// the slide `to`: every relationship it uses re-related from `to`, its
    /// native ids drawn above `to`'s high-water mark (one new id per old
    /// id), its creation ids kept unless `to` holds them. Glue to a shape
    /// outside the copy is dropped; the source is left as it was.
    CopyToSlide {
        target: Target<'a>,
        to: &'a str,
        /// `to`'s shape-id high-water mark in managed history.
        high_water: u32,
        seed: &'a [u8],
    },
}

#[derive(Debug, Clone, Copy)]
pub struct NewGroup<'a> {
    pub name: &'a str,
    /// Slide EMU; the child offset and extent are the same.
    pub offset: (i64, i64),
    pub extent: (i64, i64),
    pub high_water: u32,
    pub seed: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
pub struct NewShape<'a> {
    pub preset: Preset,
    pub name: &'a str,
    /// Slide EMU.
    pub offset: (i64, i64),
    pub extent: (i64, i64),
    /// The slide's shape-id high-water mark in managed history: the new id
    /// is above it and above every id the slide still holds.
    pub high_water: u32,
    /// Derives the new `a16:creationId`, re-drawn on a collision.
    pub seed: &'a [u8],
}

/// The closed preset set `add_shape` writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    Rect,
    RoundRect,
    Ellipse,
    Triangle,
    RightArrow,
}

impl Preset {
    pub fn name(self) -> &'static str {
        match self {
            Self::Rect => "rect",
            Self::RoundRect => "roundRect",
            Self::Ellipse => "ellipse",
            Self::Triangle => "triangle",
            Self::RightArrow => "rightArrow",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructureReport {
    /// Parts whose exported bytes differ from the input, in package order.
    pub changed_parts: Vec<String>,
    pub effects: Vec<Effect>,
}

/// What a writer did, for the independent check.
enum Plan {
    /// The new shape's id.
    Added(u32),
    /// The input slide's elements removed whole (document-order indices).
    Removed(Vec<usize>),
    Moved,
    Duplicated(slides::Duplicate),
    Reordered,
    /// A projector verb; `arrange::verify` checks it from the effects.
    Arranged,
}

impl StructureEdit<'_> {
    /// The one slide a shape verb writes.
    fn slide(&self) -> Option<&str> {
        match self {
            Self::AddShape { slide, .. } => Some(slide),
            Self::DeleteShape { target, .. } | Self::Reparent { target, .. } => Some(target.slide),
            Self::AddGroup { slide, .. } => Some(slide),
            Self::ReorderShape { target, .. } => Some(target.slide),
            Self::DuplicateSlide { .. }
            | Self::ReorderSlides { .. }
            | Self::AddSlide { .. }
            | Self::DeleteSlide { .. }
            | Self::CopyToSlide { .. } => None,
        }
    }
}

/// Apply one structural edit as a single checked operation; on any refusal
/// `deck` is left exactly as it was.
pub fn structure_patch(
    deck: &mut Package,
    op: &StructureEdit<'_>,
) -> Result<StructureReport, EditRefusal> {
    let before = DeckView::read(deck)?;
    let mut next = deck.clone();
    let (plan, effects) = match *op {
        StructureEdit::AddShape { slide, shape } => {
            let view = before
                .slides
                .iter()
                .find(|view| view.part == slide)
                .ok_or(EditRefusal::Missing("slide"))?;
            add_shape(&mut next, view, &shape)?
        }
        StructureEdit::DeleteShape { target, cascade } => {
            let (index, shape) = locate(&before, &target)?;
            delete_shape(&mut next, &before.slides[index], shape, cascade)?
        }
        StructureEdit::Reparent { target, parent } => {
            let (index, shape) = locate(&before, &target)?;
            reparent(&mut next, &before.slides[index], shape, parent)?;
            (Plan::Moved, Vec::new())
        }
        StructureEdit::DuplicateSlide {
            slide,
            expected,
            high_water,
            seed,
        } => slides::duplicate(&mut next, &before, slide, expected, high_water, seed)?,
        StructureEdit::ReorderSlides { order } => slides::reorder(&mut next, &before, order)?,
        StructureEdit::AddSlide {
            after,
            layout,
            high_water,
            seed,
        } => slides::add_blank(&mut next, &before, after, layout, high_water, seed)?,
        StructureEdit::DeleteSlide { slide, expected } => {
            slides::delete(&mut next, &before, slide, expected)?
        }
        StructureEdit::ReorderShape { target, index } => {
            let (at, shape) = locate(&before, &target)?;
            arrange::reorder(&mut next, &before.slides[at], shape, index)?
        }
        StructureEdit::AddGroup { slide, group } => {
            let view = before
                .slides
                .iter()
                .find(|view| view.part == slide)
                .ok_or(EditRefusal::Missing("slide"))?;
            arrange::add_group(&mut next, view, &group)?
        }
        StructureEdit::CopyToSlide {
            target,
            to,
            high_water,
            seed,
        } => {
            let (at, shape) = locate(&before, &target)?;
            arrange::copy_to_slide(&mut next, &before, at, shape, to, high_water, seed)?
        }
    };
    let changed = match (&plan, *op) {
        (Plan::Arranged, _) => arrange::verify(deck, &next, &before, op, &effects)?,
        (Plan::Duplicated(copy), _) => slides::duplicated(deck, &next, &before, op, copy)?,
        (Plan::Reordered, StructureEdit::ReorderSlides { order }) => {
            slides::reordered(deck, &next, &before, order)?
        }
        _ => check::verify(deck, &next, &before, op, &plan)?,
    };
    *deck = next;
    Ok(StructureReport {
        changed_parts: changed,
        effects,
    })
}

fn add_shape(
    next: &mut Package,
    slide: &SlideView,
    new: &NewShape<'_>,
) -> Result<(Plan, Vec<Effect>), EditRefusal> {
    if !xml::writable(new.name) {
        return Err(EditRefusal::Invalid(
            "the name holds a character XML cannot carry",
        ));
    }
    transform::check_ranges(&Xfrm {
        offset: Some(new.offset),
        extent: Some(new.extent),
        ..Xfrm::default()
    })?;
    let (bytes, tree) = xml::read(next, &slide.part)?;
    let id = highest_id(&tree)
        .max(new.high_water)
        .checked_add(1)
        .ok_or(EditRefusal::IdSpaceExhausted)?;
    let taken: Vec<&str> = slide
        .shapes
        .iter()
        .filter_map(|shape| shape.creation_id.as_deref())
        .collect();
    let creation_id = mint_guid(new.seed, &taken)?;
    let ((x, y), (cx, cy)) = (new.offset, new.extent);
    let element = format!(
        r#"<p:sp xmlns:p="{P}" xmlns:a="{A}"><p:nvSpPr><p:cNvPr id="{id}" name="{}"><a:extLst><a:ext uri="{SHAPE_CREATION_EXT}"><a16:creationId xmlns:a16="{A16}" id="{creation_id}"/></a:ext></a:extLst></p:cNvPr><p:cNvSpPr/><p:nvPr/></p:nvSpPr><p:spPr><a:xfrm><a:off x="{x}" y="{y}"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm><a:prstGeom prst="{}"><a:avLst/></a:prstGeom></p:spPr>{STYLE}<p:txBody><a:bodyPr rtlCol="0" anchor="ctr"/><a:lstStyle/><a:p><a:pPr algn="ctr"/></a:p></p:txBody></p:sp>"#,
        xml::escape_attribute(new.name),
        new.preset.name(),
    );
    let sp_tree = shape_tree(&tree)?;
    let at = end_of(&tree, sp_tree);
    next.replace_xml_part(
        &slide.part,
        xml::splice(&bytes, vec![(at..at, element.into_bytes())])?,
    )?;
    Ok((
        Plan::Added(id),
        vec![Effect::ShapeAdded { id, creation_id }],
    ))
}

/// The highest `p:cNvPr/@id` anywhere in the part.
fn highest_id(tree: &XmlTree) -> u32 {
    tree.nodes
        .iter()
        .filter(|node| node.is(P, "cNvPr"))
        .filter_map(|node| node.attr("id")?.parse::<u32>().ok())
        .max()
        .unwrap_or(0)
}

/// A version-4-shaped GUID from BLAKE3 over the seed and a draw counter,
/// uppercase and braced; drawn again while it collides with `taken`.
pub(crate) fn mint_guid(seed: &[u8], taken: &[&str]) -> Result<String, EditRefusal> {
    (0u32..64)
        .map(|draw| {
            let mut hasher =
                blake3::Hasher::new_derive_key("oneiron-docedit 2026-10-16 creationId");
            hasher.update(seed);
            hasher.update(&draw.to_le_bytes());
            let mut b = [0u8; 16];
            b.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
            b[6] = (b[6] & 0x0f) | 0x40;
            b[8] = (b[8] & 0x3f) | 0x80;
            let hex: String = b.iter().map(|byte| format!("{byte:02X}")).collect();
            format!(
                "{{{}-{}-{}-{}-{}}}",
                &hex[..8],
                &hex[8..12],
                &hex[12..16],
                &hex[16..20],
                &hex[20..]
            )
        })
        .find(|guid| !taken.contains(&guid.as_str()))
        .ok_or(EditRefusal::IdSpaceExhausted)
}

fn shape_tree(tree: &XmlTree) -> Result<usize, EditRefusal> {
    xml::path(tree, 0, &[(P, "cSld"), (P, "spTree")]).ok_or(EditRefusal::Missing("shape tree"))
}

/// Where a new last member of a shape container goes: before its `p:extLst`.
fn end_of(tree: &XmlTree, container: usize) -> usize {
    xml::child(tree, container, P, "extLst").map_or(tree.nodes[container].content.end, |ext| {
        tree.nodes[ext].span.start
    })
}

/// Every `p:cNvPr/@id` inside the shape element, branches the view does not
/// enter (`mc:AlternateContent`) included: what deleting it removes.
fn shape_ids(tree: &XmlTree, at: usize) -> Vec<u32> {
    timing::subtree(tree, at)
        .filter(|&n| tree.nodes[n].is(P, "cNvPr"))
        .filter_map(|n| tree.nodes[n].attr("id")?.parse().ok())
        .collect()
}

/// The view index of `shape` in its slide.
fn position(slide: &SlideView, shape: &ShapeView) -> usize {
    slide
        .shapes
        .iter()
        .position(|view| view.node == shape.node)
        .unwrap_or(usize::MAX)
}

/// `index` and every shape inside it.
fn members(slide: &SlideView, index: usize) -> impl Iterator<Item = usize> + '_ {
    (0..slide.shapes.len())
        .filter(move |&at| at == index || slide.shapes[at].group_path.contains(&index))
}

/// How many shapes sit directly in the group `group`.
fn direct_members(slide: &SlideView, group: usize) -> usize {
    slide
        .shapes
        .iter()
        .filter(|shape| shape.group_path.last() == Some(&group))
        .count()
}

fn delete_shape(
    next: &mut Package,
    slide: &SlideView,
    shape: &ShapeView,
    cascade: bool,
) -> Result<(Plan, Vec<Effect>), EditRefusal> {
    if let Some(&group) = shape.group_path.last()
        && direct_members(slide, group) == 1
    {
        return Err(EditRefusal::Invalid(
            "the last member of a group; delete the group",
        ));
    }
    let (bytes, tree) = xml::read(next, &slide.part)?;
    let deleted = shape_ids(&tree, shape.node.index);
    let mut removed = vec![shape.node.index];
    let mut effects = Vec::new();
    for link in &slide.animation.connections {
        if link.connector.is_some_and(|id| deleted.contains(&id)) {
            continue;
        }
        let mut glued = false;
        for (end, name) in [(link.start, "stCxn"), (link.end, "endCxn")] {
            if !end.is_some_and(|id| deleted.contains(&id)) {
                continue;
            }
            let glue = link
                .connector
                .filter(|_| cascade)
                .and_then(|id| check::find_shape(&tree, id))
                .and_then(|at| {
                    xml::path(&tree, at, &[(P, "nvCxnSpPr"), (P, "cNvCxnSpPr"), (A, name)])
                })
                .ok_or(EditRefusal::GluedConnector(link.connector))?;
            removed.push(glue);
            glued = true;
        }
        if glued {
            effects.push(Effect::Unglued {
                connector: link.connector,
            });
        }
    }
    if deleted
        .iter()
        .any(|&id| slide.animation.targets_of(id).next().is_some())
    {
        if !cascade {
            return Err(EditRefusal::AnimationDependencyUnsupported(
                "the shape is animated; a cascade removes its effects",
            ));
        }
        let timing = timing::cascade(&tree, &deleted)?;
        effects.push(Effect::TimingRemoved {
            timing_ids: timing::ids(&tree, &timing),
        });
        removed.extend(timing);
    }
    let out = xml::splice(
        &bytes,
        removed
            .iter()
            .map(|&at| (tree.nodes[at].span.clone(), Vec::new()))
            .collect(),
    )?;
    let kept = XmlTree::parse(&out, next.limits().xml)?;
    let used: Vec<&str> = kept
        .nodes
        .iter()
        .flat_map(|node| node.attrs_ns.iter())
        .filter(|((ns, _), _)| ns == R)
        .map(|(_, value)| value.as_str())
        .collect();
    for at in timing::subtree(&tree, shape.node.index) {
        for ((ns, _), value) in &tree.nodes[at].attrs_ns {
            let unreferenced = Effect::Unreferenced {
                relationship: value.clone(),
            };
            if ns == R && !used.contains(&value.as_str()) && !effects.contains(&unreferenced) {
                effects.push(unreferenced);
            }
        }
    }
    next.replace_xml_part(&slide.part, out)?;
    Ok((Plan::Removed(removed), effects))
}

fn reparent(
    next: &mut Package,
    slide: &SlideView,
    shape: &ShapeView,
    parent: Option<u32>,
) -> Result<(), EditRefusal> {
    let index = position(slide, shape);
    let id = shape.id.ok_or(EditRefusal::Missing("shape id"))?;
    let group = match parent {
        None => None,
        Some(parent) => {
            let mut found = slide
                .shapes
                .iter()
                .enumerate()
                .filter(|(_, view)| view.id == Some(parent));
            let (at, view) = found.next().ok_or(EditRefusal::Missing("parent group"))?;
            if found.next().is_some() {
                return Err(EditRefusal::AmbiguousAnchor(
                    "duplicate group id in the slide",
                ));
            }
            if view.kind != ShapeKind::Group {
                return Err(EditRefusal::ReparentUnsupported(
                    "the new parent is not a group",
                ));
            }
            if at == index || view.group_path.contains(&index) {
                return Err(EditRefusal::ReparentUnsupported(
                    "into itself or its own descendant",
                ));
            }
            Some(at)
        }
    };
    if shape.group_path.last().copied() == group {
        return Err(EditRefusal::Invalid("the shape is already in that parent"));
    }
    if let Some(&old) = shape.group_path.last()
        && direct_members(slide, old) == 1
    {
        return Err(EditRefusal::ReparentUnsupported(
            "the move would empty its group",
        ));
    }
    let animated = members(slide, index).any(|at| {
        slide.shapes[at]
            .id
            .is_some_and(|id| slide.animation.targets_of(id).next().is_some())
    });
    if group.is_some() && animated {
        return Err(EditRefusal::AnimationDependencyUnsupported(
            "an animated shape cannot join a group",
        ));
    }
    let (bytes, tree) = xml::read(next, &slide.part)?;
    let into = match group {
        None => Affine::IDENTITY,
        Some(at) => {
            let view = &slide.shapes[at];
            let inner = group_matrix(&tree, view.node.index).map_err(|why| match why {
                Refusal::NonInvertibleGroupTransform => EditRefusal::NonInvertibleGroupTransform,
                _ => EditRefusal::UnrepresentableTransform("the group transform is unresolved"),
            })?;
            Affine::then_outer(inner, resolved(&view.geometry.parent_transform)?)
        }
    };
    let xfrm = relocal(
        &shape.geometry,
        resolved(&shape.geometry.parent_transform)?,
        into,
    )?;
    let edits = transform::write(&bytes, &tree, shape.node.index, shape.kind, &xfrm)?;
    let written = xml::splice(&bytes, edits)?;
    let tree = XmlTree::parse(&written, next.limits().xml)?;
    let at = check::find_shape(&tree, id).ok_or(EditRefusal::Missing("shape"))?;
    let container = match parent {
        None => shape_tree(&tree)?,
        Some(parent) => {
            check::find_shape(&tree, parent).ok_or(EditRefusal::Missing("parent group"))?
        }
    };
    let span = tree.nodes[at].span.clone();
    let to = end_of(&tree, container);
    let moved = written[span.clone()].to_vec();
    next.replace_xml_part(
        &slide.part,
        xml::splice(&written, vec![(span, Vec::new()), (to..to, moved)])?,
    )?;
    Ok(())
}

/// A resolved composed parent transform.
fn resolved(value: &Value<Affine>) -> Result<Affine, EditRefusal> {
    match (value.state, value.value) {
        (State::Unresolved(Refusal::NonInvertibleGroupTransform), _) => {
            Err(EditRefusal::NonInvertibleGroupTransform)
        }
        (State::Unresolved(_), _) | (_, None) => Err(EditRefusal::UnrepresentableTransform(
            "the parent transform is unresolved",
        )),
        (_, Some(matrix)) => Ok(matrix),
    }
}

pub(super) fn invert(m: Affine) -> Result<Affine, EditRefusal> {
    let det = m.a * m.d - m.b * m.c;
    if !det.is_finite() || det.abs() < f64::EPSILON {
        return Err(EditRefusal::NonInvertibleGroupTransform);
    }
    let (a, b, c, d) = (m.d / det, -m.b / det, -m.c / det, m.a / det);
    Ok(Affine {
        a,
        b,
        c,
        d,
        e: -(a * m.e + c * m.f),
        f: -(b * m.e + d * m.f),
    })
}

/// The own transform that keeps the frame where it is in slide space under
/// a new parent: `M = P_new⁻¹ ∘ P_old` applied to the frame. `M` times the
/// frame's rotation and flips must split into a rotation, the same flips and
/// an axis scale; a reflection, or a rotation under a non-uniform scale (a
/// skew), is unrepresentable. Offsets and extents round to the EMU and the
/// angle to its 60,000th of a degree.
fn relocal(geometry: &Geometry, old: Affine, new: Affine) -> Result<Xfrm, EditRefusal> {
    let own = |value: &Value<(i64, i64)>| match (value.state, value.value) {
        (State::Explicit, Some(pair)) if !value.inherited => Ok(pair),
        _ => Err(EditRefusal::InheritedTransform),
    };
    let (off, ext) = (own(&geometry.offset)?, own(&geometry.extent)?);
    let m = Affine::then_outer(old, invert(new)?);
    let det = m.a * m.d - m.b * m.c;
    if !det.is_finite() || det.abs() < f64::EPSILON {
        return Err(EditRefusal::NonInvertibleGroupTransform);
    }
    if det < 0.0 {
        return Err(EditRefusal::UnrepresentableTransform(
            "a reflection between the parents",
        ));
    }
    let rot = geometry.rotation.value.unwrap_or(0) as f64;
    let sign = |flip: &Value<bool>| if flip.value == Some(true) { -1.0 } else { 1.0 };
    let (fx, fy) = (sign(&geometry.flip_h), sign(&geometry.flip_v));
    let (sin, cos) = (rot / 60_000.0).to_radians().sin_cos();
    let column = |x: f64, y: f64| (m.a * x + m.c * y, m.b * x + m.d * y);
    let (b1, b2) = (column(cos * fx, sin * fx), column(-sin * fy, cos * fy));
    let (s1, s2) = (b1.0.hypot(b1.1), b2.0.hypot(b2.1));
    if (b1.0 * b2.0 + b1.1 * b2.1).abs() > 1e-9 * s1 * s2 {
        return Err(EditRefusal::UnrepresentableTransform(
            "a rotation under a non-uniform scale",
        ));
    }
    let turn = (fx * b1.1).atan2(fx * b1.0).to_degrees() * 60_000.0;
    let extent = ((ext.0 as f64 * s1).round(), (ext.1 as f64 * s2).round());
    let centre = m.apply(
        off.0 as f64 + ext.0 as f64 / 2.0,
        off.1 as f64 + ext.1 as f64 / 2.0,
    );
    let offset = (
        (centre.0 - extent.0 / 2.0).round(),
        (centre.1 - extent.1 / 2.0).round(),
    );
    if ![turn, extent.0, extent.1, offset.0, offset.1]
        .iter()
        .all(|v| v.is_finite() && v.abs() < 1e15)
    {
        return Err(EditRefusal::UnrepresentableTransform(
            "the frame leaves the coordinate space",
        ));
    }
    let xfrm = Xfrm {
        offset: Some((offset.0 as i64, offset.1 as i64)),
        extent: Some((extent.0 as i64, extent.1 as i64)),
        rotation: Some((turn.round() as i64).rem_euclid(TURN)),
        ..Xfrm::default()
    };
    transform::check_ranges(&xfrm)?;
    Ok(xfrm)
}
