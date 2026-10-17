//! The deterministic export projector and the eight-step gate
//! (ARCH-0077, "Export is a deterministic projection").
//!
//! The projector writes the live model back over the retained package
//! through the checked structural and value verbs, with no clock and no
//! randomness. Live nodes and retained elements correspond by binding, never
//! by import order: a binding names its slide part and native id. Structure
//! goes first, in a fixed order: live-born slides, cross-slide moves (a copy
//! that carries its relationships), live-born shapes and groups, reparents,
//! removals (with their animation cascade), slide removals, the slide order
//! and each container's sibling order. Own geometry and text follow.
//!
//! Imported native ids are preserved. New ids are allocated only for nodes
//! that have none, in stable model-identity order within each native scope
//! and above the deck's allocation history ([`IdMarks`]), so two forks that
//! each made a shape get distinct ids once merged: allocation runs over the
//! merged head, never inside a fork's own artifact. A true no-op returns the
//! original archive bytes.
//!
//! The outcome carries every node's binding in the exported package; once
//! the export lands, [`LiveDeck::rebind`] adopts them so the next export
//! projects over the new retained bytes. A live-born picture, graphic frame
//! or connector carries no native payload and refuses. Until
//! [`Gate::is_open`], blob versions remain authoritative and exports are
//! proposal artifacts.

use super::LiveError;
use super::pptx::{
    LiveDeck, NodeBinding, NodeId, NodeKind, PreflightReport, RelationshipChange, RenderPair,
    RenderSide, SlideRender, geometry_of, slide_of, text_body,
};
use crate::deck::{DeckView, ShapeView};
use crate::edit::{
    Effect, IdMarks, NewGroup, NewShape, Preset, StructureEdit, Target, ValueEdit, Xfrm, edit,
    structure_patch,
};
use crate::retained_opc::Package;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Bump on any projector change; part of every memo key.
pub const PROJECTOR_VERSION: &str = "live-deck-projector/2";

/// A live-born shape with no own extent: one inch square.
const DEFAULT_EXTENT: (i64, i64) = (914_400, 914_400);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportProfile {
    pub name: String,
}

impl Default for ExportProfile {
    fn default() -> Self {
        Self {
            name: "pptx-live-v1".to_owned(),
        }
    }
}

/// The bounded memo key: state, retained input, ids, profile and
/// implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportKey {
    pub document: String,
    pub state_hash: [u8; 32],
    /// Hash of the retained package's part names and part hashes.
    pub package_hash: [u8; 32],
    /// Hash of the deck's native-id allocation history (its bindings ride
    /// in the state hash).
    pub allocation_hash: [u8; 32],
    pub profile: String,
    pub projector: String,
}

impl ExportKey {
    pub fn hash(&self) -> [u8; 32] {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        *blake3::hash(&bytes).as_bytes()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportOutcome {
    pub bytes: Vec<u8>,
    pub key: ExportKey,
    /// The document version the export was projected from.
    pub document_version: u64,
    pub changed_parts: Vec<String>,
    /// A true no-op: `bytes` is the original archive.
    pub noop: bool,
    /// Every live node's binding in `bytes`, model identities unchanged.
    pub bindings: BTreeMap<NodeId, NodeBinding>,
    /// BLAKE3 of every non-slide part in `bytes`.
    pub opaque_parts: BTreeMap<String, [u8; 32]>,
    /// The allocation history joined with every id `bytes` holds.
    pub id_marks: IdMarks,
}

fn package_hash(package: &Package) -> Result<[u8; 32], LiveError> {
    let mut hasher = blake3::Hasher::new();
    for name in package.names() {
        hasher.update(name.as_bytes());
        if let Some(bytes) = package.part(name)? {
            hasher.update(blake3::hash(&bytes).as_bytes());
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

/// The retained shape `native_id` on `slide_part`.
fn shape_at<'v>(view: &'v DeckView, slide_part: &str, native_id: u32) -> Option<&'v ShapeView> {
    view.slides
        .iter()
        .find(|slide| slide.part == slide_part)?
        .shapes
        .iter()
        .find(|shape| shape.id == Some(native_id))
}

/// The retained shape's current fingerprint, re-read before each verb so a
/// second verb on the same shape is never stale.
fn fingerprint_of(view: &DeckView, slide_part: &str, native_id: u32) -> Option<[u8; 32]> {
    shape_at(view, slide_part, native_id).map(|shape| shape.content_fingerprint)
}

const STALE: LiveError = LiveError::Invalid("a live binding does not match the retained package");

/// The projection in progress: the working package and where each live
/// node sits in it.
struct Work {
    next: Package,
    document: String,
    marks: IdMarks,
    /// Live node -> its slide part and native id (`p:sldId/@id` for a
    /// slide) in `next`.
    at: BTreeMap<NodeId, (String, u32)>,
    changed: BTreeSet<String>,
}

impl Work {
    fn view(&self) -> Result<DeckView, LiveError> {
        Ok(DeckView::read(&self.next)?)
    }

    /// The deterministic creation-id seed for `node`'s `role`.
    fn seed(&self, node: NodeId, role: &str) -> Vec<u8> {
        let mut seed = self.document.as_bytes().to_vec();
        seed.extend(node.0.to_le_bytes());
        seed.extend(role.as_bytes());
        seed
    }

    fn structure(&mut self, op: &StructureEdit<'_>) -> Result<Vec<Effect>, LiveError> {
        let report = structure_patch(&mut self.next, op)?;
        self.changed.extend(report.changed_parts);
        Ok(report.effects)
    }

    fn value(&mut self, op: &ValueEdit<'_>) -> Result<(), LiveError> {
        let report = edit(&mut self.next, op)?;
        self.changed.extend(report.changed_parts);
        Ok(())
    }

    /// `node`'s place and current fingerprint in `next`.
    fn target(&self, node: NodeId) -> Result<(String, u32, [u8; 32]), LiveError> {
        let (part, native) = self.at.get(&node).cloned().ok_or(LiveError::UnknownNode)?;
        let expected =
            fingerprint_of(&self.view()?, &part, native).ok_or(LiveError::UnknownNode)?;
        Ok((part, native, expected))
    }

    fn shape_mark(&self, part: &str) -> u32 {
        self.marks.shapes.get(part).copied().unwrap_or(0)
    }

    fn raise_shape(&mut self, part: &str, id: u32) {
        let own = self.marks.shapes.entry(part.to_owned()).or_default();
        *own = (*own).max(id);
    }
}

/// A live-born group's frame: its own offset and extent, or the box around
/// its direct members' own frames.
fn frame(deck: &LiveDeck, group: NodeId) -> Option<((i64, i64), (i64, i64))> {
    let node = deck.nodes.get(&group)?;
    if let (Some(offset), Some(extent)) = (node.geometry.offset, node.geometry.extent) {
        return Some((offset, extent));
    }
    let boxes: Vec<((i64, i64), (i64, i64))> = node
        .children
        .iter()
        .filter_map(|child| {
            let geometry = deck.nodes.get(child)?.geometry;
            Some((geometry.offset?, geometry.extent?))
        })
        .collect();
    let left = boxes.iter().map(|((x, _), _)| *x).min()?;
    let top = boxes.iter().map(|((_, y), _)| *y).min()?;
    let right = boxes.iter().map(|((x, _), (cx, _))| x + cx).max()?;
    let bottom = boxes.iter().map(|((_, y), (_, cy))| y + cy).max()?;
    Some(((left, top), (right - left, bottom - top)))
}

/// Project `deck` at its current version over its retained `package`.
pub fn project(
    deck: &LiveDeck,
    package: &Package,
    document: &str,
    profile: &ExportProfile,
) -> Result<ExportOutcome, LiveError> {
    let key = ExportKey {
        document: document.to_owned(),
        state_hash: deck.state_hash(),
        package_hash: package_hash(package)?,
        allocation_hash: *blake3::hash(&serde_json::to_vec(&deck.id_marks).unwrap_or_default())
            .as_bytes(),
        profile: profile.name.clone(),
        projector: PROJECTOR_VERSION.to_owned(),
    };
    // Opaque replacements carry only their hash in the live model; the
    // replacement bytes must already be the retained part's bytes.
    for (part, expected) in &deck.opaque_parts {
        match package.part(part)? {
            Some(bytes) if blake3::hash(&bytes).as_bytes() == expected => {}
            _ => {
                return Err(LiveError::Invalid(
                    "opaque replacement bytes are not in the retained package",
                ));
            }
        }
    }
    let view = DeckView::read(package)?;
    let mut marks = deck.id_marks.clone();
    marks.join(&IdMarks::of_deck(&view));
    let mut work = Work {
        next: package.clone(),
        document: document.to_owned(),
        marks,
        at: BTreeMap::new(),
        changed: BTreeSet::new(),
    };
    // Every binding must name its retained element exactly as bound.
    for (id, node) in &deck.nodes {
        if node.kind == NodeKind::Group && node.children.is_empty() {
            return Err(LiveError::Invalid(
                "a group with no members has no native form",
            ));
        }
        let Some(binding) = &node.binding else {
            continue;
        };
        let native = binding
            .native_id
            .ok_or(LiveError::Invalid("a retained element has no native id"))?;
        match node.kind {
            NodeKind::Root => continue,
            NodeKind::Slide => {
                let slide = view
                    .slides
                    .iter()
                    .find(|slide| slide.part == binding.slide_part && slide.sld_id == native)
                    .ok_or(STALE)?;
                if slide.content_fingerprint != binding.fingerprint
                    || slide.creation_id.map(|id| id.to_string()) != binding.creation_id
                {
                    return Err(STALE);
                }
            }
            _ => {
                let shape = shape_at(&view, &binding.slide_part, native).ok_or(STALE)?;
                if shape.content_fingerprint != binding.fingerprint
                    || shape.creation_id != binding.creation_id
                {
                    return Err(STALE);
                }
            }
        }
        work.at.insert(*id, (binding.slide_part.clone(), native));
    }
    let slides: Vec<NodeId> = deck
        .nodes
        .get(&NodeId(0))
        .map(|root| root.children.clone())
        .unwrap_or_default();
    let order = deck.descendants(NodeId(0));

    // 1. Live-born slides, each after its live predecessor, over the
    // predecessor's layout (or the first one any slide uses).
    let mut previous: Option<String> = None;
    for slide in &slides {
        if let Some((part, _)) = work.at.get(slide) {
            previous = Some(part.clone());
            continue;
        }
        let current = work.view()?;
        let layout = previous
            .as_ref()
            .and_then(|part| current.slides.iter().find(|s| &s.part == part))
            .and_then(|s| s.layout.clone())
            .or_else(|| current.slides.iter().find_map(|s| s.layout.clone()))
            .ok_or(LiveError::Invalid(
                "no slide layout to build a live-born slide over",
            ))?;
        let (high, seed) = (work.marks.slide, work.seed(*slide, "slide"));
        let effects = work.structure(&StructureEdit::AddSlide {
            after: previous.as_deref(),
            layout: &layout,
            high_water: high,
            seed: &seed,
        })?;
        let (part, sld_id) = effects
            .iter()
            .find_map(|effect| match effect {
                Effect::SlideAdded { part, sld_id, .. } => Some((part.clone(), *sld_id)),
                _ => None,
            })
            .ok_or(LiveError::Invalid("the slide verb added no slide"))?;
        work.marks.slide = work.marks.slide.max(sld_id);
        work.at.insert(*slide, (part.clone(), sld_id));
        previous = Some(part);
    }
    // The slide part each live node now belongs on.
    let mut home: BTreeMap<NodeId, String> = BTreeMap::new();
    for node in &order {
        let slide = slide_of(deck, *node).ok_or(LiveError::UnknownNode)?;
        let (part, _) = work.at.get(&slide).ok_or(LiveError::UnknownNode)?;
        home.insert(*node, part.clone());
    }

    // 2. Cross-slide moves, outermost first: a copy on the new slide with
    // its relationships; members bound inside it that moved too follow it.
    for node in &order {
        if deck.nodes[node].kind == NodeKind::Slide {
            continue;
        }
        let Some((part, _)) = work.at.get(node).cloned() else {
            continue;
        };
        let to = home[node].clone();
        if part == to {
            continue;
        }
        let (_, native, expected) = work.target(*node)?;
        let (high, seed) = (work.shape_mark(&to), work.seed(*node, "copy"));
        let effects = work.structure(&StructureEdit::CopyToSlide {
            target: Target {
                slide: &part,
                shape: native,
                expected,
            },
            to: &to,
            high_water: high,
            seed: &seed,
        })?;
        let copied: BTreeMap<u32, u32> = effects
            .iter()
            .filter_map(|effect| match effect {
                Effect::ShapeCopied { from, id } => Some((*from, *id)),
                _ => None,
            })
            .collect();
        for id in copied.values() {
            work.raise_shape(&to, *id);
        }
        for (other, place) in work.at.iter_mut() {
            if place.0 == part
                && home.get(other) == Some(&to)
                && let Some(new) = copied.get(&place.1)
            {
                *place = (to.clone(), *new);
            }
        }
    }

    // 3. Live-born shapes and groups, in model-identity order, topmost in
    // their slide's shape tree; the reparent pass puts them in place.
    for (id, node) in &deck.nodes {
        if matches!(node.kind, NodeKind::Root | NodeKind::Slide) || work.at.contains_key(id) {
            continue;
        }
        let part = home.get(id).cloned().ok_or(LiveError::UnknownNode)?;
        let (high, seed) = (work.shape_mark(&part), work.seed(*id, "shape"));
        let effects = match node.kind {
            NodeKind::Shape => {
                let name = node.name.clone().unwrap_or_else(|| "Shape".to_owned());
                work.structure(&StructureEdit::AddShape {
                    slide: &part,
                    shape: NewShape {
                        preset: Preset::Rect,
                        name: &name,
                        offset: node.geometry.offset.unwrap_or((0, 0)),
                        extent: node.geometry.extent.unwrap_or(DEFAULT_EXTENT),
                        high_water: high,
                        seed: &seed,
                    },
                })?
            }
            NodeKind::Group => {
                let name = node.name.clone().unwrap_or_else(|| "Group".to_owned());
                let (offset, extent) = frame(deck, *id).ok_or(LiveError::Invalid(
                    "a live-born group has no frame: give it or a member an offset and extent",
                ))?;
                work.structure(&StructureEdit::AddGroup {
                    slide: &part,
                    group: NewGroup {
                        name: &name,
                        offset,
                        extent,
                        high_water: high,
                        seed: &seed,
                    },
                })?
            }
            _ => {
                return Err(LiveError::Invalid(
                    "a live-born picture, graphic frame or connector carries no native payload",
                ));
            }
        };
        let added = effects
            .iter()
            .find_map(|effect| match effect {
                Effect::ShapeAdded { id, .. } => Some(*id),
                _ => None,
            })
            .ok_or(LiveError::Invalid("the shape verb added no shape"))?;
        work.raise_shape(&part, added);
        work.at.insert(*id, (part, added));
    }

    // 4. Reparents, outermost first, so a parent group is in place before
    // its members join it.
    for node in &order {
        let found = &deck.nodes[node];
        if found.kind == NodeKind::Slide {
            continue;
        }
        let parent = found.parent.ok_or(LiveError::UnknownNode)?;
        let wanted = match deck.nodes.get(&parent).map(|p| p.kind) {
            Some(NodeKind::Slide) => None,
            Some(_) => Some(work.at.get(&parent).ok_or(LiveError::UnknownNode)?.1),
            None => return Err(LiveError::UnknownNode),
        };
        let (part, native, expected) = work.target(*node)?;
        let current = work.view()?;
        let slide = current
            .slides
            .iter()
            .find(|slide| slide.part == part)
            .ok_or(LiveError::UnknownNode)?;
        let shape = shape_at(&current, &part, native).ok_or(LiveError::UnknownNode)?;
        let held = shape
            .group_path
            .last()
            .and_then(|&group| slide.shapes[group].id);
        if held == wanted {
            continue;
        }
        work.structure(&StructureEdit::Reparent {
            target: Target {
                slide: &part,
                shape: native,
                expected,
            },
            parent: wanted,
        })?;
    }

    // 5. Removals: every retained element no live node holds, outermost
    // first, with its animation effects and connector glue.
    let wanted: BTreeSet<(String, u32)> = work.at.values().cloned().collect();
    let kept: BTreeSet<String> = slides
        .iter()
        .filter_map(|slide| work.at.get(slide).map(|(part, _)| part.clone()))
        .collect();
    loop {
        let current = work.view()?;
        let unwanted = current
            .slides
            .iter()
            .filter(|slide| kept.contains(&slide.part))
            .find_map(|slide| {
                slide.shapes.iter().find_map(|shape| {
                    let id = shape.id?;
                    (!wanted.contains(&(slide.part.clone(), id)))
                        .then(|| (slide.part.clone(), id, shape.content_fingerprint))
                })
            });
        let Some((part, shape, expected)) = unwanted else {
            break;
        };
        work.structure(&StructureEdit::DeleteShape {
            target: Target {
                slide: &part,
                shape,
                expected,
            },
            cascade: true,
        })?;
    }

    // 6. Slide removals.
    loop {
        let current = work.view()?;
        let Some(gone) = current
            .slides
            .iter()
            .find(|slide| !kept.contains(&slide.part))
        else {
            break;
        };
        let (part, expected) = (gone.part.clone(), gone.render_fingerprint);
        work.structure(&StructureEdit::DeleteSlide {
            slide: &part,
            expected,
        })?;
    }

    // 7. The slide order.
    let wanted_order: Vec<u32> = slides
        .iter()
        .map(|slide| work.at.get(slide).map(|(_, id)| *id))
        .collect::<Option<_>>()
        .ok_or(LiveError::UnknownNode)?;
    let held_order: Vec<u32> = work.view()?.slides.iter().map(|s| s.sld_id).collect();
    if wanted_order != held_order {
        work.structure(&StructureEdit::ReorderSlides {
            order: &wanted_order,
        })?;
    }

    // 8. Each container's sibling order (z-order).
    for container in &order {
        let found = &deck.nodes[container];
        if !matches!(found.kind, NodeKind::Slide | NodeKind::Group) {
            continue;
        }
        let part = home[container].clone();
        let group = (found.kind == NodeKind::Group)
            .then(|| work.at.get(container).map(|(_, id)| *id))
            .flatten();
        for (index, child) in found.children.iter().enumerate() {
            let (_, native, expected) = work.target(*child)?;
            let current = work.view()?;
            let slide = current
                .slides
                .iter()
                .find(|slide| slide.part == part)
                .ok_or(LiveError::UnknownNode)?;
            let members: Vec<Option<u32>> = slide
                .shapes
                .iter()
                .filter(|shape| {
                    shape.group_path.last().and_then(|&at| slide.shapes[at].id) == group
                        && (group.is_some() || shape.group_path.is_empty())
                })
                .map(|shape| shape.id)
                .collect();
            if members.get(index) == Some(&Some(native)) {
                continue;
            }
            work.structure(&StructureEdit::ReorderShape {
                target: Target {
                    slide: &part,
                    shape: native,
                    expected,
                },
                index,
            })?;
        }
    }

    // 9. Own geometry and text, in model-identity order.
    for (id, node) in &deck.nodes {
        if matches!(node.kind, NodeKind::Root | NodeKind::Slide) {
            continue;
        }
        let (part, native, expected) = work.target(*id)?;
        let current = work.view()?;
        let shape = shape_at(&current, &part, native).ok_or(LiveError::UnknownNode)?;
        let held = geometry_of(shape);
        fn changed<T: PartialEq + Copy>(live: Option<T>, held: Option<T>) -> Option<T> {
            live.filter(|value| Some(*value) != held)
        }
        let xfrm = Xfrm {
            offset: changed(node.geometry.offset, held.offset),
            extent: changed(node.geometry.extent, held.extent),
            rotation: changed(node.geometry.rotation, held.rotation),
            flip_h: changed(node.geometry.flip_h, held.flip_h),
            flip_v: changed(node.geometry.flip_v, held.flip_v),
        };
        let held_text = shape
            .text
            .as_ref()
            .map(|text| text_body(text, || NodeId(0)).plain());
        if xfrm != Xfrm::default() {
            work.value(&ValueEdit::SetXfrm {
                target: Target {
                    slide: &part,
                    shape: native,
                    expected,
                },
                xfrm,
            })?;
        }
        if let Some(body) = deck.texts.get(id) {
            let plain = body.plain();
            if held_text.as_deref() != Some(plain.as_str()) {
                let (_, _, expected) = work.target(*id)?;
                work.value(&ValueEdit::SetText {
                    target: Target {
                        slide: &part,
                        shape: native,
                        expected,
                    },
                    text: &plain,
                })?;
            }
        }
    }

    // The bindings, opaque hashes and allocation history of the output.
    let output = work.view()?;
    let mut bindings = BTreeMap::new();
    for (id, (part, native)) in &work.at {
        let binding = if deck.nodes[id].kind == NodeKind::Slide {
            let slide = output
                .slides
                .iter()
                .find(|slide| &slide.part == part)
                .ok_or(LiveError::UnknownNode)?;
            NodeBinding {
                slide_part: part.clone(),
                native_id: Some(slide.sld_id),
                creation_id: slide.creation_id.map(|id| id.to_string()),
                fingerprint: slide.content_fingerprint,
            }
        } else {
            let shape = shape_at(&output, part, *native).ok_or(LiveError::UnknownNode)?;
            NodeBinding {
                slide_part: part.clone(),
                native_id: Some(*native),
                creation_id: shape.creation_id.clone(),
                fingerprint: shape.content_fingerprint,
            }
        };
        bindings.insert(*id, binding);
    }
    let slide_parts: BTreeSet<&str> = output.slides.iter().map(|s| s.part.as_str()).collect();
    let mut opaque_parts = BTreeMap::new();
    for name in work.next.names() {
        if slide_parts.contains(name) {
            continue;
        }
        if let Some(bytes) = work.next.part(name)? {
            opaque_parts.insert(name.to_owned(), *blake3::hash(&bytes).as_bytes());
        }
    }
    let mut id_marks = work.marks.clone();
    id_marks.join(&IdMarks::of_deck(&output));
    let changed_parts: Vec<String> = work.changed.into_iter().collect();
    let noop = changed_parts.is_empty();
    let bytes = work.next.export()?;
    Ok(ExportOutcome {
        bytes,
        key,
        document_version: deck.version,
        changed_parts,
        noop,
        bindings,
        opaque_parts,
        id_marks,
    })
}

impl LiveDeck {
    /// Adopt a landed export: the same model identities, now bound to the
    /// exported package, with its opaque hashes and joined allocation
    /// history. The outcome must have been projected from this exact state;
    /// the version moves, so a preflight against the old head repeats.
    pub fn rebind(&mut self, outcome: &ExportOutcome) -> Result<(), LiveError> {
        if outcome.key.state_hash != self.state_hash() {
            return Err(LiveError::Invalid(
                "the export was projected from another state",
            ));
        }
        let missing: Vec<NodeId> = self
            .nodes
            .iter()
            .filter(|(id, node)| node.kind != NodeKind::Root && !outcome.bindings.contains_key(id))
            .map(|(id, _)| *id)
            .collect();
        if !missing.is_empty() {
            return Err(LiveError::UnboundNodes(missing));
        }
        for (id, node) in &mut self.nodes {
            if let Some(binding) = outcome.bindings.get(id) {
                node.binding = Some(binding.clone());
            }
        }
        self.opaque_parts = outcome.opaque_parts.clone();
        self.id_marks.join(&outcome.id_marks);
        self.version += 1;
        Ok(())
    }
}

/// Every relationship that differs between two packages, by source part and
/// id: added (`before: None`), removed (`after: None`) or retargeted.
pub fn relationship_changes(
    before: &Package,
    after: &Package,
) -> Result<Vec<RelationshipChange>, LiveError> {
    let mut sources: BTreeSet<String> = BTreeSet::from([String::new()]);
    sources.extend(before.names().map(str::to_owned));
    sources.extend(after.names().map(str::to_owned));
    let mut out = Vec::new();
    for source in &sources {
        if source.to_ascii_lowercase().ends_with(".rels") {
            continue;
        }
        let read = |package: &Package| -> Result<BTreeMap<String, (String, String)>, LiveError> {
            if !source.is_empty() && package.part(source)?.is_none() {
                return Ok(BTreeMap::new());
            }
            Ok(package
                .relationships(source)?
                .into_iter()
                .map(|rel| (rel.id, (rel.kind, rel.target)))
                .collect())
        };
        let (old, new) = (read(before)?, read(after)?);
        let ids: BTreeSet<&String> = old.keys().chain(new.keys()).collect();
        for id in ids {
            let (was, now) = (old.get(id), new.get(id));
            if was == now {
                continue;
            }
            out.push(RelationshipChange {
                source: source.clone(),
                id: id.clone(),
                kind: now
                    .or(was)
                    .map(|(kind, _)| kind.clone())
                    .unwrap_or_default(),
                before: was.map(|(_, target)| target.clone()),
                after: now.map(|(_, target)| target.clone()),
            });
        }
    }
    Ok(out)
}

/// Attach the relationship and render components to a preflight: project
/// the current head and the actual merged candidate over the retained
/// package, compare their relationships, pin each side's slide render
/// identities at its version, and narrow the affected slides to those whose
/// render identity the candidate changes. The images come from the review
/// renderer over these named inputs; the pair is stale once the head moves.
pub fn attach_evidence(
    report: &mut PreflightReport,
    head: &LiveDeck,
    package: &Package,
    document: &str,
    profile: &ExportProfile,
) -> Result<(), LiveError> {
    let held = project(head, package, document, profile)?;
    let merged = project(&report.candidate, package, document, profile)?;
    let open = |outcome: &ExportOutcome| -> Result<Package, LiveError> {
        Ok(Package::open(&outcome.bytes, package.limits())?)
    };
    let (held_package, merged_package) = (open(&held)?, open(&merged)?);
    report.diff.relationships = relationship_changes(&held_package, &merged_package)?;
    let side = |deck: &LiveDeck,
                outcome: &ExportOutcome,
                exported: &Package|
     -> Result<RenderSide, LiveError> {
        let view = DeckView::read(exported)?;
        let slides = view
            .slides
            .iter()
            .filter_map(|slide| {
                let (node, _) = outcome.bindings.iter().find(|(id, binding)| {
                    deck.nodes
                        .get(id)
                        .is_some_and(|node| node.kind == NodeKind::Slide)
                        && binding.slide_part == slide.part
                })?;
                Some(SlideRender {
                    slide: *node,
                    part: slide.part.clone(),
                    fingerprint: slide.render_fingerprint,
                })
            })
            .collect();
        Ok(RenderSide {
            version: deck.version,
            state_hash: deck.state_hash(),
            export_key: outcome.key.hash(),
            slides,
        })
    };
    let before = side(head, &held, &held_package)?;
    let after = side(&report.candidate, &merged, &merged_package)?;
    let mut changed: BTreeSet<NodeId> = BTreeSet::new();
    for slide in &after.slides {
        if !before
            .slides
            .iter()
            .any(|held| held.slide == slide.slide && held.fingerprint == slide.fingerprint)
        {
            changed.insert(slide.slide);
        }
    }
    for slide in &before.slides {
        if !after.slides.iter().any(|kept| kept.slide == slide.slide) {
            changed.insert(slide.slide);
        }
    }
    report.diff.affected_slides = changed.iter().copied().collect();
    report.diff.renders = Some(RenderPair {
        head: before,
        candidate: after,
        changed: changed.into_iter().collect(),
    });
    Ok(())
}

/// One step of the eight-step import-then-export check. A timeout or an
/// unrun oracle is inconclusive, never a pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepOutcome {
    Passed,
    Failed(String),
    Inconclusive(String),
    NotRun,
}

/// The hashed oracle evidence one profile passed under. PowerPoint, macOS
/// and font versions are recorded on every receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleReceipt {
    pub profile: String,
    pub powerpoint_version: String,
    pub macos_version: String,
    pub font_versions: Vec<String>,
    /// The eight steps, in canon order.
    pub steps: Vec<StepOutcome>,
    /// Opened without repair.
    pub clean: bool,
}

/// The activation gate. Closed until a receipt for this exact profile
/// shows all eight steps passed on a clean oracle opening.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gate {
    pub profile: String,
    pub receipt: Option<OracleReceipt>,
}

impl Gate {
    pub fn closed(profile: &str) -> Self {
        Self {
            profile: profile.to_owned(),
            receipt: None,
        }
    }

    pub fn is_open(&self) -> bool {
        self.receipt.as_ref().is_some_and(|receipt| {
            receipt.profile == self.profile
                && receipt.clean
                && receipt.steps.len() == 8
                && receipt
                    .steps
                    .iter()
                    .all(|step| matches!(step, StepOutcome::Passed))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundtripReport {
    pub profile: String,
    /// The eight steps, in canon order.
    pub steps: Vec<StepOutcome>,
    pub baseline_preserved: bool,
    pub fixed_point: bool,
}

/// Run the steps of the eight-step check that hold in-process: baseline
/// preservation (1), the semantic fixed point (3) and package closure (5).
/// Edit preservation (2), concurrency (4), the MacBook oracle (6), non-PDF
/// checks (7) and the regression corpus (8) are reported inconclusive —
/// they need fixtures, a merge harness and the oracle seat, and an
/// unrun step is never a pass.
pub fn roundtrip_check(
    package: &Package,
    original_bytes: &[u8],
    profile: &ExportProfile,
) -> Result<RoundtripReport, LiveError> {
    let deck = LiveDeck::import(package)?;
    let outcome = project(&deck, package, "roundtrip", profile)?;
    let baseline_preserved = outcome.noop && outcome.bytes == original_bytes;
    let reopened = Package::open(&outcome.bytes, package.limits())?;
    let closure = DeckView::read(&reopened);
    let fixed_point = match &closure {
        Ok(_) => LiveDeck::import(&reopened)?.semantically_eq(&deck),
        Err(_) => false,
    };
    let step = |passed: bool, why: &str| {
        if passed {
            StepOutcome::Passed
        } else {
            StepOutcome::Failed(why.to_owned())
        }
    };
    Ok(RoundtripReport {
        profile: profile.name.clone(),
        steps: vec![
            step(baseline_preserved, "no-op export changed bytes"),
            StepOutcome::Inconclusive("edit-preservation fixtures not run".to_owned()),
            step(fixed_point, "re-import differs from the live model"),
            StepOutcome::Inconclusive("concurrency cases not run".to_owned()),
            step(closure.is_ok(), "exported package does not read back"),
            StepOutcome::Inconclusive("oracle not run".to_owned()),
            StepOutcome::Inconclusive("non-PDF checks not run".to_owned()),
            StepOutcome::Inconclusive("regression corpus not run".to_owned()),
        ],
        baseline_preserved,
        fixed_point,
    })
}
