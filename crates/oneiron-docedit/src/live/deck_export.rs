//! The deterministic export projector and the eight-step gate
//! (ARCH-0077, "Export is a deterministic projection").
//!
//! The projector writes the live model back over the retained package
//! through the checked structural and value verbs, with no clock and no
//! randomness. Live nodes and retained elements correspond by binding, never
//! by import order: a binding names its slide part and native id. Structure
//! goes first, in a fixed order: live-born slides, cross-slide moves (a copy
//! that carries its relationships), live-born shapes, groups, pictures and
//! graphic frames, then live-born connectors, reparents, removals (with their
//! animation cascade), slide removals, the slide order and each container's
//! sibling order. Own geometry and text follow.
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
//! projects over the new retained bytes. A live-born node is written from
//! what it carries: a shape from its preset, a picture over a new media part
//! from the asset its payload names (the caller's [`Assets`] supply the
//! bytes, which must hash to the reference), a table or chart through the
//! native writer, and a connector glued to the nodes its ends name once they
//! are bound on its slide. A bound node whose preset or payload the live
//! model changed is written over its retained element: its preset, its glue,
//! new media, a table's changed cells, a chart's changed series sequences.
//! Until [`Gate::is_open`], blob versions remain authoritative and exports
//! are proposal artifacts. An export that changes anything recounts the app
//! properties' words and paragraphs over the text it wrote last.

use super::LiveError;
use super::held;
use super::pptx::{
    ChartKind, ConnectorEnd, DeckNode, LiveDeck, NodeBinding, NodeId, NodeKind, NodePayload,
    PreflightReport, RelationshipChange, RenderPair, RenderSide, SlideRender, TextBody,
    WRITTEN_CHART, WRITTEN_TABLE, geometry_of, slide_of, text_body,
};
use crate::deck::{DeckView, ShapeView};
use crate::design_plan::{AssetKind, Cell, Column, ColumnKind, Dataset, Rect};
use crate::edit::geometry::{glue_of, preset_of};
use crate::edit::transaction::StepAssetKind;
use crate::edit::xml::next_part;
use crate::edit::{
    AssetRef, Assets, ConnectorPreset, Digest, EditRefusal, Effect, IdMarks, NewConnector,
    NewGroup, NewPicture, NewShape, NoAssets, Picture, Preset, RunProps, StructureEdit, Target,
    ValueEdit, Xfrm, edit, structure_patch,
};
use crate::graphic::{AssetRecord, GraphicLimits};
use crate::native_patch::{
    ChartFamily, Frame, NativeEdit, Target as Sequence, chart_data, native_patch,
};
use crate::retained_opc::Package;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Bump on any projector change; part of every memo key.
pub const PROJECTOR_VERSION: &str = "live-deck-projector/5";

/// A live-born shape (or a free connector) with no own extent: one inch
/// square.
const DEFAULT_EXTENT: (i64, i64) = (914_400, 914_400);
/// A live-born picture with no own extent is placed at its own aspect ratio
/// inside this box: three inches square.
const PICTURE_BOX: (i64, i64) = (2_743_200, 2_743_200);
/// A live-born table with no own extent: two inches per column and 0.4 inch
/// per row, the header row included.
const TABLE_CELL: (i64, i64) = (1_828_800, 365_760);
/// A live-born chart with no own extent: six inches by four.
const CHART_EXTENT: (i64, i64) = (5_486_400, 3_657_600);
/// The one sheet of a live-born chart's embedded workbook.
const CHART_SHEET: &str = "Sheet1";

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

/// The memo key [`project`] gives `deck` over `package`, read without
/// projecting: a caller holding an earlier projection's key keeps its result.
pub fn export_key(
    deck: &LiveDeck,
    package: &Package,
    document: &str,
    profile: &ExportProfile,
) -> Result<ExportKey, LiveError> {
    Ok(ExportKey {
        document: document.to_owned(),
        state_hash: deck.state_hash(),
        package_hash: package_hash(package)?,
        allocation_hash: *blake3::hash(&serde_json::to_vec(&deck.id_marks).unwrap_or_default())
            .as_bytes(),
        profile: profile.name.clone(),
        projector: PROJECTOR_VERSION.to_owned(),
    })
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

/// Assets resolved ahead of a projection and held in memory: what a caller
/// reads in its own transaction for every live-born picture its decks name.
#[derive(Debug, Default)]
pub struct HeldAssets {
    held: Vec<(AssetRef, AssetRecord, Vec<u8>)>,
}

impl HeldAssets {
    /// Every asset a picture payload in `decks` names, through `from`. One
    /// that does not resolve stays out, and an export that writes it refuses.
    pub fn resolve(from: &dyn Assets, decks: &[&LiveDeck]) -> Self {
        let mut held: Vec<(AssetRef, AssetRecord, Vec<u8>)> = Vec::new();
        for node in decks.iter().flat_map(|deck| deck.nodes.values()) {
            if let Some(NodePayload::Picture { image }) = &node.payload
                && !held.iter().any(|(asset, ..)| asset == image)
                && let Some((record, bytes)) = from.resolve(image)
            {
                held.push((image.clone(), record, bytes));
            }
        }
        Self { held }
    }
}

impl Assets for HeldAssets {
    fn resolve(&self, asset: &AssetRef) -> Option<(AssetRecord, Vec<u8>)> {
        self.held
            .iter()
            .find(|(held, ..)| held == asset)
            .map(|(_, record, bytes)| (record.clone(), bytes.clone()))
    }
}

/// Project `deck` at its current version over its retained `package`;
/// `assets` supply the bytes of its live-born pictures.
pub fn project(
    deck: &LiveDeck,
    package: &Package,
    document: &str,
    profile: &ExportProfile,
    assets: &dyn Assets,
) -> Result<ExportOutcome, LiveError> {
    let key = export_key(deck, package, document, profile)?;
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

    // 3. Live-born shapes, groups, pictures and graphic frames, in
    // model-identity order, topmost in their slide's shape tree; then the
    // live-born connectors, so every node their ends name is bound. The
    // reparent pass puts them in place.
    for connectors in [false, true] {
        for (id, node) in &deck.nodes {
            if matches!(node.kind, NodeKind::Root | NodeKind::Slide)
                || (node.kind == NodeKind::Connector) != connectors
                || work.at.contains_key(id)
            {
                continue;
            }
            let part = home.get(id).cloned().ok_or(LiveError::UnknownNode)?;
            let added = born(&mut work, deck, *id, &part, assets)?;
            work.raise_shape(&part, added);
            work.at.insert(*id, (part, added));
        }
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
            project_marks(&mut work, *id, &part, native, body)?;
        }
        if node.binding.is_some() {
            project_payload(&mut work, deck, *id, &part, native, assets)?;
        }
    }

    // The app properties' words and paragraphs, recounted over the text
    // this export wrote.
    let output = work.view()?;
    if !work.changed.is_empty()
        && let Some(props) = crate::edit::recount_slide_text(&mut work.next, &output)?
    {
        work.changed.insert(props);
    }

    // The bindings, opaque hashes and allocation history of the output.
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

/// Write the live-born node `id` topmost in `part`'s shape tree; its new
/// native id.
fn born(
    work: &mut Work,
    deck: &LiveDeck,
    id: NodeId,
    part: &str,
    assets: &dyn Assets,
) -> Result<u32, LiveError> {
    let node = &deck.nodes[&id];
    let (high, seed) = (work.shape_mark(part), work.seed(id, "shape"));
    let named = |fallback: &str| node.name.clone().unwrap_or_else(|| fallback.to_owned());
    let offset = node.geometry.offset.unwrap_or((0, 0));
    let effects = match (node.kind, &node.payload) {
        (NodeKind::Shape, _) => {
            let name = named("Shape");
            work.structure(&StructureEdit::AddShape {
                slide: part,
                shape: NewShape {
                    preset: node.preset.unwrap_or(Preset::Rect),
                    name: &name,
                    offset,
                    extent: node.geometry.extent.unwrap_or(DEFAULT_EXTENT),
                    high_water: high,
                    seed: &seed,
                },
            })?
        }
        (NodeKind::Group, _) => {
            let name = named("Group");
            let (offset, extent) = frame(deck, id).ok_or(LiveError::Invalid(
                "a live-born group has no frame: give it or a member an offset and extent",
            ))?;
            work.structure(&StructureEdit::AddGroup {
                slide: part,
                group: NewGroup {
                    name: &name,
                    offset,
                    extent,
                    high_water: high,
                    seed: &seed,
                },
            })?
        }
        (NodeKind::Picture, Some(NodePayload::Picture { image })) => {
            let (record, bytes) = resolved(image, assets)?;
            let name = named("Picture");
            work.structure(&StructureEdit::AddPicture {
                slide: part,
                picture: NewPicture {
                    name: &name,
                    picture: Picture {
                        record: &record,
                        bytes: &bytes,
                        requested: requested(image),
                        limits: GraphicLimits::default(),
                    },
                    offset,
                    extent: node.geometry.extent.unwrap_or(PICTURE_BOX),
                    fit: node.geometry.extent.is_none(),
                    high_water: high,
                    seed: &seed,
                },
            })?
        }
        (NodeKind::GraphicFrame, Some(payload)) => return native_frame(work, node, part, payload),
        (NodeKind::Connector, payload) => {
            let (preset, start, end) = match payload {
                Some(NodePayload::Connector { preset, start, end }) => (*preset, *start, *end),
                _ => (ConnectorPreset::Straight, None, None),
            };
            // Glue to a node bound on this slide; any other glue is dropped.
            let glue = |end: Option<ConnectorEnd>| {
                let end = end?;
                let kind = deck.nodes.get(&end.node)?.kind;
                let (at, native) = work.at.get(&end.node)?;
                (at == part && !matches!(kind, NodeKind::Slide | NodeKind::Group))
                    .then_some((*native, end.site))
            };
            let glued = (glue(start), glue(end));
            let (offset, extent, (flip_h, flip_v)) =
                match (node.geometry.offset, node.geometry.extent) {
                    (Some(offset), Some(extent)) => (offset, extent, (false, false)),
                    _ => span(deck, start, end).unwrap_or((
                        offset,
                        node.geometry.extent.unwrap_or(DEFAULT_EXTENT),
                        (false, false),
                    )),
                };
            let name = named("Connector");
            work.structure(&StructureEdit::AddConnector {
                slide: part,
                connector: NewConnector {
                    preset,
                    name: &name,
                    offset,
                    extent,
                    flip_h,
                    flip_v,
                    start: glued.0,
                    end: glued.1,
                    high_water: high,
                    seed: &seed,
                },
            })?
        }
        (NodeKind::Picture, None) => {
            return Err(LiveError::Invalid("a live-born picture names no image"));
        }
        (NodeKind::GraphicFrame, None) => {
            return Err(LiveError::Invalid(
                "a live-born graphic frame carries no table or chart",
            ));
        }
        (NodeKind::Picture, Some(_)) | (NodeKind::Root | NodeKind::Slide, _) => {
            return Err(LiveError::Invalid(
                "the payload does not belong to the node kind",
            ));
        }
    };
    effects
        .iter()
        .find_map(|effect| match effect {
            Effect::ShapeAdded { id, .. } => Some(*id),
            _ => None,
        })
        .ok_or(LiveError::Invalid("the shape verb added no shape"))
}

/// The asset a picture payload names, resolved through `assets`; its bytes
/// must hash to the reference and its record name the same version.
fn resolved(image: &AssetRef, assets: &dyn Assets) -> Result<(AssetRecord, Vec<u8>), LiveError> {
    let (record, bytes) = assets
        .resolve(image)
        .ok_or(LiveError::Invalid("a picture's asset does not resolve"))?;
    if Digest::of(&bytes) != image.hash
        || record.content_hash != image.hash.0
        || record.artifact != image.artifact
        || record.version != image.version
    {
        return Err(LiveError::Invalid(
            "a picture's asset bytes do not match its reference",
        ));
    }
    Ok((record, bytes))
}

fn requested(image: &AssetRef) -> AssetKind {
    match image.kind {
        StepAssetKind::Factual => AssetKind::Factual,
        StepAssetKind::Illustration => AssetKind::Illustration,
    }
}

/// Refuse a picture whose asset does not resolve through `assets`, or whose
/// bytes do not match its reference: what an operation's writer checks when
/// the operation is made, ahead of the export that writes it.
pub fn check_picture(image: &AssetRef, assets: &dyn Assets) -> Result<(), LiveError> {
    resolved(image, assets).map(|_| ())
}

/// Write what a bound node's preset or payload changed over its retained
/// element: a shape's or connector's preset, a connector's glue (to nodes
/// bound on its slide), new media for a picture, a table's changed cells,
/// and a chart's changed series names, categories and values. Each write is
/// one checked verb; a node whose retained element already reads as the
/// live model writes nothing.
fn project_payload(
    work: &mut Work,
    deck: &LiveDeck,
    id: NodeId,
    part: &str,
    native: u32,
    assets: &dyn Assets,
) -> Result<(), LiveError> {
    let node = &deck.nodes[&id];
    let view = work.view()?;
    let at = shape_at(&view, part, native)
        .ok_or(LiveError::UnknownNode)?
        .node
        .index;
    let tree = held::slide_tree(&work.next, part)?;
    let preset = match (&node.payload, node.preset) {
        (Some(NodePayload::Connector { preset, .. }), _) => Some(preset.name()),
        (_, Some(preset)) if node.kind == NodeKind::Shape => Some(preset.name()),
        _ => None,
    };
    if let Some(preset) = preset
        && preset_of(&tree, at) != Some(preset)
    {
        let (_, _, expected) = work.target(id)?;
        work.value(&ValueEdit::SetPreset {
            target: Target {
                slide: part,
                shape: native,
                expected,
            },
            preset,
        })?;
    }
    match &node.payload {
        Some(NodePayload::Connector { start, end, .. }) => {
            let glue = |end: &Option<ConnectorEnd>| {
                let end = (*end)?;
                let kind = deck.nodes.get(&end.node)?.kind;
                let (at, native) = work.at.get(&end.node)?;
                (at == part && !matches!(kind, NodeKind::Slide | NodeKind::Group))
                    .then_some((*native, end.site))
            };
            let wanted = (glue(start), glue(end));
            if glue_of(&tree, at) != wanted {
                let (_, _, expected) = work.target(id)?;
                work.value(&ValueEdit::SetGlue {
                    target: Target {
                        slide: part,
                        shape: native,
                        expected,
                    },
                    start: wanted.0,
                    end: wanted.1,
                })?;
            }
        }
        Some(NodePayload::Picture { image }) => {
            if held::picture_media(&work.next, part, &tree, at) != Some(image.hash) {
                let (record, bytes) = resolved(image, assets)?;
                let (_, _, expected) = work.target(id)?;
                work.value(&ValueEdit::SetPicture {
                    target: Target {
                        slide: part,
                        shape: native,
                        expected,
                    },
                    picture: Picture {
                        record: &record,
                        bytes: &bytes,
                        requested: requested(image),
                        limits: GraphicLimits::default(),
                    },
                })?;
            }
        }
        Some(NodePayload::Table { header, rows }) => {
            let have = held::table_cells(&tree, at).ok_or(LiveError::Invalid(WRITTEN_TABLE))?;
            let wanted: Vec<Vec<String>> = std::iter::once(header.clone())
                .chain(rows.iter().map(|row| {
                    row.iter()
                        .map(|cell| cell.clone().unwrap_or_default())
                        .collect()
                }))
                .collect();
            if have.len() != wanted.len()
                || have
                    .iter()
                    .zip(&wanted)
                    .any(|(was, now)| was.len() != now.len())
            {
                return Err(LiveError::Invalid(WRITTEN_TABLE));
            }
            for (row, (was, now)) in have.iter().zip(&wanted).enumerate() {
                for (col, (was, now)) in was.iter().zip(now).enumerate() {
                    if was == now {
                        continue;
                    }
                    let report = native_patch(
                        &mut work.next,
                        &NativeEdit::SetTableCell {
                            slide: part,
                            table: native,
                            row,
                            col,
                            expected: was,
                            value: now,
                        },
                    )?;
                    work.changed.extend(report.changed_parts);
                }
            }
        }
        Some(NodePayload::Chart {
            family,
            categories,
            series,
        }) => {
            let chart = held::chart_part(&work.next, part, &tree, at)
                .ok_or(LiveError::Invalid(WRITTEN_CHART))?;
            if held::chart_family(&work.next, &chart) != Some(*family)
                || chart_data(&work.next, &chart)?.series.len() != series.len()
            {
                return Err(LiveError::Invalid(WRITTEN_CHART));
            }
            for (index, line) in series.iter().enumerate() {
                for target in [Sequence::Name, Sequence::Categories, Sequence::Values] {
                    // Re-read before each write: a range two series share
                    // moves both caches.
                    let data = chart_data(&work.next, &chart)?;
                    let sequence = data.series.get(index).and_then(|data| match target {
                        Sequence::Name => data.name.as_ref(),
                        Sequence::Categories => data.categories.as_ref(),
                        Sequence::Values => data.values.as_ref(),
                    });
                    let cache = sequence.map_or(&[][..], |sequence| sequence.cache.as_slice());
                    let wanted: Vec<Cell> = match target {
                        Sequence::Name => {
                            if cache.first().map(held::label).as_deref() == Some(line.name.as_str())
                            {
                                continue;
                            }
                            vec![Cell::Text(line.name.clone())]
                        }
                        Sequence::Categories => {
                            if cache.iter().map(held::label).eq(categories.iter().cloned()) {
                                continue;
                            }
                            // A number category stays a number.
                            categories
                                .iter()
                                .enumerate()
                                .map(|(point, category)| match cache.get(point) {
                                    Some(Cell::Number(_)) => category.parse().map_or_else(
                                        |_| Cell::Text(category.clone()),
                                        Cell::Number,
                                    ),
                                    _ => Cell::Text(category.clone()),
                                })
                                .collect()
                        }
                        Sequence::Values => {
                            let values: Vec<Cell> = (0..categories.len())
                                .map(|point| {
                                    line.values
                                        .get(point)
                                        .and_then(|value| value.as_ref()?.as_f64())
                                        .map_or(Cell::Missing, Cell::Number)
                                })
                                .collect();
                            if cache == values.as_slice() {
                                continue;
                            }
                            values
                        }
                    };
                    let report = native_patch(
                        &mut work.next,
                        &NativeEdit::SetSeries {
                            chart: &chart,
                            series: index,
                            target,
                            values: &wanted,
                        },
                    )?;
                    work.changed.extend(report.changed_parts);
                }
            }
        }
        None => {}
    }
    Ok(())
}

/// A connector's frame from its ends' centres, when both name top-level
/// nodes with own frames: the box between them, flipped to run from the
/// start to the end.
fn span(
    deck: &LiveDeck,
    start: Option<ConnectorEnd>,
    end: Option<ConnectorEnd>,
) -> Option<((i64, i64), (i64, i64), (bool, bool))> {
    let centre = |end: Option<ConnectorEnd>| {
        let node = deck.nodes.get(&end?.node)?;
        if deck.nodes.get(&node.parent?)?.kind != NodeKind::Slide {
            return None;
        }
        let ((x, y), (cx, cy)) = (node.geometry.offset?, node.geometry.extent?);
        Some((x.checked_add(cx / 2)?, y.checked_add(cy / 2)?))
    };
    let ((x0, y0), (x1, y1)) = (centre(start)?, centre(end)?);
    let extent = (x1.checked_sub(x0)?.abs(), y1.checked_sub(y0)?.abs());
    Some(((x0.min(x1), y0.min(y1)), extent, (x1 < x0, y1 < y0)))
}

/// Write a live-born table or chart through the native writer, topmost in
/// `part`'s shape tree under the next id above the slide's mark; its id.
fn native_frame(
    work: &mut Work,
    node: &DeckNode,
    part: &str,
    payload: &NodePayload,
) -> Result<u32, LiveError> {
    let id = work
        .shape_mark(part)
        .checked_add(1)
        .ok_or(EditRefusal::IdSpaceExhausted)?;
    let (x, y) = node.geometry.offset.unwrap_or((0, 0));
    let column = |name: &str, kind| Column {
        name: name.to_owned(),
        kind,
        unit: None,
        format: None,
    };
    let count = |n: usize| i64::try_from(n).unwrap_or(i64::MAX);
    let dataset = |columns: Vec<Column>, rows: Vec<Vec<Cell>>| Dataset {
        id: String::new(),
        columns,
        rows,
        missing: None,
        sources: Vec::new(),
        merges: Vec::new(),
    };
    let report = match payload {
        NodePayload::Table { header, rows } => {
            let data = dataset(
                header
                    .iter()
                    .map(|name| column(name, ColumnKind::Text))
                    .collect(),
                rows.iter()
                    .map(|row| {
                        row.iter()
                            .map(|cell| cell.clone().map_or(Cell::Missing, Cell::Text))
                            .collect()
                    })
                    .collect(),
            );
            let (cx, cy) = node.geometry.extent.unwrap_or((
                TABLE_CELL.0.saturating_mul(count(header.len())),
                TABLE_CELL
                    .1
                    .saturating_mul(count(rows.len()).saturating_add(1)),
            ));
            let name = node.name.clone().unwrap_or_else(|| "Table".to_owned());
            native_patch(
                &mut work.next,
                &NativeEdit::CreateTable {
                    frame: Frame {
                        slide: part,
                        id,
                        name: &name,
                        bounds: Rect { x, y, cx, cy },
                        placeholder: None,
                    },
                    dataset: &data,
                    merges: &[],
                },
            )?
        }
        NodePayload::Chart {
            family,
            categories,
            series,
        } => {
            let mut columns = vec![column("", ColumnKind::Text)];
            columns.extend(
                series
                    .iter()
                    .map(|line| column(&line.name, ColumnKind::Number)),
            );
            let rows = categories
                .iter()
                .enumerate()
                .map(|(at, category)| {
                    let mut row = vec![Cell::Text(category.clone())];
                    row.extend(series.iter().map(|line| {
                        line.values
                            .get(at)
                            .and_then(|value| value.as_ref()?.as_f64())
                            .map_or(Cell::Missing, Cell::Number)
                    }));
                    row
                })
                .collect();
            let data = dataset(columns, rows);
            let (cx, cy) = node.geometry.extent.unwrap_or(CHART_EXTENT);
            let name = node.name.clone().unwrap_or_else(|| "Chart".to_owned());
            let chart = next_part(&work.next, "ppt/charts/chart", ".xml")?;
            let workbook = next_part(
                &work.next,
                "ppt/embeddings/Microsoft_Excel_Worksheet",
                ".xlsx",
            )?;
            native_patch(
                &mut work.next,
                &NativeEdit::CreateChart {
                    frame: Frame {
                        slide: part,
                        id,
                        name: &name,
                        bounds: Rect { x, y, cx, cy },
                        placeholder: None,
                    },
                    family: match family {
                        ChartKind::Bar => ChartFamily::Bar,
                        ChartKind::Line => ChartFamily::Line,
                        ChartKind::Pie => ChartFamily::Pie,
                    },
                    dataset: &data,
                    chart: &chart,
                    workbook: &workbook,
                    sheet: CHART_SHEET,
                },
            )?
        }
        NodePayload::Picture { .. } | NodePayload::Connector { .. } => {
            return Err(LiveError::Invalid(
                "the payload does not belong to the node kind",
            ));
        }
    };
    work.changed.extend(report.changed_parts);
    Ok(id)
}

/// The live run marks over the package's runs: a live run whose declared
/// marks the package's characters under it do not read is written as one
/// `SetRunProps` over its range, which splits package runs at its edges.
/// A paragraph the package does not read as the live text is left as it is.
fn project_marks(
    work: &mut Work,
    id: NodeId,
    part: &str,
    native: u32,
    body: &TextBody,
) -> Result<(), LiveError> {
    for (index, paragraph) in body.paragraphs.iter().enumerate() {
        let live_text = paragraph.text();
        let mut from = 0;
        for run in &paragraph.runs {
            let range = (from, from + run.text.chars().count());
            from = range.1;
            if range.0 == range.1 {
                continue;
            }
            let view = work.view()?;
            let shape = shape_at(&view, part, native).ok_or(LiveError::UnknownNode)?;
            let Some(held) = shape
                .text
                .as_ref()
                .and_then(|text| text.paragraphs.get(index))
            else {
                break;
            };
            let held_text: String = held.runs.iter().map(|run| run.text.as_str()).collect();
            if held_text != live_text {
                break;
            }
            let mut props = RunProps::default();
            let mut at = 0;
            for under in &held.runs {
                let span = (at, at + under.text.chars().count());
                at = span.1;
                if span.1 <= range.0 || span.0 >= range.1 {
                    continue;
                }
                if run.bold.is_some() && under.bold.value != run.bold {
                    props.bold = run.bold;
                }
                if run.italic.is_some() && under.italic.value != run.italic {
                    props.italic = run.italic;
                }
                if run.size.is_some() && under.size.value != run.size {
                    props.size = run.size;
                }
                if let Some(face) = &run.latin
                    && under
                        .latin
                        .value
                        .as_ref()
                        .map(|font| font.typeface.as_str())
                        != Some(face.as_str())
                {
                    props.latin = Some(face.as_str());
                }
            }
            if props == RunProps::default() {
                continue;
            }
            let (_, _, expected) = work.target(id)?;
            work.value(&ValueEdit::SetRunProps {
                target: Target {
                    slide: part,
                    shape: native,
                    expected,
                },
                paragraph: index,
                range,
                expected: &held_text,
                props,
            })?;
        }
    }
    Ok(())
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
    assets: &dyn Assets,
) -> Result<(), LiveError> {
    let held = project(head, package, document, profile, assets)?;
    let merged = project(&report.candidate, package, document, profile, assets)?;
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StepOutcome {
    Passed,
    Failed(String),
    Inconclusive(String),
    NotRun,
}

/// The hashed oracle evidence one profile passed under. PowerPoint, macOS
/// and font versions are recorded on every receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
    let outcome = project(&deck, package, "roundtrip", profile, &NoAssets)?;
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
