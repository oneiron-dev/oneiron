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
//! what it carries: a shape from its preset or its points, a picture over a
//! new media part from the asset its payload names (the caller's [`Assets`]
//! supply the bytes, which must hash to the reference) or over an image the
//! deck holds, cropped to its preset's shape, a table through the native
//! writer, a chart of any family through the native writer and the chart
//! rewrite, a SmartArt as the engine's outline list, and a connector glued
//! to the nodes its ends name once they are bound on its slide. A bound
//! node whose preset or payload the live model changed is written over its
//! retained element: its preset (a picture's Crop to Shape) or points, its
//! glue, new media or held media shown again (dropping an SVG extension the
//! new media does not carry), a table's changed cells or grid (its frame
//! fitted to the grid), a chart's changed series sequences or its rewritten
//! plots, axes and workbook (a new one when its data lived elsewhere), and a
//! SmartArt's node text or its nodes added, removed and moved. What it did
//! PowerPoint's way where the deck once refused rides in the outcome's
//! effects.
//! Until [`Gate::is_open`], blob versions remain authoritative and exports
//! are proposal artifacts. An export that changes anything recounts the app
//! properties' words and paragraphs over the text it wrote last.

use super::LiveError;
use super::conversion::Conversion;
use super::convert;
use super::pptx::{
    ConnectorEnd, DeckNode, LiveDeck, NodeBinding, NodeId, NodeKind, NodePayload, PreflightReport,
    RelationshipChange, RenderPair, RenderSide, SlideRender, TextBody, geometry_of, slide_of,
    text_body,
};
use super::{diagram, held, points, svg_fallback};
use crate::deck::{DeckView, ShapeView};
use crate::design_plan::AssetKind;
use crate::edit::geometry::{glue_of, preset_of};
use crate::edit::transaction::StepAssetKind;
use crate::edit::{
    AssetRef, Assets, BREAK, ConnectorPreset, Digest, EditRefusal, Effect, IdMarks, NewConnector,
    NewGroup, NewPicture, NewShape, NoAssets, Picture, Preset, RunProps, ShapeId, StructureEdit,
    Target, ValueEdit, Xfrm, edit, structure_patch,
};
use crate::graphic::{AssetRecord, GraphicLimits};
use crate::ooxml::XmlTree;
use crate::retained_opc::Package;
use serde::{Deserialize, Serialize};
use std::cell::{OnceCell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

mod chart;
mod evidence;
mod payload;
mod projector;
mod table;

pub use evidence::{attach_evidence, relationship_changes, roundtrip_check};
use payload::{native_frame, paragraph_chars, project_marks, project_payload, span};
pub use projector::project;

/// Bump on any projector change; part of every memo key.
pub const PROJECTOR_VERSION: &str = "live-deck-projector/18";

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
/// A live-born SmartArt with no own extent: a chart's six inches by four.
const SMART_ART_EXTENT: (i64, i64) = CHART_EXTENT;

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
    /// What the value edits declared beyond their own writes: a preset that
    /// replaced a shape's custom geometry, or gave a shape that inherited
    /// its geometry its own, as PowerPoint's Change Shape does; and what the
    /// projection did PowerPoint's way on a node ([`Effect::Converted`]).
    pub effects: Vec<Effect>,
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
    /// The working package. Read it as `package`; write it only through
    /// [`Work::next_mut`], which drops what was read from it.
    package: Package,
    /// What `package` reads as, until its next write.
    reads: Reads,
    document: String,
    marks: IdMarks,
    /// Live node -> its slide part and native id (`p:sldId/@id` for a
    /// slide) in `next`.
    at: BTreeMap<NodeId, (String, u32)>,
    changed: BTreeSet<String>,
    /// The value edits' declared effects, in the order they ran.
    effects: Vec<Effect>,
    /// Each chart frame whose part this projection wrote: its series
    /// identities in the order the part now holds them.
    series: BTreeMap<NodeId, Vec<NodeId>>,
}

/// One revision of the working package as read: its deck view and slide
/// trees, each read once and shared until the package is written.
#[derive(Default)]
struct Reads {
    view: OnceCell<Rc<DeckView>>,
    slides: RefCell<BTreeMap<String, Rc<XmlTree>>>,
}

impl Work {
    /// The working package as it now reads; reused until the next write,
    /// so every fingerprint it gives is current.
    fn view(&self) -> Result<Rc<DeckView>, LiveError> {
        if let Some(view) = self.reads.view.get() {
            return Ok(Rc::clone(view));
        }
        let view = Rc::new(DeckView::read(&self.package)?);
        Ok(Rc::clone(self.reads.view.get_or_init(|| view)))
    }

    /// The slide part's XML as it now reads; reused until the next write.
    fn slide_tree(&self, part: &str) -> Result<Rc<XmlTree>, LiveError> {
        if let Some(tree) = self.reads.slides.borrow().get(part) {
            return Ok(Rc::clone(tree));
        }
        let tree = Rc::new(held::slide_tree(&self.package, part)?);
        self.reads
            .slides
            .borrow_mut()
            .insert(part.to_owned(), Rc::clone(&tree));
        Ok(tree)
    }

    /// The working package, to write: every write, by any verb or writer,
    /// takes it here, so no later read sees the revision before it.
    fn next_mut(&mut self) -> &mut Package {
        self.reads = Reads::default();
        &mut self.package
    }

    /// The deterministic creation-id seed for `node`'s `role`.
    fn seed(&self, node: NodeId, role: &str) -> Vec<u8> {
        let mut seed = self.document.as_bytes().to_vec();
        seed.extend(node.0.to_le_bytes());
        seed.extend(role.as_bytes());
        seed
    }

    fn structure(&mut self, op: &StructureEdit<'_>) -> Result<Vec<Effect>, LiveError> {
        let report = structure_patch(self.next_mut(), op)?;
        self.changed.extend(report.changed_parts);
        Ok(report.effects)
    }

    fn value(&mut self, op: &ValueEdit<'_>) -> Result<(), LiveError> {
        let report = edit(self.next_mut(), op)?;
        self.changed.extend(report.changed_parts);
        self.effects.extend(report.effects);
        Ok(())
    }

    /// Record what the projection did PowerPoint's way on `node`.
    fn converted(&mut self, node: NodeId, done: impl IntoIterator<Item = Conversion>) {
        self.effects.extend(
            done.into_iter()
                .map(|conversion| Effect::Converted { node, conversion }),
        );
    }

    /// `node`'s place and current fingerprint in `next`.
    fn target(&self, node: NodeId) -> Result<(String, u32, [u8; 32]), LiveError> {
        let (part, native) = self.at.get(&node).cloned().ok_or(LiveError::UnknownNode)?;
        let view = self.view()?;
        let expected = fingerprint_of(&view, &part, native).ok_or(LiveError::UnknownNode)?;
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
        (NodeKind::Picture, Some(NodePayload::HeldPicture { media })) => {
            let model_id = id;
            // An image the deck holds: the node's own extent, else that of a
            // bound picture showing the same part, else the picture box.
            let id = work
                .shape_mark(part)
                .checked_add(1)
                .ok_or(EditRefusal::IdSpaceExhausted)?;
            let extent = node
                .geometry
                .extent
                .or_else(|| shown_extent(deck, &media.part))
                .unwrap_or(PICTURE_BOX);
            let name = named("Picture");
            let done = convert::born_held_picture(
                work.next_mut(),
                part,
                (id, &name),
                offset,
                extent,
                media,
            )?;
            if !done.is_empty() {
                work.changed
                    .extend(work.package.changed_parts().into_iter().map(str::to_owned));
            }
            work.converted(model_id, done);
            work.changed.insert(part.to_owned());
            crop_born(work, node, part, id)?;
            return Ok(id);
        }
        (NodeKind::GraphicFrame, Some(payload)) => {
            return native_frame(work, id, node, part, payload);
        }
        (NodeKind::Connector, payload) => {
            let (preset, start, end) = match payload {
                Some(NodePayload::Connector { preset, start, end }) => {
                    (preset.unwrap_or(ConnectorPreset::Straight), *start, *end)
                }
                _ => (ConnectorPreset::Straight, None, None),
            };
            // Glue to a node bound on this slide; any other glue is dropped.
            let glue = |end: Option<ConnectorEnd>| {
                let end = end?;
                let kind = deck.nodes.get(&end.node)?.kind;
                let (at, native) = work.at.get(&end.node)?;
                (at == part && !matches!(kind, NodeKind::Slide | NodeKind::Group))
                    .then_some((ShapeId::Native(*native), end.site))
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
                "a live-born graphic frame carries no table, chart or SmartArt",
            ));
        }
        (NodeKind::Picture, Some(_)) | (NodeKind::Root | NodeKind::Slide, _) => {
            return Err(LiveError::Invalid(
                "the payload does not belong to the node kind",
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
    crop_born(work, node, part, added)?;
    // A live-born freeform: the preset the shape verb drew, then its points.
    if let (NodeKind::Shape, Some(NodePayload::CustomGeometry { paths })) =
        (node.kind, &node.payload)
    {
        let glued = points::glued_sites(deck, id);
        points::write(work.next_mut(), part, added, paths, &glued)?;
        work.changed.insert(part.to_owned());
    }
    Ok(added)
}

/// A live-born picture cropped to a shape (FIX 3696): its preset over the
/// rectangle the picture was written with, through the checked preset
/// verb, which keeps its media and crop. Nothing for any other node.
fn crop_born(work: &mut Work, node: &DeckNode, part: &str, native: u32) -> Result<(), LiveError> {
    let Some(preset) = node.preset.filter(|preset| *preset != Preset::Rect) else {
        return Ok(());
    };
    if node.kind != NodeKind::Picture {
        return Ok(());
    }
    let view = work.view()?;
    let expected = fingerprint_of(&view, part, native).ok_or(LiveError::UnknownNode)?;
    work.value(&ValueEdit::SetPreset {
        target: Target {
            slide: part,
            shape: native,
            expected,
        },
        preset: preset.name(),
    })
}

/// The extent of a bound picture showing the held media part `part`, the
/// first in model-identity order that has one.
fn shown_extent(deck: &LiveDeck, part: &str) -> Option<(i64, i64)> {
    deck.nodes.values().find_map(|node| match &node.payload {
        Some(NodePayload::HeldPicture { media })
            if node.binding.is_some() && media.part == part =>
        {
            node.geometry.extent
        }
        _ => None,
    })
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
/// and font versions are recorded on every receipt, with the run it came
/// from (FIX 3772): the projector its candidates were exported through, the
/// source revision its engine half was built from and its case manifest's
/// hash, as the run's manifest pins them. A receipt is its run's evidence:
/// it opens the gate only for the projector it names.
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
    /// The projector the run exported its candidates through (the run
    /// manifest's `projector`).
    pub projector: String,
    /// The full commit id the run's engine half was built from (the run
    /// manifest's `source`).
    pub source_sha: String,
    /// The SHA-256 of the case manifest the run read, as hex (the run
    /// manifest's `case_manifest.sha256`).
    pub case_manifest_sha256: String,
}

/// The activation gate. Closed until a receipt for this exact profile,
/// from a run of the current projector, shows all eight steps passed on a
/// clean oracle opening.
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
                && receipt.projector == PROJECTOR_VERSION
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
