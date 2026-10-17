//! The live deck model: tree, text bodies, stamped operations, attribution,
//! three-way forks and landing (ARCH-0077 section "Multiplayer").
//!
//! Model identity ([`NodeId`]) is minted here and never reused; the native
//! `p:cNvPr/@id` within its slide part is retained as format evidence on the
//! node's [`NodeBinding`], exactly as the anchor contract keeps them apart.
//! Sibling position in `children` is the only order. Imported content has
//! unknown authorship: no importer or OOXML author name is ever recorded as
//! its maker.

use super::LiveError;
use crate::deck::{DeckView, ShapeKind, ShapeView, TextView};
use crate::edit::IdMarks;
use crate::retained_opc::Package;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Model identity for slides, shapes and paragraphs. The root is `NodeId(0)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Root,
    Slide,
    Group,
    Shape,
    Picture,
    GraphicFrame,
    Connector,
}

impl NodeKind {
    /// Whether a node of this kind may hold a child of `kind`: slides belong
    /// under the root; groups and shapes under slides or groups. A group
    /// cannot contain slides.
    pub fn holds(self, kind: NodeKind) -> bool {
        match kind {
            NodeKind::Slide => self == NodeKind::Root,
            NodeKind::Root => false,
            _ => matches!(self, NodeKind::Slide | NodeKind::Group),
        }
    }
}

/// How a live node binds to retained package evidence. Absent for nodes born
/// in the live body that no import produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeBinding {
    /// The slide part this node was read from.
    pub slide_part: String,
    /// `p:cNvPr/@id` (shapes) or `p:sldId/@id` (slides) as imported.
    pub native_id: Option<u32>,
    /// `a16:creationId` (shapes) or `p14:creationId` (slides, decimal).
    pub creation_id: Option<String>,
    /// Content fingerprint at import; the staleness guard for export edits.
    pub fingerprint: [u8; 32],
}

/// Own (never inherited) geometry, in EMU and 60,000ths of a degree.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeometryProps {
    pub offset: Option<(i64, i64)>,
    pub extent: Option<(i64, i64)>,
    pub rotation: Option<i64>,
    pub flip_h: Option<bool>,
    pub flip_v: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckNode {
    pub kind: NodeKind,
    pub parent: Option<NodeId>,
    /// Sibling order is position in this list; there is no other order.
    pub children: Vec<NodeId>,
    pub name: Option<String>,
    pub binding: Option<NodeBinding>,
    pub geometry: GeometryProps,
    /// Placeholder kind/index as read (`p:ph`), for export evidence.
    pub placeholder: Option<(String, u32)>,
}

/// One run of a paragraph. Formatting rides as run-property marks; scheme
/// colour and hyperlinks stay atomic values on the run that carries them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Run {
    pub text: String,
    pub bold: Option<bool>,
    pub italic: Option<bool>,
    /// Hundredths of a point.
    pub size: Option<u32>,
    pub latin: Option<String>,
}

/// A paragraph with a stable identity, kept across text edits to its runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Paragraph {
    pub id: NodeId,
    pub level: u8,
    pub runs: Vec<Run>,
}

impl Paragraph {
    pub fn text(&self) -> String {
        self.runs.iter().map(|run| run.text.as_str()).collect()
    }
}

/// One rich-text body per text shape.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextBody {
    pub paragraphs: Vec<Paragraph>,
}

impl TextBody {
    /// The plain mapping the edit verbs use: `\n` between paragraphs.
    pub fn plain(&self) -> String {
        self.paragraphs
            .iter()
            .map(Paragraph::text)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// The whole live deck: one tree, text bodies keyed by their shape node, and
/// the content hashes of every opaque (non-slide) retained part.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveDeck {
    pub nodes: BTreeMap<NodeId, DeckNode>,
    pub texts: BTreeMap<NodeId, TextBody>,
    /// BLAKE3 of each opaque part's bytes (masters, layouts, themes, media).
    pub opaque_parts: BTreeMap<String, [u8; 32]>,
    /// Next model identity to mint. Never decreases, never reuses.
    pub next_node: u64,
    /// Count of operations applied since import; the preflight pins it.
    pub version: u64,
    /// Native-id allocation history: every slide and shape id the retained
    /// packages this deck was bound to have held. An export allocates new
    /// native ids above it, so a removed node's id is never reused.
    pub id_marks: IdMarks,
}

impl LiveDeck {
    /// Import a retained package into the live model. Authorship of every
    /// imported node is unknown by construction.
    pub fn import(package: &Package) -> Result<Self, LiveError> {
        let view = DeckView::read(package)?;
        let mut deck = Self {
            nodes: BTreeMap::new(),
            texts: BTreeMap::new(),
            opaque_parts: BTreeMap::new(),
            next_node: 1,
            version: 0,
            id_marks: IdMarks::of_deck(&view),
        };
        deck.nodes.insert(
            NodeId(0),
            DeckNode {
                kind: NodeKind::Root,
                parent: None,
                children: Vec::new(),
                name: None,
                binding: None,
                geometry: GeometryProps::default(),
                placeholder: None,
            },
        );
        let slide_parts: BTreeSet<&str> = view
            .slides
            .iter()
            .map(|slide| slide.part.as_str())
            .collect();
        for slide in &view.slides {
            let slide_id = deck.mint();
            deck.nodes.insert(
                slide_id,
                DeckNode {
                    kind: NodeKind::Slide,
                    parent: Some(NodeId(0)),
                    children: Vec::new(),
                    name: None,
                    binding: Some(NodeBinding {
                        slide_part: slide.part.clone(),
                        native_id: Some(slide.sld_id),
                        creation_id: slide.creation_id.map(|id| id.to_string()),
                        fingerprint: slide.content_fingerprint,
                    }),
                    geometry: GeometryProps::default(),
                    placeholder: None,
                },
            );
            deck.nodes
                .get_mut(&NodeId(0))
                .expect("root inserted above")
                .children
                .push(slide_id);
            // First pass mints every shape identity in document order; the
            // second wires parents from each shape's group path.
            let mut ids: Vec<NodeId> = Vec::with_capacity(slide.shapes.len());
            for shape in &slide.shapes {
                let id = deck.mint();
                ids.push(id);
                let geometry = geometry_of(shape);
                deck.nodes.insert(
                    id,
                    DeckNode {
                        kind: match shape.kind {
                            ShapeKind::Shape => NodeKind::Shape,
                            ShapeKind::Picture => NodeKind::Picture,
                            ShapeKind::GraphicFrame => NodeKind::GraphicFrame,
                            ShapeKind::Connector => NodeKind::Connector,
                            ShapeKind::Group => NodeKind::Group,
                        },
                        parent: Some(slide_id),
                        children: Vec::new(),
                        name: shape.name.clone(),
                        binding: Some(NodeBinding {
                            slide_part: slide.part.clone(),
                            native_id: shape.id,
                            creation_id: shape.creation_id.clone(),
                            fingerprint: shape.content_fingerprint,
                        }),
                        geometry,
                        placeholder: shape
                            .placeholder
                            .as_ref()
                            .map(|ph| (ph.kind.clone(), ph.idx)),
                    },
                );
                if let Some(text) = &shape.text {
                    let body = text_body(text, || deck.mint());
                    deck.texts.insert(id, body);
                }
            }
            for (index, shape) in slide.shapes.iter().enumerate() {
                let parent = shape
                    .group_path
                    .last()
                    .map_or(slide_id, |group| ids[*group]);
                let id = ids[index];
                deck.nodes
                    .get_mut(&id)
                    .expect("shape inserted above")
                    .parent = Some(parent);
                deck.nodes
                    .get_mut(&parent)
                    .expect("parent inserted above")
                    .children
                    .push(id);
            }
        }
        for name in package.names() {
            if slide_parts.contains(name) {
                continue;
            }
            if let Some(bytes) = package.part(name)? {
                deck.opaque_parts
                    .insert(name.to_owned(), *blake3::hash(&bytes).as_bytes());
            }
        }
        Ok(deck)
    }

    fn mint(&mut self) -> NodeId {
        while self.nodes.contains_key(&NodeId(self.next_node)) {
            self.next_node += 1;
        }
        let id = NodeId(self.next_node);
        self.next_node += 1;
        id
    }

    /// The identity a creation names, or a fresh mint. A named identity
    /// already in the tree refuses: identities are never reused.
    fn take(&mut self, id: Option<NodeId>) -> Result<NodeId, LiveError> {
        match id {
            None => Ok(self.mint()),
            Some(id) if id == NodeId(0) || self.nodes.contains_key(&id) => {
                Err(LiveError::Invalid("the node identity is taken"))
            }
            Some(id) => Ok(id),
        }
    }

    /// Canonical state hash at the current version (export memo-key input).
    pub fn state_hash(&self) -> [u8; 32] {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        *blake3::hash(&bytes).as_bytes()
    }

    /// Semantic equality ignoring the operation counter: the fixed-point
    /// comparison of step 3 of the eight-step check.
    pub fn semantically_eq(&self, other: &Self) -> bool {
        self.nodes == other.nodes
            && self.texts == other.texts
            && self.opaque_parts == other.opaque_parts
    }

    /// Every descendant of `node`, in tree order.
    pub fn descendants(&self, node: NodeId) -> Vec<NodeId> {
        let mut out = Vec::new();
        let mut stack: Vec<NodeId> = self
            .nodes
            .get(&node)
            .map(|found| found.children.clone())
            .unwrap_or_default();
        stack.reverse();
        while let Some(id) = stack.pop() {
            out.push(id);
            if let Some(found) = self.nodes.get(&id) {
                let mut children = found.children.clone();
                children.reverse();
                stack.extend(children);
            }
        }
        out
    }

    /// The slide part `node` lives on, through its binding or its slide
    /// ancestor's.
    pub fn slide_part_of(&self, mut node: NodeId) -> Option<String> {
        loop {
            let found = self.nodes.get(&node)?;
            if let Some(binding) = &found.binding {
                return Some(binding.slide_part.clone());
            }
            node = found.parent?;
        }
    }
}

/// A retained shape's own geometry, as the live model holds it.
pub(crate) fn geometry_of(shape: &ShapeView) -> GeometryProps {
    GeometryProps {
        offset: own(&shape.geometry.offset),
        extent: own(&shape.geometry.extent),
        rotation: own(&shape.geometry.rotation),
        flip_h: own(&shape.geometry.flip_h),
        flip_v: own(&shape.geometry.flip_v),
    }
}

/// A retained text body as the live model holds it, paragraph identities
/// drawn from `mint`.
pub(crate) fn text_body(text: &TextView, mut mint: impl FnMut() -> NodeId) -> TextBody {
    TextBody {
        paragraphs: text
            .paragraphs
            .iter()
            .map(|paragraph| Paragraph {
                id: mint(),
                level: paragraph.level.value.unwrap_or(0),
                runs: paragraph
                    .runs
                    .iter()
                    .map(|run| Run {
                        text: run.text.clone(),
                        bold: run.bold.value,
                        italic: run.italic.value,
                        size: run.size.value,
                        latin: run.latin.value.as_ref().map(|font| font.typeface.clone()),
                    })
                    .collect(),
            })
            .collect(),
    }
}

/// An effective value the target element itself holds; inherited values are
/// never materialised into the live model.
fn own<T: Clone>(value: &crate::deck::Value<T>) -> Option<T> {
    if value.inherited {
        None
    } else {
        value.value.clone()
    }
}

/// One deck operation. A move keeps the node's identity; a cross-slide move
/// is reported because it also changes relationship context. A creation
/// names the identity it makes, so replaying it onto another head (a fork's
/// merge, a concurrent peer) makes the same node; `None` mints one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeckOp {
    AddSlide {
        #[serde(default)]
        id: Option<NodeId>,
    },
    AddNode {
        #[serde(default)]
        id: Option<NodeId>,
        parent: NodeId,
        kind: NodeKind,
        name: Option<String>,
        index: Option<usize>,
    },
    RemoveNode {
        node: NodeId,
    },
    MoveNode {
        node: NodeId,
        new_parent: NodeId,
        index: usize,
    },
    /// Replace a text shape's whole body; paragraph identities are caller
    /// supplied so unchanged paragraphs keep theirs.
    SetText {
        node: NodeId,
        body: TextBody,
    },
    /// Formatting-only change to the runs of one paragraph.
    SetRunMarks {
        node: NodeId,
        paragraph: NodeId,
        runs: Vec<Run>,
    },
    SetGeometry {
        node: NodeId,
        geometry: GeometryProps,
    },
    /// Whole-part replacement of an opaque part, guarded by its source hash.
    ReplaceOpaque {
        part: String,
        expected: [u8; 32],
        replacement: [u8; 32],
    },
}

impl DeckOp {
    /// The node this operation touches, when it touches exactly one.
    pub fn target(&self) -> Option<NodeId> {
        match self {
            DeckOp::AddNode { parent, .. } => Some(*parent),
            DeckOp::RemoveNode { node }
            | DeckOp::MoveNode { node, .. }
            | DeckOp::SetText { node, .. }
            | DeckOp::SetRunMarks { node, .. }
            | DeckOp::SetGeometry { node, .. } => Some(*node),
            DeckOp::AddSlide { .. } | DeckOp::ReplaceOpaque { .. } => None,
        }
    }

    /// The identity a creation names.
    pub fn created(&self) -> Option<NodeId> {
        match self {
            DeckOp::AddSlide { id } | DeckOp::AddNode { id, .. } => *id,
            _ => None,
        }
    }

    /// Name the identity of a creation that names none, from `mint`: what a
    /// writer records so every replay makes the same node.
    pub fn name_creation(&mut self, mint: impl FnOnce() -> NodeId) {
        if let DeckOp::AddSlide { id } | DeckOp::AddNode { id, .. } = self
            && id.is_none()
        {
            *id = Some(mint());
        }
    }

    pub fn kind(&self) -> ChangeKind {
        match self {
            DeckOp::AddSlide { .. } | DeckOp::AddNode { .. } | DeckOp::RemoveNode { .. } => {
                ChangeKind::Creation
            }
            DeckOp::MoveNode { .. } => ChangeKind::Movement,
            DeckOp::SetText { .. } => ChangeKind::Text,
            DeckOp::SetRunMarks { .. } => ChangeKind::Formatting,
            DeckOp::SetGeometry { .. } | DeckOp::ReplaceOpaque { .. } => ChangeKind::Property,
        }
    }
}

/// What an operation did to a unit, for attribution and effect descriptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Creation,
    Text,
    Formatting,
    Movement,
    Property,
    /// A container summarising edits below it; never written per keystroke
    /// onto the slide itself.
    Descendant,
}

/// Every operation says who made it. `made_by` is the actor the engine bound
/// to the writing peer; it is attribution evidence, never authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StampedOp {
    pub made_by: String,
    pub at: u64,
    pub op: DeckOp,
}

impl LiveDeck {
    /// Apply one stamped operation, validating the tree rules. Returns the
    /// nodes the operation affected (the target plus, for a removal, its
    /// former subtree).
    pub fn apply(&mut self, stamped: &StampedOp) -> Result<Vec<NodeId>, LiveError> {
        let affected = match &stamped.op {
            DeckOp::AddSlide { id } => {
                let id = self.take(*id)?;
                self.nodes.insert(
                    id,
                    DeckNode {
                        kind: NodeKind::Slide,
                        parent: Some(NodeId(0)),
                        children: Vec::new(),
                        name: None,
                        binding: None,
                        geometry: GeometryProps::default(),
                        placeholder: None,
                    },
                );
                self.nodes
                    .get_mut(&NodeId(0))
                    .ok_or(LiveError::UnknownNode)?
                    .children
                    .push(id);
                vec![id]
            }
            DeckOp::AddNode {
                id,
                parent,
                kind,
                name,
                index,
            } => {
                self.check_parent(*parent, *kind)?;
                let id = self.take(*id)?;
                self.nodes.insert(
                    id,
                    DeckNode {
                        kind: *kind,
                        parent: Some(*parent),
                        children: Vec::new(),
                        name: name.clone(),
                        binding: None,
                        geometry: GeometryProps::default(),
                        placeholder: None,
                    },
                );
                let children = &mut self
                    .nodes
                    .get_mut(parent)
                    .ok_or(LiveError::UnknownNode)?
                    .children;
                let at = index.map_or(children.len(), |i| i.min(children.len()));
                children.insert(at, id);
                vec![id, *parent]
            }
            DeckOp::RemoveNode { node } => {
                if *node == NodeId(0) {
                    return Err(LiveError::TreeShape("the root is not removable"));
                }
                let mut gone = self.descendants(*node);
                gone.push(*node);
                let parent = self.nodes.get(node).ok_or(LiveError::UnknownNode)?.parent;
                if let Some(parent) = parent
                    && let Some(found) = self.nodes.get_mut(&parent)
                {
                    found.children.retain(|child| child != node);
                }
                for id in &gone {
                    self.nodes.remove(id);
                    self.texts.remove(id);
                }
                gone
            }
            DeckOp::MoveNode {
                node,
                new_parent,
                index,
            } => {
                let kind = self.nodes.get(node).ok_or(LiveError::UnknownNode)?.kind;
                if self.descendants(*node).contains(new_parent) || new_parent == node {
                    return Err(LiveError::TreeShape("a node cannot contain itself"));
                }
                self.check_parent(*new_parent, kind)?;
                let old_parent = self.nodes[node].parent;
                if let Some(old) = old_parent
                    && let Some(found) = self.nodes.get_mut(&old)
                {
                    found.children.retain(|child| child != node);
                }
                let children = &mut self
                    .nodes
                    .get_mut(new_parent)
                    .ok_or(LiveError::UnknownNode)?
                    .children;
                let at = (*index).min(children.len());
                children.insert(at, *node);
                self.nodes
                    .get_mut(node)
                    .ok_or(LiveError::UnknownNode)?
                    .parent = Some(*new_parent);
                vec![*node, *new_parent]
            }
            DeckOp::SetText { node, body } => {
                if !self.nodes.contains_key(node) {
                    return Err(LiveError::UnknownNode);
                }
                self.texts.insert(*node, body.clone());
                vec![*node]
            }
            DeckOp::SetRunMarks {
                node,
                paragraph,
                runs,
            } => {
                let body = self.texts.get_mut(node).ok_or(LiveError::UnknownNode)?;
                let found = body
                    .paragraphs
                    .iter_mut()
                    .find(|candidate| candidate.id == *paragraph)
                    .ok_or(LiveError::UnknownNode)?;
                found.runs = runs.clone();
                vec![*node]
            }
            DeckOp::SetGeometry { node, geometry } => {
                self.nodes
                    .get_mut(node)
                    .ok_or(LiveError::UnknownNode)?
                    .geometry = *geometry;
                vec![*node]
            }
            DeckOp::ReplaceOpaque {
                part,
                expected,
                replacement,
            } => {
                match self.opaque_parts.get(part) {
                    Some(current) if current == expected => {}
                    Some(_) => return Err(LiveError::Invalid("opaque source hash changed")),
                    None => return Err(LiveError::Invalid("unknown opaque part")),
                }
                self.opaque_parts.insert(part.clone(), *replacement);
                Vec::new()
            }
        };
        self.version += 1;
        Ok(affected)
    }

    /// The tree rules of [`NodeKind::holds`].
    fn check_parent(&self, parent: NodeId, kind: NodeKind) -> Result<(), LiveError> {
        let found = self.nodes.get(&parent).ok_or(LiveError::UnknownNode)?;
        if found.kind.holds(kind) {
            Ok(())
        } else {
            Err(LiveError::TreeShape("parent cannot hold this node kind"))
        }
    }
}

/// The rebuildable attribution index: who made each visible thing, without
/// replaying history per inspection. Imported content resolves to no actor.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributionIndex {
    /// Node -> (actor, at) of its creation operation.
    pub created_by: BTreeMap<NodeId, (String, u64)>,
    /// Node -> contributing (actor, kind, at), causally last per actor/kind.
    pub contributions: BTreeMap<NodeId, Vec<(String, ChangeKind, u64)>>,
    /// Container -> actors with edits anywhere below it (cached summaries).
    pub descendant_actors: BTreeMap<NodeId, Vec<String>>,
}

impl AttributionIndex {
    /// Rebuild from the current deck and its stamped operation log. The log
    /// is the input; the index is a checkpoint that compaction may carry so
    /// authorship of visible content survives it.
    pub fn build(deck: &LiveDeck, log: &[StampedOp]) -> Self {
        let mut index = Self::default();
        // Minting is sequential, so the identities creation operations
        // produced are recoverable: the log's creations are the last
        // mints below the deck's high-water mark, in log order.
        let creates = log
            .iter()
            .filter(|stamped| {
                matches!(
                    stamped.op,
                    DeckOp::AddSlide { id: None } | DeckOp::AddNode { id: None, .. }
                )
            })
            .count() as u64;
        let mut next_mint = deck.next_node.saturating_sub(creates);
        for stamped in log {
            let kind = stamped.op.kind();
            let created = match stamped.op {
                DeckOp::AddSlide { id: Some(id) } | DeckOp::AddNode { id: Some(id), .. } => {
                    Some(id)
                }
                DeckOp::AddSlide { id: None } | DeckOp::AddNode { id: None, .. } => {
                    let id = NodeId(next_mint);
                    next_mint += 1;
                    Some(id)
                }
                _ => None,
            };
            let effective = created.or_else(|| stamped.op.target());
            if let Some(target) = effective {
                if kind == ChangeKind::Creation {
                    index
                        .created_by
                        .entry(target)
                        .or_insert_with(|| (stamped.made_by.clone(), stamped.at));
                }
                let entries = index.contributions.entry(target).or_default();
                entries.retain(|(actor, existing, _)| {
                    !(actor == &stamped.made_by && *existing == kind)
                });
                entries.push((stamped.made_by.clone(), kind, stamped.at));
            }
            // Summary actors on every ancestor of the touched node.
            if let Some(mut node) = effective
                && let Some(first) = deck.nodes.get(&node)
            {
                let mut cursor = first.parent;
                while let Some(parent) = cursor {
                    node = parent;
                    let actors = index.descendant_actors.entry(node).or_default();
                    if !actors.contains(&stamped.made_by) {
                        actors.push(stamped.made_by.clone());
                    }
                    cursor = deck.nodes.get(&node).and_then(|found| found.parent);
                }
            }
        }
        index
    }

    /// The actor that created `node`; `None` for imported content.
    pub fn creator(&self, node: NodeId) -> Option<&str> {
        self.created_by.get(&node).map(|(actor, _)| actor.as_str())
    }
}

/// A machine fork: the base it opened at and its actual stamped operations.
/// The fork joins a proposal by the shared proposal id; the proposer (and
/// its lineage) never settles it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckFork {
    pub proposal: String,
    pub proposer: String,
    /// The run that opened the fork, for the run approve-all scope.
    pub run_root: Option<String>,
    pub base_version: u64,
    pub base: LiveDeck,
    pub ops: Vec<StampedOp>,
}

impl LiveDeck {
    /// Open a fork at the current head. The agent writes the fork, never
    /// the live document.
    pub fn fork_at(&self, proposal: &str, proposer: &str, run_root: Option<&str>) -> DeckFork {
        DeckFork {
            proposal: proposal.to_owned(),
            proposer: proposer.to_owned(),
            run_root: run_root.map(str::to_owned),
            base_version: self.version,
            base: self.clone(),
            ops: Vec::new(),
        }
    }
}

impl DeckFork {
    pub fn record(&mut self, op: StampedOp) {
        self.ops.push(op);
    }

    /// The proposal state: the base with the fork's own operations applied.
    pub fn candidate(&self) -> Result<LiveDeck, LiveError> {
        let mut deck = self.base.clone();
        for op in &self.ops {
            deck.apply(op)?;
        }
        Ok(deck)
    }

    /// Nodes this fork touches that the head changed since the base: the
    /// units whose answers the race rule withdraws (ARCH-0075 section 4).
    pub fn stale_units(&self, head: &LiveDeck) -> Vec<NodeId> {
        let touched: BTreeSet<NodeId> = self.ops.iter().filter_map(|op| op.op.target()).collect();
        touched
            .into_iter()
            .filter(|node| unit_changed(&self.base, head, *node))
            .collect()
    }
}

/// Whether `node`'s own content differs between two states. A binding is
/// retained-package evidence, not content: an export's rebind changes none.
fn unit_changed(a: &LiveDeck, b: &LiveDeck, node: NodeId) -> bool {
    let content = |deck: &LiveDeck| {
        deck.nodes.get(&node).map(|found| DeckNode {
            binding: None,
            ..found.clone()
        })
    };
    content(a) != content(b) || a.texts.get(&node) != b.texts.get(&node)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeMove {
    pub node: NodeId,
    pub old_parent: Option<NodeId>,
    pub new_parent: Option<NodeId>,
    pub old_index: Option<usize>,
    pub new_index: Option<usize>,
    /// A cross-slide move also changes relationship context.
    pub cross_slide: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpaqueChange {
    pub part: String,
    pub base: Option<[u8; 32]>,
    pub proposal: Option<[u8; 32]>,
}

/// A concurrent-change conflict the merge must surface, never hide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Conflict {
    /// Both sides moved one shape to different places.
    BothMoved { node: NodeId },
    /// One side deleted a node (or its ancestor) the other side edited.
    DeletedVsEdited { node: NodeId, deleted_by_head: bool },
    /// Both sides changed the same text body differently.
    TextVsText { node: NodeId },
    /// Reparent on one side, geometry on the other: local coordinates
    /// acquire another meaning.
    GeometryVsReparent { node: NodeId },
    /// Both sides replaced one opaque part with different bytes.
    BothReplacedOpaque { part: String },
}

/// One relationship that differs between the head's export and the merged
/// candidate's: `before`/`after` are its target, `None` where it is absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationshipChange {
    /// The source part (`""` for the package).
    pub source: String,
    pub id: String,
    pub kind: String,
    pub before: Option<String>,
    pub after: Option<String>,
}

/// One slide's render identity: the hash of the slide and every part its
/// rendering depends on, in one export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlideRender {
    pub slide: NodeId,
    pub part: String,
    pub fingerprint: [u8; 32],
}

/// One side of the review render pair, at a named version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderSide {
    pub version: u64,
    pub state_hash: [u8; 32],
    /// The export memo key the render input was projected under.
    pub export_key: [u8; 32],
    pub slides: Vec<SlideRender>,
}

/// The current head and the actual merged candidate, each at a named
/// version. The pair is stale once the head moves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderPair {
    pub head: RenderSide,
    pub candidate: RenderSide,
    /// Slides whose render identity differs between the two, or that only
    /// one side holds.
    pub changed: Vec<NodeId>,
}

impl RenderPair {
    /// Whether `head` has moved past the version this pair rendered.
    pub fn stale(&self, head: &LiveDeck) -> bool {
        head.version != self.head.version || head.state_hash() != self.head.state_hash
    }
}

/// The three-way comparison of base, current head and proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckDiff {
    pub base_version: u64,
    pub head_version: u64,
    pub proposal_version: u64,
    pub added: Vec<NodeId>,
    pub removed: Vec<NodeId>,
    pub moved: Vec<NodeMove>,
    pub text_changed: Vec<NodeId>,
    pub formatting_changed: Vec<NodeId>,
    pub geometry_changed: Vec<NodeId>,
    pub opaque_changed: Vec<OpaqueChange>,
    /// Slides the proposal affects, including beyond the edited slide. Until
    /// render evidence is attached, any opaque replacement counts every slide;
    /// [`super::attach_evidence`] narrows it to the slides whose render
    /// identity the merged candidate changes.
    pub affected_slides: Vec<NodeId>,
    /// Nodes the head changed and the proposal did not: exactly what a
    /// switch would remove from the active head.
    pub head_only: Vec<NodeId>,
    pub conflicts: Vec<Conflict>,
    /// Relationship additions, removals and changed targets the merged
    /// candidate's export makes against the head's; empty until attached.
    pub relationships: Vec<RelationshipChange>,
    /// The review render pair; `None` until attached.
    pub renders: Option<RenderPair>,
}

pub(crate) fn slide_of(deck: &LiveDeck, mut node: NodeId) -> Option<NodeId> {
    loop {
        let found = deck.nodes.get(&node)?;
        if found.kind == NodeKind::Slide {
            return Some(node);
        }
        node = found.parent?;
    }
}

fn sibling_index(deck: &LiveDeck, node: NodeId) -> Option<usize> {
    let parent = deck.nodes.get(&node)?.parent?;
    deck.nodes
        .get(&parent)?
        .children
        .iter()
        .position(|child| *child == node)
}

/// Compare base, current head and proposal. Text and formatting are
/// reported separately; own geometry separately from moves.
pub fn diff(base: &LiveDeck, head: &LiveDeck, proposal: &LiveDeck) -> DeckDiff {
    let mut out = DeckDiff {
        base_version: base.version,
        head_version: head.version,
        proposal_version: proposal.version,
        added: Vec::new(),
        removed: Vec::new(),
        moved: Vec::new(),
        text_changed: Vec::new(),
        formatting_changed: Vec::new(),
        geometry_changed: Vec::new(),
        opaque_changed: Vec::new(),
        affected_slides: Vec::new(),
        head_only: Vec::new(),
        conflicts: Vec::new(),
        relationships: Vec::new(),
        renders: None,
    };
    let mut affected: BTreeSet<NodeId> = BTreeSet::new();
    for id in proposal.nodes.keys() {
        if !base.nodes.contains_key(id) {
            out.added.push(*id);
            if let Some(slide) = slide_of(proposal, *id) {
                affected.insert(slide);
            }
        }
    }
    for id in base.nodes.keys() {
        if !proposal.nodes.contains_key(id) {
            out.removed.push(*id);
            if let Some(slide) = slide_of(base, *id) {
                affected.insert(slide);
            }
        }
    }
    for (id, node) in &proposal.nodes {
        let Some(was) = base.nodes.get(id) else {
            continue;
        };
        let moved =
            was.parent != node.parent || sibling_index(base, *id) != sibling_index(proposal, *id);
        if moved {
            out.moved.push(NodeMove {
                node: *id,
                old_parent: was.parent,
                new_parent: node.parent,
                old_index: sibling_index(base, *id),
                new_index: sibling_index(proposal, *id),
                cross_slide: slide_of(base, *id) != slide_of(proposal, *id),
            });
        }
        if was.geometry != node.geometry {
            out.geometry_changed.push(*id);
        }
        match (base.texts.get(id), proposal.texts.get(id)) {
            (a, b) if a == b => {}
            (Some(a), Some(b)) if a.plain() == b.plain() => out.formatting_changed.push(*id),
            _ => out.text_changed.push(*id),
        }
        if moved || was.geometry != node.geometry || base.texts.get(id) != proposal.texts.get(id) {
            if let Some(slide) = slide_of(proposal, *id).or_else(|| slide_of(base, *id)) {
                affected.insert(slide);
            }
        }
        // Head-only work: changed on the head, untouched by the proposal.
        if unit_changed(base, head, *id) && !unit_changed(base, proposal, *id) {
            out.head_only.push(*id);
        }
        // Conflicts: both sides changed the same unit incompatibly.
        let head_node = head.nodes.get(id);
        if head_node.is_none() && unit_changed(base, proposal, *id) {
            out.conflicts.push(Conflict::DeletedVsEdited {
                node: *id,
                deleted_by_head: true,
            });
        } else if let Some(head_node) = head_node {
            let head_moved = was.parent != head_node.parent
                || sibling_index(base, *id) != sibling_index(head, *id);
            if moved
                && head_moved
                && (node.parent != head_node.parent
                    || sibling_index(proposal, *id) != sibling_index(head, *id))
            {
                out.conflicts.push(Conflict::BothMoved { node: *id });
            }
            if moved != head_moved
                && ((moved && was.geometry != head_node.geometry)
                    || (head_moved && was.geometry != node.geometry))
            {
                out.conflicts
                    .push(Conflict::GeometryVsReparent { node: *id });
            }
            if base.texts.get(id) != head.texts.get(id)
                && base.texts.get(id) != proposal.texts.get(id)
                && head.texts.get(id) != proposal.texts.get(id)
            {
                out.conflicts.push(Conflict::TextVsText { node: *id });
            }
        }
    }
    for id in base.nodes.keys() {
        if !proposal.nodes.contains_key(id) && unit_changed(base, head, *id) {
            out.conflicts.push(Conflict::DeletedVsEdited {
                node: *id,
                deleted_by_head: false,
            });
        }
    }
    let mut parts: BTreeSet<&str> = BTreeSet::new();
    parts.extend(base.opaque_parts.keys().map(String::as_str));
    parts.extend(proposal.opaque_parts.keys().map(String::as_str));
    for part in parts {
        let (b, h, p) = (
            base.opaque_parts.get(part),
            head.opaque_parts.get(part),
            proposal.opaque_parts.get(part),
        );
        if b != p {
            out.opaque_changed.push(OpaqueChange {
                part: part.to_owned(),
                base: b.copied(),
                proposal: p.copied(),
            });
            // A master, layout or theme replacement can affect every slide.
            affected.extend(
                proposal
                    .nodes
                    .iter()
                    .filter(|(_, node)| node.kind == NodeKind::Slide)
                    .map(|(id, _)| *id),
            );
        }
        if b != h && b != p && h != p {
            out.conflicts.push(Conflict::BothReplacedOpaque {
                part: part.to_owned(),
            });
        }
    }
    out.affected_slides = affected.into_iter().collect();
    out
}

/// The scratch-candidate check before any merge: the fork's actual
/// operations replayed onto the current head. Operations are never
/// cherry-picked and merging is never replaced with a rewrite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightReport {
    /// The head version this preflight ran against; landing requires it.
    pub head_version: u64,
    pub candidate: LiveDeck,
    pub diff: DeckDiff,
    pub replay_refusals: Vec<String>,
    pub ok: bool,
}

pub fn preflight(head: &LiveDeck, fork: &DeckFork) -> Result<PreflightReport, LiveError> {
    let proposal = fork.candidate()?;
    let comparison = diff(&fork.base, head, &proposal);
    let mut candidate = head.clone();
    let mut refusals = Vec::new();
    for op in &fork.ops {
        if let Err(error) = candidate.apply(op) {
            refusals.push(error.to_string());
        }
    }
    let ok = comparison.conflicts.is_empty() && refusals.is_empty();
    Ok(PreflightReport {
        head_version: head.version,
        candidate,
        diff: comparison,
        replay_refusals: refusals,
        ok,
    })
}

/// The three ruled approve-all scopes. A finer scope is a later addition
/// and does not delay these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApproveScope {
    /// The named actor's bundle.
    ThisActor(String),
    /// The run root and everything its children proposed.
    ThisRunAndChildren(String),
    /// One item within the reviewed set, by its proposal id.
    OneItem(String),
}

impl ApproveScope {
    /// Whether this approval covers `fork`. Later forks never inherit an
    /// earlier approval: the scope names its set exactly.
    pub fn covers(&self, fork: &DeckFork) -> bool {
        match self {
            ApproveScope::ThisActor(actor) => fork.proposer == *actor,
            ApproveScope::ThisRunAndChildren(run) => fork.run_root.as_deref() == Some(run),
            ApproveScope::OneItem(proposal) => fork.proposal == *proposal,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Landing {
    Merge,
    Switch,
}

/// The receipt a landing mints: decision scope, versions and actual
/// affected units.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LandingReceipt {
    pub proposal: String,
    pub proposer: String,
    pub settler: String,
    pub scope: ApproveScope,
    pub landing: Landing,
    pub automatic: bool,
    pub reviewed_version: u64,
    pub landed_version: u64,
    pub affected: Vec<NodeId>,
    /// Head-only nodes a switch removed; empty for a merge.
    pub switched_away: Vec<NodeId>,
}

/// Land a preflighted fork. The proposer never settles its own proposal,
/// and the head must be the one the preflight ran against.
pub fn land(
    head: &mut LiveDeck,
    fork: &DeckFork,
    report: &PreflightReport,
    settler: &str,
    scope: ApproveScope,
    landing: Landing,
    automatic: bool,
) -> Result<LandingReceipt, LiveError> {
    if settler == fork.proposer {
        return Err(LiveError::SelfSettle);
    }
    if head.version != report.head_version {
        return Err(LiveError::HeadAdvanced);
    }
    if !report.ok {
        return Err(LiveError::Invalid("preflight conflicts are unresolved"));
    }
    if !scope.covers(fork) {
        return Err(LiveError::Invalid(
            "the approval scope does not cover this fork",
        ));
    }
    let reviewed_version = head.version;
    let mut affected: BTreeSet<NodeId> = BTreeSet::new();
    affected.extend(report.diff.added.iter().copied());
    affected.extend(report.diff.removed.iter().copied());
    affected.extend(report.diff.moved.iter().map(|moved| moved.node));
    affected.extend(report.diff.text_changed.iter().copied());
    affected.extend(report.diff.formatting_changed.iter().copied());
    affected.extend(report.diff.geometry_changed.iter().copied());
    let switched_away = match landing {
        Landing::Merge => {
            *head = report.candidate.clone();
            Vec::new()
        }
        Landing::Switch => {
            let mut proposal = fork.candidate()?;
            // Bindings and the hashes of opaque parts the proposal left alone
            // are evidence of the head's retained package, which a landed
            // export may have moved past the fork's base.
            for (id, node) in &mut proposal.nodes {
                if let Some(held) = head.nodes.get(id) {
                    node.binding = held.binding.clone();
                }
            }
            for (part, hash) in &mut proposal.opaque_parts {
                if fork.base.opaque_parts.get(part) == Some(hash)
                    && let Some(held) = head.opaque_parts.get(part)
                {
                    *hash = *held;
                }
            }
            let (version, next_node) = (head.version, head.next_node);
            proposal.id_marks.join(&head.id_marks);
            *head = proposal;
            // Identity allocation stays monotonic across the switch.
            head.next_node = head.next_node.max(next_node);
            head.version = version + 1;
            report.diff.head_only.clone()
        }
    };
    Ok(LandingReceipt {
        proposal: fork.proposal.clone(),
        proposer: fork.proposer.clone(),
        settler: settler.to_owned(),
        scope,
        landing,
        automatic,
        reviewed_version,
        landed_version: head.version,
        affected: affected.into_iter().collect(),
        switched_away,
    })
}
