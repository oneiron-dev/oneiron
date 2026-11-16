//! The deck operations: what one operation is (`DeckOp`), who made it
//! (`StampedOp`), and applying it to the live deck under the tree rules
//! (`LiveDeck::apply`).

use super::chart_ops::{self, born_points};
use super::{
    ChartEdit, DeckNode, GeometryProps, LiveDeck, NodeId, NodeKind, NodePayload, Run, TableEdit,
    TextBody, table_ops,
};
use crate::edit::{AssetRef, Effect, Preset};
use crate::live::{Conversion, LiveError};
use serde::{Deserialize, Serialize};

/// One deck operation. A move keeps the node's identity; a cross-slide move
/// is reported because it also changes relationship context. A creation
/// names the identity it makes, so replaying it onto another head (a fork's
/// merge, a concurrent peer) makes the same node; `None` mints one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeckOp {
    AddSlide {
        #[serde(default)]
        id: Option<NodeId>,
    },
    /// A live-born node; a shape may name its preset, and a picture the
    /// shape it is cropped to; a picture, graphic frame or connector carries
    /// the payload it is written from.
    AddNode {
        #[serde(default)]
        id: Option<NodeId>,
        parent: NodeId,
        kind: NodeKind,
        name: Option<String>,
        index: Option<usize>,
        #[serde(default)]
        preset: Option<Preset>,
        #[serde(default)]
        payload: Option<NodePayload>,
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
    /// A shape's preset geometry, as Change Shape writes it, replacing a
    /// freeform's paths; or a picture's, as Crop to Shape writes it, the
    /// picture keeping its media and crop.
    SetPreset {
        node: NodeId,
        preset: Preset,
    },
    /// What a shape, picture, graphic frame or connector is written from:
    /// a shape's points, new media or held media the deck holds, a table's
    /// cells, a chart's data, a SmartArt's nodes, or a connector's geometry
    /// and glue. A written table or chart may change shape (rows, columns,
    /// series, categories), and a chart its type, for the whole chart or one
    /// series, as PowerPoint does; the export rewrites it. A reshaped
    /// written table's frame takes its grid's size: its own extent clears.
    /// A whole table written over a table is logged as the table edits that
    /// make it, and a whole chart written over a chart as the chart edits
    /// that make it ([`LiveDeck::lower`]); a chart series written with no
    /// identity is new. The edit's effects name what it did PowerPoint's way.
    SetPayload {
        node: NodeId,
        payload: NodePayload,
    },
    /// Edits to the table a graphic frame holds, by row and column
    /// identity, in order. A reshaped written table's frame takes its grid's
    /// size: its own extent clears.
    EditTable {
        node: NodeId,
        edits: Vec<TableEdit>,
    },
    /// Edits to the chart a graphic frame holds, by series identity, in
    /// order; the chart then settles as a whole chart written over it does.
    EditChart {
        node: NodeId,
        edits: Vec<ChartEdit>,
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
            | DeckOp::SetGeometry { node, .. }
            | DeckOp::SetPreset { node, .. }
            | DeckOp::SetPayload { node, .. }
            | DeckOp::EditTable { node, .. }
            | DeckOp::EditChart { node, .. } => Some(*node),
            DeckOp::AddSlide { .. } | DeckOp::ReplaceOpaque { .. } => None,
        }
    }

    /// The asset a picture this operation writes names.
    pub fn picture(&self) -> Option<&AssetRef> {
        match self {
            DeckOp::AddNode {
                payload: Some(payload),
                ..
            }
            | DeckOp::SetPayload { payload, .. } => payload.picture(),
            _ => None,
        }
    }

    /// The identity a creation names.
    pub fn created(&self) -> Option<NodeId> {
        match self {
            DeckOp::AddSlide { id } | DeckOp::AddNode { id, .. } => *id,
            _ => None,
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
            DeckOp::SetGeometry { .. }
            | DeckOp::SetPreset { .. }
            | DeckOp::SetPayload { .. }
            | DeckOp::EditTable { .. }
            | DeckOp::EditChart { .. }
            | DeckOp::ReplaceOpaque { .. } => ChangeKind::Property,
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
        self.apply_with_effects(stamped)
            .map(|(affected, _)| affected)
    }

    /// [`Self::apply`], with what the operation did PowerPoint's way where
    /// the deck once refused it (the Office ruling of 10-18), each an
    /// [`Effect::Converted`] on the node it names, for the edit's receipt.
    pub fn apply_with_effects(
        &mut self,
        stamped: &StampedOp,
    ) -> Result<(Vec<NodeId>, Vec<Effect>), LiveError> {
        let mut effects = Vec::new();
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
                        preset: None,
                        payload: None,
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
                preset,
                payload,
            } => {
                self.check_parent(*parent, *kind)?;
                if preset.is_some() && !takes_preset(*kind) {
                    return Err(LiveError::Invalid(ONLY_SHAPE_OR_PICTURE));
                }
                if payload
                    .as_ref()
                    .is_some_and(|payload| payload.kind() != *kind)
                {
                    return Err(LiveError::Invalid(
                        "the payload does not belong to the node kind",
                    ));
                }
                // A chart's unnamed series and points take identities after
                // its node's; the points its settlement adds take its node's
                // own (FIX 9164). A refusal mints nothing.
                let mark = self.next_node;
                let id = self.take(*id)?;
                let mut payload = payload.clone();
                if let Some(payload) = &mut payload {
                    payload.name_series(&mut || self.mint());
                }
                let settled = payload.map(|payload| -> Result<_, LiveError> {
                    let (mut settled, done) = payload.settle(None, false, &self.opaque_parts)?;
                    settled.name_categories(&mut born_points(id, settled.category_ids()));
                    settled.check()?;
                    Ok((settled, done))
                });
                let (payload, done) = match settled.transpose() {
                    Ok(Some((settled, done))) => (Some(settled), done),
                    Ok(None) => (None, Vec::new()),
                    Err(error) => {
                        self.next_node = mark;
                        return Err(error);
                    }
                };
                // A live-born freeform's paths are its outline: no preset.
                let preset = if matches!(payload, Some(NodePayload::CustomGeometry { .. })) {
                    None
                } else {
                    *preset
                };
                effects.extend(done.into_iter().map(|conversion| Effect::Converted {
                    node: id,
                    conversion,
                }));
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
                        preset,
                        payload,
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
            DeckOp::SetPreset { node, preset } => {
                let found = self.nodes.get_mut(node).ok_or(LiveError::UnknownNode)?;
                if !takes_preset(found.kind) {
                    return Err(LiveError::Invalid(ONLY_SHAPE_OR_PICTURE));
                }
                // The preset replaces a shape's custom geometry; the export's
                // effects name it. A picture's media stays its payload.
                if matches!(found.payload, Some(NodePayload::CustomGeometry { .. })) {
                    found.payload = None;
                }
                found.preset = Some(*preset);
                vec![*node]
            }
            DeckOp::SetPayload { node, payload } => {
                let mut payload = payload.clone();
                payload.name_series(&mut || self.mint());
                let found = self.nodes.get(node).ok_or(LiveError::UnknownNode)?;
                if payload.kind() != found.kind {
                    return Err(LiveError::Invalid(
                        "the payload does not belong to the node kind",
                    ));
                }
                let bound = found.binding.is_some();
                let fresh = !matches!(found.payload, Some(NodePayload::Chart { .. }));
                let (mut settled, mut done) =
                    payload.settle(found.payload.as_ref(), bound, &self.opaque_parts)?;
                // The category points the settlement adds take the deck's
                // next identities, or, over no held chart, the node's own
                // (FIX 9164).
                if fresh {
                    settled.name_categories(&mut born_points(*node, settled.category_ids()));
                } else {
                    settled.name_categories(&mut || self.mint());
                }
                settled.check()?;
                let found = self.nodes.get_mut(node).ok_or(LiveError::UnknownNode)?;
                // Edit Points draws the shape's own outline: its preset goes,
                // and a preset shape becomes a freeform.
                if matches!(settled, NodePayload::CustomGeometry { .. }) {
                    if !matches!(found.payload, Some(NodePayload::CustomGeometry { .. })) {
                        done.push(Conversion::ConvertedToFreeform);
                    }
                    found.preset = None;
                }
                // A written table that changes shape takes its grid's size at
                // export, as PowerPoint lays it out: its own extent clears.
                if bound
                    && let (Some(NodePayload::Table(was)), NodePayload::Table(now)) =
                        (&found.payload, &settled)
                    && was.shape() != now.shape()
                {
                    found.geometry.extent = None;
                }
                found.payload = Some(settled);
                effects.extend(done.into_iter().map(|conversion| Effect::Converted {
                    node: *node,
                    conversion,
                }));
                vec![*node]
            }
            DeckOp::EditTable { node, edits } => {
                let done = table_ops::edit_table(self, *node, edits)?;
                effects.extend(done.into_iter().map(|conversion| Effect::Converted {
                    node: *node,
                    conversion,
                }));
                vec![*node]
            }
            DeckOp::EditChart { node, edits } => {
                let done = chart_ops::edit_chart(self, *node, edits)?;
                effects.extend(done.into_iter().map(|conversion| Effect::Converted {
                    node: *node,
                    conversion,
                }));
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
        Ok((affected, effects))
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

const ONLY_SHAPE_OR_PICTURE: &str = "only a shape or a picture takes a preset";

/// Whether a node of `kind` takes a preset: a shape's geometry, or the
/// shape a picture is cropped to (FIX 3696).
fn takes_preset(kind: NodeKind) -> bool {
    matches!(kind, NodeKind::Shape | NodeKind::Picture)
}
