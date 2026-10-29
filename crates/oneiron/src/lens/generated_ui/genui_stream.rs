//! Stream profiles and the one incremental stream state (FIX 7968, 7970).
//!
//! The full-model profile is today's stream: `card_start`, one `card_element`
//! per node, then `card_state_update` with the whole data model. The patch
//! profile sends the same, then `card_ready`, and refines the card in place
//! with `card_state_patch` (RFC-6902 operations over the card with its nodes
//! keyed by stable id) and `card_state_snapshot` (the whole card again). A
//! card renders at its `card_state_update` under either profile; nothing
//! waits on `card_ready`.
//!
//! [`GeneratedUiStream`] reads either profile one segment at a time. Before a
//! card completes it yields the partial tree its complete elements make,
//! walked from the root: a child whose element has not arrived is listed as
//! unavailable, never invented. A segment line cut short is healed only in
//! its display text (`super::genui_heal`). A `card_start` of a protocol
//! version this build does not know turns the stream into its whole-card
//! fallback text, and nothing after it is read. Lines that are no segment
//! are kept as the stream's free text.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::genui_decode::GeneratedUiSegmentHead;
use super::genui_heal::heal_cut_json;
use super::genui_json_patch::{GeneratedUiJsonPatchOperation, apply_json_patch, diff_json};
use super::{
    GENERATED_UI_WIRE_VERSION, GeneratedUiCardStart, GeneratedUiCardStateUpdate,
    GeneratedUiCatalog, GeneratedUiCatalogVersion, GeneratedUiFallback, GeneratedUiNode,
    GeneratedUiRender, GeneratedUiSegment,
};
use crate::lens::atom::LensText;
use crate::lens::validate::validate_generated_ui_protocol_version;
use crate::lens::wire_ids::{LensAtomId, LensRenderId};
use crate::{Error, Result};

/// How a surface takes a card's stream (FIX 7968). A surface that
/// negotiated none takes today's full-model stream.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum GeneratedUiStreamProfile {
    #[default]
    FullModel,
    Patch,
}

/// The patch profile's end of generation: every element and the data model
/// have been sent. Refinements may follow.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GeneratedUiCardReady {
    pub protocol_version: u16,
    pub card_id: LensRenderId,
}

impl GeneratedUiCardReady {
    pub(super) fn validate(&self) -> Result<()> {
        validate_generated_ui_protocol_version(self.protocol_version)
    }
}

/// An RFC-6902 refinement of the card a reader holds. The document it
/// addresses is the flat render with `nodes` keyed by stable node id, so
/// `/nodes/<id>/...` and `/$state/<key>` stay put however the tree grows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GeneratedUiCardStatePatch {
    pub protocol_version: u16,
    pub card_id: LensRenderId,
    pub patch: Vec<GeneratedUiJsonPatchOperation>,
}

impl GeneratedUiCardStatePatch {
    pub(super) fn validate(&self) -> Result<()> {
        validate_generated_ui_protocol_version(self.protocol_version)
    }
}

/// The whole card again, replacing what the reader holds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GeneratedUiCardStateSnapshot {
    pub protocol_version: u16,
    pub card_id: LensRenderId,
    pub render: GeneratedUiRender,
}

impl GeneratedUiCardStateSnapshot {
    pub(super) fn validate(&self) -> Result<()> {
        validate_generated_ui_protocol_version(self.protocol_version)?;
        same_card(&self.card_id, &self.render.card_id)?;
        self.render.validate()
    }
}

fn same_card(held: &LensRenderId, named: &LensRenderId) -> Result<()> {
    if held != named {
        return Err(Error::InvalidConfig(
            "generated-ui segment card_id must match card_start".to_string(),
        ));
    }
    Ok(())
}

/// The render's members a patch addresses one entry at a time.
const KEYED_MEMBERS: &[&str] = &["nodes", "$state"];

impl GeneratedUiRender {
    /// The `card_state_patch` that turns `previous`, the card a reader
    /// holds, into this render.
    pub fn state_patch_segment(&self, previous: &Self) -> Result<GeneratedUiSegment> {
        same_card(&previous.card_id, &self.card_id)?;
        let patch = diff_json(
            &patch_document(previous)?,
            &patch_document(self)?,
            KEYED_MEMBERS,
        );
        Ok(GeneratedUiSegment::CardStatePatch(
            GeneratedUiCardStatePatch {
                protocol_version: self.protocol_version,
                card_id: self.card_id.clone(),
                patch,
            },
        ))
    }

    #[must_use]
    pub fn state_snapshot_segment(&self) -> GeneratedUiSegment {
        GeneratedUiSegment::CardStateSnapshot(Box::new(GeneratedUiCardStateSnapshot {
            protocol_version: self.protocol_version,
            card_id: self.card_id.clone(),
            render: self.clone(),
        }))
    }

    /// This render with `patch` applied, decoded and validated whole: a
    /// patched card meets every rule a complete one does, its actions
    /// included, and keeps its card id.
    pub fn apply_state_patch(&self, patch: &[GeneratedUiJsonPatchOperation]) -> Result<Self> {
        let mut document = patch_document(self)?;
        apply_json_patch(&mut document, patch)?;
        let patched = render_from_patch_document(document)?;
        same_card(&self.card_id, &patched.card_id)?;
        Ok(patched)
    }
}

fn encoding(error: serde_json::Error) -> Error {
    Error::InvalidConfig(format!("generated-ui card_state_patch document: {error}"))
}

/// The render as a patch addresses it: `nodes` keyed by stable id.
fn patch_document(render: &GeneratedUiRender) -> Result<Value> {
    let mut document = serde_json::to_value(render).map_err(encoding)?;
    let nodes = render
        .nodes
        .iter()
        .map(|node| {
            let value = serde_json::to_value(node).map_err(encoding)?;
            Ok((node.id.as_str().to_owned(), value))
        })
        .collect::<Result<serde_json::Map<_, _>>>()?;
    document["nodes"] = Value::Object(nodes);
    Ok(document)
}

/// A patched document back into a render: its keyed nodes in the order a
/// walk from the root meets them, each key its node's own id.
fn render_from_patch_document(mut document: Value) -> Result<GeneratedUiRender> {
    let Some(Value::Object(mut keyed)) = document.get_mut("nodes").map(Value::take) else {
        return Err(Error::InvalidConfig(
            "generated-ui card_state_patch must leave nodes keyed by id".to_string(),
        ));
    };
    for (key, node) in &keyed {
        if node.get("id").and_then(Value::as_str) != Some(key.as_str()) {
            return Err(Error::InvalidConfig(
                "generated-ui card_state_patch node keys must equal their node ids".to_string(),
            ));
        }
    }
    let mut ordered = Vec::with_capacity(keyed.len());
    let mut stack = document
        .get("root")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .into_iter()
        .collect::<Vec<_>>();
    while let Some(id) = stack.pop() {
        let Some(node) = keyed.remove(&id) else {
            continue;
        };
        if let Some(children) = node.get("childRefs").and_then(Value::as_array) {
            stack.extend(
                children
                    .iter()
                    .rev()
                    .filter_map(Value::as_str)
                    .map(str::to_owned),
            );
        }
        ordered.push(node);
    }
    // Nodes no walk reached stay, so the render's own orphan rule judges them.
    ordered.extend(keyed.into_iter().map(|(_, node)| node));
    document["nodes"] = Value::Array(ordered);
    serde_json::from_value(document).map_err(encoding)
}

/// One node of a partial tree, exactly as its element supplied it, with the
/// child refs whose elements have not arrived listed as unavailable.
/// `provisional` marks a node healed from a cut segment line, replaced when
/// its whole element arrives.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedUiPartialNode {
    pub node: GeneratedUiNode,
    pub unavailable: Vec<LensAtomId>,
    pub provisional: bool,
}

/// The usable part of a card still arriving: the nodes a walk from the root
/// reaches through arrived elements. It has no action manifest and no
/// `$state` yet, so nothing on it can be acted on; its whole-card
/// `fallbackText` is there from `card_start` on.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedUiPartialTree {
    pub card_id: LensRenderId,
    pub catalog: GeneratedUiCatalog,
    pub catalog_version: GeneratedUiCatalogVersion,
    pub root: LensAtomId,
    pub fallback_text: LensText,
    pub nodes: Vec<GeneratedUiPartialNode>,
}

/// What a stream has made so far, or made when it ended.
#[derive(Debug, Clone, PartialEq)]
pub enum GeneratedUiStreamOutcome {
    /// A complete, validated card, with every refinement applied.
    Render(Box<GeneratedUiRender>),
    /// A card whose elements or data model have not all arrived.
    Partial(GeneratedUiPartialTree),
    /// A card of a protocol version this build does not know: its text only.
    Fallback(GeneratedUiFallback),
    /// No card started: the stream's free text.
    Text(String),
}

struct Arriving {
    start: GeneratedUiCardStart,
    nodes: Vec<GeneratedUiNode>,
    ids: HashSet<String>,
    provisional: Option<GeneratedUiNode>,
}

enum Phase {
    Awaiting,
    Arriving(Box<Arriving>),
    Complete {
        render: Box<GeneratedUiRender>,
        ready: bool,
    },
    Fallback(GeneratedUiFallback),
}

/// The incremental reader of one card's segment stream, under either
/// profile. [`GeneratedUiRender::from_segments`] is this reader run over a
/// complete stream.
pub struct GeneratedUiStream {
    phase: Phase,
    text: String,
}

impl Default for GeneratedUiStream {
    fn default() -> Self {
        Self::new()
    }
}

impl GeneratedUiStream {
    #[must_use]
    pub fn new() -> Self {
        Self {
            phase: Phase::Awaiting,
            text: String::new(),
        }
    }

    /// One typed segment, in stream order.
    pub fn push(&mut self, segment: GeneratedUiSegment) -> Result<()> {
        segment.validate()?;
        let next = match (&mut self.phase, segment) {
            (Phase::Fallback(_), _) => None,
            (Phase::Awaiting, GeneratedUiSegment::CardStart(start)) => {
                Some(Phase::Arriving(Box::new(Arriving {
                    start,
                    nodes: Vec::new(),
                    ids: HashSet::new(),
                    provisional: None,
                })))
            }
            (Phase::Awaiting, _) => {
                return Err(Error::InvalidConfig(
                    "generated-ui segment stream must start with card_start".to_string(),
                ));
            }
            (_, GeneratedUiSegment::CardStart(_)) => {
                return Err(Error::InvalidConfig(
                    "generated-ui segment stream must contain exactly one card_start".to_string(),
                ));
            }
            (Phase::Arriving(arriving), GeneratedUiSegment::CardElement(element)) => {
                let element = *element;
                arriving.element(element.card_id, element.node)?;
                None
            }
            (Phase::Arriving(arriving), GeneratedUiSegment::CardStateUpdate(update)) => {
                Some(Phase::Complete {
                    render: Box::new(arriving.complete(&update)?),
                    ready: false,
                })
            }
            (Phase::Arriving(arriving), GeneratedUiSegment::CardStateSnapshot(snapshot)) => {
                let snapshot = *snapshot;
                same_card(&arriving.start.card_id, &snapshot.card_id)?;
                Some(Phase::Complete {
                    render: Box::new(snapshot.render),
                    ready: false,
                })
            }
            (Phase::Arriving(_), _) => {
                return Err(Error::InvalidConfig(
                    "generated-ui card_ready and card_state_patch must follow card_state_update"
                        .to_string(),
                ));
            }
            (Phase::Complete { .. }, GeneratedUiSegment::CardElement(_)) => {
                return Err(Error::InvalidConfig(
                    "generated-ui card_element segments must precede card_state_update".to_string(),
                ));
            }
            (Phase::Complete { .. }, GeneratedUiSegment::CardStateUpdate(_)) => {
                return Err(Error::InvalidConfig(
                    "generated-ui segment stream must contain exactly one card_state_update"
                        .to_string(),
                ));
            }
            (Phase::Complete { render, ready }, GeneratedUiSegment::CardReady(payload)) => {
                same_card(&render.card_id, &payload.card_id)?;
                *ready = true;
                None
            }
            (Phase::Complete { render, .. }, GeneratedUiSegment::CardStatePatch(payload)) => {
                same_card(&render.card_id, &payload.card_id)?;
                let patched = render.apply_state_patch(&payload.patch)?;
                **render = patched;
                None
            }
            (Phase::Complete { render, .. }, GeneratedUiSegment::CardStateSnapshot(snapshot)) => {
                let snapshot = *snapshot;
                same_card(&render.card_id, &snapshot.card_id)?;
                **render = snapshot.render;
                None
            }
        };
        if let Some(next) = next {
            self.phase = next;
        }
        Ok(())
    }

    /// One whole line of the stream as it arrived. A segment of this build's
    /// protocol version is pushed typed; a `card_start` of another version
    /// turns the stream into its fallback text, and every later line is
    /// left unread; a line that is no segment is kept as free text.
    pub fn push_json(&mut self, line: &str) -> Result<()> {
        // The first pass reads the segment name and the payload's version
        // and fallback text only; the rest of the line is skipped unread.
        let head = match serde_json::from_str::<GeneratedUiSegmentHead>(line) {
            Ok(head) if head.segment.is_some() => head,
            _ => {
                if !self.text.is_empty() {
                    self.text.push('\n');
                }
                self.text.push_str(line);
                return Ok(());
            }
        };
        if matches!(self.phase, Phase::Fallback(_)) {
            return Ok(());
        }
        if let Some(version) = head.payload.protocol_version()
            && version != u64::from(GENERATED_UI_WIRE_VERSION)
        {
            if matches!(self.phase, Phase::Awaiting)
                && head.segment.as_deref() == Some("card_start")
                && let Some(fallback) = head.payload.unsupported_fallback("card_start")?
            {
                self.phase = Phase::Fallback(fallback);
                return Ok(());
            }
            return Err(Error::InvalidConfig(format!(
                "unsupported generated-ui wire version {version}"
            )));
        }
        let segment = serde_json::from_str::<GeneratedUiSegment>(line)
            .map_err(|error| Error::InvalidConfig(format!("generated-ui segment: {error}")))?;
        self.push(segment)
    }

    /// The line still arriving, cut where the stream stands. A `card_element`
    /// that heals into a valid node of this card, not yet arrived whole, is
    /// shown as provisional in [`Self::outcome`]. Anything else shows nothing
    /// yet. Returns whether a provisional node is held.
    pub fn push_cut_json(&mut self, cut: &str) -> bool {
        let Phase::Arriving(arriving) = &mut self.phase else {
            return false;
        };
        let element = heal_cut_json(cut)
            .filter(|healed| {
                serde_json::from_str::<GeneratedUiSegmentHead>(healed).is_ok_and(|head| {
                    head.payload.protocol_version() == Some(u64::from(GENERATED_UI_WIRE_VERSION))
                })
            })
            .and_then(|healed| serde_json::from_str::<GeneratedUiSegment>(&healed).ok());
        if let Some(GeneratedUiSegment::CardElement(element)) = element
            && element.card_id == arriving.start.card_id
            && !arriving.ids.contains(element.node.id.as_str())
        {
            arriving.provisional = Some(element.node);
            return true;
        }
        arriving.provisional.is_some()
    }

    /// Whether the patch profile's `card_ready` has arrived.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        matches!(self.phase, Phase::Complete { ready: true, .. })
    }

    /// What the stream has made so far.
    #[must_use]
    pub fn outcome(&self) -> GeneratedUiStreamOutcome {
        match &self.phase {
            Phase::Awaiting => GeneratedUiStreamOutcome::Text(self.text.clone()),
            Phase::Arriving(arriving) => GeneratedUiStreamOutcome::Partial(arriving.partial()),
            Phase::Complete { render, .. } => GeneratedUiStreamOutcome::Render(render.clone()),
            Phase::Fallback(fallback) => GeneratedUiStreamOutcome::Fallback(fallback.clone()),
        }
    }

    /// The complete card, or the error a stream that ended short of one gets.
    pub fn into_render(self) -> Result<GeneratedUiRender> {
        match self.phase {
            Phase::Complete { render, .. } => Ok(*render),
            Phase::Awaiting => Err(Error::InvalidConfig(
                "generated-ui segment stream must contain card_start".to_string(),
            )),
            Phase::Arriving(_) => Err(Error::InvalidConfig(
                "generated-ui segment stream must end with card_state_update".to_string(),
            )),
            Phase::Fallback(fallback) => Err(Error::InvalidConfig(format!(
                "unsupported generated-ui wire version {}",
                fallback.protocol_version
            ))),
        }
    }
}

impl Arriving {
    fn element(&mut self, card_id: LensRenderId, node: GeneratedUiNode) -> Result<()> {
        // The first element past the declared count is refused before it is
        // copied, not after the whole stream.
        if self.nodes.len() >= self.start.node_count {
            return Err(Error::InvalidConfig(
                "generated-ui card_element count must match card_start node count".to_string(),
            ));
        }
        if card_id != self.start.card_id {
            return Err(Error::InvalidConfig(
                "generated-ui card_element card_id must match card_start".to_string(),
            ));
        }
        if !self.ids.insert(node.id.as_str().to_owned()) {
            return Err(Error::InvalidConfig(
                "generated-ui flat nodes must not contain duplicate ids".to_string(),
            ));
        }
        if self
            .provisional
            .as_ref()
            .is_some_and(|provisional| provisional.id == node.id)
        {
            self.provisional = None;
        }
        self.nodes.push(node);
        Ok(())
    }

    fn complete(&self, update: &GeneratedUiCardStateUpdate) -> Result<GeneratedUiRender> {
        let start = &self.start;
        let model = &update.data_model;
        let mismatch = |what: &str| -> Result<GeneratedUiRender> {
            Err(Error::InvalidConfig(format!(
                "generated-ui card_state_update {what} must match card_start"
            )))
        };
        if update.card_id != start.card_id {
            return mismatch("card_id");
        }
        if model.root != start.root {
            return mismatch("root");
        }
        if model.catalog != start.catalog {
            return mismatch("catalog");
        }
        if model.catalog_version != start.catalog_version {
            return mismatch("catalogVersion");
        }
        if model.node_count != start.node_count {
            return mismatch("node count");
        }
        if self.nodes.len() != start.node_count {
            return Err(Error::InvalidConfig(
                "generated-ui card_element count must match card_start node count".to_string(),
            ));
        }
        let render = GeneratedUiRender {
            protocol_version: start.protocol_version,
            catalog: start.catalog.clone(),
            catalog_version: start.catalog_version.clone(),
            card_id: start.card_id.clone(),
            root: start.root.clone(),
            fallback_text: start.fallback_text.clone(),
            nodes: self.nodes.clone(),
            actions: model.actions.clone(),
            state: model.state.clone(),
            lifecycle: model.lifecycle.clone(),
        };
        render.validate()?;
        Ok(render)
    }

    fn partial(&self) -> GeneratedUiPartialTree {
        let mut arrived = self
            .nodes
            .iter()
            .map(|node| (node.id.as_str(), (node, false)))
            .collect::<HashMap<_, _>>();
        if let Some(provisional) = &self.provisional {
            arrived
                .entry(provisional.id.as_str())
                .or_insert((provisional, true));
        }
        let mut nodes = Vec::new();
        let mut visited = HashSet::new();
        let mut stack = vec![self.start.root.as_str()];
        while let Some(id) = stack.pop() {
            let Some((node, provisional)) = arrived.get(id) else {
                continue;
            };
            if !visited.insert(id) {
                continue;
            }
            let unavailable = node
                .child_refs
                .iter()
                .filter(|child| !arrived.contains_key(child.as_str()))
                .cloned()
                .collect();
            stack.extend(
                node.child_refs
                    .iter()
                    .rev()
                    .map(LensAtomId::as_str)
                    .filter(|child| arrived.contains_key(child)),
            );
            nodes.push(GeneratedUiPartialNode {
                node: (*node).clone(),
                unavailable,
                provisional: *provisional,
            });
        }
        GeneratedUiPartialTree {
            card_id: self.start.card_id.clone(),
            catalog: self.start.catalog.clone(),
            catalog_version: self.start.catalog_version.clone(),
            root: self.start.root.clone(),
            fallback_text: self.start.fallback_text.clone(),
            nodes,
        }
    }
}
