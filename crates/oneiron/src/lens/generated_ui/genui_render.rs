//! Flat render validation, segment framing and reassembly, and segment wire validators.

use super::genui_app_catalog::catalog_version_or_kit;
use super::genui_state::validate_generated_ui_interactivity;
use super::{
    GENERATED_UI_WIRE_VERSION, GeneratedUiActionDeclaration, GeneratedUiCardLifecycle,
    GeneratedUiCardReady, GeneratedUiCardStatePatch, GeneratedUiCardStateSnapshot,
    GeneratedUiCatalog, GeneratedUiCatalogVersion, GeneratedUiStateSnapshot, GeneratedUiStream,
    GeneratedUiStreamProfile, LensElementRef, SelfUiBinding,
};
use crate::lens::atom::{LensAtom, LensText};
use crate::lens::validate::{
    validate_generated_ui_node_count, validate_generated_ui_protocol_version,
    validate_required_lens_text,
};
use crate::lens::wire_ids::{LensAtomId, LensHandleRef, LensRenderId};
use crate::llm::ContentPart;
use crate::{Error, Result};
use serde::{Deserialize, Deserializer, Serialize, de};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedUiRender {
    pub protocol_version: u16,
    pub catalog: GeneratedUiCatalog,
    /// The semver of the component set this render targets (FIX 9893), apart
    /// from the lens body's kit and apps-contract stamps.
    pub catalog_version: GeneratedUiCatalogVersion,
    pub card_id: LensRenderId,
    pub root: LensAtomId,
    /// The whole card as text: what a reader that does not know this
    /// `protocolVersion` shows (FIX 7967). The root node's `fallbackText`.
    pub fallback_text: LensText,
    pub nodes: Vec<GeneratedUiNode>,
    pub actions: Vec<GeneratedUiActionDeclaration>,
    #[serde(rename = "$state")]
    pub state: GeneratedUiStateSnapshot,
    pub lifecycle: GeneratedUiCardLifecycle,
}

impl GeneratedUiRender {
    pub fn new(
        card_id: LensRenderId,
        catalog: GeneratedUiCatalog,
        catalog_version: GeneratedUiCatalogVersion,
        root: LensAtomId,
        nodes: Vec<GeneratedUiNode>,
    ) -> Result<Self> {
        Self::interactive(
            card_id,
            catalog,
            catalog_version,
            root,
            nodes,
            Vec::new(),
            GeneratedUiStateSnapshot::default(),
            GeneratedUiCardLifecycle::initial(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn interactive(
        card_id: LensRenderId,
        catalog: GeneratedUiCatalog,
        catalog_version: GeneratedUiCatalogVersion,
        root: LensAtomId,
        nodes: Vec<GeneratedUiNode>,
        actions: Vec<GeneratedUiActionDeclaration>,
        state: GeneratedUiStateSnapshot,
        lifecycle: GeneratedUiCardLifecycle,
    ) -> Result<Self> {
        let render = Self {
            protocol_version: GENERATED_UI_WIRE_VERSION,
            catalog,
            catalog_version,
            card_id,
            fallback_text: root_fallback_text(&nodes, &root),
            root,
            nodes,
            actions,
            state,
            lifecycle,
        };
        render.validate()?;
        Ok(render)
    }

    /// Today's full-model stream: `card_start`, one `card_element` per node,
    /// then `card_state_update` with the whole data model.
    #[must_use]
    pub fn segments(&self) -> Vec<GeneratedUiSegment> {
        let mut segments = Vec::with_capacity(self.nodes.len() + 2);
        segments.push(GeneratedUiSegment::CardStart(GeneratedUiCardStart {
            protocol_version: self.protocol_version,
            catalog: self.catalog.clone(),
            catalog_version: self.catalog_version.clone(),
            card_id: self.card_id.clone(),
            root: self.root.clone(),
            node_count: self.nodes.len(),
            fallback_text: self.fallback_text.clone(),
        }));
        segments.extend(self.nodes.iter().cloned().map(|node| {
            GeneratedUiSegment::CardElement(Box::new(GeneratedUiCardElement {
                protocol_version: self.protocol_version,
                card_id: self.card_id.clone(),
                node,
            }))
        }));
        segments.push(GeneratedUiSegment::CardStateUpdate(
            GeneratedUiCardStateUpdate {
                protocol_version: self.protocol_version,
                card_id: self.card_id.clone(),
                data_model: GeneratedUiDataModel {
                    root: self.root.clone(),
                    node_count: self.nodes.len(),
                    catalog: self.catalog.clone(),
                    catalog_version: self.catalog_version.clone(),
                    actions: self.actions.clone(),
                    state: self.state.clone(),
                    lifecycle: self.lifecycle.clone(),
                },
            },
        ));
        segments
    }

    /// The stream `profile` frames this render as (FIX 7968). The patch
    /// profile sends today's full-model stream, then `card_ready`; the card
    /// renders at its `card_state_update` as before, and ready waits on
    /// nothing.
    #[must_use]
    pub fn segments_for_profile(
        &self,
        profile: GeneratedUiStreamProfile,
    ) -> Vec<GeneratedUiSegment> {
        let mut segments = self.segments();
        if profile == GeneratedUiStreamProfile::Patch {
            segments.push(GeneratedUiSegment::CardReady(GeneratedUiCardReady {
                protocol_version: self.protocol_version,
                card_id: self.card_id.clone(),
            }));
        }
        segments
    }

    pub fn content_parts(&self) -> Result<Vec<ContentPart>> {
        self.segments()
            .iter()
            .map(GeneratedUiSegment::to_content_part)
            .collect()
    }

    /// Reassemble a complete stream: exactly one `card_start`, its elements,
    /// one `card_state_update`, then any `card_ready`, `card_state_patch` and
    /// `card_state_snapshot` refinements, through the one incremental
    /// [`GeneratedUiStream`] a partial reader also uses.
    pub fn from_segments(segments: &[GeneratedUiSegment]) -> Result<Self> {
        let mut stream = GeneratedUiStream::new();
        for segment in segments {
            stream.push(segment.clone())?;
        }
        stream.into_render()
    }

    pub(in crate::lens) fn validate(&self) -> Result<()> {
        if self.protocol_version != GENERATED_UI_WIRE_VERSION {
            return Err(Error::InvalidConfig(format!(
                "unsupported generated-ui wire version {}",
                self.protocol_version
            )));
        }
        self.lifecycle.validate()?;
        validate_required_lens_text("generated-ui render fallbackText", &self.fallback_text)?;
        if self.nodes.is_empty() {
            return Err(Error::InvalidConfig(
                "generated-ui flat tree must contain at least one node".to_string(),
            ));
        }

        let mut ids = HashSet::with_capacity(self.nodes.len());
        let mut id_to_index = HashMap::with_capacity(self.nodes.len());
        for node in &self.nodes {
            node.validate()?;
            if !ids.insert(node.id.as_str()) {
                return Err(Error::InvalidConfig(
                    "generated-ui flat nodes must not contain duplicate ids".to_string(),
                ));
            }
            id_to_index.insert(node.id.as_str(), id_to_index.len());
        }
        let root_index = *id_to_index.get(self.root.as_str()).ok_or_else(|| {
            Error::InvalidConfig("generated-ui root must reference a declared node".to_string())
        })?;

        let mut rootless_count = 0usize;
        let mut claimed_parents = HashMap::with_capacity(self.nodes.len().saturating_sub(1));
        for node in &self.nodes {
            match node.parent.as_ref() {
                Some(parent) => {
                    if !ids.contains(parent.as_str()) {
                        return Err(Error::InvalidConfig(
                            "generated-ui parent refs must reference declared nodes".to_string(),
                        ));
                    }
                }
                None => {
                    rootless_count += 1;
                    if node.id != self.root {
                        return Err(Error::InvalidConfig(
                            "generated-ui flat tree must have exactly one root".to_string(),
                        ));
                    }
                }
            }

            let mut local_children = HashSet::with_capacity(node.child_refs.len());
            for child_ref in &node.child_refs {
                let Some(child_index) = id_to_index.get(child_ref.as_str()) else {
                    return Err(Error::InvalidConfig(
                        "generated-ui child refs must reference declared nodes".to_string(),
                    ));
                };
                if child_ref == &node.id {
                    return Err(Error::InvalidConfig(
                        "generated-ui child refs must not reference their own node".to_string(),
                    ));
                }
                if !local_children.insert(child_ref.as_str()) {
                    return Err(Error::InvalidConfig(
                        "generated-ui child refs must not contain duplicates".to_string(),
                    ));
                }
                let child = &self.nodes[*child_index];
                if child.parent.as_ref().map(LensAtomId::as_str) != Some(node.id.as_str()) {
                    return Err(Error::InvalidConfig(
                        "generated-ui child refs must agree with child parent refs".to_string(),
                    ));
                }
                if claimed_parents
                    .insert(child_ref.as_str(), node.id.as_str())
                    .is_some()
                {
                    return Err(Error::InvalidConfig(
                        "generated-ui flat nodes must have at most one parent".to_string(),
                    ));
                }
            }
        }
        if rootless_count != 1 || self.nodes[root_index].parent.is_some() {
            return Err(Error::InvalidConfig(
                "generated-ui flat tree must have exactly one root".to_string(),
            ));
        }
        for node in &self.nodes {
            if let Some(parent) = node.parent.as_ref() {
                let parent_index = id_to_index[parent.as_str()];
                let parent_node = &self.nodes[parent_index];
                if !parent_node
                    .child_refs
                    .iter()
                    .any(|child_ref| child_ref == &node.id)
                {
                    return Err(Error::InvalidConfig(
                        "generated-ui parent refs must agree with parent child refs".to_string(),
                    ));
                }
            }
        }

        let mut visited = HashSet::with_capacity(self.nodes.len());
        let mut stack = vec![root_index];
        while let Some(node_index) = stack.pop() {
            let node = &self.nodes[node_index];
            if !visited.insert(node.id.as_str()) {
                return Err(Error::InvalidConfig(
                    "generated-ui flat tree must not contain cycles".to_string(),
                ));
            }
            for child_ref in node.child_refs.iter().rev() {
                stack.push(id_to_index[child_ref.as_str()]);
            }
        }
        if visited.len() != self.nodes.len() {
            return Err(Error::InvalidConfig(
                "generated-ui flat tree must not contain orphan nodes".to_string(),
            ));
        }
        validate_generated_ui_interactivity(
            &LensElementRef::collect_flat(&self.nodes),
            &self.actions,
            &self.state,
        )
    }
}

impl<'de> Deserialize<'de> for GeneratedUiRender {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct GeneratedUiRenderWire {
            protocol_version: u16,
            catalog: GeneratedUiCatalog,
            #[serde(default)]
            catalog_version: Option<GeneratedUiCatalogVersion>,
            card_id: LensRenderId,
            root: LensAtomId,
            #[serde(default)]
            fallback_text: Option<LensText>,
            nodes: Vec<GeneratedUiNode>,
            #[serde(default)]
            actions: Vec<GeneratedUiActionDeclaration>,
            #[serde(rename = "$state", default)]
            state: GeneratedUiStateSnapshot,
            lifecycle: GeneratedUiCardLifecycle,
        }

        let wire = GeneratedUiRenderWire::deserialize(deserializer)?;
        let catalog_version = catalog_version_or_kit(&wire.catalog, wire.catalog_version)
            .map_err(de::Error::custom)?;
        let render = Self {
            protocol_version: wire.protocol_version,
            catalog: wire.catalog,
            catalog_version,
            card_id: wire.card_id,
            fallback_text: wire
                .fallback_text
                .unwrap_or_else(|| root_fallback_text(&wire.nodes, &wire.root)),
            root: wire.root,
            nodes: wire.nodes,
            actions: wire.actions,
            state: wire.state,
            lifecycle: wire.lifecycle,
        };
        render.validate().map_err(de::Error::custom)?;
        Ok(render)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GeneratedUiNode {
    pub id: LensAtomId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<LensAtomId>,
    pub atom: LensAtom,
    pub fallback_text: LensText,
    #[serde(default)]
    pub bindings: Vec<LensHandleRef>,
    #[serde(rename = "$bind", default)]
    pub state_bindings: Vec<SelfUiBinding>,
    #[serde(default)]
    pub child_refs: Vec<LensAtomId>,
}

/// The root node's `fallbackText`: the whole card as text.
fn root_fallback_text(nodes: &[GeneratedUiNode], root: &LensAtomId) -> LensText {
    nodes
        .iter()
        .find(|node| &node.id == root)
        .map_or_else(
            || LensText::new("generated ui").expect("static fallback is valid"),
            |node| node.fallback_text.clone(),
        )
}

impl GeneratedUiNode {
    pub(super) fn validate(&self) -> Result<()> {
        validate_required_lens_text("generated-ui node fallbackText", &self.fallback_text)?;
        self.atom.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "segment", content = "payload", rename_all = "snake_case")]
pub enum GeneratedUiSegment {
    CardStart(GeneratedUiCardStart),
    CardElement(Box<GeneratedUiCardElement>),
    CardStateUpdate(GeneratedUiCardStateUpdate),
    /// The patch profile's end of generation (FIX 7968).
    CardReady(GeneratedUiCardReady),
    /// An RFC-6902 refinement of the card, its nodes keyed by stable id.
    CardStatePatch(GeneratedUiCardStatePatch),
    /// The whole card again, replacing what the reader holds.
    CardStateSnapshot(Box<GeneratedUiCardStateSnapshot>),
}

impl GeneratedUiSegment {
    pub(in crate::lens) fn validate(&self) -> Result<()> {
        match self {
            Self::CardStart(payload) => payload.validate(),
            Self::CardElement(payload) => payload.validate(),
            Self::CardStateUpdate(payload) => payload.validate(),
            Self::CardReady(payload) => payload.validate(),
            Self::CardStatePatch(payload) => payload.validate(),
            Self::CardStateSnapshot(payload) => payload.validate(),
        }
    }

    /// The card this segment belongs to.
    #[must_use]
    pub fn card_id(&self) -> &LensRenderId {
        match self {
            Self::CardStart(payload) => &payload.card_id,
            Self::CardElement(payload) => &payload.card_id,
            Self::CardStateUpdate(payload) => &payload.card_id,
            Self::CardReady(payload) => &payload.card_id,
            Self::CardStatePatch(payload) => &payload.card_id,
            Self::CardStateSnapshot(payload) => &payload.card_id,
        }
    }

    pub fn to_content_part(&self) -> Result<ContentPart> {
        let text = serde_json::to_string(self).map_err(|error| {
            Error::InvalidConfig(format!(
                "generated-ui segment serialization failed: {error}"
            ))
        })?;
        Ok(ContentPart::Text { text })
    }
}

impl<'de> Deserialize<'de> for GeneratedUiSegment {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(tag = "segment", content = "payload", rename_all = "snake_case")]
        enum GeneratedUiSegmentWire {
            #[serde(rename = "card_start")]
            Start(GeneratedUiCardStart),
            #[serde(rename = "card_element")]
            Element(Box<GeneratedUiCardElement>),
            #[serde(rename = "card_state_update")]
            StateUpdate(GeneratedUiCardStateUpdate),
            #[serde(rename = "card_ready")]
            Ready(GeneratedUiCardReady),
            #[serde(rename = "card_state_patch")]
            StatePatch(GeneratedUiCardStatePatch),
            #[serde(rename = "card_state_snapshot")]
            StateSnapshot(Box<GeneratedUiCardStateSnapshot>),
        }

        let wire = GeneratedUiSegmentWire::deserialize(deserializer)?;
        let segment = match wire {
            GeneratedUiSegmentWire::Start(payload) => Self::CardStart(payload),
            GeneratedUiSegmentWire::Element(payload) => Self::CardElement(payload),
            GeneratedUiSegmentWire::StateUpdate(payload) => Self::CardStateUpdate(payload),
            GeneratedUiSegmentWire::Ready(payload) => Self::CardReady(payload),
            GeneratedUiSegmentWire::StatePatch(payload) => Self::CardStatePatch(payload),
            GeneratedUiSegmentWire::StateSnapshot(payload) => Self::CardStateSnapshot(payload),
        };
        segment.validate().map_err(de::Error::custom)?;
        Ok(segment)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GeneratedUiCardStart {
    pub protocol_version: u16,
    pub catalog: GeneratedUiCatalog,
    pub catalog_version: GeneratedUiCatalogVersion,
    pub card_id: LensRenderId,
    pub root: LensAtomId,
    pub node_count: usize,
    pub fallback_text: LensText,
}

impl GeneratedUiCardStart {
    pub(super) fn validate(&self) -> Result<()> {
        validate_generated_ui_protocol_version(self.protocol_version)?;
        validate_generated_ui_node_count("generated-ui segment node count", self.node_count)?;
        validate_required_lens_text("generated-ui segment fallbackText", &self.fallback_text)
    }
}

impl<'de> Deserialize<'de> for GeneratedUiCardStart {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct GeneratedUiCardStartWire {
            protocol_version: u16,
            catalog: GeneratedUiCatalog,
            #[serde(default)]
            catalog_version: Option<GeneratedUiCatalogVersion>,
            card_id: LensRenderId,
            root: LensAtomId,
            node_count: usize,
            fallback_text: LensText,
        }

        let wire = GeneratedUiCardStartWire::deserialize(deserializer)?;
        let catalog_version = catalog_version_or_kit(&wire.catalog, wire.catalog_version)
            .map_err(de::Error::custom)?;
        let payload = Self {
            protocol_version: wire.protocol_version,
            catalog: wire.catalog,
            catalog_version,
            card_id: wire.card_id,
            root: wire.root,
            node_count: wire.node_count,
            fallback_text: wire.fallback_text,
        };
        payload.validate().map_err(de::Error::custom)?;
        Ok(payload)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GeneratedUiCardElement {
    pub protocol_version: u16,
    pub card_id: LensRenderId,
    pub node: GeneratedUiNode,
}

impl GeneratedUiCardElement {
    pub(super) fn validate(&self) -> Result<()> {
        validate_generated_ui_protocol_version(self.protocol_version)?;
        self.node.validate()
    }
}

impl<'de> Deserialize<'de> for GeneratedUiCardElement {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct GeneratedUiCardElementWire {
            protocol_version: u16,
            card_id: LensRenderId,
            node: GeneratedUiNode,
        }

        let wire = GeneratedUiCardElementWire::deserialize(deserializer)?;
        let payload = Self {
            protocol_version: wire.protocol_version,
            card_id: wire.card_id,
            node: wire.node,
        };
        payload.validate().map_err(de::Error::custom)?;
        Ok(payload)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GeneratedUiCardStateUpdate {
    pub protocol_version: u16,
    pub card_id: LensRenderId,
    pub data_model: GeneratedUiDataModel,
}

impl GeneratedUiCardStateUpdate {
    pub(super) fn validate(&self) -> Result<()> {
        validate_generated_ui_protocol_version(self.protocol_version)?;
        self.data_model.validate()
    }
}

impl<'de> Deserialize<'de> for GeneratedUiCardStateUpdate {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct GeneratedUiCardStateUpdateWire {
            protocol_version: u16,
            card_id: LensRenderId,
            data_model: GeneratedUiDataModel,
        }

        let wire = GeneratedUiCardStateUpdateWire::deserialize(deserializer)?;
        let payload = Self {
            protocol_version: wire.protocol_version,
            card_id: wire.card_id,
            data_model: wire.data_model,
        };
        payload.validate().map_err(de::Error::custom)?;
        Ok(payload)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GeneratedUiDataModel {
    pub root: LensAtomId,
    pub node_count: usize,
    pub catalog: GeneratedUiCatalog,
    pub catalog_version: GeneratedUiCatalogVersion,
    pub actions: Vec<GeneratedUiActionDeclaration>,
    #[serde(rename = "$state")]
    pub state: GeneratedUiStateSnapshot,
    pub lifecycle: GeneratedUiCardLifecycle,
}

impl GeneratedUiDataModel {
    pub(in crate::lens) fn validate(&self) -> Result<()> {
        self.lifecycle.validate()?;
        validate_generated_ui_node_count("generated-ui data model node count", self.node_count)?;
        for declaration in &self.actions {
            declaration.validate()?;
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for GeneratedUiDataModel {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct GeneratedUiDataModelWire {
            root: LensAtomId,
            node_count: usize,
            catalog: GeneratedUiCatalog,
            #[serde(default)]
            catalog_version: Option<GeneratedUiCatalogVersion>,
            #[serde(default)]
            actions: Vec<GeneratedUiActionDeclaration>,
            #[serde(rename = "$state", default)]
            state: GeneratedUiStateSnapshot,
            lifecycle: GeneratedUiCardLifecycle,
        }

        let wire = GeneratedUiDataModelWire::deserialize(deserializer)?;
        let catalog_version = catalog_version_or_kit(&wire.catalog, wire.catalog_version)
            .map_err(de::Error::custom)?;
        let data_model = Self {
            root: wire.root,
            node_count: wire.node_count,
            catalog: wire.catalog,
            catalog_version,
            actions: wire.actions,
            state: wire.state,
            lifecycle: wire.lifecycle,
        };
        data_model.validate().map_err(de::Error::custom)?;
        Ok(data_model)
    }
}
