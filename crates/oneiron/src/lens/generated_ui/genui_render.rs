//! Flat render validation, segment framing and reassembly, and segment wire validators.

use super::genui_state::validate_generated_ui_interactivity;
use super::{
    GENERATED_UI_WIRE_VERSION, GeneratedUiActionDeclaration, GeneratedUiCardLifecycle,
    GeneratedUiCatalog, GeneratedUiStateSnapshot, LensElementRef, SelfUiBinding,
};
use crate::lens::atom::{LensAtom, LensText};
use crate::lens::validate::{
    LensBudget, validate_generated_ui_node_count, validate_generated_ui_protocol_version,
    validate_lens_collection_len, validate_required_lens_text,
};
use crate::lens::wire_ids::{LensAtomId, LensHandleRef, LensRenderId, MAX_LENS_TREE_DEPTH};
use crate::lens::wire_limits::deserialize_limited_vec;
use crate::llm::ContentPart;
use crate::{Error, Result};
use serde::{Deserialize, Deserializer, Serialize, de};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedUiRender {
    pub protocol_version: u16,
    pub catalog: GeneratedUiCatalog,
    pub card_id: LensRenderId,
    pub root: LensAtomId,
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
        root: LensAtomId,
        nodes: Vec<GeneratedUiNode>,
    ) -> Result<Self> {
        Self::interactive(
            card_id,
            catalog,
            root,
            nodes,
            Vec::new(),
            GeneratedUiStateSnapshot::default(),
            GeneratedUiCardLifecycle::initial(),
        )
    }

    pub fn interactive(
        card_id: LensRenderId,
        catalog: GeneratedUiCatalog,
        root: LensAtomId,
        nodes: Vec<GeneratedUiNode>,
        actions: Vec<GeneratedUiActionDeclaration>,
        state: GeneratedUiStateSnapshot,
        lifecycle: GeneratedUiCardLifecycle,
    ) -> Result<Self> {
        let render = Self {
            protocol_version: GENERATED_UI_WIRE_VERSION,
            catalog,
            card_id,
            root,
            nodes,
            actions,
            state,
            lifecycle,
        };
        render.validate()?;
        Ok(render)
    }

    #[must_use]
    pub fn segments(&self) -> Vec<GeneratedUiSegment> {
        let mut segments = Vec::with_capacity(self.nodes.len() + 2);
        let fallback_text = self
            .nodes
            .iter()
            .find(|node| node.id == self.root)
            .map_or_else(
                || LensText::new("generated ui").expect("static fallback is valid"),
                |node| node.fallback_text.clone(),
            );
        segments.push(GeneratedUiSegment::CardStart(GeneratedUiCardStart {
            protocol_version: self.protocol_version,
            catalog: self.catalog,
            card_id: self.card_id.clone(),
            root: self.root.clone(),
            node_count: self.nodes.len(),
            fallback_text,
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
                    catalog: self.catalog,
                    actions: self.actions.clone(),
                    state: self.state.clone(),
                    lifecycle: self.lifecycle.clone(),
                },
            },
        ));
        segments
    }

    pub fn content_parts(&self) -> Result<Vec<ContentPart>> {
        self.segments()
            .iter()
            .map(GeneratedUiSegment::to_content_part)
            .collect()
    }

    pub fn from_segments(segments: &[GeneratedUiSegment]) -> Result<Self> {
        let Some((start_segment, rest)) = segments.split_first() else {
            return Err(Error::InvalidConfig(
                "generated-ui segment stream must contain card_start".to_string(),
            ));
        };
        let GeneratedUiSegment::CardStart(start) = start_segment else {
            return Err(Error::InvalidConfig(
                "generated-ui segment stream must start with card_start".to_string(),
            ));
        };
        start.validate()?;

        let mut nodes = Vec::with_capacity(start.node_count);
        let mut budget = LensBudget::default();
        let mut interactivity = None;

        for segment in rest {
            match segment {
                GeneratedUiSegment::CardStart(_) => {
                    return Err(Error::InvalidConfig(
                        "generated-ui segment stream must contain exactly one card_start"
                            .to_string(),
                    ));
                }
                GeneratedUiSegment::CardElement(element) => {
                    if interactivity.is_some() {
                        return Err(Error::InvalidConfig(
                            "generated-ui card_element segments must precede card_state_update"
                                .to_string(),
                        ));
                    }
                    validate_generated_ui_protocol_version(element.protocol_version)?;
                    if element.card_id != start.card_id {
                        return Err(Error::InvalidConfig(
                            "generated-ui card_element card_id must match card_start".to_string(),
                        ));
                    }
                    element.node.validate_with_budget(&mut budget)?;
                    nodes.push(element.node.clone());
                }
                GeneratedUiSegment::CardStateUpdate(state) => {
                    if interactivity.is_some() {
                        return Err(Error::InvalidConfig(
                            "generated-ui segment stream must contain exactly one card_state_update"
                                .to_string(),
                        ));
                    }
                    state.validate()?;
                    if state.card_id != start.card_id {
                        return Err(Error::InvalidConfig(
                            "generated-ui card_state_update card_id must match card_start"
                                .to_string(),
                        ));
                    }
                    if state.data_model.root != start.root {
                        return Err(Error::InvalidConfig(
                            "generated-ui card_state_update root must match card_start".to_string(),
                        ));
                    }
                    if state.data_model.catalog != start.catalog {
                        return Err(Error::InvalidConfig(
                            "generated-ui card_state_update catalog must match card_start"
                                .to_string(),
                        ));
                    }
                    if state.data_model.node_count != start.node_count {
                        return Err(Error::InvalidConfig(
                            "generated-ui card_state_update node count must match card_start"
                                .to_string(),
                        ));
                    }
                    interactivity = Some(&state.data_model);
                }
            }
        }

        let Some(data_model) = interactivity else {
            return Err(Error::InvalidConfig(
                "generated-ui segment stream must end with card_state_update".to_string(),
            ));
        };
        if nodes.len() != start.node_count {
            return Err(Error::InvalidConfig(
                "generated-ui card_element count must match card_start node count".to_string(),
            ));
        }

        let render = Self {
            protocol_version: start.protocol_version,
            catalog: start.catalog,
            card_id: start.card_id.clone(),
            root: start.root.clone(),
            nodes,
            actions: data_model.actions.clone(),
            state: data_model.state.clone(),
            lifecycle: data_model.lifecycle.clone(),
        };
        render.validate()?;
        Ok(render)
    }

    pub(in crate::lens) fn validate(&self) -> Result<()> {
        if self.protocol_version != GENERATED_UI_WIRE_VERSION {
            return Err(Error::InvalidConfig(format!(
                "unsupported generated-ui wire version {}",
                self.protocol_version
            )));
        }
        self.lifecycle.validate()?;
        validate_lens_collection_len("generated-ui flat nodes", self.nodes.len())?;
        if self.nodes.is_empty() {
            return Err(Error::InvalidConfig(
                "generated-ui flat tree must contain at least one node".to_string(),
            ));
        }

        let mut ids = HashSet::with_capacity(self.nodes.len());
        let mut id_to_index = HashMap::with_capacity(self.nodes.len());
        let mut budget = LensBudget::default();
        for node in &self.nodes {
            node.validate_with_budget(&mut budget)?;
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
        let mut stack = vec![(root_index, 1usize)];
        while let Some((node_index, depth)) = stack.pop() {
            let node = &self.nodes[node_index];
            if !visited.insert(node.id.as_str()) {
                return Err(Error::InvalidConfig(
                    "generated-ui flat tree must not contain cycles".to_string(),
                ));
            }
            if depth > MAX_LENS_TREE_DEPTH {
                return Err(Error::InvalidConfig(format!(
                    "generated-ui flat tree depth must be at most {MAX_LENS_TREE_DEPTH}"
                )));
            }
            for child_ref in node.child_refs.iter().rev() {
                stack.push((id_to_index[child_ref.as_str()], depth + 1));
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
            card_id: LensRenderId,
            root: LensAtomId,
            #[serde(deserialize_with = "deserialize_limited_vec")]
            nodes: Vec<GeneratedUiNode>,
            #[serde(default, deserialize_with = "deserialize_limited_vec")]
            actions: Vec<GeneratedUiActionDeclaration>,
            #[serde(rename = "$state", default)]
            state: GeneratedUiStateSnapshot,
            lifecycle: GeneratedUiCardLifecycle,
        }

        let wire = GeneratedUiRenderWire::deserialize(deserializer)?;
        let render = Self {
            protocol_version: wire.protocol_version,
            catalog: wire.catalog,
            card_id: wire.card_id,
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
    #[serde(default, deserialize_with = "deserialize_limited_vec")]
    pub bindings: Vec<LensHandleRef>,
    #[serde(
        rename = "$bind",
        default,
        deserialize_with = "deserialize_limited_vec"
    )]
    pub state_bindings: Vec<SelfUiBinding>,
    #[serde(default, deserialize_with = "deserialize_limited_vec")]
    pub child_refs: Vec<LensAtomId>,
}

impl GeneratedUiNode {
    fn validate_with_budget(&self, budget: &mut LensBudget) -> Result<()> {
        validate_required_lens_text("generated-ui node fallbackText", &self.fallback_text)?;
        self.atom.validate()?;
        self.atom.count_collection_items(budget)?;
        budget.add_collection("generated-ui node bindings", self.bindings.len())?;
        budget.add_collection("generated-ui node $bind", self.state_bindings.len())?;
        budget.add_collection("generated-ui child refs", self.child_refs.len())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "segment", content = "payload", rename_all = "snake_case")]
pub enum GeneratedUiSegment {
    CardStart(GeneratedUiCardStart),
    CardElement(Box<GeneratedUiCardElement>),
    CardStateUpdate(GeneratedUiCardStateUpdate),
}

impl GeneratedUiSegment {
    pub(in crate::lens) fn validate(&self) -> Result<()> {
        match self {
            Self::CardStart(payload) => payload.validate(),
            Self::CardElement(payload) => payload.validate(),
            Self::CardStateUpdate(payload) => payload.validate(),
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
        }

        let wire = GeneratedUiSegmentWire::deserialize(deserializer)?;
        let segment = match wire {
            GeneratedUiSegmentWire::Start(payload) => Self::CardStart(payload),
            GeneratedUiSegmentWire::Element(payload) => Self::CardElement(payload),
            GeneratedUiSegmentWire::StateUpdate(payload) => Self::CardStateUpdate(payload),
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
    pub card_id: LensRenderId,
    pub root: LensAtomId,
    pub node_count: usize,
    pub fallback_text: LensText,
}

impl GeneratedUiCardStart {
    fn validate(&self) -> Result<()> {
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
            card_id: LensRenderId,
            root: LensAtomId,
            node_count: usize,
            fallback_text: LensText,
        }

        let wire = GeneratedUiCardStartWire::deserialize(deserializer)?;
        let payload = Self {
            protocol_version: wire.protocol_version,
            catalog: wire.catalog,
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
    fn validate(&self) -> Result<()> {
        validate_generated_ui_protocol_version(self.protocol_version)?;
        let mut budget = LensBudget::default();
        self.node.validate_with_budget(&mut budget)
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
    fn validate(&self) -> Result<()> {
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
    pub actions: Vec<GeneratedUiActionDeclaration>,
    #[serde(rename = "$state")]
    pub state: GeneratedUiStateSnapshot,
    pub lifecycle: GeneratedUiCardLifecycle,
}

impl GeneratedUiDataModel {
    pub(in crate::lens) fn validate(&self) -> Result<()> {
        self.lifecycle.validate()?;
        validate_generated_ui_node_count("generated-ui data model node count", self.node_count)?;
        validate_lens_collection_len("generated-ui action declarations", self.actions.len())?;
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
            #[serde(default, deserialize_with = "deserialize_limited_vec")]
            actions: Vec<GeneratedUiActionDeclaration>,
            #[serde(rename = "$state", default)]
            state: GeneratedUiStateSnapshot,
            lifecycle: GeneratedUiCardLifecycle,
        }

        let wire = GeneratedUiDataModelWire::deserialize(deserializer)?;
        let data_model = Self {
            root: wire.root,
            node_count: wire.node_count,
            catalog: wire.catalog,
            actions: wire.actions,
            state: wire.state,
            lifecycle: wire.lifecycle,
        };
        data_model.validate().map_err(de::Error::custom)?;
        Ok(data_model)
    }
}
