//! Authored-tree [`GeneratedUiCard`] assembly, surface lowering, and validated wire decoding.

use super::genui_state::validate_generated_ui_interactivity;
use super::{
    GENERATED_UI_WIRE_VERSION, GeneratedLens, GeneratedUiActionDeclaration,
    GeneratedUiCardLifecycle, GeneratedUiCatalog, GeneratedUiNode, GeneratedUiPrebuilt,
    GeneratedUiRender, GeneratedUiSegment, GeneratedUiStateSnapshot,
    GeneratedUiSurfaceCapabilities, LensElementRef, LensLoadAction, LensVersionStamp,
    lens_load_action,
};
use crate::lens::atom::{LensAtom, LensNode};
use crate::lens::validate::compile_atom_for_surface;
use crate::lens::wire_ids::{LensAtomId, LensRenderId};
use crate::lens::wire_limits::deserialize_limited_vec;
use crate::llm::ContentPart;
use crate::{Error, Result};
use serde::{Deserialize, Deserializer, Serialize, de};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedUiCard {
    pub protocol_version: u16,
    pub catalog: GeneratedUiCatalog,
    pub card_id: LensRenderId,
    pub tree: GeneratedLens,
    /// Engine-authored action manifest. Serialized with the card; never ambient host state.
    pub actions: Vec<GeneratedUiActionDeclaration>,
    #[serde(rename = "$state")]
    pub state: GeneratedUiStateSnapshot,
}

impl GeneratedUiCard {
    pub fn card(card_id: LensRenderId, root: LensNode) -> Result<Self> {
        Self::new(card_id, GeneratedLens::new(root)?)
    }

    pub fn prebuilt(card_id: LensRenderId, prebuilt: GeneratedUiPrebuilt) -> Result<Self> {
        Self::card(card_id, prebuilt.expand()?)
    }

    pub fn new(card_id: LensRenderId, tree: GeneratedLens) -> Result<Self> {
        Self::interactive(
            card_id,
            tree,
            Vec::new(),
            GeneratedUiStateSnapshot::default(),
        )
    }

    /// Assemble a card with its engine-authored action manifest and initial `$state`.
    /// The manifest and every `$bind` descriptor are proved against the authored tree
    /// here, before any render is emitted. A tree carrying `$bind` must be built this
    /// way: its bindings are only meaningful alongside the `$state` they address.
    pub fn interactive(
        card_id: LensRenderId,
        tree: GeneratedLens,
        actions: Vec<GeneratedUiActionDeclaration>,
        state: GeneratedUiStateSnapshot,
    ) -> Result<Self> {
        let card = Self {
            protocol_version: GENERATED_UI_WIRE_VERSION,
            catalog: GeneratedUiCatalog::LensAtomKit,
            card_id,
            tree,
            actions,
            state,
        };
        card.validate()?;
        Ok(card)
    }

    /// Attach a manifest and `$state` to an already-valid card.
    pub fn with_interactivity(
        self,
        actions: Vec<GeneratedUiActionDeclaration>,
        state: GeneratedUiStateSnapshot,
    ) -> Result<Self> {
        Self::interactive(self.card_id, self.tree, actions, state)
    }

    pub fn render(&self) -> Result<GeneratedUiRender> {
        self.render_for_surface(&GeneratedUiSurfaceCapabilities::all_atom_kit())
    }

    pub fn render_for_surface(
        &self,
        surface: &GeneratedUiSurfaceCapabilities,
    ) -> Result<GeneratedUiRender> {
        let root = self.tree.root();
        let mut nodes = Vec::new();
        let mut stack = vec![(root, None::<LensAtomId>)];

        while let Some((node, parent)) = stack.pop() {
            let child_refs = node
                .children
                .iter()
                .map(|child| child.id.clone())
                .collect::<Vec<_>>();
            // A degraded element renders as fallback text, so it can neither host a
            // control action nor drive a bound property on this surface.
            let supported = surface.supports(node.atom.primitive());
            nodes.push(GeneratedUiNode {
                id: node.id.clone(),
                parent,
                atom: compile_atom_for_surface(&node.atom, &node.fallback_text, surface)?,
                fallback_text: node.fallback_text.clone(),
                bindings: node.bindings.clone(),
                state_bindings: if supported {
                    node.state_bindings.clone()
                } else {
                    Vec::new()
                },
                child_refs,
            });

            for child in node.children.iter().rev() {
                stack.push((child, Some(node.id.clone())));
            }
        }

        let offered = nodes
            .iter()
            .filter(|node| matches!(node.atom, LensAtom::SelfUi(_)))
            .map(|node| node.id.as_str().to_owned())
            .collect::<HashSet<_>>();
        let actions = self
            .actions
            .iter()
            .filter(|declaration| offered.contains(declaration.element_id.as_str()))
            .cloned()
            .collect();

        GeneratedUiRender::interactive(
            self.card_id.clone(),
            self.catalog,
            root.id.clone(),
            nodes,
            actions,
            self.state.clone(),
            GeneratedUiCardLifecycle::initial(),
        )
    }

    pub fn segments(&self) -> Result<Vec<GeneratedUiSegment>> {
        Ok(self.render()?.segments())
    }

    pub fn segments_for_surface(
        &self,
        surface: &GeneratedUiSurfaceCapabilities,
    ) -> Result<Vec<GeneratedUiSegment>> {
        Ok(self.render_for_surface(surface)?.segments())
    }

    pub fn content_parts(&self) -> Result<Vec<ContentPart>> {
        self.segments()?
            .iter()
            .map(GeneratedUiSegment::to_content_part)
            .collect()
    }

    pub fn content_parts_for_surface(
        &self,
        surface: &GeneratedUiSurfaceCapabilities,
    ) -> Result<Vec<ContentPart>> {
        self.segments_for_surface(surface)?
            .iter()
            .map(GeneratedUiSegment::to_content_part)
            .collect()
    }

    /// Surface the stale-card decision to a shell loader. A decoded card body always
    /// stays mountable; only the returned action says whether regeneration is owed.
    #[must_use]
    pub const fn load_action(&self) -> LensLoadAction {
        lens_load_action(self.tree.version_stamp(), LensVersionStamp::current())
    }

    fn validate(&self) -> Result<()> {
        if self.protocol_version != GENERATED_UI_WIRE_VERSION {
            return Err(Error::InvalidConfig(format!(
                "unsupported generated-ui wire version {}",
                self.protocol_version
            )));
        }
        self.tree.validate()?;
        validate_generated_ui_interactivity(
            &LensElementRef::collect_tree(self.tree.root()),
            &self.actions,
            &self.state,
        )
    }
}

impl<'de> Deserialize<'de> for GeneratedUiCard {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct GeneratedUiCardWire {
            protocol_version: u16,
            catalog: GeneratedUiCatalog,
            card_id: LensRenderId,
            #[serde(default)]
            tree: Option<GeneratedLens>,
            #[serde(default)]
            prebuilt: Option<GeneratedUiPrebuilt>,
            #[serde(default, deserialize_with = "deserialize_limited_vec")]
            actions: Vec<GeneratedUiActionDeclaration>,
            #[serde(rename = "$state", default)]
            state: GeneratedUiStateSnapshot,
        }

        let wire = GeneratedUiCardWire::deserialize(deserializer)?;
        let tree = match (wire.tree, wire.prebuilt) {
            (Some(tree), None) => tree,
            (None, Some(prebuilt)) => {
                let root = prebuilt.expand().map_err(de::Error::custom)?;
                GeneratedLens::new(root).map_err(de::Error::custom)?
            }
            (Some(_), Some(_)) => {
                return Err(de::Error::custom(
                    "generated-ui card must contain either tree or prebuilt, not both",
                ));
            }
            (None, None) => {
                return Err(de::Error::custom(
                    "generated-ui card must contain tree or prebuilt",
                ));
            }
        };
        let card = Self {
            protocol_version: wire.protocol_version,
            catalog: wire.catalog,
            card_id: wire.card_id,
            tree,
            actions: wire.actions,
            state: wire.state,
        };
        card.validate().map_err(de::Error::custom)?;
        Ok(card)
    }
}
