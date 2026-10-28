//! Authored-tree [`GeneratedUiCard`] assembly, surface lowering, and validated wire decoding.

use super::genui_app_catalog::catalog_version_or_kit;
use super::genui_state::validate_generated_ui_interactivity;
use super::{
    GENERATED_UI_WIRE_VERSION, GeneratedLens, GeneratedUiActionDeclaration,
    GeneratedUiCardLifecycle, GeneratedUiCatalog, GeneratedUiCatalogVersion, GeneratedUiNode,
    GeneratedUiPrebuilt, GeneratedUiRender, GeneratedUiSegment, GeneratedUiStateSnapshot,
    GeneratedUiSurfaceCapabilities, LensElementRef, LensLoadAction, LensVersionStamp,
    lens_load_action,
};
use crate::lens::atom::{LensAtom, LensNode, LensText};
use crate::lens::validate::{fallback_text_atom, validate_required_lens_text};
use crate::lens::wire_ids::{LensAtomId, LensRenderId};
use crate::llm::ContentPart;
use crate::{Error, Result};
use serde::{Deserialize, Deserializer, Serialize, de};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedUiCard {
    pub protocol_version: u16,
    /// The catalog this card is authored for, and that catalog's semver
    /// (FIX 9893): the built-in kit at its own semver unless an app's.
    pub catalog: GeneratedUiCatalog,
    pub catalog_version: GeneratedUiCatalogVersion,
    pub card_id: LensRenderId,
    /// The whole card as text, readable without knowing this
    /// `protocolVersion` (FIX 7967): the root node's `fallbackText`.
    pub fallback_text: LensText,
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
            catalog_version: GeneratedUiCatalogVersion::lens_atom_kit(),
            card_id,
            fallback_text: tree.root().fallback_text.clone(),
            tree,
            actions,
            state,
        };
        card.validate()?;
        Ok(card)
    }

    /// The same card, authored for an app's catalog at its declared semver.
    #[must_use]
    pub fn with_catalog(
        mut self,
        catalog: GeneratedUiCatalog,
        catalog_version: GeneratedUiCatalogVersion,
    ) -> Self {
        self.catalog = catalog;
        self.catalog_version = catalog_version;
        self
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

    /// Lowers the card for `surface` in one pass (ARCH-0048 G3): every atom
    /// the surface does not draw becomes its `fallbackText`, and a degraded
    /// element can neither host a control action nor drive a bound property.
    /// A result set the surface cannot draw lowers too (FIX 9892), with its
    /// backing refs, and the controls its action bar allowlists lower beside
    /// it, their declarations and backing refs gone: what it could not offer
    /// leaves the render, and the rest of the card renders as it would.
    pub fn render_for_surface(
        &self,
        surface: &GeneratedUiSurfaceCapabilities,
    ) -> Result<GeneratedUiRender> {
        let root = self.tree.root();
        let stripped_controls = self.unsupported_result_set_controls(surface);
        let mut nodes = Vec::new();
        let mut stack = vec![(root, None::<LensAtomId>)];

        while let Some((node, parent)) = stack.pop() {
            let child_refs = node
                .children
                .iter()
                .map(|child| child.id.clone())
                .collect::<Vec<_>>();
            let stripped = stripped_controls.contains(node.id.as_str());
            let supported = !stripped && surface.supports_atom(&node.atom);
            let backed = supported || !(stripped || matches!(node.atom, LensAtom::ResultSet(_)));
            nodes.push(GeneratedUiNode {
                id: node.id.clone(),
                parent,
                atom: if supported {
                    node.atom.clone()
                } else {
                    fallback_text_atom(&node.fallback_text)
                },
                fallback_text: node.fallback_text.clone(),
                bindings: if backed {
                    node.bindings.clone()
                } else {
                    Vec::new()
                },
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
            surface.catalog.clone(),
            surface.catalog_version.clone(),
            root.id.clone(),
            nodes,
            actions,
            self.state.clone(),
            GeneratedUiCardLifecycle::initial(),
        )
    }

    /// The elements of the controls whose actions a result set `surface`
    /// cannot draw allowlists (FIX 9892).
    fn unsupported_result_set_controls(
        &self,
        surface: &GeneratedUiSurfaceCapabilities,
    ) -> HashSet<&str> {
        let mut lowered_actions = HashSet::new();
        let mut stack = vec![self.tree.root()];
        while let Some(node) = stack.pop() {
            if let Some(result_set) = node.atom.result_set_payload()
                && !surface.supports_atom(&node.atom)
            {
                lowered_actions.extend(result_set.action_bar.iter().map(|id| id.as_str()));
            }
            stack.extend(node.children.iter());
        }
        self.actions
            .iter()
            .filter(|declaration| lowered_actions.contains(declaration.action_id.as_str()))
            .map(|declaration| declaration.element_id.as_str())
            .collect()
    }

    pub fn segments(&self) -> Result<Vec<GeneratedUiSegment>> {
        Ok(self.render()?.segments())
    }

    /// The card's stream for `surface`, framed in the stream profile the
    /// surface negotiated (FIX 7968).
    pub fn segments_for_surface(
        &self,
        surface: &GeneratedUiSurfaceCapabilities,
    ) -> Result<Vec<GeneratedUiSegment>> {
        Ok(self
            .render_for_surface(surface)?
            .segments_for_profile(surface.stream))
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
        validate_required_lens_text("generated-ui card fallbackText", &self.fallback_text)?;
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
            #[serde(default)]
            catalog_version: Option<GeneratedUiCatalogVersion>,
            card_id: LensRenderId,
            #[serde(default)]
            fallback_text: Option<LensText>,
            #[serde(default)]
            tree: Option<GeneratedLens>,
            #[serde(default)]
            prebuilt: Option<GeneratedUiPrebuilt>,
            #[serde(default)]
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
        let catalog_version = catalog_version_or_kit(&wire.catalog, wire.catalog_version)
            .map_err(de::Error::custom)?;
        let card = Self {
            protocol_version: wire.protocol_version,
            catalog: wire.catalog,
            catalog_version,
            card_id: wire.card_id,
            fallback_text: wire
                .fallback_text
                .unwrap_or_else(|| tree.root().fallback_text.clone()),
            tree,
            actions: wire.actions,
            state: wire.state,
        };
        card.validate().map_err(de::Error::custom)?;
        Ok(card)
    }
}
