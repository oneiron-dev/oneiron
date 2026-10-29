//! The built-in primitive catalog, surface capability negotiation, and prebuilt card expansion.

use super::genui_app_catalog::catalog_version_or_kit;
use super::{
    GeneratedUiCatalog, GeneratedUiCatalogDescriptor, GeneratedUiCatalogVersion,
    GeneratedUiComponentAtom, GeneratedUiComponentSchema, GeneratedUiStreamProfile,
};
use crate::lens::atom::{
    CollectionAtom, LENS_ATOM_KIT_VERSION, LensAtom, LensNode, LensText, LensTextSpan,
    MetaLineAtom, RESULT_SET_ATOM_KIND, TextBlockAtom,
};
use crate::lens::validate::{validate_lens_tree, validate_required_lens_text};
use crate::lens::wire_ids::LensAtomId;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum GeneratedUiPrimitive {
    TextBlock,
    LedgerRow,
    ClaimLine,
    StatusDot,
    Seal,
    MetaLine,
    DossierSection,
    ThreadEntry,
    Sheet,
    Slip,
    Receipt,
    Charter,
    Postmark,
    PackLine,
    AnswerSheet,
    TwoClocks,
    NeighborhoodGraph,
    AsofScrubber,
    Throbber,
    VoiceLine,
    QuickFilter,
    InspectorSheet,
    InspectorRail,
    InspectorTrail,
    SelfUi,
    Media,
    ResultSet,
    /// A component an app catalog declares (FIX 9891). A surface supports one
    /// by declaring it ([`GeneratedUiSurfaceCapabilities::components`]), never
    /// through `primitives`.
    Component,
}

impl GeneratedUiPrimitive {
    /// Every built-in primitive. [`Self::Component`] is not among them: a
    /// surface supports a component by declaring it.
    pub const ALL: &'static [Self] = &[
        Self::TextBlock,
        Self::LedgerRow,
        Self::ClaimLine,
        Self::StatusDot,
        Self::Seal,
        Self::MetaLine,
        Self::DossierSection,
        Self::ThreadEntry,
        Self::Sheet,
        Self::Slip,
        Self::Receipt,
        Self::Charter,
        Self::Postmark,
        Self::PackLine,
        Self::AnswerSheet,
        Self::TwoClocks,
        Self::NeighborhoodGraph,
        Self::AsofScrubber,
        Self::Throbber,
        Self::VoiceLine,
        Self::QuickFilter,
        Self::InspectorSheet,
        Self::InspectorRail,
        Self::InspectorTrail,
        Self::SelfUi,
        Self::Media,
        Self::ResultSet,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TextBlock => "text_block",
            Self::LedgerRow => "ledger_row",
            Self::ClaimLine => "claim_line",
            Self::StatusDot => "status_dot",
            Self::Seal => "seal",
            Self::MetaLine => "meta_line",
            Self::DossierSection => "dossier_section",
            Self::ThreadEntry => "thread_entry",
            Self::Sheet => "sheet",
            Self::Slip => "slip",
            Self::Receipt => "receipt",
            Self::Charter => "charter",
            Self::Postmark => "postmark",
            Self::PackLine => "pack_line",
            Self::AnswerSheet => "answer_sheet",
            Self::TwoClocks => "two_clocks",
            Self::NeighborhoodGraph => "neighborhood_graph",
            Self::AsofScrubber => "asof_scrubber",
            Self::Throbber => "throbber",
            Self::VoiceLine => "voice_line",
            Self::QuickFilter => "quick_filter",
            Self::InspectorSheet => "inspector_sheet",
            Self::InspectorRail => "inspector_rail",
            Self::InspectorTrail => "inspector_trail",
            Self::SelfUi => "self_ui",
            Self::Media => "media",
            Self::ResultSet => RESULT_SET_ATOM_KIND,
            Self::Component => "component",
        }
    }

    /// The catalog version a surface must negotiate before this primitive may be
    /// rendered. Every pre-v3 primitive is pinned to the literal `2` it shipped at, so
    /// bumping [`LENS_ATOM_KIT_VERSION`] can never raise an existing minimum.
    #[must_use]
    pub const fn minimum_catalog_version(self) -> u16 {
        match self {
            Self::ResultSet | Self::Component => 3,
            Self::TextBlock
            | Self::LedgerRow
            | Self::ClaimLine
            | Self::StatusDot
            | Self::Seal
            | Self::MetaLine
            | Self::DossierSection
            | Self::ThreadEntry
            | Self::Sheet
            | Self::Slip
            | Self::Receipt
            | Self::Charter
            | Self::Postmark
            | Self::PackLine
            | Self::AnswerSheet
            | Self::TwoClocks
            | Self::NeighborhoodGraph
            | Self::AsofScrubber
            | Self::Throbber
            | Self::VoiceLine
            | Self::QuickFilter
            | Self::InspectorSheet
            | Self::InspectorRail
            | Self::InspectorTrail
            | Self::SelfUi
            | Self::Media => 2,
        }
    }
}

/// A surface's capability profile (ARCH-0048 G3): the catalog it draws and
/// that catalog's semver, the built-in primitives it draws up to a kit
/// stamp, the app components it declares, and its stream profile. The engine
/// lowers each card to it in one pass; a profile nobody negotiated is
/// [`Self::all_atom_kit`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    rename_all = "camelCase",
    deny_unknown_fields,
    try_from = "GeneratedUiSurfaceCapabilitiesWire"
)]
pub struct GeneratedUiSurfaceCapabilities {
    pub catalog: GeneratedUiCatalog,
    /// The semver of the component set this surface declares (FIX 9893). It
    /// defaults to the built-in kit's [`GeneratedUiCatalogVersion::lens_atom_kit`];
    /// an app catalog names its own.
    #[serde(default)]
    pub catalog_version: GeneratedUiCatalogVersion,
    /// The highest built-in kit stamp whose primitives this surface draws.
    #[serde(default = "lens_atom_kit_stamp")]
    pub max_catalog_version: u16,
    #[serde(default)]
    pub primitives: Vec<GeneratedUiPrimitive>,
    /// The components the app catalog declares, with their props schemas
    /// (FIX 9891).
    #[serde(default)]
    pub components: Vec<GeneratedUiComponentSchema>,
    #[serde(default)]
    pub stream: GeneratedUiStreamProfile,
}

const fn lens_atom_kit_stamp() -> u16 {
    LENS_ATOM_KIT_VERSION
}

/// The profile as it arrives: an app catalog must name its semver, the
/// built-in kit's defaults to its own.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GeneratedUiSurfaceCapabilitiesWire {
    catalog: GeneratedUiCatalog,
    #[serde(default)]
    catalog_version: Option<GeneratedUiCatalogVersion>,
    #[serde(default = "lens_atom_kit_stamp")]
    max_catalog_version: u16,
    #[serde(default)]
    primitives: Vec<GeneratedUiPrimitive>,
    #[serde(default)]
    components: Vec<GeneratedUiComponentSchema>,
    #[serde(default)]
    stream: GeneratedUiStreamProfile,
}

impl TryFrom<GeneratedUiSurfaceCapabilitiesWire> for GeneratedUiSurfaceCapabilities {
    type Error = Error;

    fn try_from(wire: GeneratedUiSurfaceCapabilitiesWire) -> Result<Self> {
        Ok(Self {
            catalog_version: catalog_version_or_kit(&wire.catalog, wire.catalog_version)?,
            catalog: wire.catalog,
            max_catalog_version: wire.max_catalog_version,
            primitives: wire.primitives,
            components: wire.components,
            stream: wire.stream,
        })
    }
}

impl GeneratedUiSurfaceCapabilities {
    #[must_use]
    pub fn new(
        catalog: GeneratedUiCatalog,
        max_catalog_version: u16,
        primitives: Vec<GeneratedUiPrimitive>,
    ) -> Self {
        Self {
            catalog,
            catalog_version: GeneratedUiCatalogVersion::lens_atom_kit(),
            max_catalog_version,
            primitives,
            components: Vec::new(),
            stream: GeneratedUiStreamProfile::default(),
        }
    }

    /// A surface drawing an app's declared catalog, beside the built-in
    /// `primitives` it also draws at the current kit stamp.
    #[must_use]
    pub fn for_catalog(
        descriptor: GeneratedUiCatalogDescriptor,
        primitives: Vec<GeneratedUiPrimitive>,
    ) -> Self {
        Self {
            catalog: descriptor.catalog,
            catalog_version: descriptor.catalog_version,
            max_catalog_version: LENS_ATOM_KIT_VERSION,
            primitives,
            components: descriptor.components,
            stream: GeneratedUiStreamProfile::default(),
        }
    }

    #[must_use]
    pub fn all_atom_kit() -> Self {
        Self::new(
            GeneratedUiCatalog::LensAtomKit,
            LENS_ATOM_KIT_VERSION,
            GeneratedUiPrimitive::ALL.to_vec(),
        )
    }

    #[must_use]
    pub fn text_only() -> Self {
        Self::new(
            GeneratedUiCatalog::LensAtomKit,
            LENS_ATOM_KIT_VERSION,
            vec![GeneratedUiPrimitive::TextBlock],
        )
    }

    #[must_use]
    pub fn with_stream(mut self, stream: GeneratedUiStreamProfile) -> Self {
        self.stream = stream;
        self
    }

    /// The descriptor this profile names inline: its catalog, semver and
    /// declared components.
    #[must_use]
    pub fn descriptor(&self) -> GeneratedUiCatalogDescriptor {
        GeneratedUiCatalogDescriptor {
            catalog: self.catalog.clone(),
            catalog_version: self.catalog_version.clone(),
            components: self.components.clone(),
        }
    }

    /// Whether this surface draws a built-in primitive. Text always renders.
    /// An app component is decided by [`Self::supports_atom`].
    #[must_use]
    pub fn supports(&self, primitive: GeneratedUiPrimitive) -> bool {
        primitive == GeneratedUiPrimitive::TextBlock
            || (primitive != GeneratedUiPrimitive::Component
                && self.max_catalog_version >= primitive.minimum_catalog_version()
                && self.primitives.contains(&primitive))
    }

    /// Whether this surface draws `atom` as it is: a built-in primitive it
    /// supports, or a component its own catalog declares whose props meet
    /// the declared schema.
    #[must_use]
    pub fn supports_atom(&self, atom: &LensAtom) -> bool {
        match atom {
            LensAtom::Component(component) => self.supports_component(component),
            other => self.supports(other.primitive()),
        }
    }

    fn supports_component(&self, component: &GeneratedUiComponentAtom) -> bool {
        matches!(&self.catalog, GeneratedUiCatalog::App(name) if name == &component.catalog)
            && self
                .components
                .iter()
                .find(|declared| declared.name == component.name)
                .is_some_and(|declared| declared.admits(&component.props))
    }
}

impl Default for GeneratedUiSurfaceCapabilities {
    fn default() -> Self {
        Self::all_atom_kit()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "name",
    content = "props",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum GeneratedUiPrebuilt {
    SummaryCard(GeneratedUiSummaryCardPrebuilt),
}

impl GeneratedUiPrebuilt {
    pub fn expand(&self) -> Result<LensNode> {
        match self {
            Self::SummaryCard(prebuilt) => prebuilt.expand(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GeneratedUiSummaryCardPrebuilt {
    pub title: LensText,
    pub body: LensText,
    #[serde(default)]
    pub details: Vec<MetaLineAtom>,
}

impl GeneratedUiSummaryCardPrebuilt {
    fn expand(&self) -> Result<LensNode> {
        validate_required_lens_text("generated-ui summary_card title", &self.title)?;
        validate_required_lens_text("generated-ui summary_card body", &self.body)?;

        let mut root = LensNode::with_fallback_text(
            LensAtomId::new("summary-card-root")?,
            LensAtom::Sheet(CollectionAtom {
                title: self.title.clone(),
                rows: Vec::new(),
            }),
            self.title.clone(),
        );
        root.children.push(LensNode::with_fallback_text(
            LensAtomId::new("summary-card-body")?,
            LensAtom::TextBlock(TextBlockAtom {
                spans: vec![LensTextSpan::Literal(self.body.clone())],
            }),
            self.body.clone(),
        ));
        for (index, detail) in self.details.iter().enumerate() {
            root.children.push(LensNode::new(
                LensAtomId::new(format!("summary-card-detail-{index}"))?,
                LensAtom::MetaLine(detail.clone()),
            ));
        }

        validate_lens_tree(&root)?;
        Ok(root)
    }
}
