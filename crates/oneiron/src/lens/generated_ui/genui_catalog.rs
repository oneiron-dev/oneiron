//! Closed primitive catalog, surface capability negotiation, and prebuilt card expansion.

use crate::Result;
use crate::lens::atom::{
    CollectionAtom, LENS_ATOM_KIT_VERSION, LensAtom, LensNode, LensText, LensTextSpan,
    MetaLineAtom, RESULT_SET_ATOM_KIND, TextBlockAtom,
};
use crate::lens::validate::{
    validate_lens_collection_len, validate_lens_tree, validate_required_lens_text,
};
use crate::lens::wire_ids::LensAtomId;
use crate::lens::wire_limits::deserialize_limited_vec;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratedUiCatalog {
    LensAtomKit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
}

impl GeneratedUiPrimitive {
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
        }
    }

    /// The catalog version a surface must negotiate before this primitive may be
    /// rendered. Every pre-v3 primitive is pinned to the literal `2` it shipped at, so
    /// bumping [`LENS_ATOM_KIT_VERSION`] can never raise an existing minimum.
    #[must_use]
    pub const fn minimum_catalog_version(self) -> u16 {
        match self {
            Self::ResultSet => 3,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GeneratedUiSurfaceCapabilities {
    pub catalog: GeneratedUiCatalog,
    pub max_catalog_version: u16,
    #[serde(default, deserialize_with = "deserialize_limited_vec")]
    pub primitives: Vec<GeneratedUiPrimitive>,
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
            max_catalog_version,
            primitives,
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
    pub fn supports(&self, primitive: GeneratedUiPrimitive) -> bool {
        primitive == GeneratedUiPrimitive::TextBlock
            || (self.catalog == GeneratedUiCatalog::LensAtomKit
                && self.max_catalog_version >= primitive.minimum_catalog_version()
                && self.primitives.contains(&primitive))
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
    #[serde(default, deserialize_with = "deserialize_limited_vec")]
    pub details: Vec<MetaLineAtom>,
}

impl GeneratedUiSummaryCardPrebuilt {
    fn expand(&self) -> Result<LensNode> {
        validate_required_lens_text("generated-ui summary_card title", &self.title)?;
        validate_required_lens_text("generated-ui summary_card body", &self.body)?;
        validate_lens_collection_len("generated-ui summary_card details", self.details.len())?;

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
