//! Leaf payload structs with per-atom validate and fallback impls.

use std::collections::HashSet;

use serde::{Deserialize, Deserializer, Serialize, de};

use super::LensText;
use crate::lens::generated_ui::{
    GeneratedUiActionDeclaration, GeneratedUiActionEvent, GeneratedUiActionTier,
};
use crate::lens::self_ui::{SelfUiAction, SelfUiOption};
use crate::lens::validate::{
    validate_required_lens_text, validate_selected_option, validate_self_ui_options,
};
use crate::lens::wire_ids::{
    LensHandleName, LensHandleRef, LensMediaHandle, LensResultSetRowId, SelfUiActionId,
    SelfUiControlId, SelfUiOptionValue,
};
use crate::{Error, Result};

/// One rendered row of a result set. `id` is an opaque echo token the client hands
/// back to name a row; it is never authority, and `label` is display data the host
/// never parses. The reach a row can prove is `target_handle`, which the node itself
/// has to advertise as one of its declared backing handles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GeneratedUiResultSetRow {
    pub id: LensResultSetRowId,
    pub label: LensText,
    pub target_handle: LensHandleName,
}

/// The closed select-all vocabulary. `WithinFilter` names one *host-declared*
/// predicate handle; there is no place to express a query, expression, `where`
/// clause, entity id, or replacement handle, so a client can never widen the
/// filter a select-all resolves against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum GeneratedUiResultSetSelectAll {
    Disabled {},
    WithinFilter { predicate_handle: LensHandleName },
}

/// The selectable result-set atom. `action_bar` is an *eligibility allowlist* of
/// card-declared, `self.ui`-hosted, deterministic-tier action ids: the atom hosts no
/// action of its own, so the landed one-action-per-element and
/// declarations-name-a-self.ui-control gates keep deciding what is interactive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GeneratedUiResultSetAtom {
    pub rows: Vec<GeneratedUiResultSetRow>,
    pub select_all: GeneratedUiResultSetSelectAll,
    #[serde(default)]
    pub action_bar: Vec<SelfUiActionId>,
}

/// Client-authored selection payload. It rides on the `self.ui`-hosted action event
/// and names *which rendered rows were ticked* and nothing else: `AllWithinFilter`
/// carries no fields at all, so the predicate can only come from the rendered atom.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum GeneratedUiResultSetSelection {
    Explicit { row_ids: Vec<LensResultSetRowId> },
    AllWithinFilter {},
}

/// A `self.ui`-hosted action event plus the result-set selection it carries. Selection
/// is not approval: this is still only *what was touched*.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GeneratedUiResultSetActionEvent {
    pub action: GeneratedUiActionEvent,
    pub selection: GeneratedUiResultSetSelection,
}

impl GeneratedUiResultSetAtom {
    pub(super) fn validate(&self) -> Result<()> {
        let mut row_ids = HashSet::with_capacity(self.rows.len());
        for row in &self.rows {
            if !row_ids.insert(row.id.as_str()) {
                return Err(Error::InvalidConfig(
                    "result set rows must not contain duplicate ids".to_string(),
                ));
            }
        }

        let mut action_ids = HashSet::with_capacity(self.action_bar.len());
        for action_id in &self.action_bar {
            if !action_ids.insert(action_id.as_str()) {
                return Err(Error::InvalidConfig(
                    "result set action bar must not contain duplicate action ids".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Atom/action membership only: every allowlisted id has to be one the card's own
    /// manifest declares exactly once at the deterministic-tool tier. Which element
    /// *hosts* that declaration stays the landed interactivity gate's decision, so this
    /// never lets a result set claim an action for itself.
    pub fn validate_against_actions(&self, actions: &[GeneratedUiActionDeclaration]) -> Result<()> {
        self.validate()?;
        for action_id in &self.action_bar {
            let mut declared = actions
                .iter()
                .filter(|declaration| &declaration.action_id == action_id);
            let declaration = declared.next().ok_or_else(|| {
                Error::InvalidConfig(
                    "result set action bar must reference a declared card action".to_string(),
                )
            })?;
            if declared.next().is_some() {
                return Err(Error::InvalidConfig(
                    "generated-ui action ids must be declared exactly once".to_string(),
                ));
            }
            if declaration.tier != GeneratedUiActionTier::DeterministicTool {
                return Err(Error::InvalidConfig(
                    "result set action bar must reference deterministic-tool actions".to_string(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, schemars::JsonSchema)]
pub struct TextBlockAtom {
    pub spans: Vec<LensTextSpan>,
}

impl<'de> Deserialize<'de> for TextBlockAtom {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct TextBlockAtomWire {
            spans: Vec<SpanWire>,
        }

        /// A span as it arrives: a literal of any length, framed below.
        #[derive(Deserialize)]
        #[serde(
            tag = "type",
            content = "value",
            rename_all = "snake_case",
            deny_unknown_fields
        )]
        enum SpanWire {
            Literal(String),
            Interpolation {
                key: LensHandleName,
                fallback: LensText,
            },
        }

        // A literal past one lens text's bound is carried whole as framed
        // spans in order, never refused for its length (FIX 11257).
        let wire = TextBlockAtomWire::deserialize(deserializer)?;
        let spans = wire
            .spans
            .into_iter()
            .flat_map(|span| match span {
                SpanWire::Literal(text) => LensText::frames(&text)
                    .into_iter()
                    .map(LensTextSpan::Literal)
                    .collect::<Vec<_>>(),
                SpanWire::Interpolation { key, fallback } => {
                    vec![LensTextSpan::Interpolation { key, fallback }]
                }
            })
            .collect();
        let atom = Self { spans };
        atom.validate().map_err(de::Error::custom)?;
        Ok(atom)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum LensTextSpan {
    Literal(LensText),
    Interpolation {
        key: LensHandleName,
        fallback: LensText,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MediaAtom {
    pub handle: LensMediaHandle,
    pub alt: LensText,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LedgerRowAtom {
    pub cells: Vec<LedgerCell>,
    #[serde(default)]
    pub status: Option<StatusDotAtom>,
    #[serde(default)]
    pub seal: Option<SealAtom>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LedgerCell {
    pub label: LensText,
    pub value: LensText,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimLineAtom {
    pub subject: LensText,
    pub predicate: LensText,
    pub value: LensText,
    pub status: StatusDotAtom,
    #[serde(default)]
    pub seal: Option<SealAtom>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StatusDotAtom {
    pub status: LensStatus,
    #[serde(default)]
    pub label: Option<LensText>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LensStatus {
    Proposed,
    Auto,
    Approved,
    Rejected,
    Stale,
    Missing,
    Running,
    Complete,
}

impl LensStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Auto => "auto",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Stale => "stale",
            Self::Missing => "missing",
            Self::Running => "running",
            Self::Complete => "complete",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SealAtom {
    pub level: SealLevel,
    pub label: LensText,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SealLevel {
    None,
    Local,
    Actor,
    Authority,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MetaLineAtom {
    pub label: LensText,
    pub value: LensText,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SectionAtom {
    pub title: LensText,
    #[serde(default)]
    pub lines: Vec<LensText>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreadEntryAtom {
    pub author: LensText,
    pub body: LensText,
    #[serde(default)]
    pub timestamp: Option<LensText>,
    #[serde(default)]
    pub seal: Option<SealAtom>,
}

#[derive(Debug, Clone, PartialEq, Serialize, schemars::JsonSchema)]
pub struct CollectionAtom {
    pub title: LensText,
    #[serde(default)]
    pub rows: Vec<LedgerRowAtom>,
}

impl<'de> Deserialize<'de> for CollectionAtom {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct CollectionAtomWire {
            title: LensText,
            #[serde(default)]
            rows: Vec<LedgerRowAtom>,
        }

        let wire = CollectionAtomWire::deserialize(deserializer)?;
        let atom = Self {
            title: wire.title,
            rows: wire.rows,
        };
        atom.validate().map_err(de::Error::custom)?;
        Ok(atom)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReceiptAtom {
    pub title: LensText,
    #[serde(default)]
    pub lines: Vec<MetaLineAtom>,
    #[serde(default)]
    pub seal: Option<SealAtom>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PostmarkAtom {
    pub label: LensText,
    pub timestamp: LensText,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackLineAtom {
    pub pack: LensText,
    pub summary: LensText,
    pub status: LensStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnswerSheetAtom {
    pub question: LensText,
    pub answer: LensText,
    #[serde(default)]
    pub citations: Vec<LensHandleRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TwoClocksAtom {
    pub occurred_at: LensText,
    pub learned_at: LensText,
}

#[derive(Debug, Clone, PartialEq, Serialize, schemars::JsonSchema)]
pub struct NeighborhoodGraphAtom {
    #[serde(default)]
    pub nodes: Vec<GraphNode>,
    #[serde(default)]
    pub edges: Vec<GraphEdge>,
}

impl<'de> Deserialize<'de> for NeighborhoodGraphAtom {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct NeighborhoodGraphAtomWire {
            #[serde(default)]
            nodes: Vec<GraphNode>,
            #[serde(default)]
            edges: Vec<GraphEdge>,
        }

        let wire = NeighborhoodGraphAtomWire::deserialize(deserializer)?;
        let atom = Self {
            nodes: wire.nodes,
            edges: wire.edges,
        };
        atom.validate().map_err(de::Error::custom)?;
        Ok(atom)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphNode {
    pub id: LensHandleName,
    pub label: LensText,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphEdge {
    pub from: LensHandleName,
    pub to: LensHandleName,
    pub label: LensText,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AsofScrubberAtom {
    pub value: LensText,
    #[serde(default)]
    pub min: Option<LensText>,
    #[serde(default)]
    pub max: Option<LensText>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThrobberAtom {
    pub label: LensText,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VoiceLineAtom {
    pub speaker: LensText,
    pub text: LensText,
    #[serde(default)]
    pub vad: Option<VadBadge>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VadBadge {
    Low,
    Neutral,
    High,
}

#[derive(Debug, Clone, PartialEq, Serialize, schemars::JsonSchema)]
pub struct QuickFilterAtom {
    pub id: SelfUiControlId,
    pub label: LensText,
    #[serde(default)]
    pub options: Vec<SelfUiOption>,
    #[serde(default)]
    pub selected: Vec<SelfUiOptionValue>,
    pub action: SelfUiAction,
}

impl<'de> Deserialize<'de> for QuickFilterAtom {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct QuickFilterAtomWire {
            id: SelfUiControlId,
            label: LensText,
            #[serde(default)]
            options: Vec<SelfUiOption>,
            #[serde(default)]
            selected: Vec<SelfUiOptionValue>,
            action: SelfUiAction,
        }

        let wire = QuickFilterAtomWire::deserialize(deserializer)?;
        let atom = Self {
            id: wire.id,
            label: wire.label,
            options: wire.options,
            selected: wire.selected,
            action: wire.action,
        };
        atom.validate().map_err(de::Error::custom)?;
        Ok(atom)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, schemars::JsonSchema)]
pub struct InspectorAtom {
    pub title: LensText,
    #[serde(default)]
    pub sections: Vec<SectionAtom>,
}

impl<'de> Deserialize<'de> for InspectorAtom {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct InspectorAtomWire {
            title: LensText,
            #[serde(default)]
            sections: Vec<SectionAtom>,
        }

        let wire = InspectorAtomWire::deserialize(deserializer)?;
        let atom = Self {
            title: wire.title,
            sections: wire.sections,
        };
        atom.validate().map_err(de::Error::custom)?;
        Ok(atom)
    }
}

impl TextBlockAtom {
    pub(super) fn validate(&self) -> Result<()> {
        if self.spans.is_empty() {
            return Err(Error::InvalidConfig(
                "text block must contain at least one span".to_string(),
            ));
        }
        let mut interpolation_count = 0usize;
        for span in &self.spans {
            if let LensTextSpan::Interpolation { fallback, .. } = span {
                interpolation_count += 1;
                validate_required_lens_text("text block interpolation fallback", fallback)?;
            }
        }
        if interpolation_count > 1 {
            return Err(Error::InvalidConfig(
                "text block must contain at most one escaped interpolation".to_string(),
            ));
        }
        Ok(())
    }

    pub(crate) fn fallback_text(&self) -> String {
        let mut out = String::new();
        for span in &self.spans {
            match span {
                LensTextSpan::Literal(text) => out.push_str(text.as_str()),
                LensTextSpan::Interpolation { fallback, .. } => out.push_str(fallback.as_str()),
            }
        }
        out
    }
}

impl MediaAtom {
    pub(super) fn validate(&self) -> Result<()> {
        validate_required_lens_text("media alt text", &self.alt)
    }
}

impl LedgerRowAtom {
    pub(super) fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl SectionAtom {
    pub(super) fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl CollectionAtom {
    pub(super) fn validate(&self) -> Result<()> {
        for row in &self.rows {
            row.validate()?;
        }
        Ok(())
    }
}

impl ReceiptAtom {
    pub(super) fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl AnswerSheetAtom {
    pub(super) fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl NeighborhoodGraphAtom {
    pub(super) fn validate(&self) -> Result<()> {
        let mut node_ids = HashSet::with_capacity(self.nodes.len());
        for node in &self.nodes {
            if !node_ids.insert(node.id.as_str()) {
                return Err(Error::InvalidConfig(
                    "neighborhood graph nodes must not contain duplicate ids".to_string(),
                ));
            }
        }

        for edge in &self.edges {
            if !node_ids.contains(edge.from.as_str()) || !node_ids.contains(edge.to.as_str()) {
                return Err(Error::InvalidConfig(
                    "neighborhood graph edges must reference declared nodes".to_string(),
                ));
            }
        }

        Ok(())
    }
}

impl QuickFilterAtom {
    pub(super) fn validate(&self) -> Result<()> {
        validate_self_ui_options("quick filter options", &self.options)?;
        let mut selected_values = HashSet::with_capacity(self.selected.len());
        for selected in &self.selected {
            if !selected_values.insert(selected.as_str()) {
                return Err(Error::InvalidConfig(
                    "quick filter selected values must not contain duplicates".to_string(),
                ));
            }
            validate_selected_option("quick filter selected value", &self.options, Some(selected))?;
        }
        self.action.validate()
    }
}

impl InspectorAtom {
    pub(super) fn validate(&self) -> Result<()> {
        for section in &self.sections {
            section.validate()?;
        }
        Ok(())
    }
}
