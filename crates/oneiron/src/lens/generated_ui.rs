//! The Generated-UI protocol: the [`GeneratedLens`] envelope, catalog/primitive
//! negotiation, the engine-authored action manifest, the typed `$state` schema
//! and its patch rules, card lifecycle, and the card/render/segment wire frames.
//!
//! Everything here is data the trusted renderer interprets. Turning a client
//! action event into an approved host write is the job of [`super::mediation`].

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{Error, Result, llm::ContentPart};

use super::atom::{
    CollectionAtom, FiniteF64, GeneratedUiResultSetSelectAll, LENS_ATOM_KIT_VERSION, LensAtom,
    LensNode, LensNodeSeed, LensText, LensTextSpan, MetaLineAtom, RESULT_SET_ATOM_KIND,
    TextBlockAtom,
};
use super::self_ui::{SelfUiAction, SelfUiValue};
use super::validate::{
    LensBudget, compile_atom_for_surface, validate_generated_ui_node_count,
    validate_generated_ui_protocol_version, validate_lens_collection_len, validate_lens_token,
    validate_lens_tree, validate_required_lens_text,
};
use super::wire_ids::{
    LensAtomId, LensHandleName, LensHandleRef, LensHandleRole, LensRenderId, MAX_LENS_TREE_DEPTH,
    SelfUiActionId, SelfUiOptionValue, SelfUiStateKey,
};
use super::wire_limits::{deserialize_limited_vec, serialize_tagged};

pub const GENERATED_UI_WIRE_VERSION: u16 = 2;
pub const GENERATED_UI_SEGMENT_CONTENT_TYPE: &str =
    "application/vnd.oneiron.generated-ui.segment+json";

/// The oldest atom-kit version an envelope may declare. There is no valid v1 envelope:
/// v1 predates the mandatory per-node `fallbackText`, so it is rejected by version
/// rather than sharing v2 semantics.
const MIN_LENS_ATOM_KIT_VERSION: u16 = 2;

/// The highest minimum catalog version any atom in this tree needs. A tree that uses
/// only pre-v3 atoms answers `2` however far [`LENS_ATOM_KIT_VERSION`] has moved on.
fn contained_atom_kit_version(root: &LensNode) -> u16 {
    let mut minimum = MIN_LENS_ATOM_KIT_VERSION;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        minimum = minimum.max(node.atom.primitive().minimum_catalog_version());
        stack.extend(node.children.iter());
    }
    minimum
}

/// The apps-contract revision a lens body was generated against. It answers "was this
/// body compiled for the shell contracts this build ships?", which is a different
/// question from [`LENS_ATOM_KIT_VERSION`]'s "which atoms may this tree contain?".
/// The first stamped revision is `1`; it moves independently of the atom-kit constant.
pub const LENS_APPS_CONTRACT_VERSION: u16 = 1;

/// The version pair carried in a lens body. Both components are body data, so a decoded
/// revision can be compared against the running constants without re-parsing anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LensVersionStamp {
    kit_version: u16,
    apps_contract_version: u16,
}

impl LensVersionStamp {
    #[must_use]
    pub const fn new(kit_version: u16, apps_contract_version: u16) -> Self {
        Self {
            kit_version,
            apps_contract_version,
        }
    }

    /// The pair a freshly regenerated body must carry. Regeneration always targets this
    /// pair; a stale body is never auto-stamped with it.
    #[must_use]
    pub const fn current() -> Self {
        Self::new(LENS_ATOM_KIT_VERSION, LENS_APPS_CONTRACT_VERSION)
    }

    #[must_use]
    pub const fn kit_version(self) -> u16 {
        self.kit_version
    }

    #[must_use]
    pub const fn apps_contract_version(self) -> u16 {
        self.apps_contract_version
    }
}

/// What a shell loader must do with a decoded lens body. This names caller work rather
/// than performing it: there is no queue trait, storage import, or mount mutation here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LensLoadAction {
    MountCurrent,
    MountLastGoodAndQueueRegeneration {
        stored: LensVersionStamp,
        live: LensVersionStamp,
    },
}

/// Exact pair equality means current. "Differs" is symmetric: a stamp older *or* newer
/// than the running constants both mount the decoded body as last-good and queue
/// regeneration against the live pair.
#[must_use]
pub const fn lens_load_action(stored: LensVersionStamp, live: LensVersionStamp) -> LensLoadAction {
    if stored.kit_version == live.kit_version
        && stored.apps_contract_version == live.apps_contract_version
    {
        LensLoadAction::MountCurrent
    } else {
        LensLoadAction::MountLastGoodAndQueueRegeneration { stored, live }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GeneratedLens {
    kit_version: u16,
    apps_contract_version: u16,
    root: LensNode,
}

impl GeneratedLens {
    /// Stamp the live pair, [`LensVersionStamp::current`]: a body built here was by
    /// construction compiled against the atom kit and the shell contracts this build
    /// ships, so it is exactly what [`lens_load_action`] calls current and what
    /// [`regenerate_lens`] accepts as a candidate for the requested target.
    ///
    /// Neither component is derived from the tree. The contained-atom minimum is a
    /// *floor* an envelope may not under-declare (see the tree validator below), never
    /// the stamp: stamping it would mint bodies that are born stale against the running
    /// constants, so every freshly built pre-v3 card would report
    /// [`LensLoadAction::MountLastGoodAndQueueRegeneration`] and a regenerator using
    /// this constructor could never match its own target. The accepted consequence is
    /// that a v2-only surface re-negotiates after a kit bump like any other body.
    ///
    /// The apps-contract component records the shell contracts this body was generated
    /// against, so it is likewise always the running [`LENS_APPS_CONTRACT_VERSION`].
    pub fn new(root: LensNode) -> Result<Self> {
        let current = LensVersionStamp::current();
        let lens = Self {
            kit_version: current.kit_version(),
            apps_contract_version: current.apps_contract_version(),
            root,
        };
        lens.validate()?;
        Ok(lens)
    }

    #[must_use]
    pub const fn kit_version(&self) -> u16 {
        self.kit_version
    }

    #[must_use]
    pub const fn apps_contract_version(&self) -> u16 {
        self.apps_contract_version
    }

    #[must_use]
    pub const fn version_stamp(&self) -> LensVersionStamp {
        LensVersionStamp::new(self.kit_version, self.apps_contract_version)
    }

    #[must_use]
    pub fn root(&self) -> &LensNode {
        &self.root
    }

    #[must_use]
    pub fn into_root(self) -> LensNode {
        self.root
    }

    fn validate(&self) -> Result<()> {
        validate_lens_tree(&self.root)?;
        // Version negotiation is decided after decode, against the atoms actually
        // present: an envelope may not under-declare its way past a surface check.
        let required = contained_atom_kit_version(&self.root);
        if self.kit_version < required {
            return Err(Error::InvalidConfig(format!(
                "generated lens atom kit version {} must be at least {required} for its atoms",
                self.kit_version
            )));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for GeneratedLens {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            KitVersion,
            AppsContractVersion,
            Root,
        }

        struct GeneratedLensVisitor;

        impl<'de> de::Visitor<'de> for GeneratedLensVisitor {
            type Value = GeneratedLens;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("generated lens envelope")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut kit_version = None;
                let mut apps_contract_version = None;
                let mut root = None;
                let mut skipped_root_before_versions = false;

                while let Some(field) = map.next_key::<Field>()? {
                    match field {
                        Field::KitVersion => {
                            if kit_version.is_some() {
                                return Err(de::Error::duplicate_field("kit_version"));
                            }
                            // Deliberately no window check: a stamp older or newer than
                            // the running constants is stale *state*, not a decode
                            // error, so a decodable last-good body still loads while
                            // regeneration is queued. `lens_load_action` owns that
                            // decision; unknown atom kinds and invalid payloads still
                            // fail closed below through the closed-enum tree validator.
                            kit_version = Some(map.next_value::<u16>()?);
                        }
                        Field::AppsContractVersion => {
                            if apps_contract_version.is_some() {
                                return Err(de::Error::duplicate_field("apps_contract_version"));
                            }
                            apps_contract_version = Some(map.next_value::<u16>()?);
                        }
                        Field::Root => {
                            if root.is_some() || skipped_root_before_versions {
                                return Err(de::Error::duplicate_field("root"));
                            }
                            // Either stamp field may come first, but both must precede
                            // the tree: skipping the body preserves the shipped
                            // allocation guard against an unversioned oversized root.
                            if kit_version.is_none() || apps_contract_version.is_none() {
                                map.next_value::<de::IgnoredAny>()?;
                                skipped_root_before_versions = true;
                            } else {
                                root = Some(map.next_value::<LensNode>()?);
                            }
                        }
                    }
                }

                // Fixed post-map order: missing kit_version, then missing
                // apps_contract_version, then precedence, then a missing root.
                let kit_version =
                    kit_version.ok_or_else(|| de::Error::missing_field("kit_version"))?;
                let apps_contract_version = apps_contract_version
                    .ok_or_else(|| de::Error::missing_field("apps_contract_version"))?;
                if skipped_root_before_versions {
                    return Err(de::Error::custom(
                        "generated lens version fields must precede root",
                    ));
                }
                let root = root.ok_or_else(|| de::Error::missing_field("root"))?;
                let lens = GeneratedLens {
                    kit_version,
                    apps_contract_version,
                    root,
                };
                lens.validate().map_err(de::Error::custom)?;
                Ok(lens)
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                // Positional form: 0 = kit_version, 1 = apps_contract_version, 2 = root.
                // The pair is not compared to the live constants here either.
                let kit_version = seq
                    .next_element::<u16>()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let apps_contract_version = seq
                    .next_element::<u16>()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let root = seq
                    .next_element_seed(LensNodeSeed { depth: 1 })?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;
                if seq.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::invalid_length(4, &self));
                }

                let lens = GeneratedLens {
                    kit_version,
                    apps_contract_version,
                    root,
                };
                lens.validate().map_err(de::Error::custom)?;
                Ok(lens)
            }
        }

        deserializer.deserialize_struct(
            "GeneratedLens",
            &["kit_version", "apps_contract_version", "root"],
            GeneratedLensVisitor,
        )
    }
}

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

/// JSON-Pointer prefix that addresses the flattened `$state` snapshot. State keys
/// are lens tokens (ASCII alnum, `.`, `_`, `-`), so no pointer escaping is possible
/// and a `/values/` wrapper segment can never appear.
const GENERATED_UI_STATE_POINTER_PREFIX: &str = "/$state/";

/// Ruled interaction tiers (ONEIRON-ARCH-0048 G2). Deterministic and model tiers
/// yield triggers only; execution stays behind the host-stamped write chokepoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratedUiActionTier {
    Local,
    DeterministicTool,
    ModelRoundTrip,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GeneratedUiActionDeclaration {
    pub element_id: LensAtomId,
    pub action_id: SelfUiActionId,
    pub tier: GeneratedUiActionTier,
    pub action: SelfUiAction,
}

impl GeneratedUiActionDeclaration {
    fn validate(&self) -> Result<()> {
        self.action.validate()?;
        if self.tier == GeneratedUiActionTier::Local
            && self
                .action
                .args
                .iter()
                .any(|arg| matches!(arg, SelfUiValue::Handle(_)))
        {
            return Err(Error::InvalidConfig(
                "generated-ui local actions must not declare host handle arguments".to_string(),
            ));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for GeneratedUiActionDeclaration {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct GeneratedUiActionDeclarationWire {
            element_id: LensAtomId,
            action_id: SelfUiActionId,
            tier: GeneratedUiActionTier,
            action: SelfUiAction,
        }

        let wire = GeneratedUiActionDeclarationWire::deserialize(deserializer)?;
        let declaration = Self {
            element_id: wire.element_id,
            action_id: wire.action_id,
            tier: wire.tier,
            action: wire.action,
        };
        declaration.validate().map_err(de::Error::custom)?;
        Ok(declaration)
    }
}

/// Client-authored interaction event. It names *what was touched* and nothing else:
/// no command, actor, source, approval, or authority field exists on the wire.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GeneratedUiActionEvent {
    pub card_id: LensRenderId,
    pub element_id: LensAtomId,
    pub action_id: SelfUiActionId,
    #[serde(default, deserialize_with = "deserialize_limited_vec")]
    pub patch: Vec<GeneratedUiStatePatch>,
    pub occurred_at: u64,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum SelfUiStateValue {
    Bool(bool),
    Number(FiniteF64),
    Text(LensText),
    Token(SelfUiOptionValue),
}

impl SelfUiStateValue {
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Bool(_) => "bool",
            Self::Number(_) => "number",
            Self::Text(_) => "text",
            Self::Token(_) => "token",
        }
    }

    fn has_same_type(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl Serialize for SelfUiStateValue {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Bool(value) => serialize_tagged(serializer, "type", "bool", "value", value),
            Self::Number(value) => serialize_tagged(serializer, "type", "number", "value", value),
            Self::Text(value) => serialize_tagged(serializer, "type", "text", "value", value),
            Self::Token(value) => serialize_tagged(serializer, "type", "token", "value", value),
        }
    }
}

/// The closed set of control properties a `$bind` descriptor may drive. There is no
/// expression language: a binding names one state key and one property, nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfUiBindableProperty {
    Checked,
    Selected,
    Value,
    Text,
}

impl SelfUiBindableProperty {
    fn accepts(self, value: &SelfUiStateValue) -> bool {
        match self {
            Self::Checked => matches!(value, SelfUiStateValue::Bool(_)),
            Self::Selected => matches!(value, SelfUiStateValue::Token(_)),
            Self::Text => matches!(value, SelfUiStateValue::Text(_)),
            Self::Value => matches!(
                value,
                SelfUiStateValue::Number(_) | SelfUiStateValue::Text(_)
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SelfUiBinding {
    pub state_key: SelfUiStateKey,
    pub property: SelfUiBindableProperty,
}

/// Typed `$state` snapshot. The wire shape is the map itself — `{"$state":{"<key>":…}}`
/// — so `/$state/<key>` addresses an entry with no `values` wrapper segment.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct GeneratedUiStateSnapshot {
    values: BTreeMap<SelfUiStateKey, SelfUiStateValue>,
}

impl GeneratedUiStateSnapshot {
    #[must_use]
    pub fn values(&self) -> &BTreeMap<SelfUiStateKey, SelfUiStateValue> {
        &self.values
    }

    #[must_use]
    pub fn get(&self, key: &SelfUiStateKey) -> Option<&SelfUiStateValue> {
        self.values.get(key)
    }
}

impl FromIterator<(SelfUiStateKey, SelfUiStateValue)> for GeneratedUiStateSnapshot {
    fn from_iter<I: IntoIterator<Item = (SelfUiStateKey, SelfUiStateValue)>>(iter: I) -> Self {
        Self {
            values: iter.into_iter().collect(),
        }
    }
}

impl Serialize for GeneratedUiStateSnapshot {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.values.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for GeneratedUiStateSnapshot {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = BTreeMap::<SelfUiStateKey, SelfUiStateValue>::deserialize(deserializer)?;
        validate_lens_collection_len("generated-ui $state entries", values.len())
            .map_err(de::Error::custom)?;
        Ok(Self { values })
    }
}

/// JSON-Pointer patch over `/$state/`. Paths are exact and never healed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum GeneratedUiStatePatch {
    Add {
        path: String,
        value: SelfUiStateValue,
    },
    Replace {
        path: String,
        value: SelfUiStateValue,
    },
    Remove {
        path: String,
    },
}

impl GeneratedUiStatePatch {
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Self::Add { path, .. } | Self::Replace { path, .. } | Self::Remove { path } => path,
        }
    }
}

/// Canonical card lifecycle. `completed`/`expired` are archive *reasons*, not phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratedUiCardPhase {
    Generating,
    Active,
    Responded,
    Archived,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratedUiArchiveReason {
    Completed,
    Expired,
    Dismissed,
    Superseded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GeneratedUiCardLifecycle {
    pub phase: GeneratedUiCardPhase,
    pub revision: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_reason: Option<GeneratedUiArchiveReason>,
}

impl GeneratedUiCardLifecycle {
    /// The phase a completed tree emits in `card_state_update`.
    #[must_use]
    pub fn initial() -> Self {
        Self {
            phase: GeneratedUiCardPhase::Active,
            revision: 0,
            archive_reason: None,
        }
    }

    pub fn new(
        phase: GeneratedUiCardPhase,
        revision: u64,
        archive_reason: Option<GeneratedUiArchiveReason>,
    ) -> Result<Self> {
        let lifecycle = Self {
            phase,
            revision,
            archive_reason,
        };
        lifecycle.validate()?;
        Ok(lifecycle)
    }

    /// Advance the lifecycle. Phases are totally ordered, so this admits exactly the
    /// forward edges of `generating → active → responded → archived`, rejects
    /// backwards and self transitions, and makes `archived` terminal.
    pub fn transition(
        &self,
        next: GeneratedUiCardPhase,
        archive_reason: Option<GeneratedUiArchiveReason>,
    ) -> Result<Self> {
        if next <= self.phase {
            return Err(Error::InvalidConfig(format!(
                "generated-ui card lifecycle must advance: {:?} cannot become {next:?}",
                self.phase
            )));
        }
        let revision = self.revision.checked_add(1).ok_or_else(|| {
            Error::InvalidConfig("generated-ui card lifecycle revision overflowed".to_string())
        })?;
        Self::new(next, revision, archive_reason)
    }

    fn validate(&self) -> Result<()> {
        match (self.phase, self.archive_reason) {
            (GeneratedUiCardPhase::Archived, None) => Err(Error::InvalidConfig(
                "generated-ui archived cards must carry an archive reason".to_string(),
            )),
            (phase, Some(_)) if phase != GeneratedUiCardPhase::Archived => {
                Err(Error::InvalidConfig(
                    "generated-ui archive reasons are only valid on archived cards".to_string(),
                ))
            }
            _ => Ok(()),
        }
    }
}

impl<'de> Deserialize<'de> for GeneratedUiCardLifecycle {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct GeneratedUiCardLifecycleWire {
            phase: GeneratedUiCardPhase,
            revision: u64,
            #[serde(default)]
            archive_reason: Option<GeneratedUiArchiveReason>,
        }

        let wire = GeneratedUiCardLifecycleWire::deserialize(deserializer)?;
        Self::new(wire.phase, wire.revision, wire.archive_reason).map_err(de::Error::custom)
    }
}

/// One addressable element of a card, in either the authored tree or the lowered
/// flat render. Interactivity validation is shape-agnostic across the two.
pub(super) struct LensElementRef<'a> {
    id: &'a LensAtomId,
    atom: &'a LensAtom,
    state_bindings: &'a [SelfUiBinding],
}

impl<'a> LensElementRef<'a> {
    fn collect_tree(root: &'a LensNode) -> Vec<Self> {
        let mut elements = Vec::new();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            elements.push(Self {
                id: &node.id,
                atom: &node.atom,
                state_bindings: &node.state_bindings,
            });
            stack.extend(node.children.iter());
        }
        elements
    }

    pub(super) fn collect_flat(nodes: &'a [GeneratedUiNode]) -> Vec<Self> {
        nodes
            .iter()
            .map(|node| Self {
                id: &node.id,
                atom: &node.atom,
                state_bindings: &node.state_bindings,
            })
            .collect()
    }
}

/// The single interactivity gate: every card, render, and reconstructed segment stream
/// proves its manifest and `$bind` descriptors against its own elements and `$state`.
fn validate_generated_ui_interactivity(
    elements: &[LensElementRef<'_>],
    actions: &[GeneratedUiActionDeclaration],
    state: &GeneratedUiStateSnapshot,
) -> Result<()> {
    validate_lens_collection_len("generated-ui action declarations", actions.len())?;

    let by_id = elements
        .iter()
        .map(|element| (element.id.as_str(), element))
        .collect::<HashMap<_, _>>();

    let mut declared_actions = HashSet::with_capacity(actions.len());
    let mut declared_elements = HashSet::with_capacity(actions.len());
    for declaration in actions {
        declaration.validate()?;
        if !declared_actions.insert(declaration.action_id.as_str()) {
            return Err(Error::InvalidConfig(
                "generated-ui action ids must be declared exactly once".to_string(),
            ));
        }
        if !declared_elements.insert(declaration.element_id.as_str()) {
            return Err(Error::InvalidConfig(
                "generated-ui elements must declare at most one action".to_string(),
            ));
        }
        let element = by_id.get(declaration.element_id.as_str()).ok_or_else(|| {
            Error::InvalidConfig(
                "generated-ui action declarations must reference a declared element".to_string(),
            )
        })?;
        let LensAtom::SelfUi(control) = element.atom else {
            return Err(Error::InvalidConfig(
                "generated-ui action declarations must reference a self.ui control".to_string(),
            ));
        };
        if control.action() != &declaration.action {
            return Err(Error::InvalidConfig(
                "generated-ui element action must match its manifest declaration".to_string(),
            ));
        }
    }

    // A result set declares no action of its own; its action bar is an eligibility
    // allowlist over the manifest above. Membership is proved here so an undeclared,
    // local, or model-round-trip id can never reach a rendered action bar, and so one
    // id cannot be allowlisted by two different result sets in the same card.
    let mut allowlisted = HashSet::new();
    for element in elements {
        let Some(result_set) = element.atom.result_set_payload() else {
            continue;
        };
        result_set.validate_against_actions(actions)?;
        for action_id in &result_set.action_bar {
            if !allowlisted.insert(action_id.as_str()) {
                return Err(Error::InvalidConfig(
                    "generated-ui result set action ids must be allowlisted by at most one atom"
                        .to_string(),
                ));
            }
        }
    }

    validate_generated_ui_state_bindings(elements, state)
}

/// Prove every `$bind` descriptor against a `$state` snapshot. This runs at card
/// assembly *and* after every accepted patch, so the domain a control declares for
/// itself is the same domain a client patch has to land inside.
pub(super) fn validate_generated_ui_state_bindings(
    elements: &[LensElementRef<'_>],
    state: &GeneratedUiStateSnapshot,
) -> Result<()> {
    for element in elements {
        validate_lens_collection_len(
            "generated-ui $bind descriptors",
            element.state_bindings.len(),
        )?;
        if element.state_bindings.is_empty() {
            continue;
        }
        let LensAtom::SelfUi(control) = element.atom else {
            return Err(Error::InvalidConfig(
                "generated-ui $bind descriptors are only valid on self.ui controls".to_string(),
            ));
        };
        let mut bound_properties = HashSet::with_capacity(element.state_bindings.len());
        for binding in element.state_bindings {
            if !bound_properties.insert(binding.property) {
                return Err(Error::InvalidConfig(
                    "generated-ui $bind must bind each control property at most once".to_string(),
                ));
            }
            let value = state.get(&binding.state_key).ok_or_else(|| {
                Error::InvalidConfig(
                    "generated-ui $bind must reference a declared $state key".to_string(),
                )
            })?;
            if !binding.property.accepts(value) {
                return Err(Error::InvalidConfig(format!(
                    "generated-ui $bind property {:?} does not accept a {} value",
                    binding.property,
                    value.type_name()
                )));
            }
            control.accepts_bound_value(binding.property, value)?;
        }
    }

    Ok(())
}

/// Resolve `/$state/<key>` to its key. Exact match only — no healing, no nesting, and
/// no `/values/` segment can survive because state keys are lens tokens.
fn generated_ui_state_patch_key(path: &str) -> Result<SelfUiStateKey> {
    let key = path
        .strip_prefix(GENERATED_UI_STATE_POINTER_PREFIX)
        .ok_or_else(|| {
            Error::InvalidConfig(format!(
                "generated-ui state patch path must be an exact {GENERATED_UI_STATE_POINTER_PREFIX}<key> pointer"
            ))
        })?;
    SelfUiStateKey::new(key)
}

/// Apply a client patch to the current snapshot under the card's declared schema.
/// The declared snapshot is the closed key space *and* the type schema: undeclared
/// keys and type changes are rejected before any trigger is returned.
pub(super) fn apply_generated_ui_state_patch(
    schema: &GeneratedUiStateSnapshot,
    current: &GeneratedUiStateSnapshot,
    patch: &[GeneratedUiStatePatch],
) -> Result<GeneratedUiStateSnapshot> {
    validate_lens_collection_len("generated-ui state patch", patch.len())?;

    for (key, value) in current.values() {
        let declared = schema.get(key).ok_or_else(|| {
            Error::InvalidConfig(
                "generated-ui card state must not contain undeclared $state keys".to_string(),
            )
        })?;
        if !declared.has_same_type(value) {
            return Err(Error::InvalidConfig(
                "generated-ui card state must not change a declared $state type".to_string(),
            ));
        }
    }

    let mut next = current.clone();
    for op in patch {
        let key = generated_ui_state_patch_key(op.path())?;
        let declared = schema.get(&key).ok_or_else(|| {
            Error::InvalidConfig(
                "generated-ui state patch must address a declared $state key".to_string(),
            )
        })?;
        if !matches!(op, GeneratedUiStatePatch::Add { .. }) && !next.values.contains_key(&key) {
            return Err(Error::InvalidConfig(
                "generated-ui state patch must address a present $state key".to_string(),
            ));
        }
        match op {
            GeneratedUiStatePatch::Add { value, .. }
            | GeneratedUiStatePatch::Replace { value, .. } => {
                if !declared.has_same_type(value) {
                    return Err(Error::InvalidConfig(format!(
                        "generated-ui state patch must not change {} to {}",
                        declared.type_name(),
                        value.type_name()
                    )));
                }
                next.values.insert(key, value.clone());
            }
            GeneratedUiStatePatch::Remove { .. } => {
                next.values.remove(&key);
            }
        }
    }

    Ok(next)
}

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

    pub(super) fn validate(&self) -> Result<()> {
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
    pub(super) fn validate(&self) -> Result<()> {
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
    pub(super) fn validate(&self) -> Result<()> {
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

// ── Regen-on-update: behavior fingerprint, structured diff, adoption decision ──
//
// Everything below is a pure decision path over *rendered* lens bodies. It performs no
// store write, gate call, approval mutation, queue write, mount mutation, or model
// routing, and it never accepts prompt text, generated source, source bytes, or any
// hash of them. Only validated golden renders cross into the comparison.

/// The rendered behavior of one golden corpus, keyed by fixture id.
///
/// Fixture boundaries are part of the comparison domain: the corpus is never flattened
/// into one set, so a handle or atom moving between cases stays visible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LensBehaviorFingerprint {
    cases: BTreeMap<String, LensFixtureBehavior>,
}

/// The four semantic dimensions compared per fixture.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LensFixtureBehavior {
    atom_tree: Vec<LensAtomTreeEntry>,
    bound_handles: BTreeSet<LensHandleBinding>,
    /// The subset of declared reach a result-set atom actually *points at*: every row
    /// `target_handle` and every select-all `predicate_handle`, resolved to the
    /// `(name, role)` pair its own node declared. This is not a second declared set —
    /// each pair here is by construction already in `bound_handles` — it is which of
    /// those declarations the host is really told to read.
    referenced_handles: BTreeSet<LensHandleBinding>,
    atom_inventory: BTreeMap<GeneratedUiPrimitive, u32>,
}

/// One ordered pre-order tree position. Primitive plus position plus child count encodes
/// the atom-kind shape without node ids or any text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct LensAtomTreeEntry {
    primitive: GeneratedUiPrimitive,
    child_count: usize,
}

/// The bound-read identity: the full `(name, role)` pair. Name equality alone is not
/// authority, and duplicate occurrences of an identical pair deduplicate in the set.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct LensHandleBinding {
    name: LensHandleName,
    role: LensHandleRole,
}

impl LensBehaviorFingerprint {
    /// Build behavior from already-rendered, validated golden-corpus outputs.
    ///
    /// The diff path accepts [`GeneratedLens`] values, not source text:
    ///
    /// ```compile_fail
    /// use oneiron::lens::LensBehaviorFingerprint;
    /// let _ = LensBehaviorFingerprint::from_golden_renders([
    ///     ("fixture", "generated lens source text"),
    /// ]);
    /// ```
    ///
    /// ```
    /// use oneiron::lens::{GeneratedLens, LensBehaviorFingerprint};
    ///
    /// fn fingerprint(rendered: &GeneratedLens) {
    ///     let _ = LensBehaviorFingerprint::from_golden_renders([
    ///         ("fixture", rendered),
    ///     ]);
    /// }
    ///
    /// let _ = fingerprint as fn(&GeneratedLens);
    /// ```
    pub fn from_golden_renders<'a>(
        renders: impl IntoIterator<Item = (&'a str, &'a GeneratedLens)>,
    ) -> Result<Self> {
        let mut cases = BTreeMap::new();
        for (fixture_id, rendered) in renders {
            validate_lens_token("lens golden fixture id", fixture_id)?;
            let behavior = fingerprint_render(rendered)?;
            if cases.insert(fixture_id.to_owned(), behavior).is_some() {
                return Err(Error::InvalidConfig(format!(
                    "lens golden corpus contains duplicate fixture id {fixture_id}"
                )));
            }
        }
        if cases.is_empty() {
            return Err(Error::InvalidConfig(
                "lens golden corpus must contain at least one fixture".to_string(),
            ));
        }
        Ok(Self { cases })
    }

    #[must_use]
    pub fn fixture_ids(&self) -> impl ExactSizeIterator<Item = &str> {
        self.cases.keys().map(String::as_str)
    }

    #[must_use]
    pub fn fixture_count(&self) -> usize {
        self.cases.len()
    }
}

/// Reduce one validated render to its four behavior dimensions.
///
/// Node ids, fallback text, literal/interpolated text values, labels, layout payloads,
/// and any source or prompt material are deliberately not inputs.
fn fingerprint_render(rendered: &GeneratedLens) -> Result<LensFixtureBehavior> {
    let mut atom_tree = Vec::new();
    let mut bound_handles = BTreeSet::new();
    let mut referenced_handles = BTreeSet::new();
    let mut atom_inventory: BTreeMap<GeneratedUiPrimitive, u32> = BTreeMap::new();
    let mut stack = vec![rendered.root()];

    while let Some(node) = stack.pop() {
        // The closed atom vocabulary is read through `LensAtom::primitive()`, never a
        // mirrored kind list, so any future atom participates automatically.
        let primitive = node.atom.primitive();
        atom_tree.push(LensAtomTreeEntry {
            primitive,
            child_count: node.children.len(),
        });
        let count = atom_inventory.entry(primitive).or_insert(0_u32);
        *count = count
            .checked_add(1)
            .ok_or_else(|| Error::InvalidConfig("lens atom inventory overflowed".to_string()))?;

        // `node.bindings` and `AnswerSheetAtom::citations` are the only
        // `(LensHandleName, LensHandleRole)` surfaces in a generated lens tree.
        // `node.state_bindings` (the `$bind` descriptors) are excluded on purpose: a
        // `$bind` names one `$state` key and one control property and carries no
        // `LensHandleRole`, so it belongs to the same role-less class as interpolation
        // keys, graph node/edge ids, backing refs, `SelfUiValue::Handle`, and media
        // handles. Promoting any of them here would contradict the fixed
        // `(name, role)` bound-read boundary.
        for binding in &node.bindings {
            bound_handles.insert(LensHandleBinding {
                name: binding.name.clone(),
                role: binding.role,
            });
        }
        if let LensAtom::AnswerSheet(answer) = &node.atom {
            for binding in &answer.citations {
                bound_handles.insert(LensHandleBinding {
                    name: binding.name.clone(),
                    role: binding.role,
                });
            }
        }

        // A result set's row `target_handle` and its select-all `predicate_handle` are
        // *references*, not declarations: each one has to name reach this same node
        // already advertised, and `super::mediation::select_atom` copies the host
        // backing row for exactly that handle. So swapping a row from one declared
        // handle to another leaves the declared set above byte-identical while moving
        // which host rows the selection actually reads — a data-read change the
        // `bound_handles` dimension alone cannot see.
        if let LensAtom::ResultSet(result_set) = &node.atom {
            for row in &result_set.rows {
                referenced_handles.insert(referenced_binding(node, &row.target_handle)?);
            }
            if let GeneratedUiResultSetSelectAll::WithinFilter { predicate_handle } =
                &result_set.select_all
            {
                referenced_handles.insert(referenced_binding(node, predicate_handle)?);
            }
        }

        // Reversed push keeps the pop order equal to the source child order.
        stack.extend(node.children.iter().rev());
    }

    Ok(LensFixtureBehavior {
        atom_tree,
        bound_handles,
        referenced_handles,
        atom_inventory,
    })
}

/// Resolve one result-set handle reference against the declaring node's own bindings.
///
/// The tree validator already proved every such reference names a handle this node
/// declares exactly once, so a missing or duplicated declaration is a broken invariant.
/// It fails the fingerprint rather than resolving to nothing: a reference silently
/// dropped here would read as "no reference changed" and could auto-adopt.
fn referenced_binding(node: &LensNode, handle: &LensHandleName) -> Result<LensHandleBinding> {
    let mut declared = node
        .bindings
        .iter()
        .filter(|binding| &binding.name == handle);
    let binding = declared.next().ok_or_else(|| {
        Error::InvalidConfig(
            "lens result set handle must be declared by the node that references it".to_string(),
        )
    })?;
    if declared.next().is_some() {
        return Err(Error::InvalidConfig(
            "lens result set handle must be declared exactly once by its own node".to_string(),
        ));
    }
    Ok(LensHandleBinding {
        name: binding.name.clone(),
        role: binding.role,
    })
}

/// One `(fixture, name, role)` data read that was added or removed — either a
/// declared binding or the reach a result-set reference resolves to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LensBehaviorHandle {
    fixture_id: String,
    name: LensHandleName,
    role: LensHandleRole,
}

impl LensBehaviorHandle {
    #[must_use]
    pub fn fixture_id(&self) -> &str {
        &self.fixture_id
    }

    #[must_use]
    pub const fn name(&self) -> &LensHandleName {
        &self.name
    }

    #[must_use]
    pub const fn role(&self) -> LensHandleRole {
        self.role
    }
}

/// A handle name whose role set changed. The old and new pairs are also present in
/// `removed_handles`/`added_handles`; this is the direct before/after evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LensHandleRoleChange {
    fixture_id: String,
    name: LensHandleName,
    before: BTreeSet<LensHandleRole>,
    after: BTreeSet<LensHandleRole>,
}

impl LensHandleRoleChange {
    #[must_use]
    pub fn fixture_id(&self) -> &str {
        &self.fixture_id
    }

    #[must_use]
    pub const fn name(&self) -> &LensHandleName {
        &self.name
    }

    #[must_use]
    pub const fn before(&self) -> &BTreeSet<LensHandleRole> {
        &self.before
    }

    #[must_use]
    pub const fn after(&self) -> &BTreeSet<LensHandleRole> {
        &self.after
    }
}

/// An atom-kind count that changed in one fixture. Equal counts never produce an entry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LensAtomInventoryChange {
    fixture_id: String,
    primitive: GeneratedUiPrimitive,
    before: u32,
    after: u32,
}

impl LensAtomInventoryChange {
    #[must_use]
    pub fn fixture_id(&self) -> &str {
        &self.fixture_id
    }

    #[must_use]
    pub const fn primitive(&self) -> GeneratedUiPrimitive {
        self.primitive
    }

    #[must_use]
    pub const fn before(&self) -> u32 {
        self.before
    }

    #[must_use]
    pub const fn after(&self) -> u32 {
        self.after
    }
}

/// The full behavior delta between two corpus fingerprints.
///
/// All four dimensions are reported, but only handle changes — declared *or*
/// referenced — drive the adoption lane: structure and inventory are evidence, not
/// approval authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LensBehaviorDiff {
    structural_cases: BTreeSet<String>,
    added_handles: BTreeSet<LensBehaviorHandle>,
    removed_handles: BTreeSet<LensBehaviorHandle>,
    added_referenced_handles: BTreeSet<LensBehaviorHandle>,
    removed_referenced_handles: BTreeSet<LensBehaviorHandle>,
    role_changes: Vec<LensHandleRoleChange>,
    inventory_changes: BTreeSet<LensAtomInventoryChange>,
}

impl LensBehaviorDiff {
    /// Compare two corpus fingerprints.
    ///
    /// The fixture-id sets must be equal; a missing render is never treated as empty
    /// behavior and the two sides are never intersected or position-matched.
    pub fn between(
        before: &LensBehaviorFingerprint,
        after: &LensBehaviorFingerprint,
    ) -> Result<Self> {
        if !before.cases.keys().eq(after.cases.keys()) {
            return Err(Error::InvalidConfig(
                "lens behavior fingerprints cover different golden fixtures".to_string(),
            ));
        }

        let mut diff = Self {
            structural_cases: BTreeSet::new(),
            added_handles: BTreeSet::new(),
            removed_handles: BTreeSet::new(),
            added_referenced_handles: BTreeSet::new(),
            removed_referenced_handles: BTreeSet::new(),
            role_changes: Vec::new(),
            inventory_changes: BTreeSet::new(),
        };
        // The key sets are proven equal above, so the two ordered maps walk in lockstep.
        for ((fixture_id, before_case), (_, after_case)) in
            before.cases.iter().zip(after.cases.iter())
        {
            diff.push_fixture(fixture_id, before_case, after_case);
        }
        diff.role_changes.sort_by(|left, right| {
            left.fixture_id
                .cmp(&right.fixture_id)
                .then_with(|| left.name.as_str().cmp(right.name.as_str()))
        });
        Ok(diff)
    }

    fn push_fixture(
        &mut self,
        fixture_id: &str,
        before: &LensFixtureBehavior,
        after: &LensFixtureBehavior,
    ) {
        if before.atom_tree != after.atom_tree {
            self.structural_cases.insert(fixture_id.to_owned());
        }
        self.push_inventory_changes(fixture_id, before, after);
        self.push_handle_changes(fixture_id, before, after);
        self.push_referenced_handle_changes(fixture_id, before, after);
        self.push_role_changes(fixture_id, before, after);
    }

    fn push_inventory_changes(
        &mut self,
        fixture_id: &str,
        before: &LensFixtureBehavior,
        after: &LensFixtureBehavior,
    ) {
        let primitives = before
            .atom_inventory
            .keys()
            .chain(after.atom_inventory.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        for &primitive in &primitives {
            // An absent side counts as zero; an unchanged count emits nothing at all.
            let before_count = before.atom_inventory.get(&primitive).copied().unwrap_or(0);
            let after_count = after.atom_inventory.get(&primitive).copied().unwrap_or(0);
            if before_count != after_count {
                self.inventory_changes.insert(LensAtomInventoryChange {
                    fixture_id: fixture_id.to_owned(),
                    primitive,
                    before: before_count,
                    after: after_count,
                });
            }
        }
    }

    fn push_handle_changes(
        &mut self,
        fixture_id: &str,
        before: &LensFixtureBehavior,
        after: &LensFixtureBehavior,
    ) {
        for binding in after.bound_handles.difference(&before.bound_handles) {
            self.added_handles
                .insert(behavior_handle(fixture_id, binding));
        }
        for binding in before.bound_handles.difference(&after.bound_handles) {
            self.removed_handles
                .insert(behavior_handle(fixture_id, binding));
        }
    }

    /// The same set difference over the *referenced* dimension. A pair can appear here
    /// while `added_handles`/`removed_handles` stay empty: that is exactly a result set
    /// retargeted between two handles the node declares either way.
    fn push_referenced_handle_changes(
        &mut self,
        fixture_id: &str,
        before: &LensFixtureBehavior,
        after: &LensFixtureBehavior,
    ) {
        let before_referenced = &before.referenced_handles;
        let after_referenced = &after.referenced_handles;
        for binding in after_referenced.difference(before_referenced) {
            self.added_referenced_handles
                .insert(behavior_handle(fixture_id, binding));
        }
        for binding in before_referenced.difference(after_referenced) {
            self.removed_referenced_handles
                .insert(behavior_handle(fixture_id, binding));
        }
    }

    fn push_role_changes(
        &mut self,
        fixture_id: &str,
        before: &LensFixtureBehavior,
        after: &LensFixtureBehavior,
    ) {
        let before_roles = roles_by_handle_name(&before.bound_handles);
        let after_roles = roles_by_handle_name(&after.bound_handles);
        for (name, before_set) in &before_roles {
            // Only a name present on both sides can have *changed* role; a name that
            // appears on one side alone is already an added/removed pair.
            let Some(after_set) = after_roles.get(name) else {
                continue;
            };
            if before_set == after_set {
                continue;
            }
            self.role_changes.push(LensHandleRoleChange {
                fixture_id: fixture_id.to_owned(),
                name: (*name).clone(),
                before: before_set.clone(),
                after: after_set.clone(),
            });
        }
    }

    /// True when all seven collections are empty.
    #[must_use]
    pub fn is_identical(&self) -> bool {
        self.structural_cases.is_empty()
            && self.added_handles.is_empty()
            && self.removed_handles.is_empty()
            && self.added_referenced_handles.is_empty()
            && self.removed_referenced_handles.is_empty()
            && self.role_changes.is_empty()
            && self.inventory_changes.is_empty()
    }

    /// The single adoption predicate: which reach is declared, *and* which of it a
    /// result set points at. Structural and inventory churn never forces a human stamp
    /// on its own, and `role_changes` stays evidence — every role move is already a
    /// removed/added pair here.
    #[must_use]
    pub fn has_data_read_change(&self) -> bool {
        !self.added_handles.is_empty()
            || !self.removed_handles.is_empty()
            || !self.added_referenced_handles.is_empty()
            || !self.removed_referenced_handles.is_empty()
    }

    #[must_use]
    pub const fn structural_cases(&self) -> &BTreeSet<String> {
        &self.structural_cases
    }

    #[must_use]
    pub const fn added_handles(&self) -> &BTreeSet<LensBehaviorHandle> {
        &self.added_handles
    }

    #[must_use]
    pub const fn removed_handles(&self) -> &BTreeSet<LensBehaviorHandle> {
        &self.removed_handles
    }

    /// Reach a result-set row or select-all predicate newly points at.
    #[must_use]
    pub const fn added_referenced_handles(&self) -> &BTreeSet<LensBehaviorHandle> {
        &self.added_referenced_handles
    }

    /// Reach a result-set row or select-all predicate no longer points at.
    #[must_use]
    pub const fn removed_referenced_handles(&self) -> &BTreeSet<LensBehaviorHandle> {
        &self.removed_referenced_handles
    }

    #[must_use]
    pub fn role_changes(&self) -> &[LensHandleRoleChange] {
        &self.role_changes
    }

    #[must_use]
    pub const fn inventory_changes(&self) -> &BTreeSet<LensAtomInventoryChange> {
        &self.inventory_changes
    }
}

fn behavior_handle(fixture_id: &str, binding: &LensHandleBinding) -> LensBehaviorHandle {
    LensBehaviorHandle {
        fixture_id: fixture_id.to_owned(),
        name: binding.name.clone(),
        role: binding.role,
    }
}

fn roles_by_handle_name(
    handles: &BTreeSet<LensHandleBinding>,
) -> BTreeMap<&LensHandleName, BTreeSet<LensHandleRole>> {
    let mut grouped: BTreeMap<&LensHandleName, BTreeSet<LensHandleRole>> = BTreeMap::new();
    for binding in handles {
        grouped
            .entry(&binding.name)
            .or_default()
            .insert(binding.role);
    }
    grouped
}

/// Where a regeneration attempt stopped. Every variant preserves the last-good body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LensRegenFailurePhase {
    SummaryPromptRerun,
    Compile,
    Validate,
    GoldenRender,
    BehaviorDiff,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LensRegenFailure {
    phase: LensRegenFailurePhase,
    message: String,
}

impl LensRegenFailure {
    #[must_use]
    pub fn new(phase: LensRegenFailurePhase, message: impl Into<String>) -> Self {
        Self {
            phase,
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn phase(&self) -> LensRegenFailurePhase {
        self.phase
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// A regeneration request carries the target contract stamp and nothing else — no
/// prompt, no source, no hash. The concrete regenerator is already bound to the lens
/// artifact's summary prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LensRegenRequest {
    target_version: LensVersionStamp,
}

impl LensRegenRequest {
    #[must_use]
    pub const fn new(target_version: LensVersionStamp) -> Self {
        Self { target_version }
    }

    #[must_use]
    pub const fn target_version(self) -> LensVersionStamp {
        self.target_version
    }
}

/// A validated lens paired with the behavior it produced over the golden corpus.
#[derive(Debug, Clone, PartialEq)]
pub struct LensEvaluatedRevision {
    lens: GeneratedLens,
    behavior: LensBehaviorFingerprint,
}

impl LensEvaluatedRevision {
    /// Trusted caller-owned seam. `behavior` must be the fingerprint produced by
    /// rendering `lens` over the same golden corpus used for the comparison.
    /// This constructor does not and cannot re-render to prove that pairing.
    #[must_use]
    pub const fn new(lens: GeneratedLens, behavior: LensBehaviorFingerprint) -> Self {
        Self { lens, behavior }
    }

    #[must_use]
    pub const fn lens(&self) -> &GeneratedLens {
        &self.lens
    }

    #[must_use]
    pub const fn behavior(&self) -> &LensBehaviorFingerprint {
        &self.behavior
    }

    #[must_use]
    pub fn into_lens(self) -> GeneratedLens {
        self.lens
    }
}

/// The injected regeneration seam. It is narrow on purpose: no model client, prompt
/// router, async worker, executor dependency, or cloud/local routing policy enters this
/// module. An implementation may schedule or await work internally before returning.
pub trait LensRegenerator {
    /// Re-run the summary prompt, compile/validate the candidate, render that
    /// candidate over the configured golden corpus, and return its fingerprint.
    /// Every failure is returned as a typed phase; never manufacture a blank lens.
    fn regenerate(
        &self,
        request: &LensRegenRequest,
    ) -> std::result::Result<LensEvaluatedRevision, LensRegenFailure>;
}

/// The adoption decision. There is no `None`, empty-body, or error-only return, so
/// fail-blank is impossible at this boundary.
#[derive(Debug, Clone, PartialEq)]
pub enum LensRegenOutcome {
    AutoAdopt {
        candidate: LensEvaluatedRevision,
        diff: LensBehaviorDiff,
    },
    NeedsHumanStamp {
        last_good: LensEvaluatedRevision,
        candidate: Box<LensEvaluatedRevision>,
        diff: LensBehaviorDiff,
    },
    RolledBack {
        last_good: LensEvaluatedRevision,
        failure: LensRegenFailure,
    },
}

impl LensRegenOutcome {
    /// The revision that remains mountable without any further approval.
    #[must_use]
    pub const fn active_revision(&self) -> &LensEvaluatedRevision {
        match self {
            Self::AutoAdopt { candidate, .. } => candidate,
            Self::NeedsHumanStamp { last_good, .. } | Self::RolledBack { last_good, .. } => {
                last_good
            }
        }
    }

    #[must_use]
    pub const fn diff(&self) -> Option<&LensBehaviorDiff> {
        match self {
            Self::AutoAdopt { diff, .. } | Self::NeedsHumanStamp { diff, .. } => Some(diff),
            Self::RolledBack { .. } => None,
        }
    }

    #[must_use]
    pub const fn pending_candidate(&self) -> Option<&LensEvaluatedRevision> {
        match self {
            Self::NeedsHumanStamp { candidate, .. } => Some(candidate),
            Self::AutoAdopt { .. } | Self::RolledBack { .. } => None,
        }
    }
}

/// Run one regeneration and decide adoption.
///
/// The decision is binary: the same bound data reads may auto-adopt, changed bound data
/// reads need a human stamp. There is no severity score, no heuristic, and no fourth
/// outcome. The returned value performs nothing — the caller enacts adoption, routes the
/// candidate through the existing Proposed-approval flow, or keeps the last-good body.
#[must_use]
pub fn regenerate_lens<R: LensRegenerator + ?Sized>(
    regenerator: &R,
    request: &LensRegenRequest,
    last_good: LensEvaluatedRevision,
) -> LensRegenOutcome {
    // Regeneration always targets the live pair; a stale-targeted request is rejected
    // before the regenerator is ever invoked.
    if request.target_version() != LensVersionStamp::current() {
        return LensRegenOutcome::RolledBack {
            last_good,
            failure: LensRegenFailure::new(
                LensRegenFailurePhase::Validate,
                "regen request must target the live version pair",
            ),
        };
    }

    let candidate = match regenerator.regenerate(request) {
        Ok(candidate) => candidate,
        Err(failure) => return LensRegenOutcome::RolledBack { last_good, failure },
    };

    if candidate.lens().version_stamp() != request.target_version() {
        return LensRegenOutcome::RolledBack {
            last_good,
            failure: LensRegenFailure::new(
                LensRegenFailurePhase::Validate,
                "regenerated lens version does not match requested target",
            ),
        };
    }

    let diff = match LensBehaviorDiff::between(last_good.behavior(), candidate.behavior()) {
        Ok(diff) => diff,
        Err(error) => {
            return LensRegenOutcome::RolledBack {
                last_good,
                failure: LensRegenFailure::new(
                    LensRegenFailurePhase::BehaviorDiff,
                    error.to_string(),
                ),
            };
        }
    };

    if diff.has_data_read_change() {
        LensRegenOutcome::NeedsHumanStamp {
            last_good,
            candidate: Box::new(candidate),
            diff,
        }
    } else {
        LensRegenOutcome::AutoAdopt { candidate, diff }
    }
}
