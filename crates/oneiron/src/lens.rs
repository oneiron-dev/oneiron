//! Closed generated-lens atom vocabulary.
//!
//! Generated lenses are data that the trusted renderer interprets. This module
//! intentionally contains no raw script, URL/network, browser-storage, or eval
//! leaf types.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    marker::PhantomData,
};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer, de, de::DeserializeSeed, ser::SerializeMap,
};

use crate::{
    Error, Result,
    claim::{ScopedRead, ScopedReadActorKey},
    edge::EdgeActorClass,
    entity_id::EntityId,
    llm::ContentPart,
    registry::ENTITY_TYPE_CLAIM,
};

pub const LENS_ATOM_KIT_VERSION: u16 = 2;
pub const GENERATED_UI_WIRE_VERSION: u16 = 2;
pub const GENERATED_UI_SEGMENT_CONTENT_TYPE: &str =
    "application/vnd.oneiron.generated-ui.segment+json";

pub const GENERATED_LENS_ATOM_KINDS: &[&str] = &[
    "text_block",
    "ledger_row",
    "claim_line",
    "status_dot",
    "seal",
    "meta_line",
    "dossier_section",
    "thread_entry",
    "sheet",
    "slip",
    "receipt",
    "charter",
    "postmark",
    "pack_line",
    "answer_sheet",
    "two_clocks",
    "neighborhood_graph",
    "asof_scrubber",
    "throbber",
    "voice_line",
    "quick_filter",
    "inspector_sheet",
    "inspector_rail",
    "inspector_trail",
    "self_ui",
    "media",
];

const MAX_LENS_TOKEN_BYTES: usize = 128;
const MAX_LENS_TEXT_BYTES: usize = 16 * 1024;
const MAX_LENS_TREE_DEPTH: usize = 64;
const MAX_LENS_NODE_COUNT: usize = 4096;
const MAX_LENS_COLLECTION_ITEMS: usize = 4096;

macro_rules! lens_token_type {
    ($name:ident, $context:literal) => {
        lens_token_type!($name, $context, false);
    };

    ($name:ident, $context:literal, $reject_forbidden_capability:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                validate_lens_token($context, &value)?;
                if $reject_forbidden_capability {
                    validate_lens_capability_name($context, &value)?;
                }
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = Error;

            fn try_from(value: String) -> Result<Self> {
                Self::new(value)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = Error;

            fn try_from(value: &str) -> Result<Self> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }
    };
}

lens_token_type!(LensAtomId, "lens atom id");
lens_token_type!(LensHandleName, "lens handle name");
lens_token_type!(LensRenderId, "lens render id");
lens_token_type!(LensBackingRefId, "lens backing ref id");
lens_token_type!(LensMediaHandle, "lens media handle");
lens_token_type!(SelfUiControlId, "self.ui control id");
lens_token_type!(SelfUiActionId, "self.ui action id", true);
lens_token_type!(SelfUiOptionValue, "self.ui option value");
lens_token_type!(SelfUiStateKey, "self.ui state key");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LensText(String);

impl LensText {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() > MAX_LENS_TEXT_BYTES {
            return Err(Error::InvalidConfig(format!(
                "lens text must be at most {MAX_LENS_TEXT_BYTES} bytes"
            )));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for LensText {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl TryFrom<&str> for LensText {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        Self::new(value)
    }
}

impl From<LensText> for String {
    fn from(value: LensText) -> Self {
        value.0
    }
}

impl Serialize for LensText {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for LensText {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct FiniteF64(f64);

impl FiniteF64 {
    pub fn new(value: f64) -> Result<Self> {
        if !value.is_finite() {
            return Err(Error::InvalidConfig(
                "lens numeric value must be finite".to_string(),
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn get(self) -> f64 {
        self.0
    }
}

impl TryFrom<f64> for FiniteF64 {
    type Error = Error;

    fn try_from(value: f64) -> Result<Self> {
        Self::new(value)
    }
}

impl From<FiniteF64> for f64 {
    fn from(value: FiniteF64) -> Self {
        value.0
    }
}

impl Serialize for FiniteF64 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_f64(self.0)
    }
}

impl<'de> Deserialize<'de> for FiniteF64 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = f64::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GeneratedLens {
    kit_version: u16,
    root: LensNode,
}

impl GeneratedLens {
    pub fn new(root: LensNode) -> Result<Self> {
        let lens = Self {
            kit_version: LENS_ATOM_KIT_VERSION,
            root,
        };
        lens.validate()?;
        Ok(lens)
    }

    #[must_use]
    pub fn kit_version(&self) -> u16 {
        self.kit_version
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
        validate_lens_tree(&self.root)
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
                let mut root = None;
                let mut skipped_root_before_version = false;

                while let Some(field) = map.next_key::<Field>()? {
                    match field {
                        Field::KitVersion => {
                            if kit_version.is_some() {
                                return Err(de::Error::duplicate_field("kit_version"));
                            }
                            let version = map.next_value::<u16>()?;
                            if version != LENS_ATOM_KIT_VERSION {
                                return Err(de::Error::custom(format!(
                                    "unsupported generated lens atom kit version {version}"
                                )));
                            }
                            kit_version = Some(version);
                        }
                        Field::Root => {
                            if root.is_some() || skipped_root_before_version {
                                return Err(de::Error::duplicate_field("root"));
                            }
                            if kit_version.is_none() {
                                map.next_value::<de::IgnoredAny>()?;
                                skipped_root_before_version = true;
                            } else {
                                root = Some(map.next_value::<LensNode>()?);
                            }
                        }
                    }
                }

                let kit_version =
                    kit_version.ok_or_else(|| de::Error::missing_field("kit_version"))?;
                if skipped_root_before_version {
                    return Err(de::Error::custom(
                        "generated lens kit_version must precede root",
                    ));
                }
                let root = root.ok_or_else(|| de::Error::missing_field("root"))?;
                let lens = GeneratedLens { kit_version, root };
                lens.validate().map_err(de::Error::custom)?;
                Ok(lens)
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let kit_version = seq
                    .next_element::<u16>()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                if kit_version != LENS_ATOM_KIT_VERSION {
                    return Err(de::Error::custom(format!(
                        "unsupported generated lens atom kit version {kit_version}"
                    )));
                }

                let root = seq
                    .next_element_seed(LensNodeSeed { depth: 1 })?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                if seq.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::invalid_length(3, &self));
                }

                let lens = GeneratedLens { kit_version, root };
                lens.validate().map_err(de::Error::custom)?;
                Ok(lens)
            }
        }

        deserializer.deserialize_struct(
            "GeneratedLens",
            &["kit_version", "root"],
            GeneratedLensVisitor,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LensNode {
    pub id: LensAtomId,
    pub atom: LensAtom,
    #[serde(rename = "fallbackText")]
    pub fallback_text: LensText,
    #[serde(default)]
    pub bindings: Vec<LensHandleRef>,
    /// Declarative `$state` bindings; the wire key is literally `$bind`.
    #[serde(rename = "$bind", default)]
    pub state_bindings: Vec<SelfUiBinding>,
    #[serde(default)]
    pub children: Vec<LensNode>,
}

impl LensNode {
    #[must_use]
    pub fn new(id: LensAtomId, atom: LensAtom) -> Self {
        let fallback_text = atom.default_fallback_text();
        Self::with_fallback_text(id, atom, fallback_text)
    }

    #[must_use]
    pub fn with_fallback_text(id: LensAtomId, atom: LensAtom, fallback_text: LensText) -> Self {
        Self {
            id,
            atom,
            fallback_text,
            bindings: Vec::new(),
            state_bindings: Vec::new(),
            children: Vec::new(),
        }
    }
}

impl<'de> Deserialize<'de> for LensNode {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let node = LensNodeSeed { depth: 1 }.deserialize(deserializer)?;
        validate_lens_tree(&node).map_err(de::Error::custom)?;
        Ok(node)
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
        }
    }

    #[must_use]
    pub const fn minimum_catalog_version(self) -> u16 {
        match self {
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
            | Self::Media => LENS_ATOM_KIT_VERSION,
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
    pub fn new(values: BTreeMap<SelfUiStateKey, SelfUiStateValue>) -> Self {
        Self { values }
    }

    #[must_use]
    pub fn values(&self) -> &BTreeMap<SelfUiStateKey, SelfUiStateValue> {
        &self.values
    }

    #[must_use]
    pub fn get(&self, key: &SelfUiStateKey) -> Option<&SelfUiStateValue> {
        self.values.get(key)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
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

    #[must_use]
    pub fn value(&self) -> Option<&SelfUiStateValue> {
        match self {
            Self::Add { value, .. } | Self::Replace { value, .. } => Some(value),
            Self::Remove { .. } => None,
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

impl Default for GeneratedUiCardLifecycle {
    fn default() -> Self {
        Self::initial()
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

/// Host-side outcome of `LensRenderFrame::validate_action_event`. Every variant carries
/// the emitter stamped from the frame's principal binding; none is a wire type, and
/// none is self-executing.
#[derive(Debug, Clone, PartialEq)]
pub enum GeneratedUiValidatedAction {
    Local {
        emitter: LensPrincipalBinding,
        state: GeneratedUiStateSnapshot,
    },
    DeterministicTool {
        emitter: LensPrincipalBinding,
        action: LensApprovedAction,
    },
    ModelRoundTrip {
        emitter: LensPrincipalBinding,
        callback: GeneratedUiAgentCallback,
    },
}

impl GeneratedUiValidatedAction {
    #[must_use]
    pub fn emitter(&self) -> &LensPrincipalBinding {
        match self {
            Self::Local { emitter, .. }
            | Self::DeterministicTool { emitter, .. }
            | Self::ModelRoundTrip { emitter, .. } => emitter,
        }
    }
}

/// Data handed to the next agent turn. It is not a tool call and is never auto-forwarded.
#[derive(Debug, Clone, PartialEq)]
pub struct GeneratedUiAgentCallback {
    pub action_name: SelfUiActionId,
    pub resolved_params: Vec<LensApprovedActionArg>,
    pub source_card_id: LensRenderId,
    pub source_element_id: LensAtomId,
}

/// One addressable element of a card, in either the authored tree or the lowered
/// flat render. Interactivity validation is shape-agnostic across the two.
struct LensElementRef<'a> {
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

    fn collect_flat(nodes: &'a [GeneratedUiNode]) -> Vec<Self> {
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

    for element in elements {
        validate_lens_collection_len(
            "generated-ui $bind descriptors",
            element.state_bindings.len(),
        )?;
        if !element.state_bindings.is_empty() && !matches!(element.atom, LensAtom::SelfUi(_)) {
            return Err(Error::InvalidConfig(
                "generated-ui $bind descriptors are only valid on self.ui controls".to_string(),
            ));
        }
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
fn apply_generated_ui_state_patch(
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
                atom: compile_atom_for_surface(&node.atom, &node.fallback_text, surface),
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

    fn validate(&self) -> Result<()> {
        if self.protocol_version != GENERATED_UI_WIRE_VERSION {
            return Err(Error::InvalidConfig(format!(
                "unsupported generated-ui wire version {}",
                self.protocol_version
            )));
        }
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
            #[serde(default)]
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
    fn validate(&self) -> Result<()> {
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
    fn validate(&self) -> Result<()> {
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
            #[serde(default)]
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

struct LensNodeSeed {
    depth: usize,
}

impl<'de> de::DeserializeSeed<'de> for LensNodeSeed {
    type Value = LensNode;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "camelCase")]
        enum Field {
            Id,
            Atom,
            FallbackText,
            Bindings,
            #[serde(rename = "$bind")]
            StateBindings,
            Children,
        }

        struct LensNodeVisitor {
            depth: usize,
        }

        impl<'de> de::Visitor<'de> for LensNodeVisitor {
            type Value = LensNode;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("lens node")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut id = None;
                let mut atom = None;
                let mut fallback_text = None;
                let mut bindings = None;
                let mut state_bindings = None;
                let mut children = None;

                while let Some(field) = map.next_key::<Field>()? {
                    match field {
                        Field::Id => {
                            if id.is_some() {
                                return Err(de::Error::duplicate_field("id"));
                            }
                            id = Some(map.next_value::<LensAtomId>()?);
                        }
                        Field::Atom => {
                            if atom.is_some() {
                                return Err(de::Error::duplicate_field("atom"));
                            }
                            atom = Some(map.next_value::<LensAtom>()?);
                        }
                        Field::FallbackText => {
                            if fallback_text.is_some() {
                                return Err(de::Error::duplicate_field("fallbackText"));
                            }
                            fallback_text = Some(map.next_value::<LensText>()?);
                        }
                        Field::Bindings => {
                            if bindings.is_some() {
                                return Err(de::Error::duplicate_field("bindings"));
                            }
                            bindings =
                                Some(map.next_value_seed(LimitedVecSeed::<LensHandleRef> {
                                    _marker: PhantomData,
                                })?);
                        }
                        Field::StateBindings => {
                            if state_bindings.is_some() {
                                return Err(de::Error::duplicate_field("$bind"));
                            }
                            state_bindings =
                                Some(map.next_value_seed(LimitedVecSeed::<SelfUiBinding> {
                                    _marker: PhantomData,
                                })?);
                        }
                        Field::Children => {
                            if children.is_some() {
                                return Err(de::Error::duplicate_field("children"));
                            }
                            children = Some(map.next_value_seed(LensChildrenSeed {
                                child_depth: self.depth + 1,
                            })?);
                        }
                    }
                }

                Ok(LensNode {
                    id: id.ok_or_else(|| de::Error::missing_field("id"))?,
                    atom: atom.ok_or_else(|| de::Error::missing_field("atom"))?,
                    fallback_text: fallback_text
                        .ok_or_else(|| de::Error::missing_field("fallbackText"))?,
                    bindings: bindings.unwrap_or_default(),
                    state_bindings: state_bindings.unwrap_or_default(),
                    children: children.unwrap_or_default(),
                })
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let id = seq
                    .next_element::<LensAtomId>()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let atom = seq
                    .next_element::<LensAtom>()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let fallback_text = seq
                    .next_element::<LensText>()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;
                let bindings = seq
                    .next_element_seed(LimitedVecSeed::<LensHandleRef> {
                        _marker: PhantomData,
                    })?
                    .unwrap_or_default();
                let state_bindings = seq
                    .next_element_seed(LimitedVecSeed::<SelfUiBinding> {
                        _marker: PhantomData,
                    })?
                    .unwrap_or_default();
                let children = seq
                    .next_element_seed(LensChildrenSeed {
                        child_depth: self.depth + 1,
                    })?
                    .unwrap_or_default();
                if seq.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::invalid_length(6, &self));
                }

                Ok(LensNode {
                    id,
                    atom,
                    fallback_text,
                    bindings,
                    state_bindings,
                    children,
                })
            }
        }

        if self.depth > MAX_LENS_TREE_DEPTH {
            return Err(de::Error::custom(format!(
                "generated lens tree depth must be at most {MAX_LENS_TREE_DEPTH}"
            )));
        }

        deserializer.deserialize_struct(
            "LensNode",
            &[
                "id",
                "atom",
                "fallbackText",
                "bindings",
                "$bind",
                "children",
            ],
            LensNodeVisitor { depth: self.depth },
        )
    }
}

struct LimitedVecSeed<T> {
    _marker: PhantomData<T>,
}

impl<'de, T> de::DeserializeSeed<'de> for LimitedVecSeed<T>
where
    T: Deserialize<'de>,
{
    type Value = Vec<T>;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(LimitedVecVisitor::<T> {
            _marker: PhantomData,
        })
    }
}

struct LimitedVecVisitor<T> {
    _marker: PhantomData<T>,
}

impl<'de, T> de::Visitor<'de> for LimitedVecVisitor<T>
where
    T: Deserialize<'de>,
{
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded lens collection")
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        reject_lens_sequence_hint(seq.size_hint())?;
        let mut values = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(16));
        while let Some(value) = seq.next_element::<T>()? {
            if values.len() >= MAX_LENS_COLLECTION_ITEMS {
                return Err(max_lens_collection_items_error());
            }
            values.push(value);
        }
        Ok(values)
    }
}

struct LensChildrenSeed {
    child_depth: usize,
}

impl<'de> de::DeserializeSeed<'de> for LensChildrenSeed {
    type Value = Vec<LensNode>;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(LensChildrenVisitor {
            child_depth: self.child_depth,
        })
    }
}

struct LensChildrenVisitor {
    child_depth: usize,
}

impl<'de> de::Visitor<'de> for LensChildrenVisitor {
    type Value = Vec<LensNode>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded lens node children")
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        reject_lens_sequence_hint(seq.size_hint())?;
        let mut values = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(16));
        while let Some(value) = seq.next_element_seed(LensNodeSeed {
            depth: self.child_depth,
        })? {
            if values.len() >= MAX_LENS_COLLECTION_ITEMS {
                return Err(max_lens_collection_items_error());
            }
            values.push(value);
        }
        Ok(values)
    }
}

fn deserialize_limited_vec<'de, D, T>(deserializer: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    LimitedVecSeed::<T> {
        _marker: PhantomData,
    }
    .deserialize(deserializer)
}

fn reject_lens_sequence_hint<E>(size_hint: Option<usize>) -> std::result::Result<(), E>
where
    E: de::Error,
{
    if size_hint.is_some_and(|len| len > MAX_LENS_COLLECTION_ITEMS) {
        return Err(max_lens_collection_items_error());
    }
    Ok(())
}

fn max_lens_collection_items_error<E>() -> E
where
    E: de::Error,
{
    de::Error::custom(format!(
        "lens collection must contain at most {MAX_LENS_COLLECTION_ITEMS} items"
    ))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LensHandleRef {
    pub name: LensHandleName,
    pub role: LensHandleRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LensHandleRole {
    ClaimSet,
    EntitySet,
    Timeline,
    QueryResult,
    ActionTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LensActingPrincipalKind {
    HumanView,
    AgentTask,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LensPrincipalBinding {
    principal_ref: String,
    kind: LensActingPrincipalKind,
    selected_read_key: ScopedReadActorKey,
    held_read_keys: Vec<ScopedReadActorKey>,
}

impl LensPrincipalBinding {
    pub fn human_view(
        principal_ref: impl Into<String>,
        selected_read_key: ScopedReadActorKey,
        held_read_keys: Vec<ScopedReadActorKey>,
    ) -> Result<Self> {
        Self::new(
            principal_ref,
            LensActingPrincipalKind::HumanView,
            selected_read_key,
            held_read_keys,
        )
    }

    pub fn agent_task(
        principal_ref: impl Into<String>,
        selected_read_key: ScopedReadActorKey,
        held_read_keys: Vec<ScopedReadActorKey>,
    ) -> Result<Self> {
        Self::new(
            principal_ref,
            LensActingPrincipalKind::AgentTask,
            selected_read_key,
            held_read_keys,
        )
    }

    fn new(
        principal_ref: impl Into<String>,
        kind: LensActingPrincipalKind,
        selected_read_key: ScopedReadActorKey,
        held_read_keys: Vec<ScopedReadActorKey>,
    ) -> Result<Self> {
        let principal_ref = principal_ref.into();
        let principal_ref = principal_ref.trim();
        if principal_ref.is_empty() {
            return Err(Error::InvalidConfig(
                "lens acting principal must not be empty".to_string(),
            ));
        }
        if held_read_keys.is_empty() {
            return Err(Error::InvalidConfig(
                "lens acting principal must hold at least one read key".to_string(),
            ));
        }
        if principal_ref != selected_read_key.actor_ref() {
            return Err(Error::InvalidConfig(
                "lens acting principal ref must match the selected read key actor".to_string(),
            ));
        }
        if held_read_keys
            .iter()
            .any(|key| key.actor_ref() != principal_ref)
        {
            return Err(Error::InvalidConfig(
                "lens acting principal held read keys must belong to the same actor".to_string(),
            ));
        }
        if !held_read_keys.iter().any(|key| key == &selected_read_key) {
            return Err(Error::InvalidConfig(
                "lens render read key must be held by the acting principal".to_string(),
            ));
        }
        match kind {
            LensActingPrincipalKind::HumanView => {
                if selected_read_key
                    .actor_class()
                    .is_some_and(|class| class != EdgeActorClass::Human.gate_actor_class())
                {
                    return Err(Error::InvalidConfig(
                        "lens human-view principal must use a human read key".to_string(),
                    ));
                }
            }
            LensActingPrincipalKind::AgentTask => {
                if selected_read_key.actor_class() != Some(EdgeActorClass::Agent.gate_actor_class())
                {
                    return Err(Error::InvalidConfig(
                        "lens agent-task principal must use an agent read key".to_string(),
                    ));
                }
            }
        }

        Ok(Self {
            principal_ref: principal_ref.to_owned(),
            kind,
            selected_read_key,
            held_read_keys,
        })
    }

    #[must_use]
    pub fn principal_ref(&self) -> &str {
        &self.principal_ref
    }

    #[must_use]
    pub fn kind(&self) -> LensActingPrincipalKind {
        self.kind
    }

    #[must_use]
    pub fn selected_read_key(&self) -> &ScopedReadActorKey {
        &self.selected_read_key
    }

    #[must_use]
    pub fn held_read_keys(&self) -> &[ScopedReadActorKey] {
        &self.held_read_keys
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LensBackingTargetKind {
    Entity,
    Claim,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LensBackingTarget {
    kind: LensBackingTargetKind,
    entity_id: EntityId,
    short_id: String,
    content_hash: u8,
}

impl LensBackingTarget {
    pub fn entity(
        entity_id: EntityId,
        short_id: impl Into<String>,
        content_hash: u8,
    ) -> Result<Self> {
        Self::new(
            LensBackingTargetKind::Entity,
            entity_id,
            short_id,
            content_hash,
        )
    }

    pub fn claim(
        entity_id: EntityId,
        short_id: impl Into<String>,
        content_hash: u8,
    ) -> Result<Self> {
        Self::new(
            LensBackingTargetKind::Claim,
            entity_id,
            short_id,
            content_hash,
        )
    }

    fn new(
        kind: LensBackingTargetKind,
        entity_id: EntityId,
        short_id: impl Into<String>,
        content_hash: u8,
    ) -> Result<Self> {
        let short_id = short_id.into();
        validate_lens_token("lens backing short id", &short_id)?;
        Ok(Self {
            kind,
            entity_id,
            short_id,
            content_hash,
        })
    }

    #[must_use]
    pub fn kind(&self) -> LensBackingTargetKind {
        self.kind
    }

    #[must_use]
    pub fn entity_id(&self) -> &EntityId {
        &self.entity_id
    }

    #[must_use]
    pub fn short_id(&self) -> &str {
        &self.short_id
    }

    #[must_use]
    pub fn content_hash(&self) -> u8 {
        self.content_hash
    }

    #[must_use]
    pub fn short_ref(&self) -> String {
        format!("{}:{:02x}", self.short_id, self.content_hash)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LensBackingRefToken {
    render_id: LensRenderId,
    ref_id: LensBackingRefId,
}

impl LensBackingRefToken {
    #[must_use]
    pub fn render_id(&self) -> &LensRenderId {
        &self.render_id
    }

    #[must_use]
    pub fn ref_id(&self) -> &LensBackingRefId {
        &self.ref_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LensHostBackingRef {
    token: LensBackingRefToken,
    handle: LensHandleName,
    role: LensHandleRole,
    target: LensBackingTarget,
}

impl LensHostBackingRef {
    #[must_use]
    pub fn token(&self) -> &LensBackingRefToken {
        &self.token
    }

    #[must_use]
    pub fn handle(&self) -> &LensHandleName {
        &self.handle
    }

    #[must_use]
    pub fn role(&self) -> LensHandleRole {
        self.role
    }

    #[must_use]
    pub fn target(&self) -> &LensBackingTarget {
        &self.target
    }
}

#[derive(Debug, Clone)]
pub struct LensRenderFrame {
    render_id: LensRenderId,
    principal: LensPrincipalBinding,
    backing_refs: Vec<LensHostBackingRef>,
}

impl LensRenderFrame {
    #[must_use]
    pub fn new(render_id: LensRenderId, principal: LensPrincipalBinding) -> Self {
        Self {
            render_id,
            principal,
            backing_refs: Vec::new(),
        }
    }

    #[must_use]
    pub fn render_id(&self) -> &LensRenderId {
        &self.render_id
    }

    #[must_use]
    pub fn principal(&self) -> &LensPrincipalBinding {
        &self.principal
    }

    #[must_use]
    pub fn backing_refs(&self) -> &[LensHostBackingRef] {
        &self.backing_refs
    }

    pub fn mint_backing_ref(
        &mut self,
        scoped_read: &ScopedRead<'_>,
        handle: LensHandleName,
        role: LensHandleRole,
        target: LensBackingTarget,
    ) -> Result<LensBackingRefToken> {
        self.ensure_scoped_read_actor(scoped_read)?;
        if self
            .backing_refs
            .iter()
            .any(|backing_ref| backing_ref.handle == handle)
        {
            return Err(Error::InvalidConfig(
                "lens backing handle must be host-bound at most once per render".to_string(),
            ));
        }
        Self::ensure_target_readable(scoped_read, &target)?;

        let ref_id = LensBackingRefId::new(format!("ref-{}", self.backing_refs.len()))?;
        let token = LensBackingRefToken {
            render_id: self.render_id.clone(),
            ref_id,
        };
        self.backing_refs.push(LensHostBackingRef {
            token: token.clone(),
            handle,
            role,
            target,
        });
        Ok(token)
    }

    pub fn resolve_backing_ref_token(
        &self,
        scoped_read: &ScopedRead<'_>,
        token: &LensBackingRefToken,
    ) -> Result<LensHostBackingRef> {
        self.ensure_scoped_read_actor(scoped_read)?;
        if token.render_id != self.render_id {
            return Err(Error::InvalidConfig(
                "lens backing ref token belongs to a different render".to_string(),
            ));
        }
        let backing_ref = self
            .backing_refs
            .iter()
            .find(|backing_ref| backing_ref.token.ref_id == token.ref_id)
            .ok_or_else(|| {
                Error::InvalidConfig("lens backing ref token was not host-minted".to_string())
            })?;
        Self::ensure_target_readable(scoped_read, &backing_ref.target)?;
        Ok(backing_ref.clone())
    }

    pub fn approve_action(
        &self,
        scoped_read: &ScopedRead<'_>,
        action: &SelfUiAction,
    ) -> Result<LensApprovedAction> {
        self.ensure_scoped_read_actor(scoped_read)?;
        let mut args = Vec::with_capacity(action.args.len());
        for arg in &action.args {
            args.push(match arg {
                SelfUiValue::Bool(value) => LensApprovedActionArg::Bool(*value),
                SelfUiValue::Number(value) => LensApprovedActionArg::Number(*value),
                SelfUiValue::Text(value) => LensApprovedActionArg::Text(value.clone()),
                SelfUiValue::Token(value) => LensApprovedActionArg::Token(value.clone()),
                SelfUiValue::Handle(handle) => {
                    let backing_ref = self.resolve_handle(scoped_read, handle)?;
                    LensApprovedActionArg::BackingRef(backing_ref.clone())
                }
            });
        }
        Ok(LensApprovedAction {
            command: action.command.clone(),
            args,
        })
    }

    /// Resolve a client interaction event against the engine-authored manifest.
    ///
    /// `emitter` is the host's own [`LensRenderFrame::principal`]; it is never read
    /// from event JSON and must match this frame's binding. `render.state` is the
    /// declared `$state` schema; `state` is the current snapshot the patch applies to.
    pub fn validate_action_event(
        &self,
        scoped_read: &ScopedRead<'_>,
        emitter: &LensPrincipalBinding,
        render: &GeneratedUiRender,
        state: &GeneratedUiStateSnapshot,
        event: &GeneratedUiActionEvent,
    ) -> Result<GeneratedUiValidatedAction> {
        self.ensure_scoped_read_actor(scoped_read)?;
        if emitter != &self.principal {
            return Err(Error::InvalidConfig(
                "lens action emitter must be this render frame's acting principal".to_string(),
            ));
        }
        if render.card_id != self.render_id {
            return Err(Error::InvalidConfig(
                "generated-ui render must belong to this render frame".to_string(),
            ));
        }
        if event.card_id != render.card_id {
            return Err(Error::InvalidConfig(
                "generated-ui action event card_id must match the render".to_string(),
            ));
        }
        if render.lifecycle.phase == GeneratedUiCardPhase::Archived {
            return Err(Error::InvalidConfig(
                "generated-ui archived cards must not accept action events".to_string(),
            ));
        }

        let node = render
            .nodes
            .iter()
            .find(|node| node.id == event.element_id)
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "generated-ui action event must name an element of this render".to_string(),
                )
            })?;

        let mut matches = render
            .actions
            .iter()
            .filter(|declaration| declaration.action_id == event.action_id);
        let declaration = matches.next().ok_or_else(|| {
            Error::InvalidConfig("generated-ui action event names an undeclared action".to_string())
        })?;
        if matches.next().is_some() {
            return Err(Error::InvalidConfig(
                "generated-ui action ids must be declared exactly once".to_string(),
            ));
        }
        if declaration.element_id != event.element_id {
            return Err(Error::InvalidConfig(
                "generated-ui action event element must match its declaration".to_string(),
            ));
        }
        let LensAtom::SelfUi(control) = &node.atom else {
            return Err(Error::InvalidConfig(
                "generated-ui action element must be a self.ui control".to_string(),
            ));
        };
        if control.action() != &declaration.action {
            return Err(Error::InvalidConfig(
                "generated-ui element action must match its manifest declaration".to_string(),
            ));
        }

        // Only the local tier carries client state; trigger tiers take their arguments
        // from the engine-authored declaration alone.
        if declaration.tier != GeneratedUiActionTier::Local && !event.patch.is_empty() {
            return Err(Error::InvalidConfig(
                "only local generated-ui actions may carry a $state patch".to_string(),
            ));
        }
        let next_state = apply_generated_ui_state_patch(&render.state, state, &event.patch)?;

        let emitter = self.principal.clone();
        Ok(match declaration.tier {
            GeneratedUiActionTier::Local => GeneratedUiValidatedAction::Local {
                emitter,
                state: next_state,
            },
            GeneratedUiActionTier::DeterministicTool => {
                GeneratedUiValidatedAction::DeterministicTool {
                    emitter,
                    action: self.approve_action(scoped_read, &declaration.action)?,
                }
            }
            GeneratedUiActionTier::ModelRoundTrip => {
                let approved = self.approve_action(scoped_read, &declaration.action)?;
                GeneratedUiValidatedAction::ModelRoundTrip {
                    emitter,
                    callback: GeneratedUiAgentCallback {
                        action_name: approved.command,
                        resolved_params: approved.args,
                        source_card_id: render.card_id.clone(),
                        source_element_id: event.element_id.clone(),
                    },
                }
            }
        })
    }

    fn resolve_handle(
        &self,
        scoped_read: &ScopedRead<'_>,
        handle: &LensHandleName,
    ) -> Result<&LensHostBackingRef> {
        let backing_ref = self
            .backing_refs
            .iter()
            .find(|backing_ref| &backing_ref.handle == handle)
            .ok_or_else(|| {
                Error::InvalidConfig(
                    "lens action handle was not host-bound for this render".to_string(),
                )
            })?;
        if backing_ref.role != LensHandleRole::ActionTarget {
            return Err(Error::InvalidConfig(
                "lens action handle must resolve to an action-target backing ref".to_string(),
            ));
        }
        Self::ensure_target_readable(scoped_read, &backing_ref.target)?;
        Ok(backing_ref)
    }

    fn ensure_scoped_read_actor(&self, scoped_read: &ScopedRead<'_>) -> Result<()> {
        if scoped_read.actor_key() == self.principal.selected_read_key() {
            return Ok(());
        }
        Err(Error::InvalidConfig(
            "lens render must use the acting principal's selected read key".to_string(),
        ))
    }

    fn ensure_target_readable(
        scoped_read: &ScopedRead<'_>,
        target: &LensBackingTarget,
    ) -> Result<()> {
        let Some(hydrated) =
            scoped_read.hydrate_short_id(target.short_id(), target.content_hash())?
        else {
            return Err(Error::InvalidConfig(
                "lens backing short ref is not readable by the acting principal".to_string(),
            ));
        };
        if hydrated.id != *target.entity_id() || hydrated.body.is_none() {
            return Err(Error::InvalidConfig(
                "lens backing short ref does not resolve to the target entity".to_string(),
            ));
        }
        match (target.kind(), hydrated.entity_type) {
            (LensBackingTargetKind::Claim, ENTITY_TYPE_CLAIM) => {}
            (LensBackingTargetKind::Claim, _) => {
                return Err(Error::InvalidConfig(
                    "lens claim backing ref target must resolve to a claim entity".to_string(),
                ));
            }
            (LensBackingTargetKind::Entity, ENTITY_TYPE_CLAIM) => {
                return Err(Error::InvalidConfig(
                    "lens entity backing ref target must not resolve to a claim entity".to_string(),
                ));
            }
            (LensBackingTargetKind::Entity, _) => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LensApprovedAction {
    command: SelfUiActionId,
    args: Vec<LensApprovedActionArg>,
}

impl LensApprovedAction {
    #[must_use]
    pub fn command(&self) -> &SelfUiActionId {
        &self.command
    }

    #[must_use]
    pub fn args(&self) -> &[LensApprovedActionArg] {
        &self.args
    }

    #[must_use]
    pub fn into_host_mediated_write(
        self,
        chokepoint: LensGateWriteChokepoint,
    ) -> LensHostMediatedWrite {
        LensHostMediatedWrite {
            action: self,
            chokepoint,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum LensApprovedActionArg {
    Bool(bool),
    Number(FiniteF64),
    Text(LensText),
    Token(SelfUiOptionValue),
    BackingRef(LensHostBackingRef),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LensGateWriteChokepoint {
    EvaluateGate,
    CheckClaimPolicyForWrite,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LensHostMediatedWrite {
    action: LensApprovedAction,
    chokepoint: LensGateWriteChokepoint,
}

impl LensHostMediatedWrite {
    #[must_use]
    pub fn action(&self) -> &LensApprovedAction {
        &self.action
    }

    #[must_use]
    pub fn chokepoint(&self) -> LensGateWriteChokepoint {
        self.chokepoint
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LensHostImport {
    ScopedRead,
    ResolveBackingRef,
    EmitAtom,
    VaultWrite,
    BatchWrite,
    EvaluateGate,
    CheckClaimPolicyForWrite,
}

impl LensHostImport {
    #[must_use]
    pub fn is_write(self) -> bool {
        matches!(
            self,
            Self::VaultWrite
                | Self::BatchWrite
                | Self::EvaluateGate
                | Self::CheckClaimPolicyForWrite
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LensExecutionBoundary {
    imports: Vec<LensHostImport>,
}

impl LensExecutionBoundary {
    pub fn read_only(imports: Vec<LensHostImport>) -> Result<Self> {
        if let Some(import) = imports.iter().copied().find(|import| import.is_write()) {
            return Err(Error::InvalidConfig(format!(
                "generated lens execution must not link write import {import:?}"
            )));
        }
        Ok(Self { imports })
    }

    #[must_use]
    pub fn imports(&self) -> &[LensHostImport] {
        &self.imports
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum LensAtom {
    TextBlock(TextBlockAtom),
    LedgerRow(LedgerRowAtom),
    ClaimLine(ClaimLineAtom),
    StatusDot(StatusDotAtom),
    Seal(SealAtom),
    MetaLine(MetaLineAtom),
    DossierSection(SectionAtom),
    ThreadEntry(ThreadEntryAtom),
    Sheet(CollectionAtom),
    Slip(SectionAtom),
    Receipt(ReceiptAtom),
    Charter(SectionAtom),
    Postmark(PostmarkAtom),
    PackLine(PackLineAtom),
    AnswerSheet(AnswerSheetAtom),
    TwoClocks(TwoClocksAtom),
    NeighborhoodGraph(NeighborhoodGraphAtom),
    AsofScrubber(AsofScrubberAtom),
    Throbber(ThrobberAtom),
    VoiceLine(VoiceLineAtom),
    QuickFilter(QuickFilterAtom),
    InspectorSheet(InspectorAtom),
    InspectorRail(InspectorAtom),
    InspectorTrail(InspectorAtom),
    SelfUi(SelfUiControl),
    Media(MediaAtom),
}

#[derive(Debug, Deserialize)]
#[serde(
    tag = "kind",
    content = "props",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum LensAtomWire {
    TextBlock(TextBlockAtom),
    LedgerRow(LedgerRowAtom),
    ClaimLine(ClaimLineAtom),
    StatusDot(StatusDotAtom),
    Seal(SealAtom),
    MetaLine(MetaLineAtom),
    DossierSection(SectionAtom),
    ThreadEntry(ThreadEntryAtom),
    Sheet(CollectionAtom),
    Slip(SectionAtom),
    Receipt(ReceiptAtom),
    Charter(SectionAtom),
    Postmark(PostmarkAtom),
    PackLine(PackLineAtom),
    AnswerSheet(AnswerSheetAtom),
    TwoClocks(TwoClocksAtom),
    NeighborhoodGraph(NeighborhoodGraphAtom),
    AsofScrubber(AsofScrubberAtom),
    Throbber(ThrobberAtom),
    VoiceLine(VoiceLineAtom),
    QuickFilter(QuickFilterAtom),
    InspectorSheet(InspectorAtom),
    InspectorRail(InspectorAtom),
    InspectorTrail(InspectorAtom),
    SelfUi(SelfUiControl),
    Media(MediaAtom),
}

impl From<LensAtomWire> for LensAtom {
    fn from(value: LensAtomWire) -> Self {
        match value {
            LensAtomWire::TextBlock(atom) => Self::TextBlock(atom),
            LensAtomWire::LedgerRow(atom) => Self::LedgerRow(atom),
            LensAtomWire::ClaimLine(atom) => Self::ClaimLine(atom),
            LensAtomWire::StatusDot(atom) => Self::StatusDot(atom),
            LensAtomWire::Seal(atom) => Self::Seal(atom),
            LensAtomWire::MetaLine(atom) => Self::MetaLine(atom),
            LensAtomWire::DossierSection(atom) => Self::DossierSection(atom),
            LensAtomWire::ThreadEntry(atom) => Self::ThreadEntry(atom),
            LensAtomWire::Sheet(atom) => Self::Sheet(atom),
            LensAtomWire::Slip(atom) => Self::Slip(atom),
            LensAtomWire::Receipt(atom) => Self::Receipt(atom),
            LensAtomWire::Charter(atom) => Self::Charter(atom),
            LensAtomWire::Postmark(atom) => Self::Postmark(atom),
            LensAtomWire::PackLine(atom) => Self::PackLine(atom),
            LensAtomWire::AnswerSheet(atom) => Self::AnswerSheet(atom),
            LensAtomWire::TwoClocks(atom) => Self::TwoClocks(atom),
            LensAtomWire::NeighborhoodGraph(atom) => Self::NeighborhoodGraph(atom),
            LensAtomWire::AsofScrubber(atom) => Self::AsofScrubber(atom),
            LensAtomWire::Throbber(atom) => Self::Throbber(atom),
            LensAtomWire::VoiceLine(atom) => Self::VoiceLine(atom),
            LensAtomWire::QuickFilter(atom) => Self::QuickFilter(atom),
            LensAtomWire::InspectorSheet(atom) => Self::InspectorSheet(atom),
            LensAtomWire::InspectorRail(atom) => Self::InspectorRail(atom),
            LensAtomWire::InspectorTrail(atom) => Self::InspectorTrail(atom),
            LensAtomWire::SelfUi(control) => Self::SelfUi(control),
            LensAtomWire::Media(atom) => Self::Media(atom),
        }
    }
}

impl<'de> Deserialize<'de> for LensAtom {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let atom = Self::from(LensAtomWire::deserialize(deserializer)?);
        atom.validate().map_err(de::Error::custom)?;

        let mut budget = LensBudget::default();
        atom.count_collection_items(&mut budget)
            .map_err(de::Error::custom)?;

        Ok(atom)
    }
}

impl Serialize for LensAtom {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::TextBlock(props) => {
                serialize_tagged(serializer, "kind", "text_block", "props", props)
            }
            Self::LedgerRow(props) => {
                serialize_tagged(serializer, "kind", "ledger_row", "props", props)
            }
            Self::ClaimLine(props) => {
                serialize_tagged(serializer, "kind", "claim_line", "props", props)
            }
            Self::StatusDot(props) => {
                serialize_tagged(serializer, "kind", "status_dot", "props", props)
            }
            Self::Seal(props) => serialize_tagged(serializer, "kind", "seal", "props", props),
            Self::MetaLine(props) => {
                serialize_tagged(serializer, "kind", "meta_line", "props", props)
            }
            Self::DossierSection(props) => {
                serialize_tagged(serializer, "kind", "dossier_section", "props", props)
            }
            Self::ThreadEntry(props) => {
                serialize_tagged(serializer, "kind", "thread_entry", "props", props)
            }
            Self::Sheet(props) => serialize_tagged(serializer, "kind", "sheet", "props", props),
            Self::Slip(props) => serialize_tagged(serializer, "kind", "slip", "props", props),
            Self::Receipt(props) => serialize_tagged(serializer, "kind", "receipt", "props", props),
            Self::Charter(props) => serialize_tagged(serializer, "kind", "charter", "props", props),
            Self::Postmark(props) => {
                serialize_tagged(serializer, "kind", "postmark", "props", props)
            }
            Self::PackLine(props) => {
                serialize_tagged(serializer, "kind", "pack_line", "props", props)
            }
            Self::AnswerSheet(props) => {
                serialize_tagged(serializer, "kind", "answer_sheet", "props", props)
            }
            Self::TwoClocks(props) => {
                serialize_tagged(serializer, "kind", "two_clocks", "props", props)
            }
            Self::NeighborhoodGraph(props) => {
                serialize_tagged(serializer, "kind", "neighborhood_graph", "props", props)
            }
            Self::AsofScrubber(props) => {
                serialize_tagged(serializer, "kind", "asof_scrubber", "props", props)
            }
            Self::Throbber(props) => {
                serialize_tagged(serializer, "kind", "throbber", "props", props)
            }
            Self::VoiceLine(props) => {
                serialize_tagged(serializer, "kind", "voice_line", "props", props)
            }
            Self::QuickFilter(props) => {
                serialize_tagged(serializer, "kind", "quick_filter", "props", props)
            }
            Self::InspectorSheet(props) => {
                serialize_tagged(serializer, "kind", "inspector_sheet", "props", props)
            }
            Self::InspectorRail(props) => {
                serialize_tagged(serializer, "kind", "inspector_rail", "props", props)
            }
            Self::InspectorTrail(props) => {
                serialize_tagged(serializer, "kind", "inspector_trail", "props", props)
            }
            Self::SelfUi(props) => serialize_tagged(serializer, "kind", "self_ui", "props", props),
            Self::Media(props) => serialize_tagged(serializer, "kind", "media", "props", props),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
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
            #[serde(deserialize_with = "deserialize_limited_vec")]
            spans: Vec<LensTextSpan>,
        }

        let wire = TextBlockAtomWire::deserialize(deserializer)?;
        let atom = Self { spans: wire.spans };
        atom.validate().map_err(de::Error::custom)?;
        Ok(atom)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaAtom {
    pub handle: LensMediaHandle,
    pub alt: LensText,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerRowAtom {
    #[serde(deserialize_with = "deserialize_limited_vec")]
    pub cells: Vec<LedgerCell>,
    #[serde(default)]
    pub status: Option<StatusDotAtom>,
    #[serde(default)]
    pub seal: Option<SealAtom>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerCell {
    pub label: LensText,
    pub value: LensText,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimLineAtom {
    pub subject: LensText,
    pub predicate: LensText,
    pub value: LensText,
    pub status: StatusDotAtom,
    #[serde(default)]
    pub seal: Option<SealAtom>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusDotAtom {
    pub status: LensStatus,
    #[serde(default)]
    pub label: Option<LensText>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealAtom {
    pub level: SealLevel,
    pub label: LensText,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealLevel {
    None,
    Local,
    Actor,
    Authority,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetaLineAtom {
    pub label: LensText,
    pub value: LensText,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SectionAtom {
    pub title: LensText,
    #[serde(default, deserialize_with = "deserialize_limited_vec")]
    pub lines: Vec<LensText>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadEntryAtom {
    pub author: LensText,
    pub body: LensText,
    #[serde(default)]
    pub timestamp: Option<LensText>,
    #[serde(default)]
    pub seal: Option<SealAtom>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CollectionAtom {
    pub title: LensText,
    #[serde(default, deserialize_with = "deserialize_limited_vec")]
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
            #[serde(default, deserialize_with = "deserialize_limited_vec")]
            rows: Vec<LedgerRowAtom>,
        }

        let wire = CollectionAtomWire::deserialize(deserializer)?;
        let atom = Self {
            title: wire.title,
            rows: wire.rows,
        };
        atom.validate().map_err(de::Error::custom)?;
        let mut budget = LensBudget::default();
        atom.count_collection_items(&mut budget)
            .map_err(de::Error::custom)?;
        Ok(atom)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptAtom {
    pub title: LensText,
    #[serde(default, deserialize_with = "deserialize_limited_vec")]
    pub lines: Vec<MetaLineAtom>,
    #[serde(default)]
    pub seal: Option<SealAtom>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostmarkAtom {
    pub label: LensText,
    pub timestamp: LensText,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackLineAtom {
    pub pack: LensText,
    pub summary: LensText,
    pub status: LensStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnswerSheetAtom {
    pub question: LensText,
    pub answer: LensText,
    #[serde(default, deserialize_with = "deserialize_limited_vec")]
    pub citations: Vec<LensHandleRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TwoClocksAtom {
    pub occurred_at: LensText,
    pub learned_at: LensText,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NeighborhoodGraphAtom {
    #[serde(default, deserialize_with = "deserialize_limited_vec")]
    pub nodes: Vec<GraphNode>,
    #[serde(default, deserialize_with = "deserialize_limited_vec")]
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
            #[serde(default, deserialize_with = "deserialize_limited_vec")]
            nodes: Vec<GraphNode>,
            #[serde(default, deserialize_with = "deserialize_limited_vec")]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphNode {
    pub id: LensHandleName,
    pub label: LensText,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphEdge {
    pub from: LensHandleName,
    pub to: LensHandleName,
    pub label: LensText,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsofScrubberAtom {
    pub value: LensText,
    #[serde(default)]
    pub min: Option<LensText>,
    #[serde(default)]
    pub max: Option<LensText>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThrobberAtom {
    pub label: LensText,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoiceLineAtom {
    pub speaker: LensText,
    pub text: LensText,
    #[serde(default)]
    pub vad: Option<VadBadge>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VadBadge {
    Low,
    Neutral,
    High,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
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
            #[serde(default, deserialize_with = "deserialize_limited_vec")]
            options: Vec<SelfUiOption>,
            #[serde(default, deserialize_with = "deserialize_limited_vec")]
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
        let mut budget = LensBudget::default();
        atom.count_collection_items(&mut budget)
            .map_err(de::Error::custom)?;
        Ok(atom)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InspectorAtom {
    pub title: LensText,
    #[serde(default, deserialize_with = "deserialize_limited_vec")]
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
            #[serde(default, deserialize_with = "deserialize_limited_vec")]
            sections: Vec<SectionAtom>,
        }

        let wire = InspectorAtomWire::deserialize(deserializer)?;
        let atom = Self {
            title: wire.title,
            sections: wire.sections,
        };
        atom.validate().map_err(de::Error::custom)?;
        let mut budget = LensBudget::default();
        atom.count_collection_items(&mut budget)
            .map_err(de::Error::custom)?;
        Ok(atom)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SelfUiControl {
    Button(ButtonControl),
    Toggle(ToggleControl),
    Segmented(SegmentedControl),
    Select(SelectControl),
    Slider(SliderControl),
    TextInput(TextInputControl),
}

#[derive(Debug, Deserialize)]
#[serde(
    tag = "control",
    content = "props",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum SelfUiControlWire {
    Button(ButtonControl),
    Toggle(ToggleControl),
    Segmented(SegmentedControl),
    Select(SelectControl),
    Slider(SliderControl),
    TextInput(TextInputControl),
}

impl From<SelfUiControlWire> for SelfUiControl {
    fn from(value: SelfUiControlWire) -> Self {
        match value {
            SelfUiControlWire::Button(control) => Self::Button(control),
            SelfUiControlWire::Toggle(control) => Self::Toggle(control),
            SelfUiControlWire::Segmented(control) => Self::Segmented(control),
            SelfUiControlWire::Select(control) => Self::Select(control),
            SelfUiControlWire::Slider(control) => Self::Slider(control),
            SelfUiControlWire::TextInput(control) => Self::TextInput(control),
        }
    }
}

impl<'de> Deserialize<'de> for SelfUiControl {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let control = Self::from(SelfUiControlWire::deserialize(deserializer)?);
        control.validate().map_err(de::Error::custom)?;

        let mut budget = LensBudget::default();
        control
            .count_collection_items(&mut budget)
            .map_err(de::Error::custom)?;

        Ok(control)
    }
}

impl Serialize for SelfUiControl {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Button(props) => {
                serialize_tagged(serializer, "control", "button", "props", props)
            }
            Self::Toggle(props) => {
                serialize_tagged(serializer, "control", "toggle", "props", props)
            }
            Self::Segmented(props) => {
                serialize_tagged(serializer, "control", "segmented", "props", props)
            }
            Self::Select(props) => {
                serialize_tagged(serializer, "control", "select", "props", props)
            }
            Self::Slider(props) => {
                serialize_tagged(serializer, "control", "slider", "props", props)
            }
            Self::TextInput(props) => {
                serialize_tagged(serializer, "control", "text_input", "props", props)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ButtonControl {
    pub id: SelfUiControlId,
    pub label: LensText,
    pub action: SelfUiAction,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToggleControl {
    pub id: SelfUiControlId,
    pub label: LensText,
    pub checked: bool,
    pub action: SelfUiAction,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SegmentedControl {
    pub id: SelfUiControlId,
    pub label: LensText,
    pub options: Vec<SelfUiOption>,
    #[serde(default)]
    pub selected: Option<SelfUiOptionValue>,
    pub action: SelfUiAction,
}

impl<'de> Deserialize<'de> for SegmentedControl {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SegmentedControlWire {
            id: SelfUiControlId,
            label: LensText,
            #[serde(deserialize_with = "deserialize_limited_vec")]
            options: Vec<SelfUiOption>,
            #[serde(default)]
            selected: Option<SelfUiOptionValue>,
            action: SelfUiAction,
        }

        let wire = SegmentedControlWire::deserialize(deserializer)?;
        let control = Self {
            id: wire.id,
            label: wire.label,
            options: wire.options,
            selected: wire.selected,
            action: wire.action,
        };
        control.validate().map_err(de::Error::custom)?;
        Ok(control)
    }
}

impl SegmentedControl {
    fn validate(&self) -> Result<()> {
        validate_self_ui_options("segmented control options", &self.options)?;
        validate_selected_option(
            "segmented control selected value",
            &self.options,
            self.selected.as_ref(),
        )?;
        self.action.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SelectControl {
    pub id: SelfUiControlId,
    pub label: LensText,
    pub options: Vec<SelfUiOption>,
    #[serde(default)]
    pub selected: Option<SelfUiOptionValue>,
    pub action: SelfUiAction,
}

impl<'de> Deserialize<'de> for SelectControl {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SelectControlWire {
            id: SelfUiControlId,
            label: LensText,
            #[serde(deserialize_with = "deserialize_limited_vec")]
            options: Vec<SelfUiOption>,
            #[serde(default)]
            selected: Option<SelfUiOptionValue>,
            action: SelfUiAction,
        }

        let wire = SelectControlWire::deserialize(deserializer)?;
        let control = Self {
            id: wire.id,
            label: wire.label,
            options: wire.options,
            selected: wire.selected,
            action: wire.action,
        };
        control.validate().map_err(de::Error::custom)?;
        Ok(control)
    }
}

impl SelectControl {
    fn validate(&self) -> Result<()> {
        validate_self_ui_options("select control options", &self.options)?;
        validate_selected_option(
            "select control selected value",
            &self.options,
            self.selected.as_ref(),
        )?;
        self.action.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SliderControl {
    pub id: SelfUiControlId,
    pub label: LensText,
    pub min: FiniteF64,
    pub max: FiniteF64,
    pub step: FiniteF64,
    pub value: FiniteF64,
    pub action: SelfUiAction,
}

impl SliderControl {
    fn validate(&self) -> Result<()> {
        if self.min.get() > self.max.get() {
            return Err(Error::InvalidConfig(
                "self.ui slider min must be less than or equal to max".to_string(),
            ));
        }
        if self.step.get() <= 0.0 {
            return Err(Error::InvalidConfig(
                "self.ui slider step must be positive".to_string(),
            ));
        }
        if self.value.get() < self.min.get() || self.value.get() > self.max.get() {
            return Err(Error::InvalidConfig(
                "self.ui slider value must be within min and max".to_string(),
            ));
        }
        self.action.validate()
    }
}

impl<'de> Deserialize<'de> for SliderControl {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SliderControlWire {
            id: SelfUiControlId,
            label: LensText,
            min: FiniteF64,
            max: FiniteF64,
            step: FiniteF64,
            value: FiniteF64,
            action: SelfUiAction,
        }

        let wire = SliderControlWire::deserialize(deserializer)?;
        let slider = Self {
            id: wire.id,
            label: wire.label,
            min: wire.min,
            max: wire.max,
            step: wire.step,
            value: wire.value,
            action: wire.action,
        };
        slider.validate().map_err(de::Error::custom)?;
        Ok(slider)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextInputControl {
    pub id: SelfUiControlId,
    pub label: LensText,
    #[serde(default)]
    pub placeholder: Option<LensText>,
    #[serde(default)]
    pub value: Option<LensText>,
    pub action: SelfUiAction,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfUiOption {
    pub value: SelfUiOptionValue,
    pub label: LensText,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelfUiAction {
    pub command: SelfUiActionId,
    #[serde(default, deserialize_with = "deserialize_limited_vec")]
    pub args: Vec<SelfUiValue>,
}

impl<'de> Deserialize<'de> for SelfUiAction {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SelfUiActionWire {
            command: SelfUiActionId,
            #[serde(default, deserialize_with = "deserialize_limited_vec")]
            args: Vec<SelfUiValue>,
        }

        let wire = SelfUiActionWire::deserialize(deserializer)?;
        let action = Self {
            command: wire.command,
            args: wire.args,
        };
        action.validate().map_err(de::Error::custom)?;
        Ok(action)
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum SelfUiValue {
    Bool(bool),
    Number(FiniteF64),
    Text(LensText),
    Token(SelfUiOptionValue),
    Handle(LensHandleName),
}

impl Serialize for SelfUiValue {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Bool(value) => serialize_tagged(serializer, "type", "bool", "value", value),
            Self::Number(value) => serialize_tagged(serializer, "type", "number", "value", value),
            Self::Text(value) => serialize_tagged(serializer, "type", "text", "value", value),
            Self::Token(value) => serialize_tagged(serializer, "type", "token", "value", value),
            Self::Handle(value) => serialize_tagged(serializer, "type", "handle", "value", value),
        }
    }
}

fn serialize_tagged<S, T>(
    serializer: S,
    tag_field: &'static str,
    tag: &'static str,
    content_field: &'static str,
    content: &T,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize + ?Sized,
{
    let mut map = serializer.serialize_map(Some(2))?;
    map.serialize_entry(tag_field, tag)?;
    map.serialize_entry(content_field, content)?;
    map.end()
}

impl LensAtom {
    #[must_use]
    pub const fn primitive(&self) -> GeneratedUiPrimitive {
        match self {
            Self::TextBlock(_) => GeneratedUiPrimitive::TextBlock,
            Self::LedgerRow(_) => GeneratedUiPrimitive::LedgerRow,
            Self::ClaimLine(_) => GeneratedUiPrimitive::ClaimLine,
            Self::StatusDot(_) => GeneratedUiPrimitive::StatusDot,
            Self::Seal(_) => GeneratedUiPrimitive::Seal,
            Self::MetaLine(_) => GeneratedUiPrimitive::MetaLine,
            Self::DossierSection(_) => GeneratedUiPrimitive::DossierSection,
            Self::ThreadEntry(_) => GeneratedUiPrimitive::ThreadEntry,
            Self::Sheet(_) => GeneratedUiPrimitive::Sheet,
            Self::Slip(_) => GeneratedUiPrimitive::Slip,
            Self::Receipt(_) => GeneratedUiPrimitive::Receipt,
            Self::Charter(_) => GeneratedUiPrimitive::Charter,
            Self::Postmark(_) => GeneratedUiPrimitive::Postmark,
            Self::PackLine(_) => GeneratedUiPrimitive::PackLine,
            Self::AnswerSheet(_) => GeneratedUiPrimitive::AnswerSheet,
            Self::TwoClocks(_) => GeneratedUiPrimitive::TwoClocks,
            Self::NeighborhoodGraph(_) => GeneratedUiPrimitive::NeighborhoodGraph,
            Self::AsofScrubber(_) => GeneratedUiPrimitive::AsofScrubber,
            Self::Throbber(_) => GeneratedUiPrimitive::Throbber,
            Self::VoiceLine(_) => GeneratedUiPrimitive::VoiceLine,
            Self::QuickFilter(_) => GeneratedUiPrimitive::QuickFilter,
            Self::InspectorSheet(_) => GeneratedUiPrimitive::InspectorSheet,
            Self::InspectorRail(_) => GeneratedUiPrimitive::InspectorRail,
            Self::InspectorTrail(_) => GeneratedUiPrimitive::InspectorTrail,
            Self::SelfUi(_) => GeneratedUiPrimitive::SelfUi,
            Self::Media(_) => GeneratedUiPrimitive::Media,
        }
    }

    #[must_use]
    pub fn kind(&self) -> &'static str {
        self.primitive().as_str()
    }

    #[must_use]
    pub fn default_fallback_text(&self) -> LensText {
        let fallback = match self {
            Self::TextBlock(atom) => atom.fallback_text(),
            Self::LedgerRow(atom) => atom.cells.first().map_or_else(
                || "ledger row".to_string(),
                |cell| format!("{}: {}", cell.label.as_str(), cell.value.as_str()),
            ),
            Self::ClaimLine(atom) => format!(
                "{} {} {}",
                atom.subject.as_str(),
                atom.predicate.as_str(),
                atom.value.as_str()
            ),
            Self::StatusDot(atom) => atom.label.as_ref().map_or_else(
                || atom.status.as_str().to_string(),
                |label| label.as_str().to_string(),
            ),
            Self::Seal(atom) => atom.label.as_str().to_string(),
            Self::MetaLine(atom) => format!("{}: {}", atom.label.as_str(), atom.value.as_str()),
            Self::DossierSection(atom) | Self::Slip(atom) | Self::Charter(atom) => {
                atom.title.as_str().to_string()
            }
            Self::ThreadEntry(atom) => format!("{}: {}", atom.author.as_str(), atom.body.as_str()),
            Self::Sheet(atom) => atom.title.as_str().to_string(),
            Self::Receipt(atom) => atom.title.as_str().to_string(),
            Self::Postmark(atom) => format!("{} {}", atom.label.as_str(), atom.timestamp.as_str()),
            Self::PackLine(atom) => atom.summary.as_str().to_string(),
            Self::AnswerSheet(atom) => atom.answer.as_str().to_string(),
            Self::TwoClocks(atom) => {
                format!(
                    "{} / {}",
                    atom.occurred_at.as_str(),
                    atom.learned_at.as_str()
                )
            }
            Self::NeighborhoodGraph(atom) => format!("{} nodes", atom.nodes.len()),
            Self::AsofScrubber(atom) => atom.value.as_str().to_string(),
            Self::Throbber(atom) => atom.label.as_str().to_string(),
            Self::VoiceLine(atom) => atom.text.as_str().to_string(),
            Self::QuickFilter(atom) => atom.label.as_str().to_string(),
            Self::InspectorSheet(atom) | Self::InspectorRail(atom) | Self::InspectorTrail(atom) => {
                atom.title.as_str().to_string()
            }
            Self::SelfUi(control) => control.fallback_text(),
            Self::Media(atom) => atom.alt.as_str().to_string(),
        };
        fallback_lens_text(self.kind(), fallback)
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::TextBlock(atom) => atom.validate(),
            Self::LedgerRow(atom) => atom.validate(),
            Self::ClaimLine(_) | Self::StatusDot(_) | Self::Seal(_) | Self::MetaLine(_) => Ok(()),
            Self::DossierSection(atom) | Self::Slip(atom) | Self::Charter(atom) => atom.validate(),
            Self::ThreadEntry(_) => Ok(()),
            Self::Sheet(atom) => atom.validate(),
            Self::Receipt(atom) => atom.validate(),
            Self::Postmark(_) | Self::PackLine(_) | Self::TwoClocks(_) | Self::Throbber(_) => {
                Ok(())
            }
            Self::AnswerSheet(atom) => atom.validate(),
            Self::NeighborhoodGraph(atom) => atom.validate(),
            Self::AsofScrubber(_) | Self::VoiceLine(_) => Ok(()),
            Self::QuickFilter(atom) => atom.validate(),
            Self::InspectorSheet(atom) | Self::InspectorRail(atom) | Self::InspectorTrail(atom) => {
                atom.validate()
            }
            Self::SelfUi(control) => control.validate(),
            Self::Media(atom) => atom.validate(),
        }
    }

    fn count_collection_items(&self, budget: &mut LensBudget) -> Result<()> {
        match self {
            Self::TextBlock(atom) => budget.add_collection("text block spans", atom.spans.len()),
            Self::LedgerRow(atom) => budget.add_collection("ledger row cells", atom.cells.len()),
            Self::ClaimLine(_) | Self::StatusDot(_) | Self::Seal(_) | Self::MetaLine(_) => Ok(()),
            Self::DossierSection(atom) | Self::Slip(atom) | Self::Charter(atom) => {
                budget.add_collection("lens section lines", atom.lines.len())
            }
            Self::ThreadEntry(_) => Ok(()),
            Self::Sheet(atom) => atom.count_collection_items(budget),
            Self::Receipt(atom) => budget.add_collection("receipt lines", atom.lines.len()),
            Self::Postmark(_) | Self::PackLine(_) | Self::TwoClocks(_) | Self::Throbber(_) => {
                Ok(())
            }
            Self::AnswerSheet(atom) => {
                budget.add_collection("answer sheet citations", atom.citations.len())
            }
            Self::NeighborhoodGraph(atom) => {
                budget.add_collection("neighborhood graph nodes", atom.nodes.len())?;
                budget.add_collection("neighborhood graph edges", atom.edges.len())
            }
            Self::AsofScrubber(_) | Self::VoiceLine(_) => Ok(()),
            Self::QuickFilter(atom) => atom.count_collection_items(budget),
            Self::InspectorSheet(atom) | Self::InspectorRail(atom) | Self::InspectorTrail(atom) => {
                atom.count_collection_items(budget)
            }
            Self::SelfUi(control) => control.count_collection_items(budget),
            Self::Media(_) => Ok(()),
        }
    }
}

impl TextBlockAtom {
    fn validate(&self) -> Result<()> {
        validate_lens_collection_len("text block spans", self.spans.len())?;
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

    fn fallback_text(&self) -> String {
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
    fn validate(&self) -> Result<()> {
        validate_required_lens_text("media alt text", &self.alt)
    }
}

impl LedgerRowAtom {
    fn validate(&self) -> Result<()> {
        validate_lens_collection_len("ledger row cells", self.cells.len())
    }
}

impl SectionAtom {
    fn validate(&self) -> Result<()> {
        validate_lens_collection_len("lens section lines", self.lines.len())
    }
}

impl CollectionAtom {
    fn validate(&self) -> Result<()> {
        validate_lens_collection_len("lens collection rows", self.rows.len())?;
        for row in &self.rows {
            row.validate()?;
        }
        Ok(())
    }

    fn count_collection_items(&self, budget: &mut LensBudget) -> Result<()> {
        budget.add_collection("lens collection rows", self.rows.len())?;
        for row in &self.rows {
            budget.add_collection("ledger row cells", row.cells.len())?;
        }
        Ok(())
    }
}

impl ReceiptAtom {
    fn validate(&self) -> Result<()> {
        validate_lens_collection_len("receipt lines", self.lines.len())
    }
}

impl AnswerSheetAtom {
    fn validate(&self) -> Result<()> {
        validate_lens_collection_len("answer sheet citations", self.citations.len())
    }
}

impl NeighborhoodGraphAtom {
    fn validate(&self) -> Result<()> {
        validate_lens_collection_len("neighborhood graph nodes", self.nodes.len())?;
        validate_lens_collection_len("neighborhood graph edges", self.edges.len())?;

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
    fn validate(&self) -> Result<()> {
        validate_self_ui_options("quick filter options", &self.options)?;
        validate_lens_collection_len("quick filter selected values", self.selected.len())?;
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

    fn count_collection_items(&self, budget: &mut LensBudget) -> Result<()> {
        budget.add_collection("quick filter options", self.options.len())?;
        budget.add_collection("quick filter selected values", self.selected.len())?;
        budget.add_collection("self.ui action args", self.action.args.len())
    }
}

impl InspectorAtom {
    fn validate(&self) -> Result<()> {
        validate_lens_collection_len("inspector sections", self.sections.len())?;
        for section in &self.sections {
            section.validate()?;
        }
        Ok(())
    }

    fn count_collection_items(&self, budget: &mut LensBudget) -> Result<()> {
        budget.add_collection("inspector sections", self.sections.len())?;
        for section in &self.sections {
            budget.add_collection("lens section lines", section.lines.len())?;
        }
        Ok(())
    }
}

impl SelfUiControl {
    /// The single engine-declared action embedded in this control.
    #[must_use]
    pub fn action(&self) -> &SelfUiAction {
        match self {
            Self::Button(control) => &control.action,
            Self::Toggle(control) => &control.action,
            Self::Segmented(control) => &control.action,
            Self::Select(control) => &control.action,
            Self::Slider(control) => &control.action,
            Self::TextInput(control) => &control.action,
        }
    }

    fn fallback_text(&self) -> String {
        match self {
            Self::Button(control) => control.label.as_str().to_string(),
            Self::Toggle(control) => control.label.as_str().to_string(),
            Self::Segmented(control) => control.label.as_str().to_string(),
            Self::Select(control) => control.label.as_str().to_string(),
            Self::Slider(control) => control.label.as_str().to_string(),
            Self::TextInput(control) => control.label.as_str().to_string(),
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Button(control) => control.action.validate(),
            Self::Toggle(control) => control.action.validate(),
            Self::Segmented(control) => control.validate(),
            Self::Select(control) => control.validate(),
            Self::Slider(control) => control.validate(),
            Self::TextInput(control) => control.action.validate(),
        }
    }

    fn count_collection_items(&self, budget: &mut LensBudget) -> Result<()> {
        match self {
            Self::Button(control) => {
                budget.add_collection("self.ui action args", control.action.args.len())
            }
            Self::Toggle(control) => {
                budget.add_collection("self.ui action args", control.action.args.len())
            }
            Self::Segmented(control) => {
                budget.add_collection("segmented control options", control.options.len())?;
                budget.add_collection("self.ui action args", control.action.args.len())
            }
            Self::Select(control) => {
                budget.add_collection("select control options", control.options.len())?;
                budget.add_collection("self.ui action args", control.action.args.len())
            }
            Self::Slider(control) => {
                budget.add_collection("self.ui action args", control.action.args.len())
            }
            Self::TextInput(control) => {
                budget.add_collection("self.ui action args", control.action.args.len())
            }
        }
    }
}

impl SelfUiAction {
    fn validate(&self) -> Result<()> {
        validate_lens_collection_len("self.ui action args", self.args.len())
    }
}

fn validate_lens_tree(root: &LensNode) -> Result<()> {
    let mut stack = vec![(root, 1usize)];
    let mut node_count = 0usize;
    let mut budget = LensBudget::default();
    let mut seen_node_ids = HashSet::with_capacity(MAX_LENS_NODE_COUNT);

    while let Some((node, depth)) = stack.pop() {
        node_count += 1;
        if node_count > MAX_LENS_NODE_COUNT {
            return Err(Error::InvalidConfig(format!(
                "generated lens tree must contain at most {MAX_LENS_NODE_COUNT} nodes"
            )));
        }
        if !seen_node_ids.insert(node.id.as_str()) {
            return Err(Error::InvalidConfig(
                "generated lens nodes must not contain duplicate ids".to_string(),
            ));
        }
        if depth > MAX_LENS_TREE_DEPTH {
            return Err(Error::InvalidConfig(format!(
                "generated lens tree depth must be at most {MAX_LENS_TREE_DEPTH}"
            )));
        }

        budget.add_collection("lens node bindings", node.bindings.len())?;
        budget.add_collection("lens node $bind", node.state_bindings.len())?;
        budget.add_collection("lens node children", node.children.len())?;
        validate_required_lens_text("lens node fallbackText", &node.fallback_text)?;
        node.atom.validate()?;
        node.atom.count_collection_items(&mut budget)?;

        for child in node.children.iter().rev() {
            stack.push((child, depth + 1));
        }
    }

    Ok(())
}

#[derive(Default)]
struct LensBudget {
    collection_items: usize,
}

impl LensBudget {
    fn add_collection(&mut self, context: &str, len: usize) -> Result<()> {
        validate_lens_collection_len(context, len)?;
        self.collection_items = self.collection_items.checked_add(len).ok_or_else(|| {
            Error::InvalidConfig("generated lens collection budget overflowed".to_string())
        })?;
        if self.collection_items > MAX_LENS_COLLECTION_ITEMS {
            return Err(Error::InvalidConfig(format!(
                "generated lens collections must contain at most {MAX_LENS_COLLECTION_ITEMS} total items"
            )));
        }
        Ok(())
    }
}

fn validate_lens_collection_len(context: &str, len: usize) -> Result<()> {
    if len > MAX_LENS_COLLECTION_ITEMS {
        return Err(Error::InvalidConfig(format!(
            "{context} must contain at most {MAX_LENS_COLLECTION_ITEMS} items"
        )));
    }
    Ok(())
}

fn validate_generated_ui_node_count(context: &str, len: usize) -> Result<()> {
    validate_lens_collection_len(context, len)?;
    if len == 0 {
        return Err(Error::InvalidConfig(format!("{context} must be non-zero")));
    }
    Ok(())
}

fn validate_required_lens_text(context: &str, value: &LensText) -> Result<()> {
    if value.as_str().trim().is_empty() {
        return Err(Error::InvalidConfig(format!("{context} must not be empty")));
    }
    Ok(())
}

fn validate_generated_ui_protocol_version(protocol_version: u16) -> Result<()> {
    if protocol_version != GENERATED_UI_WIRE_VERSION {
        return Err(Error::InvalidConfig(format!(
            "unsupported generated-ui wire version {protocol_version}"
        )));
    }
    Ok(())
}

fn fallback_lens_text(kind: &'static str, value: String) -> LensText {
    LensText::new(value).unwrap_or_else(|_| LensText::new(kind).expect("static fallback is valid"))
}

fn compile_atom_for_surface(
    atom: &LensAtom,
    fallback_text: &LensText,
    surface: &GeneratedUiSurfaceCapabilities,
) -> LensAtom {
    if surface.supports(atom.primitive()) {
        return atom.clone();
    }

    LensAtom::TextBlock(TextBlockAtom {
        spans: vec![LensTextSpan::Literal(fallback_text.clone())],
    })
}

fn validate_self_ui_options(context: &str, options: &[SelfUiOption]) -> Result<()> {
    validate_lens_collection_len(context, options.len())?;

    let mut seen = HashSet::with_capacity(options.len());
    for option in options {
        if !seen.insert(option.value.as_str()) {
            return Err(Error::InvalidConfig(format!(
                "{context} must not contain duplicate values"
            )));
        }
    }

    Ok(())
}

fn validate_selected_option(
    context: &str,
    options: &[SelfUiOption],
    selected: Option<&SelfUiOptionValue>,
) -> Result<()> {
    let Some(selected) = selected else {
        return Ok(());
    };

    if options
        .iter()
        .any(|option| option.value.as_str() == selected.as_str())
    {
        return Ok(());
    }

    Err(Error::InvalidConfig(format!(
        "{context} must be present in options"
    )))
}

fn validate_lens_token(context: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::InvalidConfig(format!("{context} must not be empty")));
    }
    if value.len() > MAX_LENS_TOKEN_BYTES {
        return Err(Error::InvalidConfig(format!(
            "{context} must be at most {MAX_LENS_TOKEN_BYTES} bytes"
        )));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(Error::InvalidConfig(format!(
            "{context} must use only ASCII alnum, '.', '_', or '-'"
        )));
    }

    Ok(())
}

fn validate_lens_capability_name(context: &str, value: &str) -> Result<()> {
    if names_forbidden_lens_capability(value) {
        return Err(Error::InvalidConfig(format!(
            "{context} names a forbidden lens capability"
        )));
    }

    Ok(())
}

fn names_forbidden_lens_capability(value: &str) -> bool {
    let normalized = normalize_lens_capability_name(value);
    normalized.split('_').any(|segment| {
        matches!(
            segment,
            "script" | "javascript" | "eval" | "fetch" | "network" | "storage"
        )
    })
}

fn normalize_lens_capability_name(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut normalized = String::with_capacity(value.len());

    for (index, byte) in bytes.iter().copied().enumerate() {
        match byte {
            b'.' | b'-' | b'_' => {
                if !normalized.ends_with('_') {
                    normalized.push('_');
                }
            }
            b'A'..=b'Z' => {
                let previous_is_lower_or_digit = index > 0
                    && (bytes[index - 1].is_ascii_lowercase() || bytes[index - 1].is_ascii_digit());
                let acronym_boundary = index > 0
                    && index + 1 < bytes.len()
                    && bytes[index - 1].is_ascii_uppercase()
                    && bytes[index + 1].is_ascii_lowercase();
                if (previous_is_lower_or_digit || acronym_boundary) && !normalized.ends_with('_') {
                    normalized.push('_');
                }
                normalized.push(byte.to_ascii_lowercase() as char);
            }
            _ => normalized.push(byte as char),
        }
    }

    normalized
}

#[cfg(test)]
mod tests;
