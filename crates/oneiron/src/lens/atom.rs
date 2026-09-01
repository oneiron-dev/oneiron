//! The closed [`LensAtom`] vocabulary: the atom enum, its leaf payload structs,
//! [`LensNode`] with its depth-bounded deserializer, and the per-atom
//! validate/fallback/budget impls. Interactive controls live in
//! [`super::self_ui`]; the free validators live in [`super::validate`].

use std::{collections::HashSet, fmt, marker::PhantomData};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de, de::DeserializeSeed};

use crate::{Error, Result};

use super::generated_ui::{
    GeneratedUiActionDeclaration, GeneratedUiActionEvent, GeneratedUiActionTier,
    GeneratedUiPrimitive, SelfUiBinding,
};
use super::self_ui::{SelfUiAction, SelfUiControl, SelfUiOption};
use super::validate::{
    LensBudget, fallback_lens_text, validate_lens_collection_len, validate_lens_tree,
    validate_required_lens_text, validate_selected_option, validate_self_ui_options,
};
use super::wire_ids::{
    LensAtomId, LensHandleName, LensHandleRef, LensMediaHandle, LensResultSetRowId,
    MAX_LENS_COLLECTION_ITEMS, MAX_LENS_TREE_DEPTH, SelfUiActionId, SelfUiControlId,
    SelfUiOptionValue,
};
use super::wire_limits::{
    LimitedVecSeed, deserialize_limited_vec, max_lens_collection_items_error,
    reject_lens_sequence_hint, serialize_tagged,
};

pub const LENS_ATOM_KIT_VERSION: u16 = 3;

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
    "result_set",
];

/// Wire name of the selectable result-set atom minted at catalog version 3.
pub const RESULT_SET_ATOM_KIND: &str = "result_set";

/// The single rejection a surface below catalog 3 — or one whose primitive list omits
/// [`GeneratedUiPrimitive::ResultSet`] — gets. A result set never lowers to fallback
/// text: a degraded selection surface would offer rows the host cannot resolve.
pub const LENS_RESULT_SET_UNSUPPORTED: &str = "result_set requires lens atom catalog version 3";

pub(super) const MAX_LENS_TEXT_BYTES: usize = 16 * 1024;

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

pub(super) struct LensNodeSeed {
    pub(super) depth: usize,
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
    ResultSet(GeneratedUiResultSetAtom),
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
    ResultSet(GeneratedUiResultSetAtom),
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
            LensAtomWire::ResultSet(atom) => Self::ResultSet(atom),
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
            Self::ResultSet(props) => {
                serialize_tagged(serializer, "kind", RESULT_SET_ATOM_KIND, "props", props)
            }
        }
    }
}

/// One rendered row of a result set. `id` is an opaque echo token the client hands
/// back to name a row; it is never authority, and `label` is display data the host
/// never parses. The reach a row can prove is `target_handle`, which the node itself
/// has to advertise as one of its declared backing handles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum GeneratedUiResultSetSelectAll {
    Disabled {},
    WithinFilter { predicate_handle: LensHandleName },
}

/// The selectable result-set atom. `action_bar` is an *eligibility allowlist* of
/// card-declared, `self.ui`-hosted, deterministic-tier action ids: the atom hosts no
/// action of its own, so the landed one-action-per-element and
/// declarations-name-a-self.ui-control gates keep deciding what is interactive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedUiResultSetAtom {
    #[serde(deserialize_with = "deserialize_limited_vec")]
    pub rows: Vec<GeneratedUiResultSetRow>,
    pub select_all: GeneratedUiResultSetSelectAll,
    #[serde(default, deserialize_with = "deserialize_limited_vec")]
    pub action_bar: Vec<SelfUiActionId>,
}

/// Client-authored selection payload. It rides on the `self.ui`-hosted action event
/// and names *which rendered rows were ticked* and nothing else: `AllWithinFilter`
/// carries no fields at all, so the predicate can only come from the rendered atom.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum GeneratedUiResultSetSelection {
    Explicit {
        #[serde(deserialize_with = "deserialize_limited_vec")]
        row_ids: Vec<LensResultSetRowId>,
    },
    AllWithinFilter {},
}

/// A `self.ui`-hosted action event plus the result-set selection it carries. Selection
/// is not approval: this is still only *what was touched*.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedUiResultSetActionEvent {
    pub action: GeneratedUiActionEvent,
    pub selection: GeneratedUiResultSetSelection,
}

impl GeneratedUiResultSetAtom {
    fn validate(&self) -> Result<()> {
        validate_lens_collection_len("result set rows", self.rows.len())?;
        validate_lens_collection_len("result set action bar", self.action_bar.len())?;

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

    fn count_collection_items(&self, budget: &mut LensBudget) -> Result<()> {
        budget.add_collection("result set rows", self.rows.len())?;
        budget.add_collection("result set action bar", self.action_bar.len())
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
            Self::ResultSet(_) => GeneratedUiPrimitive::ResultSet,
        }
    }

    #[must_use]
    pub fn kind(&self) -> &'static str {
        self.primitive().as_str()
    }

    /// Build a validated result-set atom. Row-id and action-bar uniqueness are proved
    /// here, exactly as they are on the wire.
    pub fn result_set(atom: GeneratedUiResultSetAtom) -> Result<Self> {
        let atom = Self::ResultSet(atom);
        atom.validate()?;
        Ok(atom)
    }

    #[must_use]
    pub fn result_set_payload(&self) -> Option<&GeneratedUiResultSetAtom> {
        match self {
            Self::ResultSet(atom) => Some(atom),
            _ => None,
        }
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
            // Row labels are display data the host never parses, and a row count is
            // reach metadata. The fallback stays a static literal.
            Self::ResultSet(_) => "result set".to_string(),
        };
        fallback_lens_text(self.kind(), fallback)
    }

    pub(super) fn validate(&self) -> Result<()> {
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
            Self::ResultSet(atom) => atom.validate(),
        }
    }

    pub(super) fn count_collection_items(&self, budget: &mut LensBudget) -> Result<()> {
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
            Self::ResultSet(atom) => atom.count_collection_items(budget),
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

    pub(super) fn fallback_text(&self) -> String {
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
