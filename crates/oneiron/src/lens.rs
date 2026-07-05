//! Closed generated-lens atom vocabulary.
//!
//! Generated lenses are data that the trusted renderer interprets. This module
//! intentionally contains no raw script, URL/network, browser-storage, or eval
//! leaf types.

use std::{collections::HashSet, fmt, marker::PhantomData};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer, de, de::DeserializeSeed, ser::SerializeMap,
};

use crate::{
    Error, Result,
    claim::{ScopedRead, ScopedReadActorKey},
    types::{ENTITY_TYPE_CLAIM, EdgeActorClass, EntityId},
};

pub const LENS_ATOM_KIT_VERSION: u16 = 1;

pub const GENERATED_LENS_ATOM_KINDS: &[&str] = &[
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
lens_token_type!(SelfUiControlId, "self.ui control id");
lens_token_type!(SelfUiActionId, "self.ui action id", true);
lens_token_type!(SelfUiOptionValue, "self.ui option value");

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
    #[serde(default)]
    pub bindings: Vec<LensHandleRef>,
    #[serde(default)]
    pub children: Vec<LensNode>,
}

impl LensNode {
    #[must_use]
    pub fn new(id: LensAtomId, atom: LensAtom) -> Self {
        Self {
            id,
            atom,
            bindings: Vec::new(),
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

struct LensNodeSeed {
    depth: usize,
}

impl<'de> de::DeserializeSeed<'de> for LensNodeSeed {
    type Value = LensNode;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if self.depth > MAX_LENS_TREE_DEPTH {
            return Err(de::Error::custom(format!(
                "generated lens tree depth must be at most {MAX_LENS_TREE_DEPTH}"
            )));
        }

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Id,
            Atom,
            Bindings,
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
                let mut bindings = None;
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
                        Field::Bindings => {
                            if bindings.is_some() {
                                return Err(de::Error::duplicate_field("bindings"));
                            }
                            bindings =
                                Some(map.next_value_seed(LimitedVecSeed::<LensHandleRef> {
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
                    bindings: bindings.unwrap_or_default(),
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
                let bindings = seq
                    .next_element_seed(LimitedVecSeed::<LensHandleRef> {
                        _marker: PhantomData,
                    })?
                    .unwrap_or_default();
                let children = seq
                    .next_element_seed(LensChildrenSeed {
                        child_depth: self.depth + 1,
                    })?
                    .unwrap_or_default();
                if seq.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::invalid_length(5, &self));
                }

                Ok(LensNode {
                    id,
                    atom,
                    bindings,
                    children,
                })
            }
        }

        deserializer.deserialize_struct(
            "LensNode",
            &["id", "atom", "bindings", "children"],
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
}

#[derive(Debug, Deserialize)]
#[serde(
    tag = "kind",
    content = "props",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum LensAtomWire {
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
}

impl From<LensAtomWire> for LensAtom {
    fn from(value: LensAtomWire) -> Self {
        match value {
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
        }
    }
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
    pub fn kind(&self) -> &'static str {
        match self {
            Self::LedgerRow(_) => "ledger_row",
            Self::ClaimLine(_) => "claim_line",
            Self::StatusDot(_) => "status_dot",
            Self::Seal(_) => "seal",
            Self::MetaLine(_) => "meta_line",
            Self::DossierSection(_) => "dossier_section",
            Self::ThreadEntry(_) => "thread_entry",
            Self::Sheet(_) => "sheet",
            Self::Slip(_) => "slip",
            Self::Receipt(_) => "receipt",
            Self::Charter(_) => "charter",
            Self::Postmark(_) => "postmark",
            Self::PackLine(_) => "pack_line",
            Self::AnswerSheet(_) => "answer_sheet",
            Self::TwoClocks(_) => "two_clocks",
            Self::NeighborhoodGraph(_) => "neighborhood_graph",
            Self::AsofScrubber(_) => "asof_scrubber",
            Self::Throbber(_) => "throbber",
            Self::VoiceLine(_) => "voice_line",
            Self::QuickFilter(_) => "quick_filter",
            Self::InspectorSheet(_) => "inspector_sheet",
            Self::InspectorRail(_) => "inspector_rail",
            Self::InspectorTrail(_) => "inspector_trail",
            Self::SelfUi(_) => "self_ui",
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
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
        }
    }

    fn count_collection_items(&self, budget: &mut LensBudget) -> Result<()> {
        match self {
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
        }
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
        budget.add_collection("lens node children", node.children.len())?;
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
mod tests {
    use serde_json::json;

    use super::*;

    fn id(value: &str) -> LensAtomId {
        LensAtomId::new(value).expect("valid atom id")
    }

    fn handle(value: &str) -> LensHandleName {
        LensHandleName::new(value).expect("valid handle")
    }

    fn render_id(value: &str) -> LensRenderId {
        LensRenderId::new(value).expect("valid render id")
    }

    fn backing_ref_id(value: &str) -> LensBackingRefId {
        LensBackingRefId::new(value).expect("valid backing ref id")
    }

    fn control_id(value: &str) -> SelfUiControlId {
        SelfUiControlId::new(value).expect("valid control id")
    }

    fn action_id(value: &str) -> SelfUiActionId {
        SelfUiActionId::new(value).expect("valid action id")
    }

    fn option_value(value: &str) -> SelfUiOptionValue {
        SelfUiOptionValue::new(value).expect("valid option value")
    }

    fn text(value: &str) -> LensText {
        LensText::new(value).expect("valid text")
    }

    fn action(command: &str) -> SelfUiAction {
        SelfUiAction {
            command: action_id(command),
            args: Vec::new(),
        }
    }

    fn finite(value: f64) -> FiniteF64 {
        FiniteF64::new(value).expect("valid finite number")
    }

    fn actor_key(value: &str) -> ScopedReadActorKey {
        ScopedReadActorKey::new(value).expect("valid actor key")
    }

    fn test_entity_id(seed: u8) -> EntityId {
        EntityId::from_bytes([seed; 16]).expect("valid entity id")
    }

    fn put_person(vault: &crate::Vault, id: &EntityId) -> Result<()> {
        vault.put_entity(
            id,
            crate::types::ENTITY_TYPE_PERSON,
            crate::types::TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
    }

    fn put_profile_claim(vault: &crate::Vault, id: &EntityId, subject: &EntityId) -> Result<()> {
        let body = crate::claim::ClaimBody::new(
            "profile.likes",
            crate::claim::ClaimSubject::Entity(*subject),
            rmpv::Value::from("tea"),
            0.75,
            crate::claim::ClaimApprovalStatus::Approved,
            crate::claim::ClaimLifecycleStatus::Active,
        );
        vault.put_claim(id, &body, crate::types::TimeRange { start: 1, end: 1 }, 2)
    }

    fn backing_target_for(
        vault: &crate::Vault,
        id: &EntityId,
        kind: LensBackingTargetKind,
    ) -> Result<LensBackingTarget> {
        let rtxn = vault.store.env.read_txn()?;
        let value = vault
            .store
            .short_ids_reverse
            .get(&rtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let (short_id, content_hash) = crate::batch::parse_short_id_value(value)?;
        match kind {
            LensBackingTargetKind::Entity => {
                LensBackingTarget::entity(*id, short_id.to_owned(), content_hash)
            }
            LensBackingTargetKind::Claim => {
                LensBackingTarget::claim(*id, short_id.to_owned(), content_hash)
            }
        }
    }

    fn test_vault() -> (tempfile::TempDir, crate::Vault) {
        crate::test_util::open_test_vault_with(crate::types::VaultConfig::default())
    }

    fn status() -> StatusDotAtom {
        StatusDotAtom {
            status: LensStatus::Approved,
            label: Some(text("approved")),
        }
    }

    fn seal() -> SealAtom {
        SealAtom {
            level: SealLevel::Actor,
            label: text("actor-sealed"),
        }
    }

    fn rows_at_collection_limit_with_one_cell_each() -> Vec<LedgerRowAtom> {
        (0..MAX_LENS_COLLECTION_ITEMS)
            .map(|index| LedgerRowAtom {
                cells: vec![LedgerCell {
                    label: text(&format!("label-{index}")),
                    value: text("value"),
                }],
                status: None,
                seal: None,
            })
            .collect()
    }

    fn sections_at_collection_limit_with_one_line_each() -> Vec<SectionAtom> {
        (0..MAX_LENS_COLLECTION_ITEMS)
            .map(|index| SectionAtom {
                title: text(&format!("section-{index}")),
                lines: vec![text(&format!("line-{index}"))],
            })
            .collect()
    }

    fn options_at_collection_limit() -> Vec<SelfUiOption> {
        (0..MAX_LENS_COLLECTION_ITEMS)
            .map(|index| SelfUiOption {
                value: option_value(&format!("option-{index}")),
                label: text(&format!("Option {index}")),
            })
            .collect()
    }

    fn sample_atoms() -> Vec<LensAtom> {
        vec![
            LensAtom::LedgerRow(LedgerRowAtom {
                cells: vec![LedgerCell {
                    label: text("predicate"),
                    value: text("works_at"),
                }],
                status: Some(status()),
                seal: Some(seal()),
            }),
            LensAtom::ClaimLine(ClaimLineAtom {
                subject: text("Ada"),
                predicate: text("works_at"),
                value: text("Analytical Engines"),
                status: status(),
                seal: Some(seal()),
            }),
            LensAtom::StatusDot(status()),
            LensAtom::Seal(seal()),
            LensAtom::MetaLine(MetaLineAtom {
                label: text("source"),
                value: text("vault"),
            }),
            LensAtom::DossierSection(SectionAtom {
                title: text("Profile"),
                lines: vec![text("Mathematician")],
            }),
            LensAtom::ThreadEntry(ThreadEntryAtom {
                author: text("Dreamer"),
                body: text("Proposed update"),
                timestamp: Some(text("2026-07-03T00:00:00Z")),
                seal: Some(seal()),
            }),
            LensAtom::Sheet(CollectionAtom {
                title: text("Claims"),
                rows: Vec::new(),
            }),
            LensAtom::Slip(SectionAtom {
                title: text("Slip"),
                lines: Vec::new(),
            }),
            LensAtom::Receipt(ReceiptAtom {
                title: text("Receipt"),
                lines: vec![MetaLineAtom {
                    label: text("hash"),
                    value: text("abc123"),
                }],
                seal: Some(seal()),
            }),
            LensAtom::Charter(SectionAtom {
                title: text("Charter"),
                lines: vec![text("Read only")],
            }),
            LensAtom::Postmark(PostmarkAtom {
                label: text("learned"),
                timestamp: text("2026-07-03T00:00:00Z"),
            }),
            LensAtom::PackLine(PackLineAtom {
                pack: text("crm"),
                summary: text("installed"),
                status: LensStatus::Complete,
            }),
            LensAtom::AnswerSheet(AnswerSheetAtom {
                question: text("Who?"),
                answer: text("Ada"),
                citations: vec![LensHandleRef {
                    name: handle("claim_set"),
                    role: LensHandleRole::ClaimSet,
                }],
            }),
            LensAtom::TwoClocks(TwoClocksAtom {
                occurred_at: text("1843"),
                learned_at: text("2026"),
            }),
            LensAtom::NeighborhoodGraph(NeighborhoodGraphAtom {
                nodes: vec![GraphNode {
                    id: handle("ada"),
                    label: text("Ada"),
                }],
                edges: Vec::new(),
            }),
            LensAtom::AsofScrubber(AsofScrubberAtom {
                value: text("now"),
                min: None,
                max: None,
            }),
            LensAtom::Throbber(ThrobberAtom {
                label: text("loading"),
            }),
            LensAtom::VoiceLine(VoiceLineAtom {
                speaker: text("Ada"),
                text: text("hello"),
                vad: Some(VadBadge::Neutral),
            }),
            LensAtom::QuickFilter(QuickFilterAtom {
                id: control_id("status_filter"),
                label: text("Status"),
                options: vec![SelfUiOption {
                    value: option_value("approved"),
                    label: text("Approved"),
                }],
                selected: vec![option_value("approved")],
                action: action("filter_status"),
            }),
            LensAtom::InspectorSheet(InspectorAtom {
                title: text("Inspector"),
                sections: Vec::new(),
            }),
            LensAtom::InspectorRail(InspectorAtom {
                title: text("Rail"),
                sections: Vec::new(),
            }),
            LensAtom::InspectorTrail(InspectorAtom {
                title: text("Trail"),
                sections: Vec::new(),
            }),
            LensAtom::SelfUi(SelfUiControl::Button(ButtonControl {
                id: control_id("refresh"),
                label: text("Refresh"),
                action: action("refresh_lens"),
            })),
        ]
    }

    #[test]
    fn atom_kind_catalog_matches_closed_enum() {
        let atoms = sample_atoms();
        assert_eq!(atoms.len(), GENERATED_LENS_ATOM_KINDS.len());

        let mut unique = HashSet::new();
        for (atom, expected_kind) in atoms.iter().zip(GENERATED_LENS_ATOM_KINDS) {
            let observed_kind = atom.kind();
            assert_eq!(observed_kind, *expected_kind);
            assert!(
                unique.insert(observed_kind),
                "duplicate kind {observed_kind}"
            );

            let value = serde_json::to_value(atom).expect("atom encodes");
            assert_eq!(
                value.get("kind").and_then(serde_json::Value::as_str),
                Some(observed_kind)
            );
            let decoded: LensAtom = serde_json::from_value(value).expect("atom decodes");
            assert_eq!(decoded.kind(), observed_kind);
        }
    }

    #[test]
    fn render_principal_key_selection_must_be_held_by_principal() {
        let human_key = actor_key("human-viewer");
        let agent_key =
            ScopedReadActorKey::with_actor_class("task-agent", "agent").expect("agent key");

        let human = LensPrincipalBinding::human_view(
            "human-viewer",
            human_key.clone(),
            vec![human_key.clone()],
        )
        .expect("human binding");
        assert_eq!(human.kind(), LensActingPrincipalKind::HumanView);
        assert_eq!(human.selected_read_key(), &human_key);

        let agent = LensPrincipalBinding::agent_task(
            "task-agent",
            agent_key.clone(),
            vec![agent_key.clone()],
        )
        .expect("agent binding");
        assert_eq!(agent.kind(), LensActingPrincipalKind::AgentTask);

        assert!(
            LensPrincipalBinding::agent_task("task-agent", human_key, vec![agent_key]).is_err(),
            "over-scope render key selection must fail containment"
        );
        assert!(
            LensPrincipalBinding::human_view(" ", actor_key("viewer"), vec![actor_key("viewer")])
                .is_err(),
            "blank principal refs cannot bind a render"
        );
        assert!(
            LensPrincipalBinding::human_view("viewer", actor_key("viewer"), Vec::new()).is_err(),
            "principal bindings must name at least one held read key"
        );
        assert!(
            LensPrincipalBinding::human_view(
                "viewer-a",
                actor_key("viewer-a"),
                vec![actor_key("viewer-b")]
            )
            .is_err(),
            "held read keys must belong to the acting principal"
        );
        assert!(
            LensPrincipalBinding::human_view(
                "viewer",
                ScopedReadActorKey::with_actor_class("viewer", "agent").expect("agent key"),
                vec![ScopedReadActorKey::with_actor_class("viewer", "agent").expect("agent key")]
            )
            .is_err(),
            "human renders must not bind an agent-class read key"
        );
    }

    #[test]
    fn forged_and_foreign_backing_ref_tokens_do_not_resolve() -> Result<()> {
        let (_tmp, vault) = test_vault();
        let target_id = test_entity_id(7);
        put_person(&vault, &target_id)?;

        let viewer_key = actor_key("viewer");
        let scoped_read = vault.scoped_read(viewer_key.clone());
        let principal =
            LensPrincipalBinding::human_view("viewer", viewer_key.clone(), vec![viewer_key])?;
        let mut frame = LensRenderFrame::new(render_id("render-a"), principal);
        let token = frame.mint_backing_ref(
            &scoped_read,
            handle("visible-person"),
            LensHandleRole::ActionTarget,
            backing_target_for(&vault, &target_id, LensBackingTargetKind::Entity)?,
        )?;

        let resolved = frame.resolve_backing_ref_token(&scoped_read, &token)?;
        assert_eq!(resolved.target().entity_id(), &target_id);

        let foreign_token = LensBackingRefToken {
            render_id: render_id("render-b"),
            ref_id: token.ref_id().clone(),
        };
        assert!(
            frame
                .resolve_backing_ref_token(&scoped_read, &foreign_token)
                .is_err(),
            "a token minted for another render must not select this render's target"
        );

        let forged_token = LensBackingRefToken {
            render_id: render_id("render-a"),
            ref_id: backing_ref_id("ref-999"),
        };
        assert!(
            frame
                .resolve_backing_ref_token(&scoped_read, &forged_token)
                .is_err(),
            "a token absent from the host backing table must not resolve"
        );

        let other_key = actor_key("other-viewer");
        let other_read = vault.scoped_read(other_key);
        assert!(
            frame
                .resolve_backing_ref_token(&other_read, &token)
                .is_err(),
            "render-bound selections must be rechecked under the acting principal key"
        );

        Ok(())
    }

    #[test]
    fn lens_actions_resolve_only_host_bound_handles() -> Result<()> {
        let (_tmp, vault) = test_vault();
        let target_id = test_entity_id(8);
        put_person(&vault, &target_id)?;

        let viewer_key = actor_key("viewer");
        let scoped_read = vault.scoped_read(viewer_key.clone());
        let principal =
            LensPrincipalBinding::human_view("viewer", viewer_key.clone(), vec![viewer_key])?;
        let mut frame = LensRenderFrame::new(render_id("render-a"), principal);
        let target = backing_target_for(&vault, &target_id, LensBackingTargetKind::Entity)?;
        let expected_short_ref = target.short_ref();
        frame.mint_backing_ref(
            &scoped_read,
            handle("selected-person"),
            LensHandleRole::ActionTarget,
            target.clone(),
        )?;
        assert!(
            frame
                .mint_backing_ref(
                    &scoped_read,
                    handle("selected-person"),
                    LensHandleRole::ActionTarget,
                    target.clone(),
                )
                .is_err(),
            "one handle must not bind multiple backing refs in a render"
        );
        frame.mint_backing_ref(
            &scoped_read,
            handle("visible-set"),
            LensHandleRole::EntitySet,
            target,
        )?;

        let action = SelfUiAction {
            command: action_id("remember"),
            args: vec![SelfUiValue::Handle(handle("selected-person"))],
        };
        let approved = frame.approve_action(&scoped_read, &action)?;
        assert_eq!(approved.command().as_str(), "remember");
        match &approved.args()[0] {
            LensApprovedActionArg::BackingRef(backing_ref) => {
                assert_eq!(backing_ref.target().entity_id(), &target_id);
                assert_eq!(backing_ref.target().short_ref(), expected_short_ref);
            }
            other => panic!("expected host backing ref, got {other:?}"),
        }

        let forged = SelfUiAction {
            command: action_id("remember"),
            args: vec![SelfUiValue::Handle(handle("cl999"))],
        };
        assert!(
            frame.approve_action(&scoped_read, &forged).is_err(),
            "lens-supplied ids that were never host-bound must fail at the action boundary"
        );
        let wrong_role = SelfUiAction {
            command: action_id("remember"),
            args: vec![SelfUiValue::Handle(handle("visible-set"))],
        };
        assert!(
            frame.approve_action(&scoped_read, &wrong_role).is_err(),
            "only action-target handles can become approved backing refs"
        );

        Ok(())
    }

    #[test]
    fn backing_refs_recheck_short_ref_and_target_kind_under_scoped_read() -> Result<()> {
        let (_tmp, vault) = test_vault();
        let subject_id = test_entity_id(9);
        let claim_id = test_entity_id(10);
        put_person(&vault, &subject_id)?;
        put_profile_claim(&vault, &claim_id, &subject_id)?;

        let viewer_key = actor_key("viewer");
        let scoped_read = vault.scoped_read(viewer_key.clone());
        let principal =
            LensPrincipalBinding::human_view("viewer", viewer_key.clone(), vec![viewer_key])?;
        let mut frame = LensRenderFrame::new(render_id("render-a"), principal);

        assert!(
            frame
                .mint_backing_ref(
                    &scoped_read,
                    handle("wrong-kind"),
                    LensHandleRole::ActionTarget,
                    backing_target_for(&vault, &subject_id, LensBackingTargetKind::Claim)?,
                )
                .is_err(),
            "claim backing refs must resolve to claim entities"
        );
        assert!(
            frame
                .mint_backing_ref(
                    &scoped_read,
                    handle("claim-as-entity"),
                    LensHandleRole::ActionTarget,
                    backing_target_for(&vault, &claim_id, LensBackingTargetKind::Entity)?,
                )
                .is_err(),
            "entity backing refs must not hide claim targets"
        );

        let mut drifted = backing_target_for(&vault, &subject_id, LensBackingTargetKind::Entity)?;
        drifted.entity_id = claim_id;
        assert!(
            frame
                .mint_backing_ref(
                    &scoped_read,
                    handle("drifted-short-ref"),
                    LensHandleRole::ActionTarget,
                    drifted,
                )
                .is_err(),
            "short refs must hydrate back to the host-selected entity"
        );

        Ok(())
    }

    #[test]
    fn lens_execution_rejects_write_imports_and_host_writes_name_gate_chokepoint() -> Result<()> {
        let boundary = LensExecutionBoundary::read_only(vec![
            LensHostImport::ScopedRead,
            LensHostImport::ResolveBackingRef,
            LensHostImport::EmitAtom,
        ])?;
        assert_eq!(boundary.imports().len(), 3);

        assert!(
            LensExecutionBoundary::read_only(vec![
                LensHostImport::ScopedRead,
                LensHostImport::BatchWrite,
            ])
            .is_err(),
            "lens execution must expose zero write imports"
        );

        let action = LensApprovedAction {
            command: action_id("propose_claim"),
            args: Vec::new(),
        };
        let write =
            action.into_host_mediated_write(LensGateWriteChokepoint::CheckClaimPolicyForWrite);
        assert_eq!(
            write.chokepoint(),
            LensGateWriteChokepoint::CheckClaimPolicyForWrite
        );

        Ok(())
    }

    #[test]
    fn allowed_atom_kit_round_trips_json_and_msgpack() {
        let mut root = LensNode::new(
            id("root"),
            LensAtom::Sheet(CollectionAtom {
                title: text("Vault"),
                rows: Vec::new(),
            }),
        );
        root.children = sample_atoms()
            .into_iter()
            .enumerate()
            .map(|(index, atom)| LensNode::new(id(&format!("atom-{index}")), atom))
            .collect();

        let lens = GeneratedLens::new(root).expect("valid lens");
        let json = serde_json::to_vec(&lens).expect("json encode");
        let decoded: GeneratedLens = serde_json::from_slice(&json).expect("json decode");
        assert_eq!(decoded, lens);

        let msgpack = rmp_serde::to_vec_named(&lens).expect("msgpack encode");
        let decoded: GeneratedLens = rmp_serde::from_slice(&msgpack).expect("msgpack decode");
        assert_eq!(decoded, lens);

        let positional_msgpack = rmp_serde::to_vec(&lens).expect("positional msgpack encode");
        let decoded: GeneratedLens =
            rmp_serde::from_slice(&positional_msgpack).expect("positional msgpack decode");
        assert_eq!(decoded, lens);
    }

    #[test]
    fn unsafe_raw_atom_variants_are_rejected() {
        for kind in [
            "raw_script",
            "script",
            "network_request",
            "storage_read",
            "eval",
        ] {
            let attempted = json!({
                "kit_version": LENS_ATOM_KIT_VERSION,
                "root": {
                    "id": "root",
                    "atom": {
                        "kind": kind,
                        "props": {
                            "code": "fetch('https://attacker.example')"
                        }
                    }
                }
            });

            assert!(
                serde_json::from_value::<GeneratedLens>(attempted).is_err(),
                "unsafe atom kind {kind} should be rejected"
            );
        }
    }

    #[test]
    fn raw_script_network_storage_eval_props_are_rejected() {
        for forbidden_prop in [
            "on_click", "script", "src", "href", "fetch", "storage", "eval",
        ] {
            let attempted = json!({
                "kit_version": LENS_ATOM_KIT_VERSION,
                "root": {
                    "id": "root",
                    "atom": {
                        "kind": "self_ui",
                        "props": {
                            "control": "button",
                            "props": {
                                "id": "refresh",
                                "label": "Refresh",
                                "action": { "command": "refresh_lens" },
                                forbidden_prop: "javascript:alert(1)"
                            }
                        }
                    }
                }
            });

            assert!(
                serde_json::from_value::<GeneratedLens>(attempted).is_err(),
                "raw prop {forbidden_prop} should be rejected"
            );

            let attempted = json!({
                "kit_version": LENS_ATOM_KIT_VERSION,
                "root": {
                    "id": "root",
                    "atom": {
                        "kind": "self_ui",
                        "props": {
                            "control": "button",
                            "props": {
                                "id": "refresh",
                                "label": "Refresh",
                                "action": { "command": "refresh_lens" }
                            },
                            forbidden_prop: "javascript:alert(1)"
                        }
                    }
                }
            });

            assert!(
                serde_json::from_value::<GeneratedLens>(attempted).is_err(),
                "raw self.ui envelope prop {forbidden_prop} should be rejected"
            );

            let attempted = json!({
                "kit_version": LENS_ATOM_KIT_VERSION,
                "root": {
                    "id": "root",
                    "atom": {
                        "kind": "self_ui",
                        "props": {
                            "control": "button",
                            "props": {
                                "id": "refresh",
                                "label": "Refresh",
                                "action": { "command": "refresh_lens" }
                            }
                        },
                        forbidden_prop: "javascript:alert(1)"
                    }
                }
            });

            assert!(
                serde_json::from_value::<GeneratedLens>(attempted).is_err(),
                "raw atom envelope prop {forbidden_prop} should be rejected"
            );
        }
    }

    #[test]
    fn self_ui_action_ids_reject_reserved_capability_names() {
        for command in [
            "javascript",
            "javaScript",
            "eval",
            "run_eval",
            "runEval",
            "fetch",
            "fetch_url",
            "fetchUrl",
            "URLFetch",
            "network",
            "network.fetch",
            "networkFetch",
            "storage",
            "storage_read",
            "storageRead",
            "read_storage",
            "local_storage",
            "localStorage",
            "session_storage",
            "raw-script",
            "rawScript",
        ] {
            let attempted = json!({
                "kit_version": LENS_ATOM_KIT_VERSION,
                "root": {
                    "id": "root",
                    "atom": {
                        "kind": "self_ui",
                        "props": {
                            "control": "button",
                            "props": {
                                "id": "refresh",
                                "label": "Refresh",
                                "action": { "command": command }
                            }
                        }
                    }
                }
            });

            assert!(
                serde_json::from_value::<GeneratedLens>(attempted).is_err(),
                "reserved command {command} should be rejected"
            );
        }
    }

    #[test]
    fn non_capability_tokens_allow_reserved_domain_values() {
        let attempted = json!({
            "kit_version": LENS_ATOM_KIT_VERSION,
            "root": {
                "id": "fetch",
                "atom": {
                    "kind": "quick_filter",
                    "props": {
                        "id": "network",
                        "label": "Backend",
                        "options": [{ "value": "storage", "label": "Storage" }],
                        "selected": ["storage"],
                        "action": {
                            "command": "filter_backend",
                            "args": [
                                { "type": "token", "value": "storage" },
                                { "type": "handle", "value": "network" }
                            ]
                        }
                    }
                }
            }
        });

        assert!(
            serde_json::from_value::<GeneratedLens>(attempted).is_ok(),
            "reserved domain words should be allowed outside capability fields"
        );
    }

    #[test]
    fn self_ui_rejects_selected_values_outside_options() {
        let attempted = json!({
            "kit_version": LENS_ATOM_KIT_VERSION,
            "root": {
                "id": "root",
                "atom": {
                    "kind": "quick_filter",
                    "props": {
                        "id": "filter",
                        "label": "Status",
                        "options": [{ "value": "approved", "label": "Approved" }],
                        "selected": ["rejected"],
                        "action": { "command": "filter_status" }
                    }
                }
            }
        });
        assert!(
            serde_json::from_value::<GeneratedLens>(attempted).is_err(),
            "quick filter selected values outside options should be rejected"
        );

        for attempted in [
            json!({
                "control": "segmented",
                "props": {
                    "id": "segmented",
                    "label": "Mode",
                    "options": [{ "value": "compact", "label": "Compact" }],
                    "selected": "expanded",
                    "action": { "command": "set_mode" }
                }
            }),
            json!({
                "control": "select",
                "props": {
                    "id": "select",
                    "label": "Mode",
                    "options": [{ "value": "compact", "label": "Compact" }],
                    "selected": "expanded",
                    "action": { "command": "set_mode" }
                }
            }),
        ] {
            assert!(
                serde_json::from_value::<SelfUiControl>(attempted).is_err(),
                "selected values outside options should be rejected"
            );
        }
    }

    #[test]
    fn quick_filter_rejects_duplicate_selected_values() {
        let props = json!({
            "id": "filter",
            "label": "Status",
            "options": [{ "value": "approved", "label": "Approved" }],
            "selected": ["approved", "approved"],
            "action": { "command": "filter_status" }
        });

        assert!(
            serde_json::from_value::<QuickFilterAtom>(props.clone()).is_err(),
            "standalone quick filters should reject duplicate selected values"
        );

        let attempted = json!({
            "kit_version": LENS_ATOM_KIT_VERSION,
            "root": {
                "id": "root",
                "atom": {
                    "kind": "quick_filter",
                    "props": props
                }
            }
        });
        assert!(
            serde_json::from_value::<GeneratedLens>(attempted).is_err(),
            "quick filters should reject duplicate selected values"
        );
    }

    #[test]
    fn self_ui_controls_round_trip_and_numbers_are_finite() {
        let controls = vec![
            SelfUiControl::Button(ButtonControl {
                id: control_id("button"),
                label: text("Button"),
                action: SelfUiAction {
                    command: action_id("button_action"),
                    args: vec![SelfUiValue::Number(finite(1.25))],
                },
            }),
            SelfUiControl::Toggle(ToggleControl {
                id: control_id("toggle"),
                label: text("Toggle"),
                checked: true,
                action: action("toggle_action"),
            }),
            SelfUiControl::Segmented(SegmentedControl {
                id: control_id("segmented"),
                label: text("Segmented"),
                options: vec![SelfUiOption {
                    value: option_value("one"),
                    label: text("One"),
                }],
                selected: Some(option_value("one")),
                action: action("segmented_action"),
            }),
            SelfUiControl::Select(SelectControl {
                id: control_id("select"),
                label: text("Select"),
                options: vec![SelfUiOption {
                    value: option_value("two"),
                    label: text("Two"),
                }],
                selected: Some(option_value("two")),
                action: action("select_action"),
            }),
            SelfUiControl::Slider(SliderControl {
                id: control_id("slider"),
                label: text("Slider"),
                min: finite(0.0),
                max: finite(10.0),
                step: finite(0.5),
                value: finite(5.0),
                action: action("slider_action"),
            }),
            SelfUiControl::TextInput(TextInputControl {
                id: control_id("text_input"),
                label: text("Text"),
                placeholder: Some(text("Type here")),
                value: Some(text("value")),
                action: action("text_action"),
            }),
        ];

        for (index, control) in controls.into_iter().enumerate() {
            let lens = GeneratedLens::new(LensNode::new(
                id(&format!("control-{index}")),
                LensAtom::SelfUi(control),
            ))
            .expect("valid self.ui lens");

            let json = serde_json::to_vec(&lens).expect("json encode");
            let decoded: GeneratedLens = serde_json::from_slice(&json).expect("json decode");
            assert_eq!(decoded, lens);
        }
    }

    #[test]
    fn self_ui_rejects_non_finite_numbers_and_invalid_sliders() {
        let value = rmpv::Value::Map(vec![
            (rmpv::Value::from("type"), rmpv::Value::from("number")),
            (rmpv::Value::from("value"), rmpv::Value::F64(f64::NAN)),
        ]);
        let mut msgpack = Vec::new();
        rmpv::encode::write_value(&mut msgpack, &value).expect("msgpack encode");
        assert!(
            rmp_serde::from_slice::<SelfUiValue>(&msgpack).is_err(),
            "non-finite self.ui numbers should be rejected"
        );

        for props in [
            json!({ "min": 10.0, "max": 0.0, "step": 1.0, "value": 5.0 }),
            json!({ "min": 0.0, "max": 10.0, "step": 0.0, "value": 5.0 }),
            json!({ "min": 0.0, "max": 10.0, "step": 1.0, "value": 11.0 }),
        ] {
            let attempted = json!({
                "kit_version": LENS_ATOM_KIT_VERSION,
                "root": {
                    "id": "root",
                    "atom": {
                        "kind": "self_ui",
                        "props": {
                            "control": "slider",
                            "props": {
                                "id": "slider",
                                "label": "Slider",
                                "min": props["min"],
                                "max": props["max"],
                                "step": props["step"],
                                "value": props["value"],
                                "action": { "command": "slider_action" }
                            }
                        }
                    }
                }
            });

            assert!(
                serde_json::from_value::<GeneratedLens>(attempted).is_err(),
                "invalid slider bounds should be rejected"
            );
        }
    }

    #[test]
    fn generated_lens_rejects_root_before_version_and_oversized_trees() {
        let root_first = r#"{
            "root": {
                "id": "root",
                "atom": {
                    "kind": "throbber",
                    "props": { "label": "loading" }
                }
            },
            "kit_version": 1
        }"#;

        assert!(
            serde_json::from_str::<GeneratedLens>(root_first).is_err(),
            "root before kit_version should be rejected before tree allocation"
        );

        let mut root = LensNode::new(
            id("root"),
            LensAtom::Sheet(CollectionAtom {
                title: text("too-wide"),
                rows: Vec::new(),
            }),
        );
        root.children = (0..=MAX_LENS_NODE_COUNT)
            .map(|index| {
                LensNode::new(
                    id(&format!("node-{index}")),
                    LensAtom::Throbber(ThrobberAtom {
                        label: text("loading"),
                    }),
                )
            })
            .collect();

        assert!(
            GeneratedLens::new(root).is_err(),
            "oversized lens trees should be rejected"
        );

        let mut root = LensNode::new(
            id("root"),
            LensAtom::Throbber(ThrobberAtom {
                label: text("loading"),
            }),
        );
        root.children = (0..MAX_LENS_NODE_COUNT)
            .map(|index| {
                LensNode::new(
                    id(&format!("standalone-node-{index}")),
                    LensAtom::Throbber(ThrobberAtom {
                        label: text("loading"),
                    }),
                )
            })
            .collect();
        let encoded = serde_json::to_value(&root).expect("node encodes");
        assert!(
            serde_json::from_value::<LensNode>(encoded).is_err(),
            "standalone lens nodes should enforce tree node budgets"
        );
    }

    #[test]
    fn generated_lens_rejects_duplicate_node_ids() {
        let mut root = LensNode::new(
            id("root"),
            LensAtom::Throbber(ThrobberAtom {
                label: text("loading"),
            }),
        );
        root.children = vec![
            LensNode::new(
                id("duplicate"),
                LensAtom::Throbber(ThrobberAtom {
                    label: text("first"),
                }),
            ),
            LensNode::new(
                id("duplicate"),
                LensAtom::Throbber(ThrobberAtom {
                    label: text("second"),
                }),
            ),
        ];

        assert!(
            GeneratedLens::new(root.clone()).is_err(),
            "generated lens trees should reject duplicate node ids"
        );

        let encoded = serde_json::to_value(&root).expect("node encodes");
        assert!(
            serde_json::from_value::<LensNode>(encoded).is_err(),
            "standalone lens nodes should reject duplicate node ids"
        );
    }

    #[test]
    fn generated_lens_rejects_aggregate_collection_budget() {
        let root = LensNode::new(
            id("root"),
            LensAtom::Sheet(CollectionAtom {
                title: text("too-many-total-items"),
                rows: rows_at_collection_limit_with_one_cell_each(),
            }),
        );

        assert!(
            GeneratedLens::new(root).is_err(),
            "nested collection totals over budget should be rejected"
        );

        let atom = LensAtom::Sheet(CollectionAtom {
            title: text("too-many-total-items"),
            rows: rows_at_collection_limit_with_one_cell_each(),
        });
        let encoded = serde_json::to_value(&atom).expect("atom encodes");
        assert!(
            serde_json::from_value::<LensAtom>(encoded).is_err(),
            "standalone atoms should enforce aggregate collection totals"
        );

        let atom = CollectionAtom {
            title: text("too-many-total-items"),
            rows: rows_at_collection_limit_with_one_cell_each(),
        };
        let encoded = serde_json::to_value(&atom).expect("collection encodes");
        assert!(
            serde_json::from_value::<CollectionAtom>(encoded).is_err(),
            "standalone collection props should enforce aggregate collection totals"
        );

        let atom = InspectorAtom {
            title: text("too-many-total-items"),
            sections: sections_at_collection_limit_with_one_line_each(),
        };
        let encoded = serde_json::to_value(&atom).expect("inspector encodes");
        assert!(
            serde_json::from_value::<InspectorAtom>(encoded).is_err(),
            "standalone inspector props should enforce aggregate collection totals"
        );

        let atom = QuickFilterAtom {
            id: control_id("filter"),
            label: text("too-many-total-items"),
            options: options_at_collection_limit(),
            selected: vec![option_value("option-0")],
            action: action("filter_status"),
        };
        let encoded = serde_json::to_value(&atom).expect("quick filter encodes");
        assert!(
            serde_json::from_value::<QuickFilterAtom>(encoded).is_err(),
            "standalone quick filter props should enforce aggregate collection totals"
        );
    }

    #[test]
    fn generated_lens_rejects_oversized_collections_during_deserialization() {
        let rows = (0..=MAX_LENS_COLLECTION_ITEMS)
            .map(|_| json!({ "cells": [] }))
            .collect::<Vec<_>>();
        let attempted = json!({
            "kit_version": LENS_ATOM_KIT_VERSION,
            "root": {
                "id": "root",
                "atom": {
                    "kind": "sheet",
                    "props": {
                        "title": "too-wide",
                        "rows": rows
                    }
                }
            }
        });

        assert!(
            serde_json::from_value::<GeneratedLens>(attempted).is_err(),
            "oversized collections should fail while decoding"
        );
    }

    #[test]
    fn neighborhood_graph_rejects_dangling_and_duplicate_edges() {
        let graph_with_dangling_edge = NeighborhoodGraphAtom {
            nodes: vec![GraphNode {
                id: handle("ada"),
                label: text("Ada"),
            }],
            edges: vec![GraphEdge {
                from: handle("ada"),
                to: handle("missing"),
                label: text("knows"),
            }],
        };

        assert!(
            GeneratedLens::new(LensNode::new(
                id("root"),
                LensAtom::NeighborhoodGraph(graph_with_dangling_edge.clone()),
            ))
            .is_err(),
            "dangling graph edges should be rejected"
        );

        let encoded = serde_json::to_value(LensAtom::NeighborhoodGraph(
            graph_with_dangling_edge.clone(),
        ))
        .expect("atom encodes");
        assert!(
            serde_json::from_value::<LensAtom>(encoded).is_err(),
            "standalone graph atoms should reject dangling edges"
        );

        let encoded = serde_json::to_value(&graph_with_dangling_edge).expect("graph encodes");
        assert!(
            serde_json::from_value::<NeighborhoodGraphAtom>(encoded).is_err(),
            "standalone graph props should reject dangling edges"
        );

        let graph_with_duplicate_nodes = NeighborhoodGraphAtom {
            nodes: vec![
                GraphNode {
                    id: handle("ada"),
                    label: text("Ada"),
                },
                GraphNode {
                    id: handle("ada"),
                    label: text("Ada duplicate"),
                },
            ],
            edges: Vec::new(),
        };

        assert!(
            GeneratedLens::new(LensNode::new(
                id("root"),
                LensAtom::NeighborhoodGraph(graph_with_duplicate_nodes.clone()),
            ))
            .is_err(),
            "duplicate graph nodes should be rejected"
        );

        let encoded = serde_json::to_value(&graph_with_duplicate_nodes).expect("graph encodes");
        assert!(
            serde_json::from_value::<NeighborhoodGraphAtom>(encoded).is_err(),
            "standalone graph props should reject duplicate node ids"
        );
    }

    #[test]
    fn standalone_self_ui_actions_reject_oversized_args() {
        let args = (0..=MAX_LENS_COLLECTION_ITEMS)
            .map(|_| json!({ "type": "bool", "value": true }))
            .collect::<Vec<_>>();
        let attempted = json!({
            "command": "bulk_set",
            "args": args
        });

        assert!(
            serde_json::from_value::<SelfUiAction>(attempted).is_err(),
            "standalone self.ui actions should enforce arg bounds"
        );
    }

    #[test]
    fn generated_lens_deserialize_rejects_unsupported_versions_and_oversized_text() {
        let attempted = json!({
            "kit_version": LENS_ATOM_KIT_VERSION + 1,
            "root": {
                "id": "root",
                "atom": {
                    "kind": "throbber",
                    "props": {
                        "label": "loading"
                    }
                }
            }
        });

        assert!(
            serde_json::from_value::<GeneratedLens>(attempted).is_err(),
            "unsupported kit version should be rejected"
        );

        let attempted = json!({
            "kit_version": LENS_ATOM_KIT_VERSION,
            "root": {
                "id": "root",
                "atom": {
                    "kind": "throbber",
                    "props": {
                        "label": "x".repeat(MAX_LENS_TEXT_BYTES + 1)
                    }
                }
            }
        });

        assert!(
            serde_json::from_value::<GeneratedLens>(attempted).is_err(),
            "oversized text should be rejected during deserialization"
        );
    }
}
