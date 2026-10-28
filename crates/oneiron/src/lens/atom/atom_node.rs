//! LensNode tree type with its Deserialize seeds: the tree decodes whole, at
//! any width or depth its codec reads (FIX 9900), and is validated once, at
//! its root.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, de, de::DeserializeSeed};

use super::{LensAtom, LensText};
use crate::lens::generated_ui::SelfUiBinding;
use crate::lens::validate::validate_lens_tree;
use crate::lens::wire_ids::{LensAtomId, LensHandleRef};

#[derive(Debug, Clone, PartialEq, Serialize, schemars::JsonSchema)]
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
        let node = LensNodeSeed.deserialize(deserializer)?;
        validate_lens_tree(&node).map_err(de::Error::custom)?;
        Ok(node)
    }
}

/// One node and its subtree, unvalidated: the root's `Deserialize` validates
/// the whole tree once.
pub(in crate::lens) struct LensNodeSeed;

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

        struct LensNodeVisitor;

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
                            bindings = Some(map.next_value::<Vec<LensHandleRef>>()?);
                        }
                        Field::StateBindings => {
                            if state_bindings.is_some() {
                                return Err(de::Error::duplicate_field("$bind"));
                            }
                            state_bindings = Some(map.next_value::<Vec<SelfUiBinding>>()?);
                        }
                        Field::Children => {
                            if children.is_some() {
                                return Err(de::Error::duplicate_field("children"));
                            }
                            children = Some(map.next_value_seed(LensChildrenSeed)?);
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
                    .next_element::<Vec<LensHandleRef>>()?
                    .unwrap_or_default();
                let state_bindings = seq
                    .next_element::<Vec<SelfUiBinding>>()?
                    .unwrap_or_default();
                let children = seq
                    .next_element_seed(LensChildrenSeed)?
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
            LensNodeVisitor,
        )
    }
}

struct LensChildrenSeed;

impl<'de> de::DeserializeSeed<'de> for LensChildrenSeed {
    type Value = Vec<LensNode>;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(LensChildrenVisitor)
    }
}

struct LensChildrenVisitor;

impl<'de> de::Visitor<'de> for LensChildrenVisitor {
    type Value = Vec<LensNode>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("lens node children")
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut children = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(16));
        while let Some(child) = seq.next_element_seed(LensNodeSeed)? {
            children.push(child);
        }
        Ok(children)
    }
}
