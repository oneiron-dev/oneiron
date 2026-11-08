//! Snapshot-bound code-symbol relations and their strict manifest values.

use std::collections::BTreeSet;

use rmpv::Value;

use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{CodeError, Error, Result};

use super::codec::{entity_id_from_value, string_key};
use super::types::CodeSymbolManifest;

const RELATION_KEYS: [&str; 3] = ["source", "kind", "target"];

/// One relation recorded by this artifact's graph writer, not a global edge
/// inferred from version-shared symbol ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeSymbolRelation {
    pub source: EntityId,
    pub kind: EdgeKind,
    pub target: EntityId,
}

impl CodeSymbolRelation {
    pub(super) fn key(self) -> (EntityId, u8, EntityId) {
        (self.source, self.kind as u8, self.target)
    }
}

pub(super) fn is_relation_kind(kind: EdgeKind) -> bool {
    matches!(kind, EdgeKind::Calls | EdgeKind::Imports | EdgeKind::Refs)
}

pub(super) fn normalize_relations(relations: &mut Vec<CodeSymbolRelation>) {
    relations.sort_unstable_by_key(|relation| relation.key());
    relations.dedup();
}

pub(super) fn validate_relations(manifest: &CodeSymbolManifest) -> Result<()> {
    let symbols = manifest
        .symbols
        .iter()
        .map(|symbol| super::keys::code_symbol_entity_id(&manifest.repo_identity, symbol))
        .collect::<Result<BTreeSet<_>>>()?;
    let mut previous = None;
    for relation in &manifest.relations {
        if !is_relation_kind(relation.kind)
            || (relation.source == relation.target && relation.kind == EdgeKind::Imports)
            || !symbols.contains(&relation.source)
            || !symbols.contains(&relation.target)
        {
            return Err(invalid(
                "relation must join manifest symbols with a supported kind",
            ));
        }
        let key = relation.key();
        if previous.is_some_and(|previous| previous >= key) {
            return Err(invalid("relations must be sorted and unique"));
        }
        previous = Some(key);
    }
    Ok(())
}

pub(super) fn encode_relations(relations: &[CodeSymbolRelation]) -> Value {
    Value::Array(
        relations
            .iter()
            .map(|relation| {
                Value::Map(vec![
                    (
                        Value::from(RELATION_KEYS[0]),
                        Value::Binary(relation.source.as_bytes().to_vec()),
                    ),
                    (
                        Value::from(RELATION_KEYS[1]),
                        Value::from(relation.kind as u8),
                    ),
                    (
                        Value::from(RELATION_KEYS[2]),
                        Value::Binary(relation.target.as_bytes().to_vec()),
                    ),
                ])
            })
            .collect(),
    )
}

pub(super) fn decode_relations(value: &Value) -> Result<Vec<CodeSymbolRelation>> {
    let Value::Array(values) = value else {
        return Err(invalid("relations must be a MessagePack array"));
    };
    values.iter().map(decode_relation).collect()
}

fn decode_relation(value: &Value) -> Result<CodeSymbolRelation> {
    let Value::Map(entries) = value else {
        return Err(invalid("relation must be a MessagePack map"));
    };
    let (mut source, mut kind, mut target) = (None, None, None);
    let mut seen = [false; RELATION_KEYS.len()];
    for (key, value) in entries {
        let key = string_key(key, "relation keys must be strings")?;
        let index = RELATION_KEYS
            .iter()
            .position(|known| *known == key)
            .ok_or_else(|| invalid("unknown relation key"))?;
        if seen[index] {
            return Err(invalid("duplicate relation key"));
        }
        seen[index] = true;
        match index {
            0 => {
                source = Some(entity_id_from_value(
                    value,
                    "relation source must be an entity id",
                )?)
            }
            1 => {
                kind = Some(
                    value
                        .as_u64()
                        .and_then(|value| u8::try_from(value).ok())
                        .and_then(EdgeKind::try_from_u8)
                        .filter(|kind| is_relation_kind(*kind))
                        .ok_or_else(|| invalid("relation kind must be Calls, Imports or Refs"))?,
                );
            }
            2 => {
                target = Some(entity_id_from_value(
                    value,
                    "relation target must be an entity id",
                )?)
            }
            _ => unreachable!("index resolved from RELATION_KEYS"),
        }
    }
    Ok(CodeSymbolRelation {
        source: source.ok_or_else(|| invalid("missing relation source"))?,
        kind: kind.ok_or_else(|| invalid("missing relation kind"))?,
        target: target.ok_or_else(|| invalid("missing relation target"))?,
    })
}

fn invalid(message: &'static str) -> Error {
    CodeError::InvalidCodeSymbolManifestBody(message).into()
}
