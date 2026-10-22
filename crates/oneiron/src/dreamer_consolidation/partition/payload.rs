//! The consolidation payload codec (FIX 7524): a branch's world and facet,
//! the thing a nightly child is cut for, the retry lineage a sibling was
//! owed under, and each conversation part's ordered TURNs and watermark. A
//! Micro or Meso partition encodes as a one-part branch. One format, read
//! strictly; there is no reader of an older one.

use std::collections::BTreeSet;

use rmpv::Value;

use super::super::branch::{BranchTurn, ConsolidationBranchPlan, ConversationPart};
use super::super::support::{
    KEY_CONVERSATION, KEY_FACET, KEY_SCHEMA_VERSION, KEY_TURNS, KEY_WATERMARK, KEY_WORLD,
    PARTITION_PAYLOAD_SCHEMA_VERSION, expect_key, expect_map, invalid_consolidation,
};
use super::super::watermark::entity_ref_from_value;
use super::ConsolidationPartitionPlan;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Result;

/// The payload key naming the thing a nightly child is cut for (OF-498c).
const KEY_THING: &str = "thing";
/// The payload key naming the attempt whose split owed this one (FIX 7524):
/// a retry's overflow or a drifted part, fanned in beside that attempt.
const KEY_ORIGIN: &str = "origin";
/// The payload key holding the branch's conversation parts.
const KEY_PARTS: &str = "parts";
/// A part's payload key naming the slice line it is read in (FIX 8724);
/// absent on a part of line zero.
const KEY_LINE: &str = "line";

/// The thing a nightly child is cut for (OF-498c, FIX 7497), carried in its
/// payload: the entity a span's reading bound (`None`: the partition's
/// structural topic) and the private thread its turns are of (`None`: off
/// any private thread). Its world and facet are the branch's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PartitionThing {
    pub(crate) entity: Option<EntityId>,
    pub(crate) audience: Option<EntityId>,
}

impl PartitionThing {
    fn encode(self) -> Value {
        Value::Map(vec![
            (Value::from("entity"), reference(self.entity)),
            (Value::from("audience"), reference(self.audience)),
        ])
    }

    fn decode(value: &Value) -> Result<Self> {
        let entries = expect_map(value, "partition payload thing must be a MessagePack map")?;
        let mut thing = Self {
            entity: None,
            audience: None,
        };
        for (key, value) in entries {
            let slot = match expect_key(key)? {
                "entity" => &mut thing.entity,
                "audience" => &mut thing.audience,
                _ => {
                    return Err(invalid_consolidation(
                        "partition payload thing key is not pinned",
                    ));
                }
            };
            *slot =
                optional_reference(value, "partition payload thing refs must be 16-byte binary")?;
        }
        Ok(thing)
    }
}

fn reference(entity: Option<EntityId>) -> Value {
    entity.map_or(Value::Nil, |id| Value::Binary(id.as_bytes().to_vec()))
}

fn optional_reference(value: &Value, reason: &'static str) -> Result<Option<EntityId>> {
    match value {
        Value::Nil => Ok(None),
        _ => entity_ref_from_value(value)
            .map(Some)
            .ok_or(invalid_consolidation(reason)),
    }
}

/// `branch` as its queued payload, naming `origin` when a split owed it.
pub(crate) fn encode_branch_payload<T: BranchTurn>(
    branch: &ConsolidationBranchPlan<T>,
    origin: Option<AttemptId>,
) -> Value {
    let parts = branch
        .parts
        .iter()
        .map(|part| {
            let mut entries = vec![
                (
                    Value::from(KEY_CONVERSATION),
                    Value::Binary(part.conversation_ref.as_bytes().to_vec()),
                ),
                (
                    Value::from(KEY_WATERMARK),
                    Value::from(part.watermark_last_learned_at),
                ),
                (
                    Value::from(KEY_TURNS),
                    Value::Array(
                        part.turns
                            .iter()
                            .map(|turn| Value::Binary(turn.turn_id().as_bytes().to_vec()))
                            .collect(),
                    ),
                ),
            ];
            if part.line != 0 {
                entries.push((Value::from(KEY_LINE), Value::from(part.line)));
            }
            Value::Map(entries)
        })
        .collect();
    let mut entries = vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(PARTITION_PAYLOAD_SCHEMA_VERSION),
        ),
        (Value::from(KEY_WORLD), reference(branch.world_ref)),
        (Value::from(KEY_FACET), reference(branch.facet_ref)),
        (Value::from(KEY_PARTS), Value::Array(parts)),
    ];
    if let Some(thing) = branch.thing {
        entries.push((Value::from(KEY_THING), thing.encode()));
    }
    if let Some(origin) = origin {
        entries.push((
            Value::from(KEY_ORIGIN),
            Value::Binary(origin.as_bytes().to_vec()),
        ));
    }
    Value::Map(entries)
}

/// One partition plan as the one-part branch payload it queues as.
pub(crate) fn encode_partition_payload(plan: &ConsolidationPartitionPlan) -> Value {
    encode_branch_payload(&plan.branch(), None)
}

/// Decodes a consolidation payload into its branch: every part in order,
/// each conversation once and each TURN in exactly one part.
pub fn decode_partition_payload(value: &Value) -> Result<ConsolidationBranchPlan<EntityId>> {
    let entries = expect_map(value, "dreamer partition payload must be a MessagePack map")?;
    super::super::branch_scope::decode_branch_scope(value)?;
    let mut schema = None;
    let mut world = None;
    let mut facet = None;
    let mut thing = None;
    let mut parts = None;
    for (key, value) in entries {
        match expect_key(key)? {
            KEY_SCHEMA_VERSION => schema = value.as_u64(),
            super::super::branch_scope::KEY_BRANCH_SCOPE => {}
            KEY_ORIGIN => {
                origin_of(value)?;
            }
            KEY_THING => thing = Some(PartitionThing::decode(value)?),
            KEY_WORLD => {
                world = Some(optional_reference(
                    value,
                    "partition payload world must be a 16-byte ref",
                )?);
            }
            KEY_FACET => {
                facet = Some(optional_reference(
                    value,
                    "partition payload facet must be a 16-byte ref",
                )?);
            }
            KEY_PARTS => parts = Some(decode_parts(value)?),
            _ => return Err(invalid_consolidation("partition payload key is not pinned")),
        }
    }
    if schema != Some(PARTITION_PAYLOAD_SCHEMA_VERSION) {
        return Err(invalid_consolidation(
            "unsupported dreamer partition payload schema",
        ));
    }
    Ok(ConsolidationBranchPlan {
        world_ref: world.ok_or(invalid_consolidation("partition payload missing world_ref"))?,
        facet_ref: facet.ok_or(invalid_consolidation("partition payload missing facet_ref"))?,
        thing,
        parts: parts.ok_or(invalid_consolidation("partition payload missing parts"))?,
    })
}

fn decode_parts(value: &Value) -> Result<Vec<ConversationPart<EntityId>>> {
    let Value::Array(items) = value else {
        return Err(invalid_consolidation(
            "partition payload parts must be an array",
        ));
    };
    if items.is_empty() {
        return Err(invalid_consolidation("partition payload has no parts"));
    }
    let mut conversations = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut parts = Vec::with_capacity(items.len());
    for item in items {
        let part = decode_part(item)?;
        if !conversations.insert(part.conversation_ref)
            || !part.turns.iter().all(|turn| seen.insert(*turn))
        {
            return Err(invalid_consolidation(
                "partition payload repeats a conversation or turn",
            ));
        }
        parts.push(part);
    }
    Ok(parts)
}

fn decode_part(value: &Value) -> Result<ConversationPart<EntityId>> {
    let entries = expect_map(value, "partition payload part must be a MessagePack map")?;
    let mut conversation = None;
    let mut watermark = None;
    let mut turns = None;
    let mut line = 0;
    for (key, value) in entries {
        match expect_key(key)? {
            KEY_CONVERSATION => conversation = entity_ref_from_value(value),
            KEY_WATERMARK => watermark = value.as_u64(),
            KEY_LINE => {
                line = value
                    .as_u64()
                    .and_then(|line| u32::try_from(line).ok())
                    .filter(|line| *line != 0)
                    .ok_or(invalid_consolidation(
                        "partition payload part line must be a nonzero u32",
                    ))?;
            }
            KEY_TURNS => {
                let Value::Array(items) = value else {
                    return Err(invalid_consolidation(
                        "partition payload turns must be an array",
                    ));
                };
                let mut ids = Vec::with_capacity(items.len());
                for item in items {
                    ids.push(entity_ref_from_value(item).ok_or(invalid_consolidation(
                        "partition payload turn refs must be 16-byte binary",
                    ))?);
                }
                turns = Some(ids);
            }
            _ => {
                return Err(invalid_consolidation(
                    "partition payload part key is not pinned",
                ));
            }
        }
    }
    Ok(ConversationPart {
        conversation_ref: conversation.ok_or(invalid_consolidation(
            "partition payload missing conversation_ref",
        ))?,
        turns: turns.ok_or(invalid_consolidation(
            "partition payload part missing turns",
        ))?,
        watermark_last_learned_at: watermark
            .ok_or(invalid_consolidation("partition payload missing watermark"))?,
        line,
    })
}

fn origin_of(value: &Value) -> Result<AttemptId> {
    let Value::Binary(bytes) = value else {
        return Err(invalid_consolidation(
            "partition payload origin must be binary",
        ));
    };
    AttemptId::from_bytes(bytes)
        .map_err(|_| invalid_consolidation("partition payload origin must be 16 bytes"))
}

/// The attempt whose split owed this payload's work; `None` when it names
/// none, or one that does not decode (its decoder refuses that payload).
pub(crate) fn decode_branch_origin(value: &Value) -> Option<AttemptId> {
    let Value::Map(entries) = value else {
        return None;
    };
    entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(KEY_ORIGIN))
        .and_then(|(_, origin)| origin_of(origin).ok())
}
