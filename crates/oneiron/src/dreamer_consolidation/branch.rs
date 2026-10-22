//! One consolidation branch (FIX 7524): a nightly thing's turns across every
//! conversation it appears in, ARCH-0026's "that thing's neighbourhood".
//! Each conversation is one part: its structural partition key, cursor and
//! admission bucket stay per conversation, and every TURN has exactly one
//! declared part. A Micro or Meso partition is a one-part branch whose
//! identity is its partition hash, byte for byte. A multi-part branch has
//! its own identity over its thing and every ordered part, never one
//! representative conversation.

use std::collections::{BTreeMap, BTreeSet};

use super::partition::{
    ConsolidationPartitionKey, ConsolidationPartitionPlan, PartitionThing,
    keyed_partition_round_hash,
};
use super::support::hash_optional_entity;
use super::watermark::WorkingSetTurn;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::llm::ScopeResource;

/// The domain of a multi-part branch's identity.
const BRANCH_IDENTITY_DOMAIN: &[u8] = b"oneiron:dreamer-branch:v1";
/// The domain of a branch's output and signals projection keys.
const BRANCH_RESOURCES_DOMAIN: &[u8] = b"oneiron:dreamer-branch-resources:v1";

/// A TURN as a branch part holds it: the planner's selection facts, or the
/// queued id alone.
pub trait BranchTurn {
    /// The TURN this part entry names.
    fn turn_id(&self) -> EntityId;
}

impl BranchTurn for EntityId {
    fn turn_id(&self) -> EntityId {
        *self
    }
}

impl BranchTurn for WorkingSetTurn {
    fn turn_id(&self) -> EntityId {
        self.turn_id
    }
}

/// One conversation's share of a branch: its ordered TURNs, the watermark
/// a retry of it widens from, and the slice line it is read in.
#[derive(Debug, Clone, PartialEq)]
pub struct ConversationPart<T = WorkingSetTurn> {
    pub conversation_ref: EntityId,
    pub turns: Vec<T>,
    pub watermark_last_learned_at: u64,
    /// The line its TURNs are sliced in (FIX 8724): one extraction slice
    /// holds TURNs of one line only. A nightly thing's parts share a line
    /// where their exposure agrees; any other part is a line of its own.
    /// Zero on every part of a one-line branch.
    pub line: u32,
}

/// One consolidation attempt's normalized input: the world and facet every
/// part shares, the thing a nightly child is cut for, and its ordered parts.
#[derive(Debug, Clone, PartialEq)]
pub struct ConsolidationBranchPlan<T = WorkingSetTurn> {
    pub world_ref: Option<EntityId>,
    pub facet_ref: Option<EntityId>,
    pub thing: Option<PartitionThing>,
    pub parts: Vec<ConversationPart<T>>,
}

/// A branch as its queued payload names it: TURN ids only.
pub(crate) type QueuedBranch = ConsolidationBranchPlan<EntityId>;

/// The axes every part of a branch shares: what a candidate drawn from any
/// of its TURNs is stamped with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BranchAxes {
    pub(crate) world_ref: Option<EntityId>,
    pub(crate) facet_ref: Option<EntityId>,
}

impl<T> ConsolidationBranchPlan<T> {
    pub(crate) fn axes(&self) -> BranchAxes {
        BranchAxes {
            world_ref: self.world_ref,
            facet_ref: self.facet_ref,
        }
    }

    /// The structural partition key of the part reading `conversation_ref`.
    pub(crate) fn part_key(&self, conversation_ref: EntityId) -> ConsolidationPartitionKey {
        ConsolidationPartitionKey {
            conversation_ref,
            world_ref: self.world_ref,
            facet_ref: self.facet_ref,
        }
    }

    /// Every part's conversation, in part order.
    pub(crate) fn conversations(&self) -> impl Iterator<Item = EntityId> + '_ {
        self.parts.iter().map(|part| part.conversation_ref)
    }

    /// Every part's structural partition key, in part order.
    pub(crate) fn partition_keys(&self) -> impl Iterator<Item = ConsolidationPartitionKey> + '_ {
        self.conversations().map(|id| self.part_key(id))
    }

    /// The sorted, deduplicated set of its parts' partition buckets: what
    /// MACRO admission holds for it, all or none.
    pub(crate) fn bucket_set(&self) -> Vec<ConsolidationPartitionKey> {
        self.partition_keys()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// How many TURNs it queues across every part.
    pub(crate) fn turn_count(&self) -> usize {
        self.parts.iter().map(|part| part.turns.len()).sum()
    }

    /// The branch's exact identity. A one-part branch is its partition's
    /// hash, so a Micro or Meso round keeps every key it had; a multi-part
    /// branch hashes its axes, its thing and every ordered part with its
    /// TURN count.
    pub(crate) fn identity(&self) -> [u8; 32] {
        if let [part] = self.parts.as_slice() {
            return self.part_key(part.conversation_ref).partition_hash();
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(BRANCH_IDENTITY_DOMAIN);
        hash_optional_entity(&mut hasher, self.world_ref.as_ref());
        hash_optional_entity(&mut hasher, self.facet_ref.as_ref());
        match self.thing {
            Some(thing) => {
                hasher.update(&[1]);
                hash_optional_entity(&mut hasher, thing.entity.as_ref());
                hash_optional_entity(&mut hasher, thing.audience.as_ref());
            }
            None => {
                hasher.update(&[0]);
            }
        }
        hasher.update(&(self.parts.len() as u64).to_be_bytes());
        for part in &self.parts {
            hasher.update(&self.part_key(part.conversation_ref).partition_hash());
            hasher.update(&(part.turns.len() as u64).to_be_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    /// The subject a branch's durable steps record: a one-part branch's
    /// conversation; a multi-part branch's thing, never one of its parts.
    pub(crate) fn subject(&self) -> Option<EntityId> {
        match self.parts.as_slice() {
            [part] => Some(part.conversation_ref),
            _ => self.thing.and_then(|thing| thing.entity),
        }
    }
}

impl<T: BranchTurn> ConsolidationBranchPlan<T> {
    /// Every queued TURN, part by part, each part in its own order.
    pub(crate) fn turn_ids(&self) -> Vec<EntityId> {
        self.parts
            .iter()
            .flat_map(|part| part.turns.iter().map(BranchTurn::turn_id))
            .collect()
    }

    /// Each queued TURN's declared part, by that part's conversation.
    pub(crate) fn turn_parts(&self) -> BTreeMap<EntityId, EntityId> {
        self.parts
            .iter()
            .flat_map(|part| {
                part.turns
                    .iter()
                    .map(move |turn| (turn.turn_id(), part.conversation_ref))
            })
            .collect()
    }

    /// The real sink boundary over its ordered TURNs.
    pub(crate) fn output_resource(&self) -> ScopeResource {
        ScopeResource::Projection {
            key: format!("dreamer:consolidation:v1:{}", self.resources_key()),
        }
    }

    /// The graph/vector signals projection over its ordered TURNs.
    pub(crate) fn signals_resource(&self) -> ScopeResource {
        ScopeResource::Projection {
            key: format!("dreamer:signals:v1:{}", self.resources_key()),
        }
    }

    fn resources_key(&self) -> String {
        let turns = self.turn_ids();
        let mut hasher = blake3::Hasher::new();
        hasher.update(BRANCH_RESOURCES_DOMAIN);
        hasher.update(&self.identity());
        hasher.update(&(turns.len() as u64).to_be_bytes());
        for turn in &turns {
            hasher.update(turn.as_bytes());
        }
        bytes_to_hex_lower(hasher.finalize().as_bytes())
    }
}

impl ConsolidationBranchPlan<WorkingSetTurn> {
    /// The exact ordered TURN batch's round hash, each TURN at the carrier
    /// it was selected at: a re-dirtied TURN makes a new round.
    pub(crate) fn round_hash(&self) -> [u8; 32] {
        let turns: Vec<WorkingSetTurn> = self
            .parts
            .iter()
            .flat_map(|part| part.turns.iter().copied())
            .collect();
        let carried = turns
            .iter()
            .filter_map(|turn| Some((turn.turn_id, turn.carrier?)))
            .collect();
        keyed_partition_round_hash(&turns, &carried)
    }
}

impl ConsolidationPartitionPlan {
    /// This partition as the one-part branch it queues as.
    pub(crate) fn branch(&self) -> ConsolidationBranchPlan {
        ConsolidationBranchPlan {
            world_ref: self.key.world_ref,
            facet_ref: self.key.facet_ref,
            thing: None,
            parts: vec![ConversationPart {
                conversation_ref: self.key.conversation_ref,
                turns: self.turns.clone(),
                watermark_last_learned_at: self.watermark_last_learned_at,
                line: 0,
            }],
        }
    }
}
