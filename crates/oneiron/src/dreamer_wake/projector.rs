//! The projector's surprise check (ARCH-0026 RD-26): a due wake writes only
//! when its material is new to the projection it already holds.
//!
//! This first build is deterministic. The material of a turn is its
//! statements: each sentence's words, lowercased and stripped of punctuation,
//! as a BLAKE3 digest. The projection holds, per consolidation partition, the
//! statements of every round it queued. A due wake compares each partition's
//! statements with what that partition holds; a partition with fewer new
//! statements than the policy row asks for writes nothing, and its turns are
//! consumed as read. A paraphrase is new material here; only the same words
//! are held. A model-backed comparison replaces the digest later.
//!
//! A held statement names the round that queued it, and a round is queued
//! until its consolidation attempt completes, when the completing transaction
//! marks it applied. Both states are rows, so a restart between queue and
//! apply neither loses the round (its attempt is still in the queue) nor
//! doubles it (its statements are still held). A round whose attempt ended
//! without completing holds nothing: its statements are new again. The rows
//! are derived and local; erasing a turn takes its statements out.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::sieve::{Chunk, turn_chunks_in_txn};
use crate::attempt_queue::{AttemptQueue, AttemptRecord};
use crate::dreamer_consolidation::{
    ConsolidationPartitionKey, ConsolidationWatermark, WorkingSetTurn, partition_turns_in_txn,
};
use crate::dreamer_runner::EnqueueDreamerAttemptOutcome;
use crate::error::{Error, Result};
use crate::side_table::{self, LegacyJson, Named, Raw, SideTable};
use crate::{EntityId, Vault};

const POLICY: SideTable<(), ProjectorPolicy, LegacyJson> =
    SideTable::new(&side_table::DREAMER_PROJECTOR_POLICY);
const DEFAULT_POLICY: &str = include_str!("projector_policy_defaults.json");
/// A statement the projection holds. Key: partition hash, statement digest.
/// Value: the round that queued it.
const HELD: SideTable<HeldKey, [u8; 32], Raw> = SideTable::new(&side_table::DREAMER_PROJECTION_HELD);
/// A round the projector queued. Key: round id.
const ROUND: SideTable<[u8; 32], ProjectionRound, Named> =
    SideTable::new(&side_table::DREAMER_PROJECTION_ROUND);
/// The held statements each TURN gave, for erasure. Key: TURN id.
const GIVEN: SideTable<EntityId, Vec<HeldKey>, Named> =
    SideTable::new(&side_table::DREAMER_PROJECTION_GIVEN);

type HeldKey = ([u8; 32], [u8; 32]);

/// The projector's policy row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectorPolicy {
    /// New statements a partition needs before its wake writes. Zero writes
    /// on every due wake.
    pub min_new_statements: u32,
}

/// One queued round: the attempt identity that carries it, and whether that
/// attempt completed.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProjectionRound {
    kind: String,
    dedupe_key: String,
    applied: bool,
}

/// What a due wake found new.
#[derive(Debug, Default)]
pub(crate) struct ProjectionPlan {
    /// The turns of every partition whose material surprised the projection.
    pub(crate) turns: Vec<EntityId>,
    /// Per surprised partition: each new statement and the turn that gave it.
    new: BTreeMap<[u8; 32], BTreeMap<[u8; 32], EntityId>>,
}

fn invalid() -> Error {
    Error::InvalidConfig("invalid dreamer projector policy row".into())
}

fn policy_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<ProjectorPolicy> {
    Ok(
        match POLICY.get(&vault.store, txn, &()).map_err(|error| match error {
            Error::Store(crate::error::StoreError::SideTableRow { .. }) => invalid(),
            other => other,
        })? {
            Some(row) => row,
            None => serde_json::from_str(DEFAULT_POLICY).map_err(|_| invalid())?,
        },
    )
}

impl Vault {
    /// The projector policy row this vault reads, or the shipped default.
    pub fn dreamer_projector_policy(&self) -> Result<ProjectorPolicy> {
        let txn = self.store.env.read_txn()?;
        policy_in_txn(self, &txn)
    }

    /// An owner-authenticated projector policy write.
    pub fn set_dreamer_projector_policy(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        policy: ProjectorPolicy,
    ) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            crate::dreamer_runner::maintenance::validate_owner_in_txn(self, txn, owner)?;
            POLICY.put(&self.store, txn, &(), &policy)
        })
    }
}

/// Compares a due window's material with the projection, partition by
/// partition, in the wake's transaction. Writes nothing.
pub(crate) fn plan_in_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    window: &[WorkingSetTurn],
    watermark: &ConsolidationWatermark,
) -> Result<ProjectionPlan> {
    let policy = policy_in_txn(vault, txn)?;
    let mut rounds = BTreeMap::new();
    let mut plan = ProjectionPlan::default();
    for partition in partition_turns_in_txn(vault, txn, window, watermark)? {
        let scope = partition.key.partition_hash();
        let mut new = BTreeMap::new();
        for turn in &partition.turns {
            let Some(chunks) = turn_chunks_in_txn(vault, txn, &turn.turn_id)? else {
                continue;
            };
            for statement in statements(&chunks) {
                if !new.contains_key(&statement)
                    && !holds_in_txn(vault, txn, &(scope, statement), &mut rounds)?
                {
                    new.insert(statement, turn.turn_id);
                }
            }
        }
        if new.len() >= policy.min_new_statements as usize {
            plan.turns
                .extend(partition.turns.iter().map(|turn| turn.turn_id));
            plan.new.insert(scope, new);
        }
    }
    Ok(plan)
}

/// Holds a plan's new statements under the rounds that queued them, in the
/// enqueue's transaction.
pub(crate) fn hold_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    plan: &ProjectionPlan,
    enqueued: &[(ConsolidationPartitionKey, EnqueueDreamerAttemptOutcome)],
) -> Result<()> {
    let mut given: BTreeMap<EntityId, Vec<HeldKey>> = BTreeMap::new();
    for (key, outcome) in enqueued {
        let scope = key.partition_hash();
        let Some(new) = plan.new.get(&scope) else {
            continue;
        };
        let (EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status)) = outcome;
        let Some(round) = queue_round_in_txn(vault, txn, &status.attempt)? else {
            continue;
        };
        for (statement, turn) in new {
            HELD.put(&vault.store, txn, &(scope, *statement), &round)?;
            given.entry(*turn).or_default().push((scope, *statement));
        }
    }
    for (turn, keys) in given {
        let mut held = GIVEN.get(&vault.store, txn, &turn)?.unwrap_or_default();
        held.extend(keys);
        held.sort_unstable();
        held.dedup();
        GIVEN.put(&vault.store, txn, &turn, &held)?;
    }
    Ok(())
}

/// The completing transaction of a Dreamer attempt marks the round it
/// carries applied.
pub(crate) fn apply_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: &AttemptRecord,
) -> Result<()> {
    let Some(dedupe_key) = &attempt.dedupe_key else {
        return Ok(());
    };
    let id = round_id(&attempt.kind, dedupe_key);
    let Some(mut round) = ROUND.get(&vault.store, txn, &id)? else {
        return Ok(());
    };
    round.applied = true;
    ROUND.put(&vault.store, txn, &id, &round)
}

/// Takes the statements an erased TURN gave out of the projection.
pub(crate) fn erase_turn_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
) -> Result<()> {
    let Some(keys) = GIVEN.get(&vault.store, txn, turn)? else {
        return Ok(());
    };
    for key in &keys {
        HELD.delete(&vault.store, txn, key)?;
    }
    GIVEN.delete(&vault.store, txn, turn)?;
    Ok(())
}

/// Records the round an attempt carries, queued unless it already applied.
fn queue_round_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: &AttemptRecord,
) -> Result<Option<[u8; 32]>> {
    let Some(dedupe_key) = &attempt.dedupe_key else {
        return Ok(None);
    };
    let id = round_id(&attempt.kind, dedupe_key);
    if ROUND.get(&vault.store, txn, &id)?.is_none() {
        let round = ProjectionRound {
            kind: attempt.kind.clone(),
            dedupe_key: dedupe_key.clone(),
            applied: false,
        };
        ROUND.put(&vault.store, txn, &id, &round)?;
    }
    Ok(Some(id))
}

/// Whether the projection holds a statement: its round applied, or its
/// attempt is still pending under the round's dedupe key (a retry or a
/// landing's successor carries the key on).
fn holds_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &HeldKey,
    rounds: &mut BTreeMap<[u8; 32], bool>,
) -> Result<bool> {
    let Some(id) = HELD.get(&vault.store, txn, key)? else {
        return Ok(false);
    };
    if let Some(holds) = rounds.get(&id) {
        return Ok(*holds);
    }
    let holds = match ROUND.get(&vault.store, txn, &id)? {
        None => false,
        Some(round) if round.applied => true,
        Some(round) => AttemptQueue::new(vault)
            .pending_dedupe_in_txn(txn, &round.kind, &round.dedupe_key)?
            .is_some(),
    };
    rounds.insert(id, holds);
    Ok(holds)
}

fn round_id(kind: &str, dedupe_key: &str) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron:dreamer-projector:round:v1");
    hash.update(&(kind.len() as u64).to_be_bytes());
    hash.update(kind.as_bytes());
    hash.update(dedupe_key.as_bytes());
    *hash.finalize().as_bytes()
}

/// The statement digests of a reading: one per sentence with words in it.
fn statements(chunks: &[Chunk]) -> BTreeSet<[u8; 32]> {
    let mut out = BTreeSet::new();
    for chunk in chunks {
        for sentence in chunk
            .text
            .split(['.', '!', '?', '\n', '。', '！', '？'])
        {
            let words: Vec<String> = sentence
                .split(|ch: char| !ch.is_alphanumeric())
                .filter(|word| !word.is_empty())
                .map(str::to_lowercase)
                .collect();
            if words.is_empty() {
                continue;
            }
            let mut hash = blake3::Hasher::new();
            hash.update(b"oneiron:dreamer-projector:statement:v1");
            hash.update(words.join(" ").as_bytes());
            out.insert(*hash.finalize().as_bytes());
        }
    }
    out
}
