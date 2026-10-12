//! The projector's surprise check (ARCH-0026 RD-26): a due wake writes only
//! when its material is new to the projection it already holds.
//!
//! This first build is deterministic. The material of a turn is its
//! statements, read from the text a consolidation branch reads of it (the
//! turn's own author bucket, final words only): each sentence's whitespace
//! tokens, lowercased, with formatting punctuation trimmed from their edges,
//! as a BLAKE3 digest. Signs, currency and units stay in their tokens. A
//! paraphrase is new material here; only the same words are held. A
//! model-backed comparison replaces the digest later.
//!
//! The projection holds, per consolidation partition, its latest round once
//! that round's attempt has completed: the statements of the turns the
//! attempt was given. A due wake compares each partition's statements with
//! it; a partition with fewer new statements than the policy row asks for
//! writes nothing, and its turns are consumed as read, riders on the round
//! that held them. Only the latest round holds, so a return to an earlier
//! value is new again. A queued round holds nothing until its attempt
//! completes, so a round that ends any other way (failed, cancelled while
//! landing, its source erased) has consumed no repeat of its words.
//!
//! Queued and applied state are rows: a restart between queue and apply
//! keeps the queued attempt, and the window it planned stays read. The rows
//! are derived and local. A round applies in the transaction that completes
//! its attempt, at whichever door completes it. Erasing a turn retires the
//! rounds it gave words to and puts their riders back on the shared
//! re-dirty carrier, so a surviving repeat is read as new.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptRecord;
use crate::dreamer_consolidation::{
    ConsolidationPartitionKey, ConsolidationWatermark, WorkingSetTurn, decode_partition_payload,
    partition_turns_in_txn, projected_turn_text_in,
};
use crate::dreamer_runner::EnqueueDreamerAttemptOutcome;
use crate::error::{Error, Result};
use crate::side_table::{self, LegacyJson, Named, Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault};

const POLICY: SideTable<(), ProjectorPolicy, LegacyJson> =
    SideTable::new(&side_table::DREAMER_PROJECTOR_POLICY);
const DEFAULT_POLICY: &str = include_str!("projector_policy_defaults.json");
/// The latest round queued for a partition. Key: partition hash.
const LATEST: SideTable<[u8; 32], [u8; 32], Raw> =
    SideTable::new(&side_table::DREAMER_PROJECTION_LATEST);
/// A round the projector queued. Key: round id.
const ROUND: SideTable<[u8; 32], ProjectionRound, Named> =
    SideTable::new(&side_table::DREAMER_PROJECTION_ROUND);
/// The rounds each TURN gave words to, for erasure. Key: TURN id.
const GIVEN: SideTable<EntityId, Vec<[u8; 32]>, Named> =
    SideTable::new(&side_table::DREAMER_PROJECTION_GIVEN);

/// The projector's policy row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectorPolicy {
    /// New statements a partition needs before its wake writes. Zero writes
    /// on every due wake.
    pub min_new_statements: u32,
}

/// One queued round.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProjectionRound {
    partition: [u8; 32],
    /// Whether the attempt that carries it completed.
    applied: bool,
    /// The statements of the turns its attempt was given, sorted.
    statements: Vec<[u8; 32]>,
    /// Turns consumed because this round held their words.
    riders: Vec<EntityId>,
}

/// What a due wake found new.
#[derive(Debug, Default)]
pub(crate) struct ProjectionPlan {
    /// The turns of every partition whose material surprised the projection.
    pub(crate) turns: Vec<EntityId>,
    /// Each turn read: its statements.
    statements: BTreeMap<EntityId, BTreeSet<[u8; 32]>>,
    /// Per partition that writes nothing: the round that held its words and
    /// the turns that rode it.
    riders: Vec<([u8; 32], Vec<EntityId>)>,
}

fn invalid() -> Error {
    Error::InvalidConfig("invalid dreamer projector policy row".into())
}

fn policy_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<ProjectorPolicy> {
    Ok(
        match POLICY
            .get(&vault.store, txn, &())
            .map_err(|error| match error {
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
    let mut plan = ProjectionPlan::default();
    for partition in partition_turns_in_txn(vault, txn, window, watermark)? {
        let held = held_in_txn(&vault.store, txn, &partition.key.partition_hash())?;
        let mut new = BTreeSet::new();
        let mut unread = false;
        let mut riders = Vec::new();
        for turn in &partition.turns {
            // Words a branch would refuse to read are the branch's to refuse.
            let Some(statements) = turn_statements_in_txn(vault, txn, &turn.turn_id)? else {
                unread = true;
                continue;
            };
            let mut rode = false;
            for statement in &statements {
                if held
                    .as_ref()
                    .is_some_and(|(_, round)| round.statements.binary_search(statement).is_ok())
                {
                    rode = true;
                } else {
                    new.insert(*statement);
                }
            }
            if rode {
                riders.push(turn.turn_id);
            }
            plan.statements.insert(turn.turn_id, statements);
        }
        if unread || new.len() >= policy.min_new_statements as usize {
            plan.turns
                .extend(partition.turns.iter().map(|turn| turn.turn_id));
        } else if let Some((round, _)) = held
            && !riders.is_empty()
        {
            plan.riders.push((round, riders));
        }
    }
    Ok(plan)
}

/// Records what a wake queued and what it consumed, in the enqueue's
/// transaction: each queued round becomes its partition's latest, unapplied,
/// holding the statements of the turns its payload carries (the screen's
/// kept turns, never the ones it skipped), and each partition that wrote
/// nothing rides the round that held it.
pub(crate) fn hold_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    plan: &ProjectionPlan,
    enqueued: &[(ConsolidationPartitionKey, EnqueueDreamerAttemptOutcome)],
) -> Result<()> {
    let store = &vault.store;
    for (key, outcome) in enqueued {
        let (EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status)) = outcome;
        let Some(dedupe_key) = &status.attempt.dedupe_key else {
            continue;
        };
        let id = round_id(&status.attempt.kind, dedupe_key);
        let partition = key.partition_hash();
        let (_, turns, _) = decode_partition_payload(&status.payload.input)?;
        let mut statements = BTreeSet::new();
        for turn in &turns {
            match plan.statements.get(turn) {
                Some(read) => statements.extend(read),
                None => {
                    statements.extend(turn_statements_in_txn(vault, txn, turn)?.unwrap_or_default())
                }
            }
            let mut given = GIVEN.get(store, txn, turn)?.unwrap_or_default();
            if !given.contains(&id) {
                given.push(id);
                GIVEN.put(store, txn, turn, &given)?;
            }
        }
        let mut round = ROUND
            .get(store, txn, &id)?
            .unwrap_or_else(|| ProjectionRound {
                partition,
                applied: false,
                statements: Vec::new(),
                riders: Vec::new(),
            });
        // A replay of a completed batch is a new attempt under the same key.
        if matches!(outcome, EnqueueDreamerAttemptOutcome::Enqueued(_)) {
            round.applied = false;
        }
        round.statements = statements.into_iter().collect();
        ROUND.put(store, txn, &id, &round)?;
        if let Some(previous) = LATEST.get(store, txn, &partition)?
            && previous != id
        {
            supersede_in_txn(store, txn, &previous)?;
        }
        LATEST.put(store, txn, &partition, &id)?;
    }
    for (id, riders) in &plan.riders {
        let Some(mut round) = ROUND.get(store, txn, id)? else {
            continue;
        };
        round.riders.extend(riders);
        round.riders.sort_unstable();
        round.riders.dedup();
        ROUND.put(store, txn, id, &round)?;
    }
    Ok(())
}

/// The completing transaction of an attempt marks the round it carries
/// applied. Every completion door reaches it; an attempt that carries no
/// round leaves nothing to mark.
pub(crate) fn apply_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    attempt: &AttemptRecord,
) -> Result<()> {
    let Some(dedupe_key) = &attempt.dedupe_key else {
        return Ok(());
    };
    let id = round_id(&attempt.kind, dedupe_key);
    let Some(mut round) = ROUND.get(store, txn, &id)? else {
        return Ok(());
    };
    if !round.applied {
        round.applied = true;
        ROUND.put(store, txn, &id, &round)?;
    }
    Ok(())
}

/// Takes an erased TURN's words out of the projection: every round it gave
/// words to holds nothing more, and the riders that round consumed are
/// re-dirtied, so a live repeat of what the turn said is read as new.
pub(crate) fn erase_turn_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
) -> Result<()> {
    let Some(given) = GIVEN.get(store, txn, turn)? else {
        return Ok(());
    };
    for id in &given {
        let Some(round) = ROUND.get(store, txn, id)? else {
            continue;
        };
        for rider in round.riders.iter().filter(|rider| *rider != turn) {
            crate::dreamer_consolidation::redirty::requeue_turn_in_txn(store, txn, rider)?;
        }
        if LATEST.get(store, txn, &round.partition)? == Some(*id) {
            LATEST.delete(store, txn, &round.partition)?;
        }
        ROUND.delete(store, txn, id)?;
    }
    GIVEN.delete(store, txn, turn)?;
    Ok(())
}

/// A round a newer one replaced as its partition's latest holds nothing
/// more. It is kept only while turns ride it, for their erasure.
fn supersede_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, id: &[u8; 32]) -> Result<()> {
    let Some(mut round) = ROUND.get(store, txn, id)? else {
        return Ok(());
    };
    if round.riders.is_empty() {
        return ROUND.delete(store, txn, id).map(|_| ());
    }
    round.statements = Vec::new();
    ROUND.put(store, txn, id, &round)
}

/// The partition's latest round, when its attempt has completed.
fn held_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    partition: &[u8; 32],
) -> Result<Option<([u8; 32], ProjectionRound)>> {
    let Some(id) = LATEST.get(store, txn, partition)? else {
        return Ok(None);
    };
    Ok(ROUND
        .get(store, txn, &id)?
        .filter(|round| round.applied)
        .map(|round| (id, round)))
}

/// A turn's statements, from the words a branch reads of it. `None` when a
/// branch would refuse those words (a changed binding, a mixed bucket).
fn turn_statements_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<Option<BTreeSet<[u8; 32]>>> {
    match projected_turn_text_in(vault, txn, turn) {
        Ok(text) => Ok(Some(text.as_deref().map(statements).unwrap_or_default())),
        Err(Error::InvalidClaimBody(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

fn round_id(kind: &str, dedupe_key: &str) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron:dreamer-projector:round:v1");
    hash.update(&(kind.len() as u64).to_be_bytes());
    hash.update(kind.as_bytes());
    hash.update(dedupe_key.as_bytes());
    *hash.finalize().as_bytes()
}

/// Punctuation that only formats a token: trimmed from its edges. A sign,
/// a currency symbol or a unit is part of what the token says.
const FORMATTING: &[char] = &[
    '"', '\'', '“', '”', '‘', '’', '«', '»', '「', '」', '『', '』', '.', ',', '!', '?', ':', ';',
    '(', ')', '[', ']', '*', '_', '`', '…', '、', '。', '！', '？',
];
/// Tokens that only mark a list item or a quote.
const BULLETS: &[&str] = &["-", "–", "—", "•", "·", ">", "+"];

/// The statement digests of a text: one per sentence with words in it. A
/// sentence ends at a line break, a CJK full stop, or `.`, `!` or `?`
/// before whitespace or the end, so a decimal point never splits one.
fn statements(text: &str) -> BTreeSet<[u8; 32]> {
    let mut out = BTreeSet::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((at, ch)) = chars.next() {
        let ends = match ch {
            '\n' | '。' | '！' | '？' => true,
            '.' | '!' | '?' => chars.peek().is_none_or(|(_, next)| next.is_whitespace()),
            _ => false,
        };
        if ends {
            out.extend(statement(&text[start..at]));
            start = at + ch.len_utf8();
        }
    }
    out.extend(statement(&text[start..]));
    out
}

fn statement(sentence: &str) -> Option<[u8; 32]> {
    let tokens: Vec<String> = sentence
        .split_whitespace()
        .filter(|token| !BULLETS.contains(token))
        .map(|token| token.trim_matches(FORMATTING).to_lowercase())
        .filter(|token| !token.is_empty())
        .collect();
    if tokens.is_empty() {
        return None;
    }
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron:dreamer-projector:statement:v2");
    hash.update(tokens.join(" ").as_bytes());
    Some(*hash.finalize().as_bytes())
}
