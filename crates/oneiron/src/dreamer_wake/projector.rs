//! The projector's surprise check (ARCH-0026 RD-26): a due wake writes only
//! when its material is new to the projection it already holds.
//!
//! This first build is deterministic. The material of a turn is its
//! statements, read from the text a consolidation branch reads of it (the
//! turn's own author bucket, final words only): each sentence's whitespace
//! tokens, lowercased, with formatting punctuation trimmed from their edges,
//! as a BLAKE3 digest. Normalisation never changes a number: signs,
//! currency, units, percent and a leading decimal point stay in their
//! tokens. Each digest carries the turn's evidence class (DESIGN-PIN B1: a
//! user's words are what they stated, an assistant's are generated), so the
//! assistant saying something never stands in for the user saying it. A
//! paraphrase is new material here; only the same words are held. A
//! model-backed comparison against the claims replaces the digest later.
//!
//! The projection holds one turn, vault-wide: the latest the projector has
//! queued by temporal key `(learned_at, id)`, once its round's attempt has
//! completed, while its words read as they did when it was queued. A text
//! comparison cannot tell which of two statements supersedes the other, so
//! nothing else holds: a turn is a repeat only when it says the held turn's
//! whole statement set again, in the held turn's partition. A subset, a
//! return to an earlier value, or a value a batch superseded is new
//! material. A due wake whose other turns carry fewer new statements than
//! the policy row asks for writes nothing; its repeats are consumed as read,
//! riders on the held turn's round. Otherwise the whole window is queued.
//!
//! Holding less never drops a reversal, so every doubt releases the hold. A
//! queued round holds nothing until its attempt completes, so a round that
//! ends any other way (failed, cancelled while landing, its source erased)
//! has consumed no repeat. A held turn whose words change holds nothing
//! more, even if they later return to what was queued: the attempt may have
//! read either version. A rider whose words change, or that loses a
//! MESSAGE, is read again: no attempt read its new words. A turn rides
//! once, under its current key. A rider is also planned again when the
//! words of the turn it repeated change, when that turn is queued again
//! under whatever key it has then, or when material older than the rider
//! but newer than that turn is queued later (a parked turn whose edge
//! landed, a re-dirtied turn), because each may change the value the rider
//! returned to.
//!
//! Each turn's words are queued once: a window leaves out every turn whose
//! current words a round already took, and queues the rest, so a cycle
//! drains (L07, Dreamer proof run 1: a re-read turn was extracted again in
//! every Micro round). A turn is taken again when its words change, and
//! when the projector puts it back because what a round read of it is gone
//! (a rider, or a queued batch-mate of an erased or demoted turn). A re-tag
//! that only puts a turn back on the carrier counts toward the wake, but
//! does not queue its words twice.
//!
//! Queued and applied state are rows: a restart between queue and apply
//! keeps the queued attempt, and the window it planned stays read. The rows
//! are derived and local. A round applies in the transaction that completes
//! its attempt, at whichever door completes it. Erasing a turn retires the
//! rounds it gave words to and puts back on the shared re-dirty carrier
//! every live turn they consumed: their riders, and while a round is still
//! queued the other turns its attempt can no longer read with the erased
//! one.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;

use serde::{Deserialize, Serialize};

use crate::attempt_queue::AttemptRecord;
use crate::claim::ClaimSource;
use crate::dreamer_consolidation::redirty::requeue_turn_in_txn;
use crate::dreamer_consolidation::{
    ConsolidationPartitionKey, ConsolidationWatermark, WorkingSetTurn, decode_partition_payload,
    decode_turn_body, partition_turns_in_txn, projected_turn_text_in, turn_trust_class,
};
use crate::dreamer_runner::{EnqueueDreamerAttemptOutcome, dreamer_turn_role};
use crate::error::{Error, Result};
use crate::ports::{EntityStoreRead, TombstoneStoreRead, withdrawn_in_txn};
use crate::side_table::{self, LegacyJson, Named, Raw, SideTable};
use crate::store::Store;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};

use super::read_phase::WakeStop;

mod erasure;
#[cfg(feature = "sync")]
pub(crate) use erasure::demote_turns_in_txn;
pub(crate) use erasure::erase_turn_in_txn;

const POLICY: SideTable<(), ProjectorPolicy, LegacyJson> =
    SideTable::new(&side_table::DREAMER_PROJECTOR_POLICY);
const DEFAULT_POLICY: &str = include_str!("projector_policy_defaults.json");
/// The latest turn the projector queued. Key: ().
const LATEST: SideTable<(), LatestTurn, Named> =
    SideTable::new(&side_table::DREAMER_PROJECTION_LATEST);
/// A round the projector queued. Key: round id.
const ROUND: SideTable<[u8; 32], ProjectionRound, Named> =
    SideTable::new(&side_table::DREAMER_PROJECTION_ROUND);
/// The rounds each TURN gave words to, for erasure, and the reading of the
/// words the last of them took. Key: TURN id.
const GIVEN: SideTable<EntityId, Given, Named> =
    SideTable::new(&side_table::DREAMER_PROJECTION_GIVEN);
/// A turn consumed as a repeat of the held turn. Key: its temporal key.
const RIDER: SideTable<TurnKey, Rider, Named> =
    SideTable::new(&side_table::DREAMER_PROJECTION_RIDER);
/// The riders of each TURN repeated. Key: (repeated TURN id, rider's key).
const RIDER_OF: SideTable<(EntityId, TurnKey), (), Raw> =
    SideTable::new(&side_table::DREAMER_PROJECTION_RIDER_OF);
/// The temporal key each riding TURN rides under, one per TURN. Key: TURN id.
const RIDES: SideTable<EntityId, TurnKey, Named> =
    SideTable::new(&side_table::DREAMER_PROJECTION_RIDES);

/// A TURN's own temporal key, `(learned_at, id)`.
type TurnKey = (u64, EntityId);

/// The projector's policy row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectorPolicy {
    /// New statements a due window needs before its wake writes. Zero writes
    /// on every due wake. Above one, a window with fewer is consumed unread.
    pub min_new_statements: u32,
}

/// The latest turn queued, vault-wide.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LatestTurn {
    /// Its temporal key. A later queue moves the row only forward.
    key: TurnKey,
    /// The round that queued it.
    round: [u8; 32],
    /// The hash of its consolidation partition.
    partition: [u8; 32],
    /// The digest of its statements when it was queued; `None` once its
    /// words were published again or its round was erased, or when a
    /// branch would refuse them. It holds nothing then.
    reading: Option<[u8; 32]>,
}

/// What one TURN gave the projector's rounds.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Given {
    /// The rounds it gave words to, for erasure.
    rounds: Vec<[u8; 32]>,
    /// The reading of the words the latest assignment that queued it took
    /// (a projector round, or a Micro selection retry's widening or owed
    /// chunk); `None` once those words changed or the projector put it back
    /// to be read again. A window leaves the turn out while its words still
    /// read this way.
    taken: Option<[u8; 32]>,
}

/// One queued round.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProjectionRound {
    /// Whether the attempt that carries it completed.
    applied: bool,
    /// The turns its attempt was given.
    turns: Vec<EntityId>,
    /// Turns consumed as repeats of the held turn this round queued.
    riders: Vec<TurnKey>,
}

/// What a rider rode.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Rider {
    round: [u8; 32],
    /// The held turn it repeated.
    after: TurnKey,
}

/// The held turn and what it says.
struct Held {
    key: TurnKey,
    round: [u8; 32],
    partition: [u8; 32],
    statements: BTreeSet<[u8; 32]>,
}

/// What a due wake found new.
#[derive(Debug, Default)]
pub(crate) struct ProjectionPlan {
    /// The window less the turns whose words a round already took, when its
    /// material surprised the projection; else empty.
    pub(crate) turns: Vec<EntityId>,
    /// Each turn read: its statements.
    statements: BTreeMap<EntityId, BTreeSet<[u8; 32]>>,
    /// When the window writes nothing: the held turn's round and key, and
    /// the repeats that ride it.
    ride: Option<([u8; 32], TurnKey, Vec<TurnKey>)>,
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

/// Compares a due window's material with the held turn, in the wake's
/// transaction. Writes nothing. `None` when `stop` stopped the plan.
pub(crate) fn plan_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    window: &[WorkingSetTurn],
    watermark: &ConsolidationWatermark,
    stop: WakeStop<'_>,
) -> Result<Option<ProjectionPlan>> {
    let policy = policy_in_txn(vault, txn)?;
    let held = held_in_txn(vault, txn)?;
    let mut plan = ProjectionPlan::default();
    let mut new = BTreeSet::new();
    let mut unread = false;
    let mut repeats = Vec::new();
    let mut taken = BTreeSet::new();
    for partition in partition_turns_in_txn(vault, txn, window, watermark)? {
        let hash = partition.key.partition_hash();
        for turn in &partition.turns {
            if stop.stopped() {
                return Ok(None);
            }
            // Words a branch would refuse to read are the branch's to refuse.
            let Some(statements) = turn_statements_in_txn(vault, txn, &turn.turn_id)? else {
                unread = true;
                continue;
            };
            // Words a round already took are read, not queued again.
            if taken_in_txn(&vault.store, txn, &turn.turn_id)? == Some(reading(&statements)) {
                taken.insert(turn.turn_id);
                continue;
            }
            if held.as_ref().is_some_and(|held| {
                held.partition == hash && !statements.is_empty() && held.statements == statements
            }) {
                repeats.push(turn.turn_id);
            } else {
                new.extend(statements.iter().copied());
            }
            plan.statements.insert(turn.turn_id, statements);
        }
    }
    if unread || new.len() >= policy.min_new_statements as usize {
        plan.turns = window
            .iter()
            .map(|turn| turn.turn_id)
            .filter(|turn| !taken.contains(turn))
            .collect();
    } else if let Some(held) = held
        && !repeats.is_empty()
    {
        let mut riders = Vec::with_capacity(repeats.len());
        for turn in &repeats {
            riders.extend(turn_key_in_txn(&vault.store, txn, turn)?);
        }
        plan.ride = Some((held.round, held.key, riders));
    }
    Ok(Some(plan))
}

/// Records what a wake queued and what it consumed, in the enqueue's
/// transaction. Each queued round is kept with the turns its payload carries
/// (the screen's kept turns, never the ones it skipped). The latest of those
/// turns becomes the projection's latest when no later turn was queued
/// before it, and every rider whose repeat the queued material may have
/// broken is planned again. A window that wrote nothing rides the held turn.
pub(crate) fn hold_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    plan: &ProjectionPlan,
    enqueued: &[(ConsolidationPartitionKey, EnqueueDreamerAttemptOutcome)],
) -> Result<()> {
    let store = &vault.store;
    let mut queued = BTreeSet::new();
    let mut latest: Option<(TurnKey, [u8; 32], [u8; 32], EntityId)> = None;
    for (key, outcome) in enqueued {
        let (EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status)) = outcome;
        let Some(dedupe_key) = &status.attempt.dedupe_key else {
            continue;
        };
        let id = round_id(&status.attempt.kind, dedupe_key);
        let payload = decode_partition_payload(&status.payload.input)?.turn_ids();
        // A replay of a completed batch is a new attempt under the same key;
        // an attempt still pending was counted when it was queued.
        let fresh = matches!(outcome, EnqueueDreamerAttemptOutcome::Enqueued(_));
        for turn in &payload {
            let mut given = GIVEN.get(store, txn, turn)?.unwrap_or_default();
            if !given.rounds.contains(&id) {
                given.rounds.push(id);
            }
            if fresh {
                given.taken = match plan.statements.get(turn) {
                    Some(statements) => Some(reading(statements)),
                    None => turn_statements_in_txn(vault, txn, turn)?
                        .as_ref()
                        .map(reading),
                };
            }
            GIVEN.put(store, txn, turn, &given)?;
            let Some(at) = turn_key_in_txn(store, txn, turn)? else {
                continue;
            };
            queued.insert(at);
            if fresh && latest.as_ref().is_none_or(|(before, ..)| at > *before) {
                latest = Some((at, id, key.partition_hash(), *turn));
            }
        }
        let mut round = ROUND
            .get(store, txn, &id)?
            .unwrap_or_else(|| ProjectionRound {
                applied: false,
                turns: Vec::new(),
                riders: Vec::new(),
            });
        if fresh {
            round.applied = false;
        }
        round.turns = payload;
        ROUND.put(store, txn, &id, &round)?;
    }
    if let Some((key, round, partition, turn)) = latest {
        let previous = LATEST.get(store, txn, &())?;
        if previous.as_ref().is_none_or(|previous| key >= previous.key) {
            let read = match plan.statements.get(&turn) {
                Some(read) => Some(read.clone()),
                None => turn_statements_in_txn(vault, txn, &turn)?,
            };
            let row = LatestTurn {
                key,
                round,
                partition,
                reading: read.as_ref().map(reading),
            };
            LATEST.put(store, txn, &(), &row)?;
            if let Some(previous) = previous
                && previous.round != round
            {
                retire_in_txn(store, txn, &previous.round)?;
            }
        }
    }
    // A turn queued again rides nothing.
    for (_, turn) in &queued {
        unride_in_txn(store, txn, turn)?;
    }
    release_in_txn(store, txn, &queued)?;
    if let Some((id, after, riders)) = &plan.ride {
        // A turn rides once, under its current key.
        for (_, turn) in riders {
            unride_in_txn(store, txn, turn)?;
        }
        let Some(mut round) = ROUND.get(store, txn, id)? else {
            return Ok(());
        };
        for at in riders {
            let rider = Rider {
                round: *id,
                after: *after,
            };
            RIDER.put(store, txn, at, &rider)?;
            RIDER_OF.put(store, txn, &(after.1, *at), &())?;
            RIDES.put(store, txn, &at.1, at)?;
            round.riders.push(*at);
        }
        round.riders.sort_unstable();
        round.riders.dedup();
        ROUND.put(store, txn, id, &round)?;
    }
    Ok(())
}

/// Plans again every rider the `queued` material may have changed the value
/// of: a rider of a queued turn, which is that turn queued again under any
/// key, and a rider a queued turn falls strictly between the turn it
/// repeated and itself, queued later. A queue in temporal order reads only
/// its own turns' rounds.
fn release_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    queued: &BTreeSet<TurnKey>,
) -> Result<()> {
    let Some(first) = queued.first() else {
        return Ok(());
    };
    let sources = queued.iter().map(|(_, turn)| *turn).collect();
    let mut released = riders_of_in_txn(store, txn, &sources)?;
    for row in RIDER.iter_range(store, txn, Bound::Excluded(first), Bound::Unbounded)? {
        let (at, rider) = row?;
        if rider.after < at
            && queued
                .range((Bound::Excluded(rider.after), Bound::Excluded(at)))
                .next()
                .is_some()
        {
            released.insert(at.1);
        }
    }
    requeue_riders_in_txn(store, txn, &released)
}

/// The riders that repeated one of `sources`, whatever key each has now.
fn riders_of_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    sources: &BTreeSet<EntityId>,
) -> Result<BTreeSet<EntityId>> {
    let mut riders = BTreeSet::new();
    for source in sources {
        for row in RIDER_OF.iter_from(store, txn, source.as_bytes())? {
            let ((_, (_, rider)), ()) = row?;
            riders.insert(rider);
        }
    }
    Ok(riders)
}

/// Ends each turn's ride and puts it back on the carrier.
fn requeue_riders_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    turns: &BTreeSet<EntityId>,
) -> Result<()> {
    for turn in turns {
        unride_in_txn(store, txn, turn)?;
        reread_in_txn(store, txn, turn)?;
    }
    Ok(())
}

/// Ends a TURN's ride, if it rides: its rows go and the round it rode drops
/// it. Returns whether it rode.
fn unride_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, turn: &EntityId) -> Result<bool> {
    let Some(at) = RIDES.get(store, txn, turn)? else {
        return Ok(false);
    };
    RIDES.delete(store, txn, turn)?;
    let Some(rider) = RIDER.get(store, txn, &at)? else {
        return Ok(true);
    };
    RIDER.delete(store, txn, &at)?;
    RIDER_OF.delete(store, txn, &(rider.after.1, at))?;
    if let Some(mut round) = ROUND.get(store, txn, &rider.round)? {
        round.riders.retain(|other| *other != at);
        keep_in_txn(store, txn, &rider.round, &round)?;
    }
    Ok(true)
}

/// Writes a round back, or deletes it once it can hold nothing and has
/// nothing to put back on erasure: applied, ridden by no turn, and no
/// longer the latest.
fn keep_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &[u8; 32],
    round: &ProjectionRound,
) -> Result<()> {
    if round.applied
        && round.riders.is_empty()
        && LATEST
            .get(store, txn, &())?
            .is_none_or(|latest| latest.round != *id)
    {
        return ROUND.delete(store, txn, id).map(|_| ());
    }
    ROUND.put(store, txn, id, round)
}

/// A round a newer one replaced as the latest: kept, for erasure, while
/// turns ride it or its attempt is still queued.
fn retire_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, id: &[u8; 32]) -> Result<()> {
    match ROUND.get(store, txn, id)? {
        Some(round) => keep_in_txn(store, txn, id, &round),
        None => Ok(()),
    }
}

/// The transaction that completes an attempt marks the round it carries
/// applied. Every completion door reaches it; an attempt that carries no
/// round leaves nothing to mark. Only the transition to completed applies:
/// the dedupe index keeps one pending attempt per key, and a round is
/// queued again under its key only once the attempt before it ended, so the
/// attempt completing is the one the round was queued for.
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
    round.applied = true;
    keep_in_txn(store, txn, &id, &round)
}

/// A TURN whose words changed. As the held turn it stops holding, for
/// good: an attempt queued before the change may have read either version,
/// so a later return to the queued words proves nothing. As a rider it is
/// read again: no attempt has read its new words. The turns that rode on
/// what it said are read again too, whether or not its new words are
/// queued: an attempt still pending may read them.
pub(crate) fn words_changed_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
) -> Result<()> {
    // Its new words, even a return to the taken ones, are queued again.
    forget_taken_in_txn(store, txn, turn)?;
    let mut read = riders_of_in_txn(store, txn, &BTreeSet::from([*turn]))?;
    if RIDES.get(store, txn, turn)?.is_some() {
        read.insert(*turn);
    }
    requeue_riders_in_txn(store, txn, &read)?;
    let Some(mut latest) = LATEST.get(store, txn, &())? else {
        return Ok(());
    };
    if latest.key.1 != *turn || latest.reading.is_none() {
        return Ok(());
    }
    latest.reading = None;
    LATEST.put(store, txn, &(), &latest)
}

/// The latest turn holds nothing more while it was queued by round `id`.
#[cfg(feature = "sync")]
fn release_hold_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, id: &[u8; 32]) -> Result<()> {
    if let Some(mut latest) = LATEST.get(store, txn, &())?
        && latest.round == *id
        && latest.reading.is_some()
    {
        latest.reading = None;
        LATEST.put(store, txn, &(), &latest)?;
    }
    Ok(())
}

/// Whether `missing`, the sources an attempt of `kind` under `dedupe_key`
/// cannot read, are all member TURNs of the round it carries that this
/// replica does not hold, while a legal hold stands on that round (FIX
/// 3592). Such an attempt waits for promotion instead of refusing: the
/// absence is a demotion, never an erasure. A held participant cannot be
/// erased, since a legal hold blocks every byte-destroying path; erasing any
/// other member retires every round it gave words to
/// ([`erase_turn_in_txn`]); demotion keeps a held round whole, its members
/// and riders unchanged ([`demote_turns_in_txn`]). So a held round that
/// still stands with a member absent here lost it to a demotion, and a
/// promotion brings it back.
pub(crate) fn held_round_members_away_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    (kind, dedupe_key): (&str, &str),
    missing: &[EntityId],
) -> Result<bool> {
    let Some(round) = ROUND.get(store, txn, &round_id(kind, dedupe_key))? else {
        return Ok(false);
    };
    for id in missing {
        if !round.turns.contains(id) || store.port_entity_present(txn, id)? {
            return Ok(false);
        }
    }
    Ok(!missing.is_empty() && round_held_in_txn(store, txn, &round)?)
}

/// Whether a legal hold stands on a turn of `round` or on one of its riders.
fn round_held_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    round: &ProjectionRound,
) -> Result<bool> {
    for turn in round
        .turns
        .iter()
        .chain(round.riders.iter().map(|(_, rider)| rider))
    {
        if crate::store::legal_hold::held_in_txn(store, txn, turn.as_bytes())? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The latest turn, when its round's attempt has completed and its words
/// still read as when it was queued.
fn held_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Option<Held>> {
    let Some(latest) = LATEST.get(&vault.store, txn, &())? else {
        return Ok(None);
    };
    let Some(queued) = latest.reading else {
        return Ok(None);
    };
    if !ROUND
        .get(&vault.store, txn, &latest.round)?
        .is_some_and(|round| round.applied)
    {
        return Ok(None);
    }
    let Some(statements) = turn_statements_in_txn(vault, txn, &latest.key.1)? else {
        return Ok(None);
    };
    if reading(&statements) != queued {
        return Ok(None);
    }
    Ok(Some(Held {
        key: latest.key,
        round: latest.round,
        partition: latest.partition,
        statements,
    }))
}

/// A TURN's own temporal key, while its row exists.
fn turn_key_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<Option<TurnKey>> {
    Ok(store
        .port_entity_record(txn, turn)?
        .map(|row| (row.learned_at, *turn)))
}

/// A turn's statements, from the words a branch reads of it, in its
/// evidence class. `None` when a branch would refuse those words (a changed
/// binding, a mixed bucket, a TURN or MESSAGE the Dreamer may not read).
fn turn_statements_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<Option<BTreeSet<[u8; 32]>>> {
    let text = match projected_turn_text_in(vault, txn, turn) {
        Ok(text) => text,
        Err(Error::InvalidClaimBody(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    let Some(text) = text else {
        return Ok(Some(BTreeSet::new()));
    };
    let class = turn_class_in_txn(vault, txn, turn)?;
    Ok(Some(super::statement_material::statements(&text, class)))
}

/// The trust class a turn's words carry as consolidation evidence: the
/// mapping a branch applies, `None` for a role it never classifies.
fn turn_class_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<Option<ClaimSource>> {
    let Some(row) = vault.store.port_entity_record(txn, turn)? else {
        return Ok(None);
    };
    let facts = decode_turn_body(&row.body);
    let role = dreamer_turn_role(
        facts.speaker.as_deref(),
        &vault.config.assistant_display_names,
    );
    Ok(turn_trust_class(role, facts.imported))
}

/// The reading of the words the latest round that queued `turn` took,
/// while it still stands.
fn taken_in_txn(store: &Store, txn: &heed::RoTxn<'_>, turn: &EntityId) -> Result<Option<[u8; 32]>> {
    Ok(GIVEN.get(store, txn, turn)?.and_then(|given| given.taken))
}

/// Forgets the words a round took of `turn`, so the next window queues it.
fn forget_taken_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, turn: &EntityId) -> Result<()> {
    if let Some(mut given) = GIVEN.get(store, txn, turn)?
        && given.taken.is_some()
    {
        given.taken = None;
        GIVEN.put(store, txn, turn, &given)?;
    }
    Ok(())
}

/// Puts a TURN the projector consumed back on the carrier to be read again:
/// what a round read of it is gone, so the words it took no longer count.
fn reread_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, turn: &EntityId) -> Result<()> {
    forget_taken_in_txn(store, txn, turn)?;
    requeue_turn_in_txn(store, txn, turn)
}

/// Whether a round already took `turn`'s current words, so a Micro
/// selection retry's widening leaves it out (FIX 12246): only words no round
/// has queued, or changed since, are new work for the retry.
pub(crate) fn words_taken_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<bool> {
    let Some(taken) = taken_in_txn(&vault.store, txn, turn)? else {
        return Ok(false);
    };
    Ok(turn_statements_in_txn(vault, txn, turn)?
        .is_some_and(|statements| reading(&statements) == taken))
}

/// The reading of `text` said in `class`, as a branch froze it: the
/// version a completed widened branch records as taken, never a live
/// reread after its commit.
pub(crate) fn reading_of_text(text: &str, class: Option<ClaimSource>) -> [u8; 32] {
    reading(&super::statement_material::statements(text, class))
}

/// Records one frozen reading as taken by the widened branch that read it
/// (FIX 12246): without it a later deferral re-widens to the same peer and
/// extracts its words again.
pub(crate) fn take_reading_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
    reading: [u8; 32],
) -> Result<()> {
    let mut given = GIVEN.get(&vault.store, txn, turn)?.unwrap_or_default();
    given.taken = Some(reading);
    GIVEN.put(&vault.store, txn, turn, &given)
}

/// Whether `turn` is still live and still reads as `frozen` in `txn`:
/// the guard a widened stamp owes the gap since its branch opened
/// (FIX 12246). A turn erased in that gap must get no stamp at all -
/// recording its erased words' digest would undo the erasure's
/// delete - and a turn whose words moved on must not be marked read
/// at a reading it no longer has. Liveness is checked before
/// equality: a gone turn reads as the empty set, which would equal an
/// empty frozen reading. The live reading is a comparand only; it is
/// never stamped. Row presence is not liveness: a soft-deleted, stale
/// or archived TURN keeps its row as a header-only shell whose absent
/// text reads as the empty set - equal to an empty frozen reading -
/// so the liveness leg is the chunk gate's: a live row whose words
/// are not withdrawn.
pub(crate) fn reading_current_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    frozen: [u8; 32],
) -> Result<bool> {
    if !matches!(
        live_entity_row_in_txn(&vault.store, txn, turn)?,
        LiveEntityRow::Live { .. }
    ) || withdrawn_in_txn(&vault.store, txn, turn)?
    {
        return Ok(false);
    }
    Ok(turn_statements_in_txn(vault, txn, turn)?.is_some_and(|live| reading(&live) == frozen))
}

/// Whether the carrier round `round` still stands for `originals` (FIX
/// 12246 follow-on): the guard the widened stamp owes a gap erasure of
/// an original. A present round proceeds as today. A missing round
/// proceeds only when every queued original is still live, unwithdrawn,
/// and still linked to it - the keep-deleted replay, whose `keep`
/// deleted the ROUND row but left every member's GIVEN link. An
/// erasure (or unheld demotion) deletes the member's GIVEN row with
/// the round, so a retired carrier fails here and the whole stamp
/// skips: recreating the round would resurrect retired membership
/// under words the erase already released.
pub(crate) fn carrier_round_live_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    round: &[u8; 32],
    originals: &[EntityId],
) -> Result<bool> {
    if ROUND.get(&vault.store, txn, round)?.is_some() {
        return Ok(true);
    }
    for turn in originals {
        let linked = GIVEN
            .get(&vault.store, txn, turn)?
            .is_some_and(|given| given.rounds.contains(round));
        if !linked
            || !matches!(
                live_entity_row_in_txn(&vault.store, txn, turn)?,
                LiveEntityRow::Live { .. }
            )
            || withdrawn_in_txn(&vault.store, txn, turn)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Stamps a completed original's frozen reading as taken (FIX 12246
/// follow-on): an away chunk member registered its round at enqueue
/// without a digest, and runs as a queued original after promotion, so
/// no other stamp covers it. Fires only while taken is `None` -
/// ordinary members keep exactly what their enqueue stamped - and only
/// while the turn still reads as frozen in its frozen partition. No
/// membership write: the enqueue already linked it. Returns whether
/// it stamped: only a fired stamp joins the caller's assignment set,
/// so the chain moves past the returned words and their riders
/// release - an unrided-but-untaken turn would strand, and untaken
/// words must re-enter through the usual doors, never become latest.
pub(crate) fn take_returned_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
    frozen: [u8; 32],
    partition: [u8; 32],
) -> Result<bool> {
    let taken = GIVEN
        .get(&vault.store, txn, turn)?
        .and_then(|given| given.taken);
    if taken.is_some() {
        return Ok(false);
    }
    if !reading_current_in_txn(vault, txn, turn, frozen)? {
        return Ok(false);
    }
    if crate::dreamer_consolidation::turn_partition_hash_in_txn(vault, txn, turn)?
        != Some(partition)
    {
        return Ok(false);
    }
    take_reading_in_txn(vault, txn, turn, frozen)?;
    Ok(true)
}

/// The latest-round bookkeeping of `hold_in_txn` for an assignment a
/// Micro selection retry records outside a window (a completed widened
/// branch's stamp, an owed chunk's enqueue): the stamped turns join
/// `round`'s membership the way a window's payload does, the newest
/// stamped turn moves `LATEST` forward under `round` - the carrier
/// attempt's own round, which its completion applies through the usual
/// door - the previous latest round retires, stamped turns ride
/// nothing, and riders their assignment may have changed the value of
/// are released. Without it a stamped turn left an earlier one
/// holding, and a later return to its words was consumed as that
/// turn's repeat; without the membership, erasing the stamped turn
/// never found the round its later repeats rode. `stamped` carries the
/// readings the caller already recorded as taken; they are never
/// recomputed here. No round: membership and the forward move are
/// skipped.
pub(crate) fn note_assignment_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    round: Option<[u8; 32]>,
    stamped: &[(EntityId, [u8; 32])],
) -> Result<()> {
    let store = &vault.store;
    let mut queued = BTreeSet::new();
    let mut latest: Option<(TurnKey, [u8; 32], EntityId)> = None;
    for (turn, reading) in stamped {
        let Some(at) = turn_key_in_txn(store, txn, turn)? else {
            continue;
        };
        queued.insert(at);
        if latest.as_ref().is_none_or(|(before, ..)| at > *before) {
            latest = Some((at, *reading, *turn));
        }
    }
    if let Some(round_id) = round
        && !queued.is_empty()
    {
        // The stamped turns join the carrier round the way a window's
        // payload does, so erasing or demoting one later finds the round
        // and releases the repeats that rode its hold. Append, never
        // overwrite: the carrier's original members stay members. A
        // caller that already registered them (owed chunks) makes this
        // a no-op.
        let existing = ROUND.get(store, txn, &round_id)?;
        let mut linked = existing.is_none();
        let mut round_row = existing.unwrap_or_else(|| ProjectionRound {
            applied: false,
            turns: Vec::new(),
            riders: Vec::new(),
        });
        for (_, turn) in &queued {
            let mut given = GIVEN.get(store, txn, turn)?.unwrap_or_default();
            if !given.rounds.contains(&round_id) {
                given.rounds.push(round_id);
                GIVEN.put(store, txn, turn, &given)?;
            }
            if !round_row.turns.contains(turn) {
                round_row.turns.push(*turn);
                linked = true;
            }
        }
        if linked {
            ROUND.put(store, txn, &round_id, &round_row)?;
        }
    }
    if let (Some(round), Some((key, reading, turn))) = (round, latest) {
        let previous = LATEST.get(store, txn, &())?;
        if previous.as_ref().is_none_or(|previous| key >= previous.key) {
            let partition =
                crate::dreamer_consolidation::turn_partition_hash_in_txn(vault, txn, &turn)?;
            if let Some(partition) = partition {
                let row = LatestTurn {
                    key,
                    round,
                    partition,
                    reading: Some(reading),
                };
                LATEST.put(store, txn, &(), &row)?;
                if let Some(previous) = previous
                    && previous.round != round
                {
                    retire_in_txn(store, txn, &previous.round)?;
                }
            }
        }
    }
    // A turn assigned again rides nothing.
    for (_, turn) in &queued {
        unride_in_txn(store, txn, turn)?;
    }
    release_in_txn(store, txn, &queued)
}

/// Records a fresh owed chunk as a projection round and its turns'
/// snapshot-frozen words as taken, in its enqueue transaction (FIX
/// 12246; frozen readings FIX 12544): the same
/// assignment-time record `hold_in_txn` makes, so erasing or demoting one
/// pending chunk member retires the round and puts its surviving turns
/// back to be read again. A member demoted while a mate is legally held
/// registers its round without stamping absent words, so the chunk
/// waits for its promotion. Completion marks this round applied through
/// the same kind + dedupe-key id every projector round uses.
pub(crate) fn take_chunk_words_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    kind: &str,
    dedupe_key: &str,
    turns: &[EntityId],
    frozen: &BTreeMap<EntityId, ([u8; 32], [u8; 32])>,
) -> Result<()> {
    // Each member is live (its words read here), gone (erased, deleted,
    // or otherwise withdrawn: no promotion brings its words back), or
    // away (its row is demoted to thin while no deletion marker names
    // it: a promotion may bring it back). A soft-deleted TURN keeps its
    // row as a header-only shell, so raw row presence cannot tell live
    // from gone.
    let mut live = Vec::with_capacity(turns.len());
    let mut away = Vec::new();
    let mut gone = false;
    for turn in turns {
        match live_entity_row_in_txn(&vault.store, txn, turn)? {
            LiveEntityRow::Live { .. } => {
                // The one live state whose words still read as absent.
                if withdrawn_in_txn(&vault.store, txn, turn)? {
                    gone = true;
                } else {
                    live.push(*turn);
                }
            }
            // Soft-deleted, stale, archived: reads as absent, refuses as
            // missing, never defers.
            LiveEntityRow::DeletedShell => gone = true,
            LiveEntityRow::Absent => {
                // A hard erase leaves its deletion marker; a demotion
                // leaves none (and without sync nothing demotes at all,
                // so every absence there is an erasure).
                let erased =
                    vault.store.port_deletion_state(txn, turn)?.deleted || !cfg!(feature = "sync");
                if erased {
                    gone = true;
                } else {
                    away.push(*turn);
                }
            }
        }
    }
    // Any gone member makes the chunk stillborn: its payload still names
    // a turn whose words never come back, so preparation refuses the
    // whole one-part chunk and nothing stamped here is ever extracted.
    // Stamp nothing, register no round, leave every gone member exactly
    // as its erasure left it, and put the live members back: the
    // batch-mate reread the erasure owed the round it could not see yet.
    // Away members are not reread: there is no row to requeue, and
    // their words are away, not gone.
    if gone {
        for turn in &live {
            reread_in_txn(&vault.store, txn, turn)?;
        }
        return Ok(());
    }
    // An away member with no legal hold on the chunk defers nowhere:
    // the residency check needs a held round, and without one
    // preparation refuses. Take the stillborn shape too, so the live
    // members are read again now and the away one when its promotion
    // brings it back.
    if !away.is_empty() {
        let mut held = false;
        for turn in turns {
            if crate::store::legal_hold::held_in_txn(&vault.store, txn, turn.as_bytes())? {
                held = true;
                break;
            }
        }
        if !held {
            for turn in &live {
                reread_in_txn(&vault.store, txn, turn)?;
            }
            return Ok(());
        }
    }
    let id = round_id(kind, dedupe_key);
    let mut round = ROUND
        .get(&vault.store, txn, &id)?
        .unwrap_or_else(|| ProjectionRound {
            applied: false,
            turns: Vec::new(),
            riders: Vec::new(),
        });
    round.applied = false;
    // Full membership, away members included: the residency check defers
    // the chunk only while every missing source is a member of its round.
    round.turns = turns.to_vec();
    ROUND.put(&vault.store, txn, &id, &round)?;
    let mut stamped = Vec::new();
    for turn in turns {
        let mut given = GIVEN.get(&vault.store, txn, turn)?.unwrap_or_default();
        if !given.rounds.contains(&id) {
            given.rounds.push(id);
        }
        if away.contains(turn) {
            // Away words are not here to take: the rounds link stays, so
            // a later erase or retire finds the round, but no digest is
            // stamped for words this replica does not hold.
        } else if let Some((reading, partition)) = frozen.get(turn)
            && reading_current_in_txn(vault, txn, turn, *reading)?
            && crate::dreamer_consolidation::turn_partition_hash_in_txn(vault, txn, turn)?
                == Some(*partition)
        {
            // Only the frozen reading is stamped, and only while the
            // turn still reads as frozen in its frozen partition (FIX
            // 12544): a republication or same-text scope move since the
            // wake's snapshot keeps its own reset and re-enters through
            // the usual doors. Members with no frozen entry (their text
            // refused at the snapshot) take the rounds link only, like
            // away members; both run as the chunk's originals, whose
            // completion stamp covers them.
            given.taken = Some(*reading);
            stamped.push((*turn, *reading));
        }
        GIVEN.put(&vault.store, txn, turn, &given)?;
    }
    note_assignment_in_txn(vault, txn, Some(id), &stamped)
}

/// The version of one turn's statements.
fn reading(statements: &BTreeSet<[u8; 32]>) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron:dreamer-projector:reading:v1");
    hash.update(&(statements.len() as u64).to_be_bytes());
    for statement in statements {
        hash.update(statement);
    }
    *hash.finalize().as_bytes()
}

pub(crate) fn round_id(kind: &str, dedupe_key: &str) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron:dreamer-projector:round:v1");
    hash.update(&(kind.len() as u64).to_be_bytes());
    hash.update(kind.as_bytes());
    hash.update(dedupe_key.as_bytes());
    *hash.finalize().as_bytes()
}
