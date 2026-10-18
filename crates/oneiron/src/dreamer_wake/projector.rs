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
use crate::ports::EntityStoreRead;
use crate::side_table::{self, LegacyJson, Named, Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault};

const POLICY: SideTable<(), ProjectorPolicy, LegacyJson> =
    SideTable::new(&side_table::DREAMER_PROJECTOR_POLICY);
const DEFAULT_POLICY: &str = include_str!("projector_policy_defaults.json");
/// The latest turn the projector queued. Key: ().
const LATEST: SideTable<(), LatestTurn, Named> =
    SideTable::new(&side_table::DREAMER_PROJECTION_LATEST);
/// A round the projector queued. Key: round id.
const ROUND: SideTable<[u8; 32], ProjectionRound, Named> =
    SideTable::new(&side_table::DREAMER_PROJECTION_ROUND);
/// The rounds each TURN gave words to, for erasure. Key: TURN id.
const GIVEN: SideTable<EntityId, Vec<[u8; 32]>, Named> =
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
    /// The window, when its material surprised the projection; else empty.
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
/// transaction. Writes nothing.
pub(crate) fn plan_in_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    window: &[WorkingSetTurn],
    watermark: &ConsolidationWatermark,
) -> Result<ProjectionPlan> {
    let policy = policy_in_txn(vault, txn)?;
    let held = held_in_txn(vault, txn)?;
    let mut plan = ProjectionPlan::default();
    let mut new = BTreeSet::new();
    let mut unread = false;
    let mut repeats = Vec::new();
    for partition in partition_turns_in_txn(vault, txn, window, watermark)? {
        let hash = partition.key.partition_hash();
        for turn in &partition.turns {
            // Words a branch would refuse to read are the branch's to refuse.
            let Some(statements) = turn_statements_in_txn(vault, txn, &turn.turn_id)? else {
                unread = true;
                continue;
            };
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
        plan.turns = window.iter().map(|turn| turn.turn_id).collect();
    } else if let Some(held) = held
        && !repeats.is_empty()
    {
        let mut riders = Vec::with_capacity(repeats.len());
        for turn in &repeats {
            riders.extend(turn_key_in_txn(&vault.store, txn, turn)?);
        }
        plan.ride = Some((held.round, held.key, riders));
    }
    Ok(plan)
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
        let (_, payload, _) = decode_partition_payload(&status.payload.input)?;
        // A replay of a completed batch is a new attempt under the same key;
        // an attempt still pending was counted when it was queued.
        let fresh = matches!(outcome, EnqueueDreamerAttemptOutcome::Enqueued(_));
        for turn in &payload {
            let mut given = GIVEN.get(store, txn, turn)?.unwrap_or_default();
            if !given.contains(&id) {
                given.push(id);
                GIVEN.put(store, txn, turn, &given)?;
            }
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
        requeue_turn_in_txn(store, txn, turn)?;
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

/// Takes an erased TURN's words out of the projection: every round it gave
/// words to holds nothing more. The riders that round consumed are
/// re-dirtied, so a live repeat of what the turn said is read as new, and so
/// are the other turns of a round still queued, whose attempt cannot read
/// its batch without the erased turn. The turn rides nothing more: a TURN
/// erased itself (`gone`) is read no more, and a TURN that lost a MESSAGE
/// is read again, since no attempt has read the words it keeps.
pub(crate) fn erase_turn_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
    gone: bool,
) -> Result<()> {
    if unride_in_txn(store, txn, turn)? && !gone {
        requeue_turn_in_txn(store, txn, turn)?;
    }
    let Some(given) = GIVEN.get(store, txn, turn)? else {
        return Ok(());
    };
    for id in &given {
        let Some(round) = ROUND.get(store, txn, id)? else {
            continue;
        };
        for at in &round.riders {
            if let Some(rider) = RIDER.get(store, txn, at)? {
                RIDER_OF.delete(store, txn, &(rider.after.1, *at))?;
            }
            RIDER.delete(store, txn, at)?;
            RIDES.delete(store, txn, &at.1)?;
            requeue_turn_in_txn(store, txn, &at.1)?;
        }
        let batch: &[_] = if round.applied { &[] } else { &round.turns };
        for member in batch.iter().filter(|member| *member != turn) {
            requeue_turn_in_txn(store, txn, member)?;
        }
        if let Some(mut latest) = LATEST.get(store, txn, &())?
            && latest.round == *id
        {
            latest.reading = None;
            LATEST.put(store, txn, &(), &latest)?;
        }
        ROUND.delete(store, txn, id)?;
    }
    GIVEN.delete(store, txn, turn)?;
    Ok(())
}

/// Takes the TURNs a window demotion removes out of the projection, in the
/// remover's transaction before their rows go (OF-534). Their words are
/// away, not erased: each round one gave words to holds nothing more and is
/// retired as [`erase_turn_in_txn`] retires it, but only kept live turns go
/// back on the carrier, its riders and, while it is queued, its other
/// turns. A round with a participant under a legal hold stays whole, since
/// retiring it would change that record's projection; it only stops
/// holding, and the removed turn keeps its entry for it. A removed turn
/// rides nothing more. Attempts and their receipts are not read.
#[cfg(feature = "sync")]
pub(crate) fn demote_turns_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    turns: &BTreeSet<EntityId>,
) -> Result<()> {
    if let Some(latest) = LATEST.get(store, txn, &())?
        && turns.contains(&latest.key.1)
    {
        release_hold_in_txn(store, txn, &latest.round)?;
    }
    for turn in turns {
        unride_in_txn(store, txn, turn)?;
        let Some(given) = GIVEN.get(store, txn, turn)? else {
            continue;
        };
        let mut kept = Vec::new();
        for id in given {
            let Some(round) = ROUND.get(store, txn, &id)? else {
                continue;
            };
            release_hold_in_txn(store, txn, &id)?;
            if round_held_in_txn(store, txn, &round)? {
                kept.push(id);
                continue;
            }
            for at in &round.riders {
                if let Some(rider) = RIDER.get(store, txn, at)? {
                    RIDER_OF.delete(store, txn, &(rider.after.1, *at))?;
                }
                RIDER.delete(store, txn, at)?;
                RIDES.delete(store, txn, &at.1)?;
                if !turns.contains(&at.1) {
                    requeue_turn_in_txn(store, txn, &at.1)?;
                }
            }
            let batch: &[_] = if round.applied { &[] } else { &round.turns };
            for member in batch.iter().filter(|member| !turns.contains(*member)) {
                requeue_turn_in_txn(store, txn, member)?;
            }
            ROUND.delete(store, txn, &id)?;
        }
        if kept.is_empty() {
            GIVEN.delete(store, txn, turn)?;
        } else {
            GIVEN.put(store, txn, turn, &kept)?;
        }
    }
    Ok(())
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

/// Whether a legal hold stands on a turn of `round` or on one of its riders.
#[cfg(feature = "sync")]
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
    Ok(Some(statements(&text, class)))
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

fn round_id(kind: &str, dedupe_key: &str) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron:dreamer-projector:round:v1");
    hash.update(&(kind.len() as u64).to_be_bytes());
    hash.update(kind.as_bytes());
    hash.update(dedupe_key.as_bytes());
    *hash.finalize().as_bytes()
}

/// Punctuation that only formats a token: trimmed from its edges. A sign,
/// a currency symbol, a unit or a percent is part of what the token says,
/// and so is a number's leading `.` or `,` before a digit.
const FORMATTING: &[char] = &[
    '"', '\'', '“', '”', '‘', '’', '«', '»', '「', '」', '『', '』', '.', ',', '!', '?', ':', ';',
    '(', ')', '[', ']', '*', '_', '`', '…', '、', '。', '！', '？',
];
/// Tokens that only mark a list item or a quote where a sentence starts.
const BULLETS: &[&str] = &["-", "–", "—", "•", "·", ">", "+"];

/// The statement digests of a text said in `class`: one per sentence with
/// words in it. A sentence ends at a line break, a CJK full stop, or `.`,
/// `!` or `?` before whitespace or the end, so a decimal point never splits
/// one.
fn statements(text: &str, class: Option<ClaimSource>) -> BTreeSet<[u8; 32]> {
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
            out.extend(statement(&text[start..at], class));
            start = at + ch.len_utf8();
        }
    }
    out.extend(statement(&text[start..], class));
    out
}

fn statement(sentence: &str, class: Option<ClaimSource>) -> Option<[u8; 32]> {
    let tokens: Vec<String> = sentence
        .split_whitespace()
        .skip_while(|token| BULLETS.contains(token))
        .map(|token| trim_token(token).to_lowercase())
        .filter(|token| !token.is_empty())
        .collect();
    if tokens.is_empty() {
        return None;
    }
    let class = class.map_or("", ClaimSource::as_str);
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron:dreamer-projector:statement:v3");
    hash.update(&(class.len() as u64).to_be_bytes());
    hash.update(class.as_bytes());
    hash.update(tokens.join(" ").as_bytes());
    Some(*hash.finalize().as_bytes())
}

/// A token without its formatting punctuation. A token with a digit keeps
/// a leading `.` or `,` that opens a number: `.5` is not `5`.
fn trim_token(token: &str) -> &str {
    let token = token.trim_end_matches(FORMATTING);
    if !token.chars().any(|ch| ch.is_ascii_digit()) {
        return token.trim_start_matches(FORMATTING);
    }
    let mut rest = token;
    while let Some(first) = rest.chars().next() {
        let after = &rest[first.len_utf8()..];
        let opens_number =
            matches!(first, '.' | ',') && after.starts_with(|ch: char| ch.is_ascii_digit());
        if !FORMATTING.contains(&first) || opens_number {
            break;
        }
        rest = after;
    }
    rest
}
