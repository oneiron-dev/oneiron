//! The Dreamer's cheap arm as a follower session over the admitted log
//! (ARCH-0026 #cheap-arm, FIX 7510).
//!
//! One session per (Dreamer authority, read scope) follows the ordered feed
//! of newly admitted source observations, read forward from its own change
//! cursor. It holds a prefix of everything it has read: the policy's fixed
//! instruction, the standing keyframe if any, then its frames, each kept as
//! the exact bytes it was first rendered as. Each call appends a suffix: the
//! frames not yet sent, then the one-shot question over the owed novelty
//! spans, one reading each. A suffix moves through Prepared (its spans, its
//! new frames, the prefix digest it was prepared over and its question's
//! digest, durable here), a checked durable model step, and one publish:
//! the readings through the interest queue, the result row, the prefix's
//! promotion and the applied cursor, together. A retry sends the prepared
//! bytes again; a trap or a failure never moves the applied cursor.
//!
//! A keyframe resets the prefix: an explicit event, a prefix past the
//! model's window, or an erase that took words a keyframe folded. A route
//! change, an instruction change or a new reported cache identity resends
//! the same coverage cold under a new epoch. A suffix already prepared
//! drains first, and survives a reset. Caching is the backend's to report:
//! nothing here reads a hit from a digest, a warm bit, a TTL or an epoch.
//!
//! One wake per turn is the default, not a duty: a wake with nothing owed
//! asks nothing, and the frames it read wait for the next question.

mod keyframe;
mod log;
mod state;

use std::collections::BTreeSet;

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::dreamer_runner::{
    DreamerAttemptPayload, DreamerAttemptStatus, DreamerConsolidationScope, DreamerRunnerStore,
};
use crate::dreamer_wake::SieveSpan;
use crate::dreamer_wake::recipes::{WakeRecipePolicy, policy_in_txn};
use crate::dreamer_wake::sieve::follower::{
    candidates_in_txn, novelty_owed_in_txn, owed_novelty_in_txn, still_queued_in_txn,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::llm::Scope;
use crate::store::Store;

pub(crate) use keyframe::{
    FoldWork, KeyframeCommit, Sizing, commit_keyframe_in_txn, erase_in_txn, fold_groups,
};
use keyframe::{Standing, fold_work, foldable};
use log::{Log, quote_in};
pub(crate) use state::{
    AskedSpan, CacheResidency, CallEvidence, Pin, Publication, Receipt, Writer, publish_in_txn,
    unpaid_in,
};
use state::{FollowerResult, PreparedSuffix, Session, SessionKey, held_session_in_txn, pins_of};

/// The follower's attempt type: a Micro job, one queued per session.
pub(crate) const FOLLOWER_ATTEMPT: &str = "dreamer.sieve.follower";

const SESSION_DOMAIN: &[u8] = b"oneiron:dreamer-follower:session:v1";
/// The read scope every session reads under at this head: the Dreamer's own
/// gate over the vault. An off-record or private route never reaches the
/// sieve, so it never shares a session.
const READ_SCOPE: &[u8] = b"dreamer-gate:vault";
const PREFIX_DOMAIN: &[u8] = b"oneiron:dreamer-follower:prefix:v1";
const QUESTION_DOMAIN: &[u8] = b"oneiron:dreamer-follower:question:v1";

/// The follower attempt's input: the session it writes.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FollowerInput {
    session: String,
}

fn invalid() -> Error {
    Error::InvalidConfig("invalid Dreamer follower payload".into())
}

/// The session of the vault-local Dreamer authority under its read scope.
pub(crate) fn session_key() -> Result<SessionKey> {
    let authority = crate::dreamer_runner::authority::dreamer_actor_id()?;
    Ok(*blake3::Hasher::new()
        .update(SESSION_DOMAIN)
        .update(authority.as_bytes())
        .update(READ_SCOPE)
        .finalize()
        .as_bytes())
}

/// The session a follower attempt's `input` names, when it is the live one.
pub(crate) fn check_input(input: &Value) -> Result<SessionKey> {
    let input: FollowerInput =
        serde_json::from_str(input.as_str().ok_or_else(invalid)?).map_err(|_| invalid())?;
    let key = session_key()?;
    if input.session != bytes_to_hex_lower(&key) {
        return Err(invalid());
    }
    Ok(key)
}

/// Queues the session's follower attempt, deduped: one waits per session.
fn enqueue_in_txn(
    store: &DreamerRunnerStore<'_>,
    txn: &mut heed::RwTxn<'_>,
    parent: Option<&DreamerAttemptStatus>,
    key: &SessionKey,
    now: u64,
) -> Result<()> {
    let session = bytes_to_hex_lower(key);
    let input = serde_json::to_string(&FollowerInput {
        session: session.clone(),
    })
    .map_err(|_| invalid())?;
    store.enqueue_kind_in_txn(
        txn,
        DreamerConsolidationScope::Micro.attempt_kind(),
        DreamerAttemptPayload {
            attempt_type: FOLLOWER_ATTEMPT.into(),
            input: Value::from(input),
            parent_attempt: parent.map(|parent| parent.attempt.id),
        },
        Some(format!("sieve:follower:{session}")),
        parent.and_then(|parent| parent.attempt.run_id.clone()),
        now,
    )?;
    Ok(())
}

/// The router's door: frames `span`'s chunk now and queues the follower,
/// returning true; false leaves the span on its own rung, as before, when
/// its chunk cannot be framed or it was handed back already.
pub(crate) fn route_in_txn(
    store: &DreamerRunnerStore<'_>,
    txn: &mut heed::RwTxn<'_>,
    parent: Option<&DreamerAttemptStatus>,
    span: &SieveSpan,
    now: u64,
) -> Result<bool> {
    let vault = store.vault();
    let policy = policy_in_txn(vault, txn)?;
    let key = session_key()?;
    let mut session = state::open_in_txn(vault, txn, key, &policy.follower_instruction, [0; 32])?;
    if session.state.handed.contains(&span.id) {
        return Ok(false);
    }
    // The span's chunk is found by key (FIX 8531), never by loading every
    // frame; only a chunk not yet framed appends one.
    let routed = state::framed_span_in_txn(&vault.store, txn, &session, span)?.is_some()
        || log::frame_span_in_txn(vault, txn, &mut session, &mut Log::empty(), span)?.is_some();
    if !routed {
        session.state.handed.push(span.id);
    }
    state::save_in_txn(&vault.store, txn, &session)?;
    if routed {
        enqueue_in_txn(store, txn, parent, &key, now)?;
    }
    Ok(routed)
}

/// The turn producer's wake (one per turn by default): queues the follower
/// when it is on and a queued span owes the novelty rung. Returns whether
/// it queued.
pub(crate) fn wake_in_txn(vault: &Vault, txn: &mut heed::RwTxn<'_>, now: u64) -> Result<bool> {
    if !policy_in_txn(vault, txn)?.follower_enabled || !novelty_owed_in_txn(vault, txn)? {
        return Ok(false);
    }
    enqueue_in_txn(
        &DreamerRunnerStore::new(vault),
        txn,
        None,
        &session_key()?,
        now,
    )?;
    Ok(true)
}

/// The sieve pass's wake, for a pass that just queued spans: queues the
/// follower when it is on, without the queue-wide novelty scan, since every
/// new span owes the novelty rung. Returns whether it queued.
pub(crate) fn wake_queued_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    now: u64,
) -> Result<bool> {
    if !policy_in_txn(vault, txn)?.follower_enabled {
        return Ok(false);
    }
    enqueue_in_txn(
        &DreamerRunnerStore::new(vault),
        txn,
        None,
        &session_key()?,
        now,
    )?;
    Ok(true)
}

/// One follower attempt's fixed inputs for a transaction.
pub(crate) struct FollowerCall<'a> {
    pub(crate) key: SessionKey,
    pub(crate) writer: Writer,
    pub(crate) parent: &'a DreamerAttemptStatus,
    pub(crate) policy: &'a WakeRecipePolicy,
    /// The model and locality the call goes out on, hashed.
    pub(crate) route: [u8; 32],
    pub(crate) sizing: Sizing,
    pub(crate) now: u64,
}

/// A span a suffix asks about, with the words its offsets index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Asked {
    pub(crate) asked: AskedSpan,
    pub(crate) quote: String,
}

/// A suffix to send: the prefix parts in order (keyframe, then the frames
/// already sent), the new frames, the question and its spans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AskWork {
    pub(crate) seq: u64,
    pub(crate) instruction: String,
    pub(crate) prefix: Vec<String>,
    pub(crate) fresh: Vec<String>,
    pub(crate) question: String,
    pub(crate) asked: Vec<Asked>,
    pub(crate) pins: Vec<Pin>,
    pub(crate) base_prefix: [u8; 32],
}

/// What a follower attempt does next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Next {
    /// Nothing is owed: the frames read wait for the next question.
    Idle,
    Fold(FoldWork),
    Ask(AskWork),
}

/// The session's next step, in one transaction: the writer fence taken, the
/// log read forward, then a prepared suffix to drain, a keyframe owed, or a
/// new suffix over the owed spans. `question` renders a suffix's question.
pub(crate) fn next_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    call: &FollowerCall<'_>,
    question: &dyn Fn(&[Asked]) -> Result<String>,
) -> Result<Next> {
    let instruction = &call.policy.follower_instruction;
    let mut session = state::open_in_txn(vault, txn, call.key, instruction, call.route)?;
    session.state.writer = Some(call.writer);
    // A route change resends the same coverage cold, under a new epoch.
    if session.state.route != call.route {
        session.state.route = call.route;
        session.state.epoch = session.state.epoch.saturating_add(1);
    }
    // A new instruction opens a new prefix once no suffix waits on the old.
    if session.state.suffix.is_none() && session.state.instruction != *instruction {
        session.state.instruction.clone_from(instruction);
        session.state.epoch = session.state.epoch.saturating_add(1);
    }
    let mut log = Log::load_in_txn(&vault.store, txn, &session)?;
    log::materialize_in_txn(vault, txn, &mut session, &mut log)?;
    let standing = standing_in_txn(&vault.store, txn, &session)?;
    let next = plan_in_txn(
        vault,
        txn,
        call,
        &mut session,
        &mut log,
        standing.as_ref(),
        question,
    )?;
    state::save_in_txn(&vault.store, txn, &session)?;
    Ok(next)
}

/// The standing keyframe, read from its result row.
fn standing_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    session: &Session,
) -> Result<Option<Standing>> {
    let Some(key) = session.state.keyframe else {
        return Ok(None);
    };
    Ok(match state::result_in_txn(store, txn, &key)? {
        Some(FollowerResult::Keyframe { bytes, turns, .. }) => Some(Standing { bytes, turns }),
        _ => None,
    })
}

fn plan_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    call: &FollowerCall<'_>,
    session: &mut Session,
    log: &mut Log,
    standing: Option<&Standing>,
    question: &dyn Fn(&[Asked]) -> Result<String>,
) -> Result<Next> {
    let applied = session.state.applied_through;
    // A prepared suffix drains first, rebased on the prefix it goes out
    // over; one the window no longer holds waits under a keyframe.
    if let Some(suffix) = session.state.suffix.take()
        && let Some(ask) = resume(session, log, standing, &suffix, question)?
    {
        if call.sizing.fits(ask_bytes(&ask)) || !foldable(session, applied) {
            session.state.suffix = Some(PreparedSuffix {
                base_prefix: ask.base_prefix,
                ..suffix
            });
            return Ok(Next::Ask(ask));
        }
        session.state.suffix = Some(suffix);
        return Ok(Next::Fold(fold_work(session, standing, log, applied)));
    }
    if session.state.fold_due {
        if foldable(session, applied) {
            return Ok(Next::Fold(fold_work(session, standing, log, applied)));
        }
        session.state.fold_due = false;
    }
    let prefix = prefix_bytes(session, log, standing);
    let room = call.sizing.room(prefix);
    let owed = owed_novelty_in_txn(vault, txn)?;
    session
        .state
        .handed
        .retain(|id| owed.iter().any(|(span, _)| span.id == *id));
    let mut asked = Vec::new();
    let mut planned = 0_usize;
    for (span, readable) in owed {
        if !readable || session.state.handed.contains(&span.id) {
            continue;
        }
        let framed = log.find(&span).is_some();
        // Pacing, not a cap: a span past this suffix's room waits owed.
        if !framed && !asked.is_empty() && room.is_some_and(|room| planned >= room) {
            continue;
        }
        let Some((frame, chunk)) = log::frame_span_in_txn(vault, txn, session, log, &span)? else {
            hand_span_in_txn(vault, txn, call, session, &span)?;
            continue;
        };
        let Some(quote) = quote_in(log, frame, chunk, &span)? else {
            hand_span_in_txn(vault, txn, call, session, &span)?;
            continue;
        };
        let mut scope = Scope::default();
        // A turn or source the Dreamer cannot read now waits for its grant.
        let Some(candidates) = candidates_in_txn(vault, txn, &span, &quote, &mut scope)? else {
            continue;
        };
        let entry = Asked {
            asked: AskedSpan {
                span,
                frame,
                chunk,
                candidates,
                pins: pins_of(&scope),
            },
            quote,
        };
        if !framed {
            planned = planned
                .saturating_add(log.held_mut(frame).map_or(0, |held| held.frame.bytes.len()));
        }
        planned = planned.saturating_add(question(std::slice::from_ref(&entry))?.len());
        asked.push(entry);
    }
    if asked.is_empty() {
        return Ok(Next::Idle);
    }
    asked.sort_by_key(|entry| {
        (
            entry.asked.frame,
            entry.asked.chunk,
            entry.asked.span.start,
            entry.asked.span.id,
        )
    });
    pack(call, session, log, standing, asked, question)
}

/// Packs a suffix from `asked`, sorted by frame: the spans of frames already
/// sent, then each new frame in order with its spans, while the window
/// holds them. A prefix the window cannot hold beside the least suffix that
/// moves the log on folds first.
fn pack(
    call: &FollowerCall<'_>,
    session: &mut Session,
    log: &Log,
    standing: Option<&Standing>,
    asked: Vec<Asked>,
    question: &dyn Fn(&[Asked]) -> Result<String>,
) -> Result<Next> {
    let applied = session.state.applied_through;
    let prefix = prefix_bytes(session, log, standing);
    let first = asked.first().map_or(applied, |entry| entry.asked.frame);
    let need = if first <= applied { applied } else { first };
    let pending: Vec<(u64, usize)> = log
        .frames
        .iter()
        .filter(|held| held.ordinal > applied)
        .map(|held| (held.ordinal, held.frame.bytes.len()))
        .collect();
    let mut costs = Vec::with_capacity(asked.len());
    for entry in &asked {
        costs.push(question(std::slice::from_ref(entry))?.len());
    }
    let least = pending
        .iter()
        .filter(|(ordinal, _)| *ordinal <= need)
        .map(|(_, len)| *len)
        .sum::<usize>()
        .saturating_add(costs.first().copied().unwrap_or_default());
    if !call.sizing.fits(prefix.saturating_add(least)) {
        let through = if need > applied { need - 1 } else { applied };
        if foldable(session, through) {
            return Ok(Next::Fold(fold_work(session, standing, log, through)));
        }
    }
    let mut used = prefix;
    let mut through = applied;
    let mut chosen = Vec::new();
    let mut rest = asked.into_iter().zip(costs).peekable();
    let mut full = false;
    while let Some((entry, cost)) = rest.next_if(|(entry, _)| entry.asked.frame <= applied) {
        if !chosen.is_empty() && !call.sizing.fits(used.saturating_add(cost)) {
            full = true;
            break;
        }
        used = used.saturating_add(cost);
        chosen.push(entry);
    }
    for (ordinal, len) in pending {
        if full {
            break;
        }
        let mut here = Vec::new();
        while let Some(item) = rest.next_if(|(entry, _)| entry.asked.frame == ordinal) {
            here.push(item);
        }
        if ordinal <= need {
            used = used.saturating_add(len);
            through = ordinal;
            for (entry, cost) in here {
                if !chosen.is_empty() && !call.sizing.fits(used.saturating_add(cost)) {
                    full = true;
                    break;
                }
                used = used.saturating_add(cost);
                chosen.push(entry);
            }
            continue;
        }
        let total = here
            .iter()
            .map(|(_, cost)| *cost)
            .fold(len, usize::saturating_add);
        if !call.sizing.fits(used.saturating_add(total)) {
            break;
        }
        used = used.saturating_add(total);
        through = ordinal;
        chosen.extend(here.into_iter().map(|(entry, _)| entry));
    }
    let seq = session.state.next_seq;
    session.state.next_seq = seq.saturating_add(1);
    let ask = build(session, log, standing, seq, through, chosen, question)?;
    session.state.suffix = Some(PreparedSuffix {
        seq,
        frames_through: through,
        spans: ask.asked.iter().map(|entry| entry.asked.clone()).collect(),
        base_prefix: ask.base_prefix,
        question: question_digest(&ask.question),
    });
    Ok(Next::Ask(ask))
}

/// The prepared suffix as it goes out now: `None` when a span's frame was
/// folded or erased, a new frame went, or the question no longer renders
/// the bytes it was prepared as. Its spans are then asked anew.
fn resume(
    session: &Session,
    log: &mut Log,
    standing: Option<&Standing>,
    suffix: &PreparedSuffix,
    question: &dyn Fn(&[Asked]) -> Result<String>,
) -> Result<Option<AskWork>> {
    let applied = session.state.applied_through;
    if suffix.frames_through < applied {
        return Ok(None);
    }
    let fresh = log
        .frames
        .iter()
        .filter(|held| held.ordinal > applied && held.ordinal <= suffix.frames_through)
        .count();
    if u64::try_from(fresh).ok() != Some(suffix.frames_through - applied) {
        return Ok(None);
    }
    let mut asked = Vec::with_capacity(suffix.spans.len());
    for span in &suffix.spans {
        if span.frame <= session.state.covered_through {
            return Ok(None);
        }
        let Some(quote) = quote_in(log, span.frame, span.chunk, &span.span)? else {
            return Ok(None);
        };
        asked.push(Asked {
            asked: span.clone(),
            quote,
        });
    }
    let ask = build(
        session,
        log,
        standing,
        suffix.seq,
        suffix.frames_through,
        asked,
        question,
    )?;
    Ok((question_digest(&ask.question) == suffix.question).then_some(ask))
}

/// The suffix's request parts over the session's prefix.
fn build(
    session: &Session,
    log: &Log,
    standing: Option<&Standing>,
    seq: u64,
    through: u64,
    asked: Vec<Asked>,
    question: &dyn Fn(&[Asked]) -> Result<String>,
) -> Result<AskWork> {
    let applied = session.state.applied_through;
    let mut prefix = Vec::new();
    if let Some(standing) = standing {
        prefix.push(standing.bytes.clone());
    }
    let mut fresh = Vec::new();
    let mut pins = BTreeSet::new();
    for held in &log.frames {
        if held.ordinal <= applied {
            prefix.push(held.frame.bytes.clone());
        } else if held.ordinal <= through {
            fresh.push(held.frame.bytes.clone());
        } else {
            continue;
        }
        pins.extend(held.frame.pins.iter().cloned());
    }
    for entry in &asked {
        pins.extend(entry.asked.pins.iter().cloned());
    }
    let question = question(&asked)?;
    let base_prefix = prefix_digest(&session.state.instruction, &prefix);
    Ok(AskWork {
        seq,
        instruction: session.state.instruction.clone(),
        prefix,
        fresh,
        question,
        asked,
        pins: pins.into_iter().collect(),
        base_prefix,
    })
}

/// The bytes of the prefix as it stands: instruction, keyframe, sent frames.
fn prefix_bytes(session: &Session, log: &Log, standing: Option<&Standing>) -> usize {
    let applied = session.state.applied_through;
    log.frames
        .iter()
        .filter(|held| held.ordinal <= applied)
        .map(|held| held.frame.bytes.len())
        .fold(
            session
                .state
                .instruction
                .len()
                .saturating_add(standing.map_or(0, |standing| standing.bytes.len())),
            usize::saturating_add,
        )
}

/// Every byte one suffix's request carries.
fn ask_bytes(ask: &AskWork) -> usize {
    ask.prefix.iter().chain(&ask.fresh).map(String::len).fold(
        ask.instruction.len().saturating_add(ask.question.len()),
        usize::saturating_add,
    )
}

/// The chained digest of a prefix's parts, the instruction first.
fn prefix_digest(instruction: &str, parts: &[String]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PREFIX_DOMAIN);
    for part in std::iter::once(instruction).chain(parts.iter().map(String::as_str)) {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn question_digest(question: &str) -> [u8; 32] {
    *blake3::Hasher::new()
        .update(QUESTION_DOMAIN)
        .update(question.as_bytes())
        .finalize()
        .as_bytes()
}

/// Hands `span` back to its own rung, as the per-span path asks it, and
/// keeps the session from asking it again while it waits queued.
fn hand_span_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    call: &FollowerCall<'_>,
    session: &mut Session,
    span: &SieveSpan,
) -> Result<()> {
    crate::dreamer_wake::sieve::per_span_in_txn(
        &DreamerRunnerStore::new(vault),
        txn,
        call.parent,
        span,
        false,
        call.policy.clone(),
        call.now,
    )?;
    if !session.state.handed.contains(&span.id) {
        session.state.handed.push(span.id);
    }
    Ok(())
}

/// A suffix the model refused as a request: each of its spans still queued
/// goes back to its own rung, as the per-span path asks it, and the retained
/// frames fold before the next suffix. The applied cursor stays.
pub(crate) fn hand_back_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    call: &FollowerCall<'_>,
    seq: u64,
) -> Result<bool> {
    let Some(mut session) = held_session_in_txn(&vault.store, txn, call.key, call.writer)? else {
        return Ok(false);
    };
    let Some(suffix) = session.state.suffix.take() else {
        return Ok(false);
    };
    if suffix.seq != seq {
        return Ok(false);
    }
    for asked in &suffix.spans {
        if still_queued_in_txn(vault, txn, &asked.span)? {
            hand_span_in_txn(vault, txn, call, &mut session, &asked.span)?;
        }
    }
    session.state.fold_due = session.state.applied_through > session.state.covered_through;
    state::save_in_txn(&vault.store, txn, &session)?;
    Ok(true)
}

/// A fold the model refused as a request: the prepared suffix's spans and
/// every other owed span go back to their own rungs, as the per-span path
/// asks them, and no fold stays owed. The applied cursor stays.
pub(crate) fn hand_back_owed_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    call: &FollowerCall<'_>,
) -> Result<bool> {
    let Some(mut session) = held_session_in_txn(&vault.store, txn, call.key, call.writer)? else {
        return Ok(false);
    };
    if let Some(suffix) = session.state.suffix.take() {
        for asked in &suffix.spans {
            if still_queued_in_txn(vault, txn, &asked.span)? {
                hand_span_in_txn(vault, txn, call, &mut session, &asked.span)?;
            }
        }
    }
    for (span, readable) in owed_novelty_in_txn(vault, txn)? {
        if readable && !session.state.handed.contains(&span.id) {
            hand_span_in_txn(vault, txn, call, &mut session, &span)?;
        }
    }
    session.state.fold_due = false;
    state::save_in_txn(&vault.store, txn, &session)?;
    Ok(true)
}
