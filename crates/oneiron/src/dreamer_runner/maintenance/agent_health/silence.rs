//! `silent` (OF-568 L5, agent-mind §3: "A task is open, with no streamed
//! receipt, no open wait, no running tool call and no blocked report"): a
//! leased attempt that has gone the dial without activity of its own. The
//! nightly review and the targeted reviews judge it here, alike.
//!
//! Its activity clock is the newest of its claim, its own calls (receipts
//! that name it at its current lease generation), its own model steps (its
//! step replay capsules at that generation, by their capture time) and its
//! actor's newest call since the claim that names no attempt. That last call
//! cannot be attributed (FIX 8107: a spawned action row or a code-mode verb
//! carries no witness), so it still speaks for every leased attempt of the
//! actor. A call that names another attempt, or another generation of this
//! one, is never this attempt's activity: it shows on the card, as
//! [`AgentHealthCounter::OtherSessionActive`] and in its `silence`, and never
//! hides the silence.
//!
//! An open `silent` card whose attempt has spoken since shows what was read
//! now: its `silence` is refreshed without a finding (FIX 8376), so the card
//! never reads "silent since" past the attempt's newer activity.
//!
//! When this vault runs the attempt, its runtime witness joins them
//! (`code_run::activity`): an open tool call or model call means it is not
//! quiet, and its last streamed frame and last finished call join the clock.
//! The witness is in memory only; with none, the evidence above decides.
//!
//! A read that fails for one attempt (its capsules, its park row, its
//! blocked reports) makes no claim for that attempt, with a warning, and the
//! pass goes on with the others: a failed read is never quiet. So does a row
//! that did not read and may be its newest activity: a step capsule of its
//! generation, or a call receipt newer than all the activity it read.

use serde::{Deserialize, Serialize};

use super::call_evidence::{AgentCalls, CallActivity};
use super::{
    AgentHealthCounter, AgentHealthOutcome, Attempts, CARDS, DialBook, Dispatches, Finding, Traps,
    card_key, entity, said_blocked, task_of,
};
use crate::attempt_queue::{AttemptId, AttemptRecord, AttemptState};
use crate::code_run::activity::AttemptActivity;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::receipt::CallAttemptRef;
use crate::self_heal::AgentHealthSignal;
use crate::{EntityId, Error, Result, Vault};

/// The activity `silent` judged one leased attempt's quiet by (OF-568 L5),
/// each part the newest of its kind since the attempt's claim. A card holds
/// its newest finding's; none of it is evidence, so it never reopens a
/// settled card.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthSilenceActivity {
    /// Its own newest call: a receipt that names it at its current lease
    /// generation, in Unix seconds.
    pub own_call_at: Option<u64>,
    /// Its own newest model step at that generation: the step replay
    /// capsule's capture time, in Unix seconds.
    pub own_step_at: Option<u64>,
    /// Its actor's newest call that names no attempt, even when older than
    /// the dial. It cannot be attributed, so it counts for every leased
    /// attempt of the actor.
    pub actor_only_at: Option<u64>,
    /// The runtime's last streamed output frame for this lease, in Unix
    /// seconds, while this vault runs it. In memory only: a restart, or the
    /// end of its last run's binding, drops it.
    pub stream_at: Option<u64>,
    /// The runtime's last finished tool call for this lease (answered,
    /// refused or failed), in Unix seconds; in memory only, as `stream_at`.
    pub tool_finished_at: Option<u64>,
    /// Its actor's newest call that names another attempt, or another
    /// generation of this one: counter-evidence only.
    pub other_session: Option<HealthOtherSession>,
}

/// Another session of the same agent that made a call since the attempt's
/// claim (OF-568 L5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthOtherSession {
    /// The attempt the call's receipt names.
    pub attempt: EntityId,
    /// The lease generation the receipt names.
    pub generation: u32,
    /// When the call was recorded, in Unix seconds.
    pub at: u64,
}

/// A card's key: its subject, signal and TASK.
type CardKey = ([u8; 16], [u8; 1], [u8; 16]);

/// An open `silent` card's activity as read now, for a leased attempt
/// `silent` found active (FIX 8376): `land` writes it onto the card.
pub(super) struct SilenceRefresh {
    pub(super) key: CardKey,
    pub(super) silence: HealthSilenceActivity,
}

/// Where `silent` takes each leased attempt's calls from.
pub(super) enum SilenceCalls<'a> {
    /// Every agent's calls in the nightly review's lookback, read once, and
    /// the newest time a receipt that did not read may hold.
    Actors(&'a AgentCalls, Option<u64>),
    /// One attempt's, from its targeted review's scan.
    Attempt(AttemptId, CallActivity),
}

impl SilenceCalls<'_> {
    /// One leased attempt's calls since `claimed`; `None` when this source
    /// holds no read of them.
    fn of(
        &self,
        actor: EntityId,
        attempt: AttemptId,
        own: CallAttemptRef,
        claimed: u64,
    ) -> Option<CallActivity> {
        match self {
            Self::Actors(calls, unread) => Some(CallActivity {
                unread: *unread,
                ..CallActivity::of(
                    calls.get(&actor).map_or(&[][..], Vec::as_slice),
                    own,
                    claimed,
                )
            }),
            Self::Attempt(read, activity) => (*read == attempt).then_some(*activity),
        }
    }
}

/// `silent`: each leased attempt whose own activity is older than the dial,
/// with no open wait (an ask, a trap, a park) and no word that it is stuck
/// (a Blocked TASK or a blocked report). Saying it is stuck is the honest
/// move. Each leased attempt with activity inside the dial refreshes its
/// open `silent` card, when the card holds older activity.
pub(super) fn silent_findings(
    vault: &Vault,
    calls: &SilenceCalls<'_>,
    dispatched: &Dispatches,
    attempts: &Attempts,
    traps: &Traps,
    book: &DialBook,
    now: u64,
) -> (Vec<Finding>, Vec<SilenceRefresh>) {
    let runner = DreamerRunnerStore::new(vault);
    let mut out = Vec::new();
    let mut refreshes = Vec::new();
    for (id, dispatch) in dispatched {
        let Some(record) = attempts.get(id) else {
            continue;
        };
        if record.state != AttemptState::Leased {
            continue;
        }
        let Some(attempt) = entity(record.id) else {
            continue;
        };
        let generation = record.attempt_count;
        let claimed = record.claimed_at.unwrap_or(record.updated_at);
        let Some(called) = calls.of(
            dispatch.actor,
            record.id,
            CallAttemptRef {
                attempt,
                generation,
            },
            claimed,
        ) else {
            continue;
        };
        let dials = book.of(Some(dispatch));
        let task = task_of(record);
        let key = card_key(dispatch.actor, AgentHealthSignal::Silent, task);
        // The claim, its own calls and its actor's calls that name no
        // attempt; its model steps are read only when these leave it quiet.
        let heard = claimed
            .max(called.own.unwrap_or(0))
            .max(called.actor_only.unwrap_or(0));
        if now.saturating_sub(heard) < dials.silent_secs {
            refreshes.extend(refreshed(vault, key, &called, attempt, record, None));
            continue;
        }
        let asked = record
            .asks
            .iter()
            .any(|ask| ask.answers.len() < ask.questions.len());
        if asked || traps.contains_key(id) {
            continue;
        }
        let (stepped, step_unread) = match own_step(vault, attempt, generation) {
            Ok(read) => read,
            Err(error) => {
                unread("step capsules", &error);
                continue;
            }
        };
        let active = heard.max(stepped.unwrap_or(0));
        let step = Some((stepped, step_unread));
        if now.saturating_sub(active) < dials.silent_secs {
            refreshes.extend(refreshed(vault, key, &called, attempt, record, step));
            continue;
        }
        // The runtime's witness of this lease, when this vault runs it: an
        // open tool or model call is not quiet, and its last frame and
        // finished call join the clock. With none, the reads above decide.
        let runtime = vault.attempt_activity.snapshot(record.id, generation);
        if runtime.is_some_and(AttemptActivity::running) {
            refreshes.extend(refreshed(vault, key, &called, attempt, record, step));
            continue;
        }
        let stream_at = runtime.and_then(|seen| seen.last_stream_at);
        let tool_finished_at = runtime.and_then(|seen| seen.last_call_finished_at);
        let active = active
            .max(stream_at.unwrap_or(0))
            .max(tool_finished_at.unwrap_or(0));
        let quiet = now.saturating_sub(active);
        if quiet < dials.silent_secs {
            refreshes.extend(refreshed(vault, key, &called, attempt, record, step));
            continue;
        }
        if step_unread {
            unreadable("step capsules");
            continue;
        }
        if called.unread.is_some_and(|newest| newest > active) {
            unreadable("call receipts");
            continue;
        }
        match runner.parked_attempt(record.id) {
            Ok(None) => {}
            Ok(Some(_)) => continue,
            Err(error) => {
                unread("park", &error);
                continue;
            }
        }
        match said_blocked(vault, dispatch.actor, task, claimed, Some(record.id)) {
            Ok(false) => {}
            Ok(true) => continue,
            Err(error) => {
                unread("blocked reports", &error);
                continue;
            }
        }
        let other_session = other_session(&called);
        out.push(Finding {
            subject: dispatch.actor,
            signal: AgentHealthSignal::Silent,
            task,
            attempt: Some(record.id),
            evidence: vec![attempt],
            window: (active, now),
            actual: 0,
            dial: 1,
            measured: quiet as i64,
            // Another session's call is shown, and never hides this one.
            counter: other_session
                .map(|_| AgentHealthCounter::OtherSessionActive)
                .into_iter()
                .collect(),
            confession: None,
            blocked: false,
            observed_brief: None,
            silence: Some(HealthSilenceActivity {
                own_call_at: called.own,
                own_step_at: stepped,
                actor_only_at: called.actor_only,
                stream_at,
                tool_finished_at,
                other_session,
            }),
        });
    }
    (out, refreshes)
}

/// Another session's newest call since the claim, as the card shows it.
fn other_session(called: &CallActivity) -> Option<HealthOtherSession> {
    called.other.map(|(named, at)| HealthOtherSession {
        attempt: named.attempt,
        generation: named.generation,
        at,
    })
}

/// The refresh of a leased attempt's open `silent` card, the attempt found
/// active: its activity as read now, each part as a finding holds it, when
/// that differs from the card's. Its step capsules are read here unless the
/// caller read them (`step`). A read that fails, or a row that did not read,
/// refreshes nothing: the card keeps what it holds.
fn refreshed(
    vault: &Vault,
    key: CardKey,
    called: &CallActivity,
    attempt: EntityId,
    record: &AttemptRecord,
    step: Option<(Option<u64>, bool)>,
) -> Option<SilenceRefresh> {
    read_refresh(vault, key, called, attempt, record, step).unwrap_or_else(|error| {
        tracing::warn!(
            kind = ?error.kind(),
            "agent-health silence card not refreshed for an active attempt: a read failed"
        );
        None
    })
}

/// [`refreshed`]'s reads; an error is a read that failed.
fn read_refresh(
    vault: &Vault,
    key: CardKey,
    called: &CallActivity,
    attempt: EntityId,
    record: &AttemptRecord,
    step: Option<(Option<u64>, bool)>,
) -> Result<Option<SilenceRefresh>> {
    let held = {
        let rtxn = vault.store.env.read_txn()?;
        CARDS.get(&vault.store, &rtxn, &key)?
    };
    let Some(card) = held.filter(|card| card.outcome == AgentHealthOutcome::Open) else {
        return Ok(None);
    };
    if called.unread.is_some() {
        return Ok(None);
    }
    let (stepped, undecodable) = match step {
        Some(read) => read,
        None => own_step(vault, attempt, record.attempt_count)?,
    };
    if undecodable {
        return Ok(None);
    }
    let runtime = vault
        .attempt_activity
        .snapshot(record.id, record.attempt_count);
    let silence = HealthSilenceActivity {
        own_call_at: called.own,
        own_step_at: stepped,
        actor_only_at: called.actor_only,
        stream_at: runtime.and_then(|seen| seen.last_stream_at),
        tool_finished_at: runtime.and_then(|seen| seen.last_call_finished_at),
        other_session: other_session(called),
    };
    Ok((card.silence != Some(silence)).then_some(SilenceRefresh { key, silence }))
}

/// The newest model step of `attempt` at lease `generation`: the capture
/// time of its newest step replay capsule there, and whether a capsule row
/// there did not read, from one snapshot. Each row the reader returns is held
/// to the attempt and the generation here.
fn own_step(vault: &Vault, attempt: EntityId, generation: u32) -> Result<(Option<u64>, bool)> {
    let rtxn = vault.store.env.read_txn()?;
    let capsules = crate::code_run::step_replay_capsules_in_txn(vault, &rtxn, attempt)?;
    let undecodable =
        crate::code_run::undecodable_step_capsule_in_txn(vault, &rtxn, attempt, generation)?;
    let newest = capsules
        .iter()
        .filter(|capsule| capsule.attempt == attempt && capsule.lease_generation == generation)
        .map(|capsule| capsule.captured_at)
        .max();
    Ok((newest, undecodable))
}

/// One attempt's silence goes unjudged: one of its reads failed, and a
/// failed read is never quiet. The pass goes on with the others.
fn unread(read: &'static str, error: &Error) {
    tracing::warn!(
        read,
        kind = ?error.kind(),
        "agent-health silence not judged for an attempt: a read failed"
    );
}

/// One attempt's silence goes unjudged: a row of `read` did not read and may
/// be its newest activity. The pass goes on with the others.
fn unreadable(read: &'static str) {
    tracing::warn!(
        read,
        "agent-health silence not judged for an attempt: a row did not read"
    );
}
