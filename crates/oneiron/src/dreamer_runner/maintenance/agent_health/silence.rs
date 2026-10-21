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
//! A read that fails for one attempt (its capsules, its park row, its
//! blocked reports) makes no claim for that attempt, with a warning, and the
//! pass goes on with the others: a failed read is never quiet.

use serde::{Deserialize, Serialize};

use super::call_evidence::{AgentCalls, CallActivity};
use super::{
    AgentHealthCounter, Attempts, DialBook, Dispatches, Finding, Traps, entity, said_blocked,
    task_of,
};
use crate::attempt_queue::{AttemptId, AttemptState};
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

/// Where `silent` takes each leased attempt's calls from.
pub(super) enum SilenceCalls<'a> {
    /// Every agent's calls in the nightly review's lookback, read once.
    Actors(&'a AgentCalls),
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
            Self::Actors(calls) => Some(CallActivity::of(
                calls.get(&actor).map_or(&[][..], Vec::as_slice),
                own,
                claimed,
            )),
            Self::Attempt(read, activity) => (*read == attempt).then_some(*activity),
        }
    }
}

/// `silent`: each leased attempt whose own activity is older than the dial,
/// with no open wait (an ask, a trap, a park) and no word that it is stuck
/// (a Blocked TASK or a blocked report). Saying it is stuck is the honest
/// move.
pub(super) fn silent_findings(
    vault: &Vault,
    calls: &SilenceCalls<'_>,
    dispatched: &Dispatches,
    attempts: &Attempts,
    traps: &Traps,
    book: &DialBook,
    now: u64,
) -> Vec<Finding> {
    let runner = DreamerRunnerStore::new(vault);
    let mut out = Vec::new();
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
        // The claim, its own calls and its actor's calls that name no
        // attempt; its model steps are read only when these leave it quiet.
        let heard = claimed
            .max(called.own.unwrap_or(0))
            .max(called.actor_only.unwrap_or(0));
        if now.saturating_sub(heard) < dials.silent_secs {
            continue;
        }
        let asked = record
            .asks
            .iter()
            .any(|ask| ask.answers.len() < ask.questions.len());
        if asked || traps.contains_key(id) {
            continue;
        }
        let stepped = match own_step(vault, attempt, generation) {
            Ok(stepped) => stepped,
            Err(error) => {
                unread("step capsules", &error);
                continue;
            }
        };
        let active = heard.max(stepped.unwrap_or(0));
        let quiet = now.saturating_sub(active);
        if quiet < dials.silent_secs {
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
        let task = task_of(record);
        match said_blocked(vault, dispatch.actor, task, claimed, Some(record.id)) {
            Ok(false) => {}
            Ok(true) => continue,
            Err(error) => {
                unread("blocked reports", &error);
                continue;
            }
        }
        let other_session = called.other.map(|(named, at)| HealthOtherSession {
            attempt: named.attempt,
            generation: named.generation,
            at,
        });
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
                other_session,
            }),
        });
    }
    out
}

/// The newest model step of `attempt` at lease `generation`: the capture
/// time of its newest step replay capsule there. Each row the reader returns
/// is held to the attempt and the generation here.
fn own_step(vault: &Vault, attempt: EntityId, generation: u32) -> Result<Option<u64>> {
    let rtxn = vault.store.env.read_txn()?;
    let capsules = crate::code_run::step_replay_capsules_in_txn(vault, &rtxn, attempt)?;
    Ok(capsules
        .iter()
        .filter(|capsule| capsule.attempt == attempt && capsule.lease_generation == generation)
        .map(|capsule| capsule.captured_at)
        .max())
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
