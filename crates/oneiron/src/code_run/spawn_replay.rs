//! The one comparison of a recorded bridge row's request with the request
//! its call makes again (FIX 7447), for every replay of a row: the replay
//! cursor, which never issues a call, and a resumed program's entry, which
//! issues live what no row answers.
//!
//! A spawn's row also names the targets its host resolved for it (FIX 9180,
//! Engine C1): [`SpawnTargets`], text-free. An erase of one of them takes
//! the call's ask and nothing else (C2, [`erase_spawn_call`]): the request
//! keeps every other field, its ask the typed marker
//! `{state: erased, cause: target_erased}`, and the call answers the typed
//! `TargetErased` its replay hands back without launching (C3). A nil ask
//! stays nil and is compared exactly: it is never an erased wildcard.

use std::collections::BTreeSet;

use rmpv::Value;

use super::coordination_codec::SPAWN_INTENT_KEYS;
use super::payload::{
    decode_self_dispatch_outcome, keep_row_receipt, row_receipt, self_dispatch_outcome_value,
};
use super::replay::CodeRunBridgeCall;
use super::support::{
    decode_array, entity_id_value, entity_value, fixed_binary, invalid_code_run_replay, pinned_map,
    request_map, required, str_value,
};
use super::types::{SelfAgentSpawnResult, SelfDispatchOutcome, SelfEffect};
use crate::attempt_queue::AttemptId;
use crate::batch::secret_scan::admitted_from;
use crate::{EntityId, Result};

/// The request key of a spawn's ask.
const ASK_KEY: &str = "ask";

/// The keys of a stored [`SpawnTargets`], in order.
const SPAWN_TARGET_KEYS: [&str; 3] = ["seats", "attempt", "proposal"];

/// How a recorded row's request meets the request its call makes now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReplayRequestMatch {
    /// The very request the row recorded: the row answers it. A request the
    /// side-row wall masked still matches the secrets it holds (OF-067).
    Hit,
    /// The same spawn asked for another project or other objectives (FIX
    /// 7447): a replay miss, never the row's answer. A live caller issues
    /// the call live through its ordinary gates; a replay-only one reports
    /// the mismatch.
    SpawnMiss,
    /// Any other request: the drift each caller answers as it did.
    Drift,
}

impl ReplayRequestMatch {
    /// Whether the row answers the call.
    pub(super) const fn is_hit(self) -> bool {
        matches!(self, Self::Hit)
    }
}

/// `stored`, the request a row of `effect` recorded, against `offered`, the
/// request its call makes now under the row's own bridge stamp. Pure: it
/// reads and writes nothing.
///
/// # Errors
///
/// A request the side-row wall cannot compare: unreadable.
pub(super) fn replay_request_match(
    effect: SelfEffect,
    stored: &Value,
    offered: &Value,
) -> Result<ReplayRequestMatch> {
    if stored == offered || admitted_from(stored, offered)? {
        return Ok(ReplayRequestMatch::Hit);
    }
    if effect == SelfEffect::AgentsSpawn {
        return spawn_match(stored, offered);
    }
    Ok(ReplayRequestMatch::Drift)
}

/// A spawn's request that is not its row's: the row's answer when an erase
/// of its target took its ask and every other field is the same (FIX 9180),
/// else a miss when the two differ only in the project or the objectives
/// asked for.
fn spawn_match(stored: &Value, offered: &Value) -> Result<ReplayRequestMatch> {
    if barrier_hit(stored, offered)? {
        return Ok(ReplayRequestMatch::Hit);
    }
    if erased_hit(stored, offered)? {
        return Ok(ReplayRequestMatch::Hit);
    }
    let (Some(stored), Some(offered)) = (without_intent(stored), without_intent(offered)) else {
        return Ok(ReplayRequestMatch::Drift);
    };
    Ok(if stored == offered || admitted_from(&stored, &offered)? {
        ReplayRequestMatch::SpawnMiss
    } else {
        ReplayRequestMatch::Drift
    })
}

/// A spawn request without its project and objectives; `None` for a request
/// that is not a map.
fn without_intent(request: &Value) -> Option<Value> {
    let Value::Map(fields) = request else {
        return None;
    };
    Some(Value::Map(
        fields
            .iter()
            .filter(|(key, _)| {
                !key.as_str()
                    .is_some_and(|name| SPAWN_INTENT_KEYS.contains(&name))
            })
            .cloned()
            .collect(),
    ))
}

/// Whether `stored`, a spawn whose ask an erase of its target took, is the
/// spawn `offered` asks again (Engine C3): `offered` asks something, and
/// every other field is the same, its project and objectives included, a
/// field the side-row wall masked matching the secrets it holds. A nil ask
/// on either side is never this arm's.
fn erased_hit(stored: &Value, offered: &Value) -> Result<bool> {
    let (Value::Map(stored), Value::Map(offered)) = (stored, offered) else {
        return Ok(false);
    };
    if !ask_of(stored).is_some_and(is_erased_ask) || !ask_of(offered).is_some_and(Value::is_str) {
        return Ok(false);
    }
    let (stored, offered) = (without_ask(stored), without_ask(offered));
    Ok(stored == offered || admitted_from(&stored, &offered)?)
}

/// The content-free marker of an undispatched spawn barrier: no call ran,
/// so its row keeps no ask text. It is valid only with a live wait/failure
/// answer (FIX 11391).
fn barrier_ask() -> Value {
    request_map(vec![("state", Value::from("barrier"))])
}

fn is_barrier_ask(value: &Value) -> bool {
    *value == barrier_ask()
}

/// A stored barrier and a live spawn request are the same call when every
/// field except the ask text matches. The call never ran, so no target proof
/// is needed for that identity.
fn barrier_hit(stored: &Value, offered: &Value) -> Result<bool> {
    let (Value::Map(stored), Value::Map(offered)) = (stored, offered) else {
        return Ok(false);
    };
    if !ask_of(stored).is_some_and(is_barrier_ask) || !ask_of(offered).is_some_and(Value::is_str) {
        return Ok(false);
    }
    let (stored, offered) = (without_ask(stored), without_ask(offered));
    Ok(stored == offered || admitted_from(&stored, &offered)?)
}

/// The ask a spawn request's fields hold, when they hold the key.
fn ask_of(fields: &[(Value, Value)]) -> Option<&Value> {
    fields
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some(ASK_KEY)).then_some(value))
}

/// A spawn request's fields without its ask.
fn without_ask(fields: &[(Value, Value)]) -> Value {
    Value::Map(
        fields
            .iter()
            .filter(|(key, _)| key.as_str() != Some(ASK_KEY))
            .cloned()
            .collect(),
    )
}

/// FIX 9180 (Engine C3): the stored marker of an ask an erase of the
/// spawn's target took, a typed map no live ask spells (a live ask is its
/// JSON text).
fn erased_ask() -> Value {
    request_map(vec![
        ("state", Value::from("erased")),
        ("cause", Value::from("target_erased")),
    ])
}

fn is_erased_ask(value: &Value) -> bool {
    *value == erased_ask()
}

/// The targets a spawn call's host resolved for it (FIX 9180, Engine C1):
/// every seat it observed, a plan's and each planned member's, a direct
/// AGENT_DEF, a workflow's leaves, and the attenuated fork dispatched in a
/// seat's place beside that seat, set as each resolved and kept through a
/// failed launch. Never a guest's target, never read off an outcome. Once
/// an erase took the call's ask, `prior` keeps the text-free id its spawn
/// answered with before: the attempt it queued or the widen it proposed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SpawnTargets {
    /// Sorted and distinct.
    seats: Vec<EntityId>,
    prior: Option<SpawnPrior>,
}

/// What a spawn answered before an erase of its target took its ask.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SpawnPrior {
    Attempt(AttemptId),
    Proposal(String),
}

impl SpawnTargets {
    fn is_empty(&self) -> bool {
        self.seats.is_empty() && self.prior.is_none()
    }

    /// Whether an erase of `erased` reaches one of these seats.
    pub(crate) fn reached_by(&self, erased: &BTreeSet<EntityId>) -> bool {
        self.seats.iter().any(|seat| erased.contains(seat))
    }

    /// Every seat, sorted and distinct.
    pub(crate) fn seats(&self) -> &[EntityId] {
        &self.seats
    }
}

/// `targets` as a bridge row stores them: Nil for none.
pub(super) fn spawn_targets_value(targets: &SpawnTargets) -> Value {
    if targets.is_empty() {
        return Value::Nil;
    }
    let (attempt, proposal) = match &targets.prior {
        None => (Value::Nil, Value::Nil),
        Some(SpawnPrior::Attempt(id)) => (Value::Binary(id.as_bytes().to_vec()), Value::Nil),
        Some(SpawnPrior::Proposal(id)) => (Value::Nil, Value::from(id.as_str())),
    };
    request_map(vec![
        (
            SPAWN_TARGET_KEYS[0],
            Value::Array(targets.seats.iter().copied().map(entity_id_value).collect()),
        ),
        (SPAWN_TARGET_KEYS[1], attempt),
        (SPAWN_TARGET_KEYS[2], proposal),
    ])
}

/// The targets a bridge row stores, in their one spelling: Nil for none,
/// else sorted distinct seats and at most one prior id.
///
/// # Errors
///
/// Any other spelling.
pub(super) fn decode_spawn_targets(value: &Value) -> Result<SpawnTargets> {
    if value.is_nil() {
        return Ok(SpawnTargets::default());
    }
    let fields = pinned_map(value, &SPAWN_TARGET_KEYS, "spawn targets")?;
    let seats = decode_array(required(fields[0], "missing spawn seats")?, entity_value)?;
    let prior = match (
        required(fields[1], "missing spawn prior attempt")?,
        required(fields[2], "missing spawn prior proposal")?,
    ) {
        (Value::Nil, Value::Nil) => None,
        (attempt, Value::Nil) => Some(SpawnPrior::Attempt(AttemptId::from_bytes(
            &fixed_binary::<16>(attempt, "spawn prior attempt")?,
        )?)),
        (Value::Nil, proposal) => Some(SpawnPrior::Proposal(str_value(proposal)?.to_owned())),
        _ => {
            return Err(invalid_code_run_replay(
                "spawn targets name two prior answers",
            ));
        }
    };
    let targets = SpawnTargets { seats, prior };
    if targets.is_empty() || !targets.seats.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(invalid_code_run_replay(
            "spawn targets are not in their one spelling",
        ));
    }
    Ok(targets)
}

/// The one selective erase of a spawn call an erase of one of its targets
/// reached (FIX 9180, Engine C2): its ask takes the erased marker (a nil
/// ask stays nil) and its outcome the typed `TargetErased`, the id it
/// answered before kept as its prior and a row receipt it stated kept on
/// the new outcome. Every other field of the call stays as it was: its seq,
/// effect, the rest of its request, its times, its action digest and its
/// targets. Pure; `true` when the call changed. A call of another effect is
/// left as it is.
///
/// # Errors
///
/// An outcome that does not encode.
pub(crate) fn erase_spawn_call(call: &mut CodeRunBridgeCall) -> Result<bool> {
    if call.effect != SelfEffect::AgentsSpawn {
        return Ok(false);
    }
    let before = call.clone();
    if let Value::Map(fields) = &mut call.request {
        for (key, value) in fields {
            if key.as_str() == Some(ASK_KEY) && value.is_str() {
                *value = erased_ask();
            }
        }
    }
    let prior = match decode_self_dispatch_outcome(&call.outcome) {
        Ok(SelfDispatchOutcome::AgentSpawn(SelfAgentSpawnResult::TargetErased)) => None,
        Ok(SelfDispatchOutcome::AgentSpawn(SelfAgentSpawnResult::Queued {
            attempt_ref, ..
        })) => Some(Some(SpawnPrior::Attempt(attempt_ref))),
        Ok(SelfDispatchOutcome::AgentSpawn(SelfAgentSpawnResult::ProposedWiden {
            proposal_ref,
            ..
        })) => Some(Some(SpawnPrior::Proposal(proposal_ref))),
        _ => Some(None),
    };
    if let Some(prior) = prior {
        let receipt = row_receipt(&call.outcome);
        call.outcome = self_dispatch_outcome_value(&SelfDispatchOutcome::AgentSpawn(
            SelfAgentSpawnResult::TargetErased,
        ))?;
        if let Some(receipt) = receipt {
            keep_row_receipt(&mut call.outcome, &receipt);
        }
        if call.spawn_targets.prior.is_none() {
            call.spawn_targets.prior = prior;
        }
    }
    Ok(*call != before)
}

/// FIX 9180 (coord-b slice d): the ask of a spawn call a checkpoint
/// carries apart from its row, owed to the targets its host resolved: a
/// spawn with seats and a live ask. A spawn with no target proof keeps its
/// ask where its row does, as does an erased or a nil one. `None` for any
/// other call.
pub(crate) fn spawn_ask_part(call: &CodeRunBridgeCall) -> Option<&Value> {
    if call.effect != SelfEffect::AgentsSpawn || call.spawn_targets.seats.is_empty() {
        return None;
    }
    let Value::Map(fields) = &call.request else {
        return None;
    };
    ask_of(fields).filter(|ask| ask.is_str())
}

/// Makes an undispatched spawn barrier content-free at birth: its ask takes
/// the barrier marker and every other field, including its Nil targets and
/// live outcome, stays exactly as it was. Other effects and live calls are
/// unchanged (FIX 11391).
pub(crate) fn barrier_spawn_call(call: &mut CodeRunBridgeCall) -> Result<bool> {
    if call.effect != SelfEffect::AgentsSpawn {
        return Ok(false);
    }
    let before = call.clone();
    if let Value::Map(fields) = &mut call.request {
        for (key, value) in fields {
            if key.as_str() == Some(ASK_KEY) && value.is_str() {
                *value = barrier_ask();
            }
        }
    }
    Ok(*call != before)
}

/// Puts `ask` in the place of `call`'s ask, and returns the ask it held: a
/// checkpoint takes a carried ask out of its call, nil in its place, and
/// puts it back. `None` for a request with no ask.
pub(crate) fn swap_spawn_ask(call: &mut CodeRunBridgeCall, ask: Value) -> Option<Value> {
    let Value::Map(fields) = &mut call.request else {
        return None;
    };
    fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some(ASK_KEY))
        .map(|(_, value)| std::mem::replace(value, ask))
}

/// How a spawn row's outcome stands for its coherence.
#[derive(PartialEq, Eq)]
enum SpawnAnswer {
    /// The typed `TargetErased`.
    Erased,
    /// A checkpoint image's retired stub (`response_erased`).
    Stub,
    /// Anything else the spawn answered.
    Live,
}

impl CodeRunBridgeCall {
    /// This row with the targets its host resolved for its spawn, `seats`
    /// (FIX 9180, Engine C1), on a success and a failure alike. A row of
    /// another effect resolves none and is left as it is.
    #[must_use]
    pub(crate) fn with_spawn_seats(mut self, mut seats: Vec<EntityId>) -> Self {
        if self.effect == SelfEffect::AgentsSpawn {
            seats.sort_unstable();
            seats.dedup();
            self.spawn_targets.seats = seats;
        }
        self
    }

    /// A spawn row whose host answered `TargetErased` keeps no ask (FIX
    /// 9180): the newly captured ask takes its erased marker at once, with
    /// no seat needed to reach it, as an erase finds it.
    ///
    /// # Errors
    ///
    /// An outcome that does not decode.
    pub(super) fn scrub_target_erased_ask(&mut self) -> Result<()> {
        if self.effect == SelfEffect::AgentsSpawn
            && matches!(
                decode_self_dispatch_outcome(&self.outcome)?,
                SelfDispatchOutcome::AgentSpawn(SelfAgentSpawnResult::TargetErased)
            )
        {
            erase_spawn_call(self)?;
        }
        Ok(())
    }

    /// FIX 9180: the row's spawn facts are one fact, checked wherever a row
    /// is built, encoded, decoded or replayed, before its request can match.
    /// Targets name a spawn's seats; an erased ask and a prior id belong to
    /// a spawn that answers `TargetErased` (or a checkpoint image's retired
    /// stub of one), and such a spawn keeps no live ask. A live spawn's row,
    /// whatever it asked and answered, is never refused here.
    ///
    /// # Errors
    ///
    /// A row no host records: targets on another effect, an ask that is
    /// neither text, nil nor the erased marker, an erased ask or prior id
    /// beside a live answer, or a live ask beside `TargetErased`.
    pub(super) fn validate_spawn_coherence(&self) -> Result<()> {
        if self.effect != SelfEffect::AgentsSpawn {
            if self.spawn_targets.is_empty() {
                return Ok(());
            }
            return Err(invalid_code_run_replay(
                "spawn targets on a call that spawns nothing",
            ));
        }
        let ask = match &self.request {
            Value::Map(fields) => ask_of(fields),
            _ => None,
        };
        let erased = ask.is_some_and(is_erased_ask);
        let barrier = ask.is_some_and(is_barrier_ask);
        let live = ask.is_some_and(Value::is_str);
        if !erased && !barrier && !live && ask.is_some_and(|ask| !ask.is_nil()) {
            return Err(invalid_code_run_replay(
                "spawn ask is neither an ask nor its erased marker",
            ));
        }
        let answer = match decode_self_dispatch_outcome(&self.outcome)? {
            SelfDispatchOutcome::AgentSpawn(SelfAgentSpawnResult::TargetErased) => {
                SpawnAnswer::Erased
            }
            SelfDispatchOutcome::Failed(failed) if failed.error == super::RESPONSE_ERASED => {
                SpawnAnswer::Stub
            }
            _ => SpawnAnswer::Live,
        };
        if (erased || self.spawn_targets.prior.is_some()) && answer == SpawnAnswer::Live {
            return Err(invalid_code_run_replay(
                "an erased spawn carries a live answer",
            ));
        }
        if answer == SpawnAnswer::Erased && (live || barrier) {
            return Err(invalid_code_run_replay(
                "a target-erased spawn keeps its ask",
            ));
        }
        Ok(())
    }
}
