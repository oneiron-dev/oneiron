//! Attach point 2 (ARCH-0080 §3): the verb hooks of each call a run serves
//! itself. A verb-table call is left out: its row's door is attach point 1,
//! and a second wrap here would fire its hooks twice. `self.context` takes
//! its hooks without the door: a descriptor is no effect, and with no hook
//! bound to it, it performs no read.
//!
//! A hook reads the call's input as JSON, in the shape the guest wrote it, and
//! after the call the guest's view of its result. A rewrite decodes back into
//! the same call, which then meets its own gate as the guest's call would; the
//! host's own fields carry over, and the refs it changes are admitted again. A
//! Redact changes only the guest's view, never the run's record. In an
//! off-record room the run's search takes its hooks in the room ([`session`]).

mod args;
mod parked;
mod rewrite;
mod session;

use serde_json::{Value, json};

use super::{ExecutorCallSite, HostSelfDispatcher};
use crate::claim::ScopedReadActorKey;
use crate::code_run::replay::CodeRunBridgeCall;
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::types::{
    RunCall, SelfAgentSpawnResult, SelfCall, SelfDeniedResult, SelfDispatchOutcome,
    SelfDurableWait, SelfDurableWaitReason, SelfEffect, SelfLeaderCall,
};
use crate::error::{Error, Result};
use crate::runtime_hooks::{
    InvocationId, VerbCall, VerbCallScope, VerbDomain, VerbHookPre, VerbHookStop, hook_class,
};
use crate::task_verb::{TaskAskStatus, TaskAskWait};
use crate::{EntityId, Vault};

pub(super) use self::parked::ParkedHook;

use self::args::hook_args;
use self::parked::ParkedOffer;
use self::rewrite::{Rewritten, rewrite, rewritten_refs};

/// The refusal a guest reads when a pre-hook skipped its call. Its reason
/// codes are the hook and the hook's reason.
const VERB_HOOK_SKIPPED: &str = "verb_hook_skipped";
/// The refusal a guest reads when a blocking hook failed safe and hid the
/// result. Its reason code is the hook.
const VERB_HOOK_HIDDEN: &str = "verb_hook_hidden";
/// The refusal a guest reads when a hook asked first and the call keeps no
/// wait. Its reason codes are the invocation and the ask.
const VERB_HOOK_PENDING: &str = "verb_hook_pending";
/// What the wait a hook's ask parks a call on says, before the invocation the
/// ask waits under.
const VERB_HOOK_WAIT: &str = "verb_hook:";
/// The refusal a guest reads when settlement already ran the call a hook's
/// ask stopped, so it never runs twice. Its reason codes are the invocation,
/// and the error's code when the call failed.
const VERB_HOOK_COMPLETED: &str = "verb_hook_completed";

/// A call by its replay row, less the bridge's own stamps.
pub(crate) type ParkedCall = (SelfEffect, rmpv::Value);

/// A call past its pre chain, as its post chain picks it up. The first
/// `None` when no hook runs for the call; the second carries the dispatched
/// rewritten call (FIX 1442), `None` when no hook rewrote it.
pub(crate) struct HookedCall(pub(crate) Option<VerbHookPre>, pub(crate) Option<SelfCall>);

impl HostSelfDispatcher<'_> {
    /// `dispatch_effect` inside the call's verb hooks, and the dispatched
    /// rewritten call (FIX 1442): `Some` when a hook rewrote it, `None`
    /// otherwise. A stop is the guest's typed answer, from either attach
    /// point: a verb-table call's door raises its own. A parked call whose
    /// row an erase took the words of answers before either attach point
    /// and the effect (FIX 6534), a verb-table call too.
    pub(super) fn dispatch_hooked(
        &self,
        call: SelfCall,
        site: Option<ExecutorCallSite<'_>>,
        read_as: Option<ScopedReadActorKey>,
    ) -> Result<(SelfDispatchOutcome, Option<SelfCall>)> {
        let effect = call.effect();
        let (call, hooked) = match self.enter_verb_hooks(call, site, read_as.clone())? {
            Ok(entered) => entered,
            Err(stopped) => return Ok((stopped, None)),
        };
        let rewritten = hooked.1.clone();
        match self.dispatch_effect(call, site, read_as) {
            Ok(outcome) => Ok((self.leave_verb_hooks(hooked, outcome)?, rewritten)),
            Err(error) => {
                // A room call's pre carries no keep key (FIX 1431): had it a
                // vault it would fall into the canonical branch and no-op,
                // so only canonical storage compensates here.
                if crate::runtime_hooks::verb::error_failed_storage(&error) {
                    if let (ExecutorStorage::Canonical(vault), Some(pre)) =
                        (&self.storage, hooked.0.as_ref())
                    {
                        vault.reopen_resumed_ask(pre);
                    }
                }
                self.keep_room_verb_hooks(hooked);
                match error {
                    Error::VerbHook(stop) => Ok((stopped(effect, *stop), rewritten)),
                    error => Err(error),
                }
            }
        }
    }

    /// Runs the pre chain of `call`. `Ok` carries the call to dispatch,
    /// rewritten when a hook rewrote it, and what its post chain picks up;
    /// `Err` the answer a stop gives in its place. A run bound to an
    /// off-record session runs its search's hooks in the room ([`session`]).
    /// A call no binding can take passes before its args are built, unless
    /// an earlier try of its invocation is parked on a hook's ask or settled
    /// there: that one always meets its saved continuation. A hook
    /// reads under `read_as`, the key the run's door admitted the call with,
    /// and as the run's actor when its host binds no door. The call's scope
    /// is the room that key reads inside, if any. Each rewrite is decoded as
    /// the guest's input is, and the refs it changes admitted again. A call
    /// a hook's ask parked on a row an erase took the words of answers
    /// first, before any hook runs (FIX 6534).
    pub(crate) fn enter_verb_hooks(
        &self,
        call: SelfCall,
        site: Option<ExecutorCallSite<'_>>,
        read_as: Option<ScopedReadActorKey>,
    ) -> Result<std::result::Result<(SelfCall, HookedCall), SelfDispatchOutcome>> {
        if let Some(erased) = self.parked_erased_answer(&call, site)? {
            return Ok(Err(erased));
        }
        let vault = match &self.storage {
            ExecutorStorage::Canonical(vault) => vault,
            ExecutorStorage::Session(_) => return self.enter_room_verb_hooks(call, site, read_as),
        };
        if matches!(call, SelfCall::AgentVerb(_))
            || self
                .pre_hooked_fold
                .as_ref()
                .is_some_and(|pre| pre.covers(self.actor, &call))
        {
            return Ok(Ok((call, HookedCall(None, None))));
        }
        let effect = call.effect();
        let invocation = self.verb_invocation(&call, site)?;
        if !vault.verb_hooks_may_run(effect.as_str())
            && !vault.verb_hook_invocation_saved(invocation)?
        {
            return Ok(Ok((call, HookedCall(None, None))));
        }
        let args = hook_args(&call)?;
        let scope = read_as
            .as_ref()
            .and_then(ScopedReadActorKey::room_turn)
            .map(|turn| VerbCallScope::Named(format!("room:{}", turn.room.to_hex())));
        let hook_call = VerbCall {
            verb: effect.as_str().to_owned(),
            invocation,
            actor: self.actor.entity_ref(),
            class: hook_class(self.actor.actor_class()),
            scope,
            board_epoch: None,
            turn: None,
            domain: hook_domain(&call),
            reader: read_as,
        };
        let check = |rewritten: &Value| -> Rewritten<()> {
            let next = rewrite(&call, rewritten)?;
            self.admit_rewritten_refs(vault, &call, &next)
        };
        let pre = match vault.pre_verb_hooks(hook_call, args.clone(), &check)? {
            Ok(pre) => pre,
            Err(stop) => return Ok(Err(stopped(effect, stop))),
        };
        if pre.args == args {
            return Ok(Ok((call, HookedCall(Some(pre), None))));
        }
        let rewritten = rewrite(&call, &pre.args).map_err(|reason| {
            Error::InvalidConfig(format!("{} rewrite: {reason}", effect.as_str()))
        })?;
        Ok(Ok((
            rewritten.clone(),
            HookedCall(Some(pre), Some(rewritten)),
        )))
    }

    /// Admits the entities a rewrite of `call` newly names, as the facade
    /// admits a row's rewritten refs: the run's door rules on the call once
    /// more, and each must be readable on the lane the call's hooks read,
    /// the door's key or the run's actor's own, within the waking slip's
    /// target bounds when one woke the program. The reason refuses the rewrite.
    fn admit_rewritten_refs(
        &self,
        vault: &Vault,
        call: &SelfCall,
        next: &SelfCall,
    ) -> Rewritten<()> {
        let refs = rewritten_refs(call, next);
        if refs.is_empty() {
            return Ok(());
        }
        let key = match self.admit_run_call(RunCall::Bridge(call.effect())) {
            Ok(Ok(Some(key))) => key,
            Ok(Ok(None)) => vault
                .memory(self.actor.entity_ref(), self.actor.actor_class())
                .read_key()
                .map_err(|error| error.to_string())?,
            Ok(Err(refusal)) => return Err(refusal.code),
            Err(error) => return Err(error.to_string()),
        };
        if let Some(proof) = self.program_proof() {
            let Some(proof_key) = vault
                .credential_target_key(proof)
                .map_err(|error| error.to_string())?
            else {
                return Err("a rewrite names an entity this call cannot read".to_owned());
            };
            if !vault
                .scoped_read(proof_key)
                .all_refs_readable(&refs)
                .map_err(|error| error.to_string())?
            {
                return Err("a rewrite names an entity this call cannot read".to_owned());
            }
        }
        let readable = vault
            .scoped_read(key)
            .all_refs_readable(&refs)
            .map_err(|error| error.to_string())?;
        if !readable {
            return Err("a rewrite names an entity this call cannot read".to_owned());
        }
        Ok(())
    }

    /// Runs the post chain over the guest's view of `outcome`. The outcome
    /// stands as the run records it; a Redact, or a blocking hook that hid
    /// the result, leaves the guest's own view for the host's reply. A call
    /// refused, failed or parked made no result, so no post chain runs.
    pub(crate) fn leave_verb_hooks(
        &self,
        hooked: HookedCall,
        outcome: SelfDispatchOutcome,
    ) -> Result<SelfDispatchOutcome> {
        if let ExecutorStorage::Session(_) = &self.storage {
            return self.leave_room_verb_hooks(hooked, outcome);
        }
        let (Some(pre), ExecutorStorage::Canonical(vault)) = (hooked.0, &self.storage) else {
            return Ok(outcome);
        };
        if matches!(
            outcome,
            SelfDispatchOutcome::Denied(_)
                | SelfDispatchOutcome::Failed(_)
                | SelfDispatchOutcome::DurableWait(_)
        ) {
            return Ok(outcome);
        }
        // A wait still pending parks rather than answers: no result to show.
        let Some(view) = outcome_view(&outcome) else {
            return Ok(outcome);
        };
        let seen = match vault.post_verb_hooks(pre, view.clone())? {
            Ok(seen) => seen,
            Err(stop) => stopped_view(&stop),
        };
        if seen != view {
            *self.hook_view.borrow_mut() = Some(seen);
        }
        Ok(outcome)
    }

    /// The guest's view of the last call's result, when a hook changed it.
    /// Taken once: the host replies with it in place of the result's own.
    pub(crate) fn take_hook_view(&self) -> Option<Value> {
        self.hook_view.take()
    }

    /// The invocation a call's hooks run under. The same call a hook's ask
    /// parked takes that ask's invocation again, so made later it resumes
    /// the ask; any other takes its place in the run, which a replay of its
    /// step keeps. A call outside a durable run takes a fresh one.
    pub(super) fn verb_invocation(
        &self,
        call: &SelfCall,
        site: Option<ExecutorCallSite<'_>>,
    ) -> Result<InvocationId> {
        let Some(site) = site else {
            return Ok(InvocationId::mint());
        };
        if let Some(parked) = self.parked_hook(call, Some(site), ParkedHook::invocation)? {
            return Ok(parked);
        }
        Ok(InvocationId::of_run_step(site.run_id.as_bytes(), site.seq))
    }

    /// Notes, in order, the calls a hook's ask parked in `bridge_calls`. A
    /// later row of the same call, parked or answered, replaces its note, so
    /// an ask is resumed once. A row meets a note by the rule a call made
    /// again meets it (FIX 6534): a later row of an erased call clears its
    /// note and never revives it. A row whose request cannot be read clears
    /// no note: the same call made again meets that note and reads the error.
    pub(super) fn observe_parked_hooks(&self, bridge_calls: &[CodeRunBridgeCall]) {
        let mut parked = self.parked_hooks.borrow_mut();
        for row in bridge_calls {
            let parks = ParkedHook::of(row);
            // With nothing parked, a row that parks nothing has nothing to clear.
            if parks.is_none() && parked.is_empty() {
                continue;
            }
            parked.retain(|held| !matches!(held.meets(ParkedOffer::Row(row)), Ok(true)));
            parked.extend(parks);
        }
    }
}

/// The guest's answer to a call a hook stopped before it ran. An ask parks
/// the call on its ask, as `tasks.wait` parks on one; the wait names the
/// invocation, so the same call made later resumes it. A skip, or a result
/// hidden, is a typed refusal.
fn stopped(effect: SelfEffect, stop: VerbHookStop) -> SelfDispatchOutcome {
    let hook_notice = matches!(
        &stop,
        VerbHookStop::Completed {
            hook_notice: Some(true),
            ..
        } | VerbHookStop::CompletedWithError {
            hook_notice: Some(true),
            ..
        }
    );
    let mut outcome = match stop {
        VerbHookStop::Pending { invocation, ask } => {
            // An owner policy write keeps no wait in its record.
            let group = EntityId::from_hex(&ask)
                .ok()
                .filter(|_| effect != SelfEffect::WakePolicyWrite);
            match group {
                Some(group) => SelfDispatchOutcome::DurableWait(SelfDurableWait {
                    wait_id: group,
                    effect: SelfEffect::TasksWait,
                    reason: SelfDurableWaitReason::PeerResult,
                    prompt: Some(format!("{VERB_HOOK_WAIT}{invocation}")),
                }),
                None => denied(effect, VERB_HOOK_PENDING, vec![invocation, ask]),
            }
        }
        VerbHookStop::Skipped { hook, reason } => {
            denied(effect, VERB_HOOK_SKIPPED, vec![hook, reason])
        }
        VerbHookStop::Hidden { hook } => denied(effect, VERB_HOOK_HIDDEN, vec![hook]),
        VerbHookStop::Completed { invocation, .. } => {
            denied(effect, VERB_HOOK_COMPLETED, vec![invocation])
        }
        VerbHookStop::CompletedWithError {
            invocation, code, ..
        } => denied(effect, VERB_HOOK_COMPLETED, vec![invocation, code]),
    };
    if hook_notice && let SelfDispatchOutcome::Denied(result) = &mut outcome {
        result.hook_notice = Some(json!(crate::task_verb::revoke_lands::CALLER_NOTICE_SUMMARY));
    }
    outcome
}

fn denied(effect: SelfEffect, outcome: &str, reason_codes: Vec<String>) -> SelfDispatchOutcome {
    SelfDispatchOutcome::Denied(SelfDeniedResult {
        hook_notice: None,
        effect,
        outcome: outcome.to_owned(),
        reason_codes,
    })
}

/// The guest's view of a result a post-hook stopped: the refusal it reads.
fn stopped_view(stop: &VerbHookStop) -> Value {
    let (word, codes) = match stop {
        VerbHookStop::Skipped { hook, reason } => (VERB_HOOK_SKIPPED, vec![hook, reason]),
        VerbHookStop::Pending { invocation, ask } => (VERB_HOOK_PENDING, vec![invocation, ask]),
        VerbHookStop::Hidden { hook } => (VERB_HOOK_HIDDEN, vec![hook]),
        VerbHookStop::Completed { invocation, .. } => (VERB_HOOK_COMPLETED, vec![invocation]),
        VerbHookStop::CompletedWithError {
            invocation, code, ..
        } => (VERB_HOOK_COMPLETED, vec![invocation, code]),
    };
    json!({"denied": word, "reasonCodes": codes})
}

/// A call as its replay row names it, less the bridge's own stamps, so the
/// same call made at another place in the run is the same call.
fn parked_call(effect: SelfEffect, mut request: rmpv::Value) -> ParkedCall {
    if bridge_stamped(effect)
        && let rmpv::Value::Map(entries) = &mut request
    {
        entries.retain(|(key, _)| !matches!(key.as_str(), Some("order" | "occurred_at")));
    }
    (effect, request)
}

/// Whether the bridge stamps its own order and time onto a call of
/// `effect`, as [`SelfCall::with_bridge_stamp`] does: a speech bubble's
/// and a blocked report's.
fn bridge_stamped(effect: SelfEffect) -> bool {
    effect.is_speech() || effect == SelfEffect::ReportBlocked
}

/// The invocation a recorded outcome parked on a hook's ask, if it did.
fn parked_invocation(outcome: &rmpv::Value) -> Option<InvocationId> {
    if entry(outcome, "kind")?.as_str()? != "durable_wait" {
        return None;
    }
    InvocationId::parse_hex(
        entry(outcome, "prompt")?
            .as_str()?
            .strip_prefix(VERB_HOOK_WAIT)?,
    )
}

fn entry<'a>(value: &'a rmpv::Value, key: &str) -> Option<&'a rmpv::Value> {
    let rmpv::Value::Map(entries) = value else {
        return None;
    };
    entries
        .iter()
        .find_map(|(name, value)| (name.as_str() == Some(key)).then_some(value))
}

/// Whether a call reads or writes: a blocking hook that fails hides a read's
/// result and sends a write to an ask.
fn hook_domain(call: &SelfCall) -> VerbDomain {
    match call {
        SelfCall::MemorySearch(_)
        | SelfCall::TasksWait(_)
        | SelfCall::TasksWaitSet(_)
        | SelfCall::InferenceDefaultsRead
        | SelfCall::Context(_)
        // Advice and a pattern load start no work and write no memory.
        | SelfCall::Leader(SelfLeaderCall::Advice { .. } | SelfLeaderCall::Pattern { .. }) => {
            VerbDomain::Read
        }
        SelfCall::Fold(fold) if !fold.writes() => VerbDomain::Read,
        SelfCall::AgentVerb(verb) if !verb.verb.writes() => VerbDomain::Read,
        SelfCall::Repo(call) if !call.writes() => VerbDomain::Read,
        _ => VerbDomain::Write,
    }
}

/// The guest's view of `outcome`, framed as the code-mode bridge frames its
/// reply. `None` for a wait still pending, which the bridge parks rather than
/// answers.
fn outcome_view(outcome: &SelfDispatchOutcome) -> Option<Value> {
    Some(match outcome {
        SelfDispatchOutcome::MemoryWrite(value) => json!({"output": {"id": value.id.to_hex()}}),
        SelfDispatchOutcome::MemoryEdgeWrite(value) => json!({"output": {
            "src": value.src.to_hex(),
            "kind": value.kind.name(),
            "tgt": value.tgt.to_hex(),
        }}),
        SelfDispatchOutcome::MemorySearch(value) => json!({"output": {"results": value
            .results
            .iter()
            .map(|hit| json!({"id": hit.id.to_hex(), "score": hit.score}))
            .collect::<Vec<_>>()}}),
        SelfDispatchOutcome::DurableWait(value) => json!({"waitId": value.wait_id.to_hex()}),
        SelfDispatchOutcome::TaskRefusal(value) => json!({"output": {
            "task": value.task_ref.to_hex(),
            "level": value.level.as_str(),
            "outcome": value.outcome_word(),
            "replay": value.replay,
        }}),
        SelfDispatchOutcome::AgentVerb(answer) => json!({"output": answer.output}),
        SelfDispatchOutcome::SkillCall(value) => json!({"output": value.output}),
        SelfDispatchOutcome::Denied(value) => {
            json!({"denied": value.outcome, "reasonCodes": value.reason_codes})
        }
        SelfDispatchOutcome::Failed(_) => json!({"failed": true}),
        SelfDispatchOutcome::AgentDefinitionPut(value) => json!({"output": {
            "id": value.id.to_hex(),
            "disposition": value.disposition.as_str(),
        }}),
        SelfDispatchOutcome::AgentSpawn(SelfAgentSpawnResult::Queued { attempt_ref, .. }) => {
            json!({
                "kind": "agent_spawn",
                "state": "queued",
                "attempt": crate::entity_id::bytes_to_hex_lower(attempt_ref.as_bytes()),
            })
        }
        SelfDispatchOutcome::AgentSpawn(SelfAgentSpawnResult::ProposedWiden {
            proposal_ref,
            ..
        }) => json!({"kind": "agent_spawn", "state": "proposed_widen", "proposal": proposal_ref}),
        SelfDispatchOutcome::AgentSpawn(
            erased @ (SelfAgentSpawnResult::TargetErased | SelfAgentSpawnResult::AskerErased),
        ) => json!({"kind": "agent_spawn", "state": erased.erasure()}),
        // The bare `ask` and `wait` answer their rows' outputs.
        SelfDispatchOutcome::TaskAsk(receipt) => json!({"output": receipt}),
        SelfDispatchOutcome::TaskAskStatus(TaskAskStatus::Pending { .. }) => return None,
        SelfDispatchOutcome::TaskAskStatus(TaskAskStatus::Changed { voided, generation }) => {
            let wait = TaskAskWait::Changed {
                voided: voided.clone(),
                generation: *generation,
            };
            json!({"output": wait})
        }
        SelfDispatchOutcome::TaskAskStatus(TaskAskStatus::Settled(result)) => {
            let wait = TaskAskWait::Ready(result.clone());
            json!({"output": wait})
        }
        SelfDispatchOutcome::TaskAskStatus(TaskAskStatus::WorldPrivacy(request)) => {
            let wait = TaskAskWait::WorldPrivacyReady(request.clone());
            json!({"output": wait})
        }
        SelfDispatchOutcome::Speech(value) => {
            json!({"order": value.order, "isVisible": value.is_visible})
        }
        SelfDispatchOutcome::ReportBlocked { receipt } => json!({"receipt": receipt.to_hex()}),
        SelfDispatchOutcome::InferenceDefaults(text) => json!({"json": text}),
        SelfDispatchOutcome::StoredReply(value) => {
            let mut body = json!({"output": value.output});
            if !value.program_steps.is_empty() {
                body["programSteps"] = json!(value.program_steps);
            }
            body
        }
        SelfDispatchOutcome::Fold(answer) => json!({"output": answer.guest_output()}),
        SelfDispatchOutcome::Context(value) => json!({"spec": value.spec}),
        SelfDispatchOutcome::WakePolicyWritten(policy) => json!({"policy": policy}),
        SelfDispatchOutcome::ReaderSpawn(receipt) => json!({"output": receipt}),
        SelfDispatchOutcome::ReaderReport(receipt) => json!({"output": receipt}),
        SelfDispatchOutcome::TaskWaitSet(result) => json!({"output": result}),
        SelfDispatchOutcome::Summarize(reply) => json!({"output": reply.output()}),
        SelfDispatchOutcome::Leader(text) => json!({"output": serde_json::from_str::<Value>(text)
            .unwrap_or_else(|_| Value::String(text.clone()))}),
        SelfDispatchOutcome::Team(result) => json!({"output": result.answer}),
        SelfDispatchOutcome::TeamSubmitted(answer) => json!({"output": answer}),
    })
}
