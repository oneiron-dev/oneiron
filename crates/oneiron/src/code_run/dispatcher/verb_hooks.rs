//! Attach point 2 (ARCH-0080 §3): the verb hooks of each call a run serves
//! itself. A verb-table call is left out: its row's door is attach point 1,
//! and a second wrap here would fire its hooks twice. `self.context` is left
//! out too: it performs no read, and a hook run would be one.
//!
//! A hook reads the call's input as JSON, in the shape the guest wrote it, and
//! after the call the guest's view of its result. A rewrite decodes back into
//! the same call, which then meets its own gate as the guest's call would. A
//! Redact changes only the guest's view, never the run's record.

use serde::Deserialize;
use serde_json::{Value, json};

use super::{ExecutorCallSite, HostSelfDispatcher};
use crate::agent_def::RefusalDomain;
use crate::agent_dispatch::AgentDispatchTarget;
use crate::claim::ScopedReadActorKey;
use crate::code_run::JS_SAFE_INTEGER;
use crate::code_run::blocked::BlockedCategory;
use crate::code_run::payload::self_call_request_value;
use crate::code_run::replay::CodeRunBridgeCall;
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::types::{
    SelfAgentSpawnResult, SelfAskCall, SelfCall, SelfDeniedResult, SelfDispatchOutcome,
    SelfDurableWait, SelfDurableWaitReason, SelfEffect, SelfFixtureEffectCall, SelfLeaderCall,
    SelfMemoryPutClaimCall, SelfMemoryPutEdgeCall, SelfMemorySearchCall,
    SelfMemorySupersedeClaimCall, SelfSkillCall, SelfSpeechCall, SelfTaskRefuseCall,
    SelfWakePolicyWriteCall,
};
use crate::compaction::SelfFoldCall;
use crate::error::{Error, Result};
use crate::runtime_hooks::{
    InvocationId, VerbCall, VerbDomain, VerbHookPre, VerbHookStop, hook_class,
};
use crate::task_verb::TaskAskStatus;
use crate::{ClaimCandidate, ClaimSubject, EdgeKind, EntityId, TimeRange};

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

/// A call by its replay row, less the bridge's own stamps.
pub(crate) type ParkedCall = (SelfEffect, rmpv::Value);

/// A call past its pre chain, as its post chain picks it up. `None` when no
/// hook runs for the call.
pub(crate) struct HookedCall(Option<VerbHookPre>);

impl HostSelfDispatcher<'_> {
    /// `dispatch_effect` inside the call's verb hooks. A stop is the guest's
    /// typed answer, from either attach point: a verb-table call's door
    /// raises its own.
    pub(super) fn dispatch_hooked(
        &self,
        call: SelfCall,
        site: Option<ExecutorCallSite<'_>>,
        read_as: Option<ScopedReadActorKey>,
    ) -> Result<SelfDispatchOutcome> {
        let effect = call.effect();
        let (call, hooked) = match self.enter_verb_hooks(call, site)? {
            Ok(entered) => entered,
            Err(stopped) => return Ok(stopped),
        };
        match self.dispatch_effect(call, site, read_as) {
            Ok(outcome) => self.leave_verb_hooks(hooked, outcome),
            Err(Error::VerbHook(stop)) => Ok(stopped(effect, *stop)),
            Err(error) => Err(error),
        }
    }

    /// Runs the pre chain of `call`. `Ok` carries the call to dispatch,
    /// rewritten when a hook rewrote it, and what its post chain picks up;
    /// `Err` the answer a stop gives in its place. A run bound to an
    /// off-record session runs no hook: its receipts would land on record.
    /// A call no binding can take passes before its args are built.
    pub(crate) fn enter_verb_hooks(
        &self,
        call: SelfCall,
        site: Option<ExecutorCallSite<'_>>,
    ) -> Result<std::result::Result<(SelfCall, HookedCall), SelfDispatchOutcome>> {
        let ExecutorStorage::Canonical(vault) = &self.storage else {
            return Ok(Ok((call, HookedCall(None))));
        };
        if matches!(call, SelfCall::AgentVerb(_) | SelfCall::Context(_)) {
            return Ok(Ok((call, HookedCall(None))));
        }
        let effect = call.effect();
        if !vault.verb_hooks_may_run(effect.as_str()) {
            return Ok(Ok((call, HookedCall(None))));
        }
        let args = hook_args(&call)?;
        let hook_call = VerbCall {
            verb: effect.as_str().to_owned(),
            invocation: self.verb_invocation(&call, site)?,
            actor: self.actor.entity_ref(),
            class: hook_class(self.actor.actor_class()),
            scope: None,
            board_epoch: None,
            domain: hook_domain(&call),
        };
        let check = |rewritten: &Value| rewrite(&call, rewritten).map(|_| ());
        let pre = match vault.pre_verb_hooks(hook_call, args.clone(), &check)? {
            Ok(pre) => pre,
            Err(stop) => return Ok(Err(stopped(effect, stop))),
        };
        if pre.args == args {
            return Ok(Ok((call, HookedCall(Some(pre)))));
        }
        let rewritten = rewrite(&call, &pre.args).map_err(|reason| {
            Error::InvalidConfig(format!("{} rewrite: {reason}", effect.as_str()))
        })?;
        Ok(Ok((rewritten, HookedCall(Some(pre)))))
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
        let view = outcome_view(&outcome);
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
        if !self.parked_hooks.borrow().is_empty() {
            let key = parked_call(call.effect(), self_call_request_value(call)?);
            let parked = self
                .parked_hooks
                .borrow()
                .iter()
                .find(|(held, _)| *held == key)
                .map(|(_, invocation)| *invocation);
            if let Some(parked) = parked {
                return Ok(parked);
            }
        }
        Ok(InvocationId::of_run_step(site.run_id.as_bytes(), site.seq))
    }

    /// Notes, in order, the calls a hook's ask parked in `bridge_calls`. A
    /// later row of the same call, parked or answered, replaces its note, so
    /// an ask is resumed once.
    pub(super) fn observe_parked_hooks(&self, bridge_calls: &[CodeRunBridgeCall]) {
        let mut parked = self.parked_hooks.borrow_mut();
        for row in bridge_calls {
            let invocation = parked_invocation(&row.outcome);
            // With nothing parked, a row that parks nothing has nothing to clear.
            if invocation.is_none() && parked.is_empty() {
                continue;
            }
            let key = parked_call(row.effect, row.request.clone());
            parked.retain(|(held, _)| *held != key);
            if let Some(invocation) = invocation {
                parked.push((key, invocation));
            }
        }
    }
}

/// The guest's answer to a call a hook stopped before it ran. An ask parks
/// the call on its ask, as `tasks.wait` parks on one; the wait names the
/// invocation, so the same call made later resumes it. A skip, or a result
/// hidden, is a typed refusal.
fn stopped(effect: SelfEffect, stop: VerbHookStop) -> SelfDispatchOutcome {
    match stop {
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
    }
}

fn denied(effect: SelfEffect, outcome: &str, reason_codes: Vec<String>) -> SelfDispatchOutcome {
    SelfDispatchOutcome::Denied(SelfDeniedResult {
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
    };
    json!({"denied": word, "reasonCodes": codes})
}

/// A call as its replay row names it, less the bridge's own stamps, so the
/// same call made at another place in the run is the same call.
fn parked_call(effect: SelfEffect, mut request: rmpv::Value) -> ParkedCall {
    if (effect.is_speech() || effect == SelfEffect::ReportBlocked)
        && let rmpv::Value::Map(entries) = &mut request
    {
        entries.retain(|(key, _)| !matches!(key.as_str(), Some("order" | "occurred_at")));
    }
    (effect, request)
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
        | SelfCall::Leader(_) => VerbDomain::Read,
        SelfCall::Fold(fold) if !fold.writes() => VerbDomain::Read,
        SelfCall::AgentVerb(verb) if !verb.verb.writes() => VerbDomain::Read,
        _ => VerbDomain::Write,
    }
}

/// The guest's view of `outcome`, framed as the code-mode bridge frames its
/// reply.
fn outcome_view(outcome: &SelfDispatchOutcome) -> Value {
    match outcome {
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
        SelfDispatchOutcome::AgentDefinitionPut(value) => {
            json!({"id": value.id.to_hex(), "disposition": value.disposition.as_str()})
        }
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
        SelfDispatchOutcome::TaskAsk(value) => json!({
            "kind": "task_ask",
            "group": value.handle.group_ref.to_hex(),
            "tasks": value.task_refs.iter().map(EntityId::to_hex).collect::<Vec<_>>(),
            "hold": value.hold.as_ref().map(|_| "no_live_route"),
            "replay": value.idempotent_replay,
        }),
        SelfDispatchOutcome::TaskAskStatus(TaskAskStatus::Pending { hold }) => json!({
            "kind": "task_ask_status",
            "state": "pending",
            "hold": hold.as_ref().map(|_| "no_live_route"),
        }),
        SelfDispatchOutcome::TaskAskStatus(TaskAskStatus::Changed { voided, generation }) => {
            json!({
                "kind": "task_ask_status",
                "state": "changed",
                "voided": voided.iter().map(EntityId::to_hex).collect::<Vec<_>>(),
                "generation": generation,
            })
        }
        SelfDispatchOutcome::TaskAskStatus(TaskAskStatus::Settled(result)) => {
            json!({"kind": "task_ask_status", "state": "settled", "result": result})
        }
        SelfDispatchOutcome::Speech(value) => {
            json!({"order": value.order, "isVisible": value.is_visible})
        }
        SelfDispatchOutcome::ReportBlocked { receipt } => json!({"receipt": receipt.to_hex()}),
        SelfDispatchOutcome::InferenceDefaults(text) => json!({"json": text}),
        SelfDispatchOutcome::Fold(text) => json!({"output": serde_json::from_str::<Value>(text)
            .unwrap_or_else(|_| Value::String(text.clone()))}),
        SelfDispatchOutcome::Context(value) => json!({"spec": value.spec}),
        SelfDispatchOutcome::WakePolicyWritten(policy) => json!({"policy": policy}),
        SelfDispatchOutcome::ReaderSpawn(receipt) => json!({"output": receipt}),
        SelfDispatchOutcome::ReaderReport(receipt) => json!({"output": receipt}),
        SelfDispatchOutcome::TaskWaitSet(result) => json!({"output": result}),
        SelfDispatchOutcome::Leader(text) => json!({"output": serde_json::from_str::<Value>(text)
            .unwrap_or_else(|_| Value::String(text.clone()))}),
        SelfDispatchOutcome::Team(answer) => json!({"output": answer}),
    }
}

/// A call's input as a hook reads it: the shape the guest wrote, ids in hex.
/// The bridge's own stamps (a bubble's order and time) are not the guest's
/// and stay out.
fn hook_args(call: &SelfCall) -> Result<Value> {
    Ok(match call {
        SelfCall::AgentsSpawn(spawn) => {
            let target = spawn.target.as_ref().map(|target| match target {
                AgentDispatchTarget::Custom(id) => json!({"kind": "agent_def", "id": id.to_hex()}),
                AgentDispatchTarget::Workflow(id) => json!({"kind": "workflow", "id": id.to_hex()}),
            });
            json!({
                "target": target,
                "intentKey": spawn.intent_key,
                "contextSpec": to_json(&spawn.context.context_spec)?,
                "contextFrom": spawn
                    .context
                    .context_from
                    .iter()
                    .map(EntityId::to_hex)
                    .collect::<Vec<_>>(),
                "depthRemaining": spawn.context.depth_remaining,
                "projectRef": spawn.context.project_ref.map(|id| id.to_hex()),
                "typeRef": spawn.context.type_ref.as_ref().map(ToString::to_string),
                "ask": to_json(&spawn.ask)?,
            })
        }
        SelfCall::AgentsPut(put) => json!({
            "id": put.id.to_hex(),
            "occurred": span(put.occurred),
            "learnedAt": put.learned_at,
        }),
        SelfCall::TasksAsk(spec) => to_json(spec.as_ref())?,
        SelfCall::TasksWait(handle) => to_json(handle)?,
        SelfCall::TasksRefuse(refuse) => json!({
            "taskRef": refuse.task_ref.map(|id| id.to_hex()),
            "domain": refuse.domain.as_str(),
            "reasonRef": refuse.reason_ref,
            "at": refuse.at,
        }),
        SelfCall::SkillsCall(skill) => json!({"skill": skill.skill.to_hex(), "args": skill.args}),
        SelfCall::MemorySearch(search) => json!({"query": search.query, "limit": search.limit}),
        SelfCall::MemoryWriteFixture(write) => claim_args(
            call,
            write.id,
            &write.candidate,
            write.occurred,
            write.learned_at,
        )?,
        SelfCall::MemoryPutClaim(put) => {
            claim_args(call, put.id, &put.candidate, put.occurred, put.learned_at)?
        }
        SelfCall::MemorySupersedeClaim(supersede) => json!({
            "newId": supersede.new_id.to_hex(),
            "oldId": supersede.old_id.to_hex(),
            "now": supersede.now,
        }),
        SelfCall::MemoryPutEdge(edge) => json!({
            "src": edge.src.to_hex(),
            "kind": edge.kind.name(),
            "tgt": edge.tgt.to_hex(),
            "weight": edge.weight,
        }),
        SelfCall::Ask(ask) => json!({"prompt": ask.prompt}),
        SelfCall::DestructiveFixture(fixture) | SelfCall::OutboundFixture(fixture) => {
            json!({"label": fixture.label})
        }
        SelfCall::Context(context) => json!({"spec": to_json(&context.spec)?}),
        SelfCall::Speak(speech) | SelfCall::Think(speech) | SelfCall::Express(speech) => {
            json!({"text": speech.text})
        }
        SelfCall::ReportBlocked(blocked) => {
            json!({"category": to_json(&blocked.category)?, "detail": blocked.detail})
        }
        SelfCall::InferenceDefaultsRead => json!({}),
        SelfCall::InferenceDefaultsReplace(text) => json!({"json": text}),
        SelfCall::WakePolicyWrite(write) => json!({"policy": to_json(&write.policy)?}),
        SelfCall::AgentVerb(verb) => json!({"verb": verb.verb.as_str(), "input": verb.input}),
        SelfCall::Fold(fold) => to_json(fold)?,
        SelfCall::ReaderSpawn(spawn) => json!({
            "source": spawn.source,
            "ask": spawn.ask,
            "intent_key": spawn.intent_key,
        }),
        SelfCall::ReaderReport(report) => json!({
            "task_ref": report.task.to_hex(),
            "resultRef": report.result_ref,
        }),
        SelfCall::TasksWaitSet(wait) => to_json(wait)?,
        SelfCall::Leader(SelfLeaderCall::Advice { top }) => json!({"top": top}),
        SelfCall::Leader(SelfLeaderCall::Pattern { skill }) => json!({"skill": skill.to_hex()}),
        SelfCall::Team(team) => to_json(team)?,
    })
}

/// A claim write's input, as the guest's `vault.claims.put` takes it.
fn claim_args(
    call: &SelfCall,
    id: EntityId,
    candidate: &ClaimCandidate,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<Value> {
    let (value, confidence) = candidate_fields(call)?;
    Ok(json!({
        "id": id.to_hex(),
        "predicate": candidate.predicate(),
        "subject": subject_json(candidate.subject()),
        "value": rmpv_json(&value),
        "confidence": confidence,
        "occurred": span(occurred),
        "learnedAt": learned_at,
    }))
}

/// A claim candidate's value and confidence, as the call's replay request
/// records them: the candidate keeps both to itself.
fn candidate_fields(call: &SelfCall) -> Result<(rmpv::Value, Option<f64>)> {
    let request = self_call_request_value(call)?;
    let candidate = entry(&request, "candidate");
    Ok((
        candidate
            .and_then(|candidate| entry(candidate, "value"))
            .cloned()
            .unwrap_or(rmpv::Value::Nil),
        candidate
            .and_then(|candidate| entry(candidate, "confidence"))
            .and_then(rmpv::Value::as_f64),
    ))
}

fn subject_json(subject: ClaimSubject) -> Value {
    match subject {
        ClaimSubject::Entity(id) => Value::String(id.to_hex()),
        ClaimSubject::Edge {
            source,
            kind,
            target,
        } => json!({"source": source.to_hex(), "kind": kind.name(), "target": target.to_hex()}),
    }
}

fn span(range: TimeRange) -> Value {
    json!({"start": range.start, "end": range.end})
}

fn to_json(value: &impl serde::Serialize) -> Result<Value> {
    serde_json::to_value(value)
        .map_err(|error| Error::InvalidConfig(format!("verb hook args do not encode: {error}")))
}

/// A claim value as JSON: bytes as lowercase hex, a map with other than
/// string keys as a list of pairs.
fn rmpv_json(value: &rmpv::Value) -> Value {
    match value {
        rmpv::Value::Nil | rmpv::Value::Ext(..) => Value::Null,
        rmpv::Value::Boolean(flag) => Value::Bool(*flag),
        rmpv::Value::Integer(number) => number
            .as_i64()
            .map(Value::from)
            .or_else(|| number.as_u64().map(Value::from))
            .unwrap_or(Value::Null),
        rmpv::Value::F32(number) => json!(number),
        rmpv::Value::F64(number) => json!(number),
        rmpv::Value::String(text) => text.as_str().map_or_else(
            || Value::String(crate::entity_id::bytes_to_hex_lower(text.as_bytes())),
            |text| Value::String(text.to_owned()),
        ),
        rmpv::Value::Binary(bytes) => Value::String(crate::entity_id::bytes_to_hex_lower(bytes)),
        rmpv::Value::Array(values) => Value::Array(values.iter().map(rmpv_json).collect()),
        rmpv::Value::Map(entries) if entries.iter().all(|(key, _)| key.as_str().is_some()) => {
            Value::Object(
                entries
                    .iter()
                    .filter_map(|(key, value)| Some((key.as_str()?.to_owned(), rmpv_json(value))))
                    .collect(),
            )
        }
        rmpv::Value::Map(entries) => Value::Array(
            entries
                .iter()
                .map(|(key, value)| json!([rmpv_json(key), rmpv_json(value)]))
                .collect(),
        ),
    }
}

/// A guest's JSON value as a claim value, as the bridge reads the guest's.
fn json_rmpv(value: Value) -> rmpv::Value {
    match value {
        Value::Null => rmpv::Value::Nil,
        Value::Bool(flag) => rmpv::Value::Boolean(flag),
        Value::Number(number) => {
            if let Some(number) = number.as_u64() {
                rmpv::Value::from(number)
            } else if let Some(number) = number.as_i64() {
                rmpv::Value::from(number)
            } else {
                rmpv::Value::F64(number.as_f64().unwrap_or_default())
            }
        }
        Value::String(text) => rmpv::Value::from(text),
        Value::Array(values) => rmpv::Value::Array(values.into_iter().map(json_rmpv).collect()),
        Value::Object(entries) => rmpv::Value::Map(
            entries
                .into_iter()
                .map(|(key, value)| (rmpv::Value::from(key), json_rmpv(value)))
                .collect(),
        ),
    }
}

type Rewritten<T> = std::result::Result<T, String>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TextArgs {
    text: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PromptArgs {
    prompt: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LabelArgs {
    label: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockedArgs {
    category: BlockedCategory,
    detail: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchArgs {
    query: String,
    limit: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SpanArgs {
    start: u64,
    end: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ClaimArgs {
    id: String,
    predicate: String,
    subject: Value,
    value: Value,
    confidence: Option<f64>,
    occurred: SpanArgs,
    learned_at: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EdgeSubjectArgs {
    source: String,
    kind: String,
    target: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SupersedeArgs {
    new_id: String,
    old_id: String,
    now: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EdgeArgs {
    src: String,
    kind: String,
    tgt: String,
    weight: f64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RefuseArgs {
    task_ref: Option<String>,
    domain: String,
    reason_ref: String,
    at: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SkillArgs {
    skill: String,
    args: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyArgs {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonArgs {
    json: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyArgs {
    policy: crate::dreamer_wake::DreamerWakePolicy,
}

/// A fold verb's input, as [`SelfFoldCall`] encodes it.
#[derive(Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
enum FoldArgs {
    Mark {
        from: u64,
        through: u64,
        note: Option<String>,
    },
    Compact {
        note: Option<String>,
    },
    Unfold {
        fold: u64,
    },
    List,
    Describe {
        fold: u64,
    },
}

/// Decodes rewritten args back into the call they rewrite, checked as the
/// guest's own input is. The bridge's stamps carry over. A call a hook does
/// not read whole takes no rewrite.
fn rewrite(call: &SelfCall, args: &Value) -> Rewritten<SelfCall> {
    Ok(match call {
        SelfCall::Speak(speech) => SelfCall::Speak(speech_rewrite(speech, args)?),
        SelfCall::Think(speech) => SelfCall::Think(speech_rewrite(speech, args)?),
        SelfCall::Express(speech) => SelfCall::Express(speech_rewrite(speech, args)?),
        SelfCall::Ask(_) => SelfCall::Ask(SelfAskCall::new(decode::<PromptArgs>(args)?.prompt)),
        SelfCall::DestructiveFixture(_) => SelfCall::DestructiveFixture(
            SelfFixtureEffectCall::new(decode::<LabelArgs>(args)?.label),
        ),
        SelfCall::OutboundFixture(_) => {
            SelfCall::OutboundFixture(SelfFixtureEffectCall::new(decode::<LabelArgs>(args)?.label))
        }
        SelfCall::ReportBlocked(blocked) => {
            let args: BlockedArgs = decode(args)?;
            let mut next = blocked.clone();
            next.category = args.category;
            next.detail = args.detail;
            SelfCall::ReportBlocked(next)
        }
        SelfCall::MemorySearch(_) => {
            let args: SearchArgs = decode(args)?;
            SelfCall::MemorySearch(SelfMemorySearchCall::new(args.query, args.limit))
        }
        SelfCall::MemoryPutClaim(put) => {
            let (id, candidate, occurred, learned_at) = claim_rewrite(call, &put.candidate, args)?;
            SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
                id, candidate, occurred, learned_at,
            ))
        }
        SelfCall::MemorySupersedeClaim(_) => {
            let args: SupersedeArgs = decode(args)?;
            SelfCall::MemorySupersedeClaim(SelfMemorySupersedeClaimCall::new(
                hex_id(&args.new_id)?,
                hex_id(&args.old_id)?,
                guest_time(args.now)?,
            ))
        }
        SelfCall::MemoryPutEdge(_) => {
            let args: EdgeArgs = decode(args)?;
            let kind = EdgeKind::from_name(&args.kind).ok_or("unknown edge kind")?;
            SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
                hex_id(&args.src)?,
                kind,
                hex_id(&args.tgt)?,
                guest_f32(args.weight)?,
            ))
        }
        SelfCall::TasksAsk(_) => SelfCall::TasksAsk(Box::new(decode(args)?)),
        SelfCall::TasksWait(_) => SelfCall::TasksWait(decode(args)?),
        SelfCall::TasksRefuse(_) => {
            let args: RefuseArgs = decode(args)?;
            SelfCall::TasksRefuse(SelfTaskRefuseCall {
                task_ref: args.task_ref.as_deref().map(hex_id).transpose()?,
                domain: RefusalDomain::parse(&args.domain).ok_or("unknown refusal domain")?,
                reason_ref: args.reason_ref,
                at: guest_time(args.at)?,
            })
        }
        SelfCall::SkillsCall(_) => {
            let args: SkillArgs = decode(args)?;
            SelfCall::SkillsCall(SelfSkillCall {
                skill: hex_id(&args.skill)?,
                args: args.args,
            })
        }
        SelfCall::InferenceDefaultsRead => {
            let EmptyArgs {} = decode(args)?;
            SelfCall::InferenceDefaultsRead
        }
        SelfCall::InferenceDefaultsReplace(_) => {
            SelfCall::InferenceDefaultsReplace(decode::<JsonArgs>(args)?.json)
        }
        SelfCall::WakePolicyWrite(_) => SelfCall::WakePolicyWrite(SelfWakePolicyWriteCall::new(
            decode::<PolicyArgs>(args)?.policy,
        )),
        SelfCall::Fold(fold) => SelfCall::Fold(fold_rewrite(fold, args)?),
        SelfCall::TasksWaitSet(_) => SelfCall::TasksWaitSet(decode(args)?),
        // A reader's source and finding are resolved by the host before the
        // hooks run: a rewrite would name a result nothing resolved.
        SelfCall::AgentsSpawn(_)
        | SelfCall::AgentsPut(_)
        | SelfCall::MemoryWriteFixture(_)
        | SelfCall::Context(_)
        | SelfCall::AgentVerb(_)
        | SelfCall::ReaderSpawn(_)
        | SelfCall::ReaderReport(_)
        | SelfCall::Leader(_)
        | SelfCall::Team(_) => {
            return Err(format!("{} takes no rewrite", call.effect().as_str()));
        }
    })
}

fn decode<T: serde::de::DeserializeOwned>(args: &Value) -> Rewritten<T> {
    serde_json::from_value(args.clone()).map_err(|error| error.to_string())
}

fn speech_rewrite(speech: &SelfSpeechCall, args: &Value) -> Rewritten<SelfSpeechCall> {
    Ok(SelfSpeechCall {
        text: decode::<TextArgs>(args)?.text,
        ..speech.clone()
    })
}

/// A rewritten claim write. A candidate carrying more than the guest's input
/// holds would lose it, so it takes no rewrite.
fn claim_rewrite(
    call: &SelfCall,
    original: &ClaimCandidate,
    args: &Value,
) -> Rewritten<(EntityId, ClaimCandidate, TimeRange, u64)> {
    let (value, confidence) = candidate_fields(call).map_err(|error| error.to_string())?;
    let plain = ClaimCandidate::new(
        original.predicate(),
        original.subject(),
        value,
        confidence.unwrap_or(1.0) as f32,
    );
    if plain != *original {
        return Err("this claim carries fields a rewrite cannot keep".to_owned());
    }
    let args: ClaimArgs = decode(args)?;
    let occurred = TimeRange {
        start: guest_time(args.occurred.start)?,
        end: guest_time(args.occurred.end)?,
    };
    if occurred.start > occurred.end {
        return Err("invalid claim time range".to_owned());
    }
    let candidate = ClaimCandidate::new(
        args.predicate,
        claim_subject(args.subject)?,
        json_rmpv(args.value),
        guest_f32(args.confidence.unwrap_or(1.0))?,
    );
    Ok((
        hex_id(&args.id)?,
        candidate,
        occurred,
        guest_time(args.learned_at)?,
    ))
}

fn claim_subject(subject: Value) -> Rewritten<ClaimSubject> {
    if let Value::String(id) = &subject {
        return Ok(ClaimSubject::Entity(hex_id(id)?));
    }
    let edge: EdgeSubjectArgs = decode(&subject)?;
    Ok(ClaimSubject::Edge {
        source: hex_id(&edge.source)?,
        kind: EdgeKind::from_name(&edge.kind).ok_or("unknown edge kind")?,
        target: hex_id(&edge.target)?,
    })
}

/// A rewritten fold call: the same fold verb, new arguments.
fn fold_rewrite(fold: &SelfFoldCall, args: &Value) -> Rewritten<SelfFoldCall> {
    let next = match decode::<FoldArgs>(args)? {
        FoldArgs::Mark {
            from,
            through,
            note,
        } => SelfFoldCall::Mark {
            from,
            through,
            note,
        },
        FoldArgs::Compact { note } => SelfFoldCall::Compact { note },
        FoldArgs::Unfold { fold } => SelfFoldCall::Unfold { fold },
        FoldArgs::List => SelfFoldCall::List,
        FoldArgs::Describe { fold } => SelfFoldCall::Describe { fold },
    };
    if std::mem::discriminant(&next) != std::mem::discriminant(fold) {
        return Err("a rewrite keeps the fold verb".to_owned());
    }
    Ok(next)
}

fn hex_id(text: &str) -> Rewritten<EntityId> {
    EntityId::from_hex(text).map_err(|error| error.to_string())
}

/// A guest time: past JavaScript's safe range it was rounded, so it is
/// refused.
fn guest_time(value: u64) -> Rewritten<u64> {
    if value > JS_SAFE_INTEGER {
        return Err("invalid guest integer".to_owned());
    }
    Ok(value)
}

/// A guest number for an `f32` field: past its range it is refused, never
/// rounded.
fn guest_f32(value: f64) -> Rewritten<f32> {
    if !value.is_finite() || value.abs() > f64::from(f32::MAX) {
        return Err("invalid guest number".to_owned());
    }
    Ok(value as f32)
}
