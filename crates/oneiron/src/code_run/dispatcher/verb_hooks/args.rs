//! A call's input as its verb hooks read it (ARCH-0080 §3): the shape the
//! guest wrote, ids in hex, with the bridge's own stamps left out.

use serde_json::{Value, json};

use crate::agent_dispatch::AgentDispatchTarget;
use crate::code_run::agent_put_draft;
use crate::code_run::payload::self_call_request_value;
use crate::code_run::types::{SelfCall, SelfLeaderCall};
use crate::error::{Error, Result};
use crate::{ClaimCandidate, ClaimSubject, EntityId, TimeRange};

use super::entry;

/// A call's input as a hook reads it: the shape the guest wrote, ids in hex.
/// The bridge's own stamps (a bubble's order and time) are not the guest's
/// and stay out.
pub(super) fn hook_args(call: &SelfCall) -> Result<Value> {
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
            "definition": agent_put_draft(&put.definition),
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
        SelfCall::ConsultResult(request) => to_json(request)?,
        SelfCall::SkillsCall(skill) => json!({"skill": skill.skill.to_hex(), "args": skill.args}),
        SelfCall::MemorySearch(search) => match &search.filter {
            Some(filter) => {
                json!({"query": search.query, "limit": search.limit, "filter": to_json(filter)?})
            }
            None => json!({"query": search.query, "limit": search.limit}),
        },
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
        SelfCall::ConnectorAnswer(request) => to_json(request)?,
        SelfCall::WorldPrivacySet(input) => to_json(input)?,
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
        SelfCall::Summarize(summary) => json!({
            "ref": summary.reference,
            "effort": summary.effort.map(crate::code_run::SummarizeEffort::as_str),
            "group": summary.group,
            "defer": summary.defer,
        }),
        SelfCall::Leader(SelfLeaderCall::Advice { top }) => json!({"top": top}),
        SelfCall::Leader(SelfLeaderCall::Pattern { skill }) => json!({"skill": skill.to_hex()}),
        SelfCall::Leader(SelfLeaderCall::Split { leader, slice }) => json!({
            "leader": leader.as_ref().map(EntityId::to_hex),
            "slice": slice.as_ref().map(to_json).transpose()?,
        }),
        SelfCall::Team(team) => to_json(team)?,
        SelfCall::TeamSubmit(submit) => to_json(submit)?,
        SelfCall::WorkflowDispatch(request) => to_json(request.as_ref())?,
        SelfCall::Repo(call) => to_json(call)?,
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
pub(super) fn candidate_fields(call: &SelfCall) -> Result<(rmpv::Value, Option<f64>)> {
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
