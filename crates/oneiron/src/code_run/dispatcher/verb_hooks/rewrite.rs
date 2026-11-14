//! A hook's rewrite of a call's input, decoded back into the call it
//! rewrites (ARCH-0080 §3): checked as the guest's own input is, with the
//! bridge's stamps and the host's own fields carried over.

use serde::Deserialize;
use serde_json::Value;

use crate::agent_def::RefusalDomain;
use crate::agent_dispatch::AgentDispatchTarget;
use crate::code_run::blocked::BlockedCategory;
use crate::code_run::types::{
    SelfAgentDefinitionPutCall, SelfAgentSpawnCall, SelfAskCall, SelfCall, SelfContextCall,
    SelfFixtureEffectCall, SelfMemoryPutClaimCall, SelfMemoryPutEdgeCall, SelfMemorySearchCall,
    SelfMemorySupersedeClaimCall, SelfMemoryWriteFixtureCall, SelfSkillCall, SelfSpawnAsk,
    SelfSpeechCall, SelfTaskRefuseCall, SelfWakePolicyWriteCall,
};
use crate::code_run::{JS_SAFE_INTEGER, agent_put_draft, parse_agent_put_request};
use crate::compaction::SelfFoldCall;
use crate::context_projection::{
    ChatProjection, ContextSpec, MemoryProjection, normalize_context_spec, validate_context_spec,
};
use crate::task_type::TaskTypeRef;
use crate::{ClaimCandidate, ClaimSubject, EdgeKind, EntityId, TimeRange};

use super::super::coordination::SPAWN_INTENT_KEY_MAX_BYTES;
use super::args::candidate_fields;

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

pub(super) type Rewritten<T> = std::result::Result<T, String>;

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
    #[serde(default)]
    filter: Option<crate::memory::ReadFilterInput>,
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

/// A spawn's input as a hook reads it: the fields the guest may set, never
/// the host's.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SpawnArgs {
    target: Option<SpawnTargetArgs>,
    intent_key: String,
    context_spec: Option<ContextSpecArgs>,
    context_from: Vec<String>,
    depth_remaining: Option<u64>,
    project_ref: Option<String>,
    type_ref: Option<String>,
    ask: Option<SelfSpawnAsk>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum SpawnTargetArgs {
    AgentDef { id: String },
    Workflow { id: String },
}

/// A definition put as a hook reads it: the guest's draft under the host's
/// clock.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AgentPutArgs {
    id: String,
    definition: Value,
    occurred: SpanArgs,
    learned_at: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextArgs {
    spec: ContextSpecArgs,
}

/// A context descriptor as a hook writes it: whole, and nothing more.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextSpecArgs {
    layers: Vec<String>,
    memory: MemoryProjection,
    chat: ChatProjection,
    briefing: Option<String>,
    #[serde(rename = "_annotation", default)]
    annotation: Option<String>,
}

impl ContextSpecArgs {
    fn into_spec(self) -> ContextSpec {
        ContextSpec {
            layers: self.layers,
            memory: self.memory,
            chat: self.chat,
            briefing: self.briefing,
            annotation: self.annotation,
        }
    }
}

/// A fold verb's input, as [`SelfFoldCall`] encodes it.
#[derive(Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
enum FoldArgs {
    Mark {
        from: u64,
        through: u64,
        note: Option<String>,
        #[serde(default)]
        kind: Option<crate::compaction::FoldKind>,
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
/// guest's own input is. The bridge's stamps and the host's own fields carry
/// over. A call a hook does not read whole takes no rewrite.
pub(super) fn rewrite(call: &SelfCall, args: &Value) -> Rewritten<SelfCall> {
    Ok(match call {
        SelfCall::Speak(speech) => SelfCall::Speak(speech_rewrite(speech, args)?),
        SelfCall::Think(speech) => SelfCall::Think(speech_rewrite(speech, args)?),
        SelfCall::ThinkAloud(speech) => SelfCall::ThinkAloud(speech_rewrite(speech, args)?),
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
        SelfCall::MemorySearch(search) => {
            let args: SearchArgs = decode(args)?;
            // A rewrite keeps the caller's own filter: it may narrow it,
            // never drop it (FIX 3977).
            SelfCall::MemorySearch(
                SelfMemorySearchCall::new(args.query, args.limit)
                    .with_read_filter(search.filter.clone())
                    .with_read_filter(args.filter),
            )
        }
        SelfCall::MemoryWriteFixture(write) => {
            let (id, candidate, occurred, learned_at) =
                claim_rewrite(call, &write.candidate, args)?;
            SelfCall::MemoryWriteFixture(SelfMemoryWriteFixtureCall::new(
                id, candidate, occurred, learned_at,
            ))
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
        SelfCall::AgentsSpawn(spawn) => {
            SelfCall::AgentsSpawn(Box::new(spawn_rewrite(spawn, args)?))
        }
        SelfCall::AgentsPut(put) => SelfCall::AgentsPut(Box::new(agent_put_rewrite(put, args)?)),
        SelfCall::Context(_) => {
            let spec = normalize_context_spec(decode::<ContextArgs>(args)?.spec.into_spec());
            validate_context_spec(&spec).map_err(|error| error.to_string())?;
            SelfCall::Context(SelfContextCall::new(spec))
        }
        // A run repo row is rewritten only into its own row's input; the
        // binding is rebuilt at dispatch (FIX 6867).
        SelfCall::Repo(call) => SelfCall::Repo(Box::new(call.rewrite(args)?)),
        // A reader's source and finding, and a summary's members, are
        // resolved by the host before the hooks run: a rewrite would name a
        // result nothing resolved.
        // An answer is frozen once and checked as given (ONE-2510).
        // A world-settings request is judged as the agent gave it (FIX 4480).
        // A consult's answer or abstention lands as the peer gave it
        // (DOOR-063).
        // A TASK binding is judged as the agent gave it, on the lane its
        // door admitted (FIX 5316).
        SelfCall::AgentVerb(_)
        | SelfCall::ConnectorAnswer(_)
        | SelfCall::WorldPrivacySet(_)
        | SelfCall::ConsultResult(_)
        | SelfCall::WorkflowDispatch(_)
        | SelfCall::ReaderSpawn(_)
        | SelfCall::ReaderReport(_)
        | SelfCall::Summarize(_)
        | SelfCall::Leader(_)
        | SelfCall::Team(_)
        | SelfCall::TeamSubmit(_) => {
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

/// A rewritten spawn: the call with the fields a hook reads replaced. The
/// host's own context (its budget, spend, origin, room, team and scope)
/// carries over; a plan made for another target, type or ask is dropped, so
/// dispatch plans again.
fn spawn_rewrite(spawn: &SelfAgentSpawnCall, args: &Value) -> Rewritten<SelfAgentSpawnCall> {
    let args: SpawnArgs = decode(args)?;
    if args.intent_key.trim().is_empty() || args.intent_key.len() > SPAWN_INTENT_KEY_MAX_BYTES {
        return Err("invalid spawn intent key".to_owned());
    }
    let mut next = spawn.clone();
    next.target = match args.target {
        Some(SpawnTargetArgs::AgentDef { id }) => Some(AgentDispatchTarget::Custom(hex_id(&id)?)),
        Some(SpawnTargetArgs::Workflow { id }) => Some(AgentDispatchTarget::Workflow(hex_id(&id)?)),
        None => None,
    };
    next.intent_key = args.intent_key;
    next.context.context_spec = args.context_spec.map(ContextSpecArgs::into_spec);
    if let Some(spec) = &next.context.context_spec {
        validate_context_spec(spec).map_err(|error| error.to_string())?;
    }
    next.context.context_from = args
        .context_from
        .iter()
        .map(|id| hex_id(id))
        .collect::<Rewritten<_>>()?;
    next.context.depth_remaining = args.depth_remaining;
    next.context.project_ref = args.project_ref.as_deref().map(hex_id).transpose()?;
    next.context.type_ref = args
        .type_ref
        .as_deref()
        .map(TaskTypeRef::parse_wire)
        .transpose()
        .map_err(|error| error.to_string())?;
    next.ask = args.ask;
    if next.target != spawn.target
        || next.context.type_ref != spawn.context.type_ref
        || next.ask != spawn.ask
    {
        next.context.plan = None;
    }
    Ok(next)
}

/// The entities a rewritten spawn names that the spawn it rewrote did not:
/// its target, its project and the results it reads.
pub(super) fn rewritten_refs(call: &SelfCall, next: &SelfCall) -> Vec<EntityId> {
    let (SelfCall::AgentsSpawn(call), SelfCall::AgentsSpawn(next)) = (call, next) else {
        return Vec::new();
    };
    let mut refs = Vec::new();
    if next.target != call.target
        && let Some(AgentDispatchTarget::Custom(id) | AgentDispatchTarget::Workflow(id)) =
            &next.target
    {
        refs.push(*id);
    }
    if next.context.project_ref != call.context.project_ref {
        refs.extend(next.context.project_ref);
    }
    refs.extend(
        next.context
            .context_from
            .iter()
            .filter(|id| !call.context.context_from.contains(id)),
    );
    refs
}

/// A rewritten definition put: the draft parsed as the guest's own is, under
/// the host's clock. A definition holding more than its draft would lose it,
/// so it takes no rewrite; nor does the clock.
fn agent_put_rewrite(
    put: &SelfAgentDefinitionPutCall,
    args: &Value,
) -> Rewritten<SelfAgentDefinitionPutCall> {
    if agent_put_draft(&put.definition).is_none() {
        return Err("this definition carries fields a rewrite cannot keep".to_owned());
    }
    let args: AgentPutArgs = decode(args)?;
    if args.occurred.start != put.occurred.start
        || args.occurred.end != put.occurred.end
        || args.learned_at != put.learned_at
    {
        return Err("a rewrite keeps the host's clock".to_owned());
    }
    let mut next = parse_agent_put_request(&args.id, args.definition, put.learned_at)
        .map_err(|error| error.to_string())?;
    next.occurred = put.occurred;
    Ok(next)
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
            kind,
        } => SelfFoldCall::Mark {
            from,
            through,
            note,
            kind,
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
