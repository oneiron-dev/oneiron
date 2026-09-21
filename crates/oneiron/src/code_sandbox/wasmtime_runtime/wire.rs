//! Internal bounded JSON bridge between typed WIT and the borrowed engine host.

use super::{Bridge, failure};
use crate::code_run::{
    SelfAskHumanCall, SelfCall, SelfDispatchOutcome, SelfMemoryPutClaimCall, SelfMemoryPutEdgeCall,
    SelfMemorySearchCall, SelfMemorySupersedeClaimCall, SelfSpeechCall,
};
use crate::code_sandbox::{
    SandboxCredentialCall, SandboxCredentialHandle, SandboxReadFile, SandboxVirtualPath,
};
use crate::engine_executor::{JsCodeModeOutput, JsCodeModeStepOutcome, SelfDispatchResponse};
use crate::{ClaimCandidate, ClaimSubject, EdgeKind, EntityId, Result, TimeRange};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Claim {
    id: String,
    predicate: String,
    subject: String,
    value: Value,
    confidence: Option<f32>,
    occurred: Option<Occurred>,
    learned_at: Option<u64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Occurred {
    start: u64,
    end: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Supersede {
    new_id: String,
    old_id: String,
    now: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Edge {
    src: String,
    kind: String,
    tgt: String,
    weight: Option<f32>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Search {
    query: String,
    limit: Option<usize>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Speech {
    text: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ask {
    prompt: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    path: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Credential {
    operation: String,
    credential_handle: String,
    args: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Random {
    length: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

fn parse<T: serde::de::DeserializeOwned>(input: &str) -> Result<T> {
    serde_json::from_str(input).map_err(|_| failure("invalid typed component arguments"))
}

pub(super) fn dispatch(state: &mut Bridge<'_>, name: &str, input: &str) -> Result<String> {
    match name {
        "sandbox.fs.read_file" => {
            let args: File = parse(input)?;
            let service = state
                .adapter
                .as_mut()
                .ok_or(failure("file service unavailable"))?;
            let result = service.read_file(SandboxReadFile::new(SandboxVirtualPath::try_new(
                &args.path,
            )?))?;
            Ok(json!({"path": result.path.as_str(), "bytes": result.bytes}).to_string())
        }
        "sandbox.credential.call" => {
            let args: Credential = parse(input)?;
            let service = state
                .adapter
                .as_mut()
                .ok_or(failure("credential service unavailable"))?;
            let result = service.call_credential(SandboxCredentialCall::read_only(
                args.operation,
                SandboxCredentialHandle::new(args.credential_handle)?,
                json_value(args.args),
            )?)?;
            Ok(json!({"operation": result.operation().as_str(), "credentialHandle": result.credential().as_str()}).to_string())
        }
        "oneiron.clock.now_unix_ms" => {
            let _: Empty = parse(input)?;
            Ok(json!({"value":state.determinism.frozen_unix_ms}).to_string())
        }
        "oneiron.random.bytes" => {
            let args: Random = parse(input)?;
            if args.length > state.message_bytes / 4 {
                return Err(failure("random byte limit"));
            }
            let mut bytes = vec![0; args.length];
            let mut hash = blake3::Hasher::new_keyed(&state.determinism.rng_seed);
            hash.update(b"oneiron:component-random:v1");
            hash.update(&state.step_seq.to_le_bytes());
            hash.update(&state.random_counter.to_le_bytes());
            state.random_counter = state
                .random_counter
                .checked_add(1)
                .ok_or(failure("random counter overflow"))?;
            hash.finalize_xof().fill(&mut bytes);
            Ok(json!({"bytes":bytes}).to_string())
        }
        _ => {
            let call = self_call(name, input, state.determinism.frozen_unix_ms / 1000)?;
            response(state.host.dispatch_self(call)?)
        }
    }
}

fn self_call(name: &str, input: &str, now: u64) -> Result<SelfCall> {
    Ok(match name {
        "self.memory.put_claim" => {
            let args: Claim = parse(input)?;
            let occurred = args.occurred.unwrap_or(Occurred {
                start: now,
                end: now,
            });
            if occurred.start > occurred.end {
                return Err(failure("invalid claim time range"));
            }
            let candidate = ClaimCandidate::new(
                args.predicate,
                ClaimSubject::Entity(EntityId::from_hex(&args.subject)?),
                json_value(args.value),
                args.confidence.unwrap_or(1.0),
            );
            SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
                EntityId::from_hex(&args.id)?,
                candidate,
                TimeRange {
                    start: occurred.start,
                    end: occurred.end,
                },
                args.learned_at.unwrap_or(now),
            ))
        }
        "self.memory.supersede_claim" => {
            let args: Supersede = parse(input)?;
            SelfCall::MemorySupersedeClaim(SelfMemorySupersedeClaimCall::new(
                EntityId::from_hex(&args.new_id)?,
                EntityId::from_hex(&args.old_id)?,
                args.now,
            ))
        }
        "self.memory.put_edge" => {
            let args: Edge = parse(input)?;
            let kind = edge_kind(&args.kind)?;
            let weight = args
                .weight
                .or_else(|| kind.default_weight())
                .ok_or(failure("edge weight required"))?;
            SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
                EntityId::from_hex(&args.src)?,
                kind,
                EntityId::from_hex(&args.tgt)?,
                weight,
            ))
        }
        "self.memory.search" => {
            let args: Search = parse(input)?;
            SelfCall::MemorySearch(SelfMemorySearchCall::new(
                args.query,
                args.limit.unwrap_or(20),
            ))
        }
        "self.ask_human" | "self.askHuman" => {
            SelfCall::AskHuman(SelfAskHumanCall::new(parse::<Ask>(input)?.prompt))
        }
        "self.speak" => SelfCall::Speak(SelfSpeechCall::new(parse::<Speech>(input)?.text)),
        "self.think" => SelfCall::Think(SelfSpeechCall::new(parse::<Speech>(input)?.text)),
        "self.express" => SelfCall::Express(SelfSpeechCall::new(parse::<Speech>(input)?.text)),
        _ => return Err(failure("unlinked self call")),
    })
}

fn response(response: SelfDispatchResponse) -> Result<String> {
    let body = match &response.outcome {
        SelfDispatchOutcome::MemoryWrite(value) => json!({"id":value.id.to_hex()}),
        SelfDispatchOutcome::MemoryEdgeWrite(value) => {
            json!({"src":value.src.to_hex(),"kind":value.kind as u8,"tgt":value.tgt.to_hex()})
        }
        SelfDispatchOutcome::MemorySearch(value) => json!({"results":value.results.iter().map(|hit|
            json!({"id":hit.id.to_hex(),"score":hit.score})).collect::<Vec<_>>()}),
        SelfDispatchOutcome::DurableWait(value) => json!({"waitId":value.wait_id.to_hex()}),
        SelfDispatchOutcome::Denied(value) => {
            json!({"denied":value.outcome,"reasonCodes":value.reason_codes})
        }
        SelfDispatchOutcome::Failed(_) => json!({"failed":true}),
        SelfDispatchOutcome::Speech(value) => {
            json!({"order":value.order,"isVisible":value.is_visible})
        }
        SelfDispatchOutcome::ReportBlocked { receipt } => {
            json!({"receipt":receipt.to_hex()})
        }
        SelfDispatchOutcome::Context(_) => {
            return Err(failure("context is not a linked component import"));
        }
    };
    Ok(response.guest_json(body).to_string())
}

fn json_value(value: Value) -> rmpv::Value {
    match value {
        Value::Null => rmpv::Value::Nil,
        Value::Bool(v) => rmpv::Value::Boolean(v),
        Value::Number(v) => {
            if let Some(v) = v.as_u64() {
                rmpv::Value::from(v)
            } else if let Some(v) = v.as_i64() {
                rmpv::Value::from(v)
            } else {
                rmpv::Value::F64(v.as_f64().unwrap_or_default())
            }
        }
        Value::String(v) => rmpv::Value::from(v),
        Value::Array(v) => rmpv::Value::Array(v.into_iter().map(json_value).collect()),
        Value::Object(v) => rmpv::Value::Map(
            v.into_iter()
                .map(|(k, v)| (rmpv::Value::from(k), json_value(v)))
                .collect(),
        ),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Output {
    done: bool,
    observation: String,
    #[serde(default)]
    outputs: Vec<OutputFile>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputFile {
    path: String,
    bytes: Vec<u8>,
}

pub(super) fn decode_output(output: &str, limit: usize) -> Result<JsCodeModeStepOutcome> {
    if output.len() > limit {
        return Err(failure("component output exceeds message limit"));
    }
    let output: Output = parse(output)?;
    let mut outputs = Vec::new();
    for file in output.outputs {
        let path = SandboxVirtualPath::try_new(&file.path)?;
        if path.mount() != crate::code_sandbox::SandboxMount::Outputs {
            return Err(failure("component output must be under /mnt/outputs"));
        }
        outputs.push(JsCodeModeOutput::new(path.as_str(), file.bytes));
    }
    Ok(JsCodeModeStepOutcome {
        done: output.done,
        observation: output.observation,
        outputs,
    })
}

pub(super) fn edge_kind(name: &str) -> Result<EdgeKind> {
    Ok(match name {
        "authored_by" => EdgeKind::AuthoredBy,
        "scoped_to" => EdgeKind::ScopedTo,
        "part_of" => EdgeKind::PartOf,
        "supersedes" => EdgeKind::Supersedes,
        "belongs_to" => EdgeKind::BelongsTo,
        "claim_of" => EdgeKind::ClaimOf,
        "child_of" => EdgeKind::ChildOf,
        "assigned_to" => EdgeKind::AssignedTo,
        "derived_from" => EdgeKind::DerivedFrom,
        "mentions" => EdgeKind::Mentions,
        "about" => EdgeKind::About,
        "supports" => EdgeKind::Supports,
        "opposes" => EdgeKind::Opposes,
        "participates_in" => EdgeKind::ParticipatesIn,
        "attached" => EdgeKind::Attached,
        "employed_by" => EdgeKind::EmployedBy,
        "has_facet" => EdgeKind::HasFacet,
        "facet_of" => EdgeKind::FacetOf,
        "in_world" => EdgeKind::InWorld,
        "set_in" => EdgeKind::SetIn,
        "same_as" => EdgeKind::SameAs,
        "merged_into" => EdgeKind::MergedInto,
        "split_into" => EdgeKind::SplitInto,
        "blocked_by" => EdgeKind::BlockedBy,
        "blocks" => EdgeKind::Blocks,
        "fulfills" => EdgeKind::Fulfills,
        "discharged_by" => EdgeKind::DischargedBy,
        _ => return Err(failure("invalid edge kind")),
    })
}
