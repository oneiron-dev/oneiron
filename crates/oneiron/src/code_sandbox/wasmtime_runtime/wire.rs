//! Internal bounded JSON bridge between typed WIT and the borrowed engine host.

use super::{Bridge, StreamTarget, failure};
use crate::code_run::{
    ResultFacet, SelfAskCall, SelfCall, SelfDispatchOutcome, SelfSpeechCall,
    blocked::{BlockedCategory, SelfReportBlockedCall},
};
use crate::code_sandbox::{
    SandboxCredentialCall, SandboxCredentialHandle, SandboxReadFile, SandboxVirtualPath,
};
#[cfg(test)]
use crate::engine_executor::SelfDispatchResponse;
use crate::engine_executor::{
    JsCodeModeHost, JsCodeModeOutput, JsCodeModeStepOutcome, JsResultCall, JsResultRef,
    JsResultTarget, RESULT_REPLY_INLINE_BYTES,
};
use crate::task_verb::sdk::{AgentVerb, RunVerb};
use crate::{EntityId, Result};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonValidation {
    schema: Value,
    value: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerbCall {
    verb: String,
    input: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Store {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    sources: Vec<String>,
    #[serde(default)]
    receipt: Option<crate::engine_executor::StoreReceiptInput>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentPut {
    id: String,
    definition: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Speech {
    text: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportBlocked {
    category: String,
    detail: String,
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

fn decode<T: serde::de::DeserializeOwned>(input: Value) -> Result<T> {
    serde_json::from_value(input).map_err(|_| failure("invalid typed component arguments"))
}

/// `bytes` as text when they are UTF-8 and their JSON string is no longer than
/// the base64 other bytes cross the channel as, four bytes for every three.
/// Escaped control characters can make the string the longer one.
fn reply_text(bytes: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(bytes).ok()?;
    let escaped = text
        .bytes()
        .map(|byte| match byte {
            b'"' | b'\\' | b'\x08' | b'\x0c' | b'\n' | b'\r' | b'\t' => 2,
            0..=0x1f => 6,
            _ => 1,
        })
        .sum::<usize>();
    (escaped <= bytes.len().div_ceil(3) * 4).then_some(text)
}

/// Bytes as the channel carries them when they are not text.
fn base64_bytes(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A file reply: text crosses the channel as a JSON string, other bytes as
/// base64, never as a number array.
fn file_reply(path: &str, bytes: &[u8]) -> Value {
    match reply_text(bytes) {
        Some(text) => json!({"path": path, "text": text}),
        None => json!({"path": path, "base64": base64_bytes(bytes)}),
    }
}

/// Fit a recoverable chunk inside the *encoded* host reply ceiling, cutting
/// text only at a character boundary; other bytes cross as base64, whose
/// expansion the measured encoding counts. The caller advances by the
/// returned byte length, never by a guessed cap.
fn bounded_recoverable_reply(path: &str, bytes: &[u8], limit: usize) -> Result<String> {
    let text = reply_text(bytes);
    let cut = |count: usize| text.map_or(count, |text| text.floor_char_boundary(count));
    let encode = |count: usize| {
        let reply = match text {
            Some(text) => json!({"path": path, "text": &text[..count]}),
            None => json!({"path": path, "base64": base64_bytes(&bytes[..count])}),
        };
        serde_json::to_string(&reply).map_err(|_| failure("recoverable output encoding failed"))
    };
    let full = encode(bytes.len())?;
    if full.len() <= limit {
        return Ok(full);
    }
    let mut fits = 0;
    let mut exceeds = bytes.len();
    while exceeds - fits > 1 {
        let probe = fits + (exceeds - fits) / 2;
        if encode(cut(probe))?.len() <= limit {
            fits = probe;
        } else {
            exceeds = probe;
        }
    }
    let fits = cut(fits);
    if fits == 0 {
        return Err(failure(
            "recoverable output cannot fit guest message budget",
        ));
    }
    encode(fits)
}

pub(super) fn dispatch(state: &mut Bridge<'_>, name: &str, input: &str) -> Result<String> {
    match name {
        "sandbox.fs.read_file" => {
            let args: File = parse(input)?;
            let path = SandboxVirtualPath::try_new(&args.path)?;
            // The run's own recorded outputs: past observations and bridge
            // results stored as bodies, each read a chunk at a time.
            if path
                .as_str()
                .starts_with("/mnt/outputs/.oneiron-context-ref/")
                || path
                    .as_str()
                    .starts_with(crate::engine_executor::RESULT_READ_ROOT)
            {
                let bytes = state
                    .host
                    .read_recoverable_output(path.as_str())?
                    .ok_or(failure("recoverable output unavailable"))?;
                return bounded_recoverable_reply(path.as_str(), &bytes, state.message_bytes);
            }
            let service = state
                .adapter
                .as_mut()
                .ok_or(failure("file service unavailable"))?;
            let result = service.read_file(SandboxReadFile::new(SandboxVirtualPath::try_new(
                &args.path,
            )?))?;
            Ok(file_reply(result.path.as_str(), &result.bytes).to_string())
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
        "self.json.validate" => {
            let args: JsonValidation = parse(input)?;
            let valid = crate::llm::validate_json_schema(&args.schema, &args.value).is_ok();
            Ok(json!({"valid":valid}).to_string())
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
            Ok(json!({"base64":base64_bytes(&bytes)}).to_string())
        }
        _ => {
            if name == "self.verbs.call"
                && let Some(call) = result_call(input)?
            {
                return Ok(state.host.result_call(call)?.to_string());
            }
            if let Some(refusal) = wrong_root_call(name, input) {
                return Ok(json!({ "error": refusal }).to_string());
            }
            let call = self_call(name, input, state.determinism.frozen_unix_ms / 1000)?;
            // A callable skill runs a step of its own while this one waits on
            // the reply (OF-353), on a fresh sibling of this runtime: never
            // on this step's store.
            let answered = if matches!(call, SelfCall::SkillsCall(_)) {
                let mut sibling = state.nested.fresh();
                state.host.dispatch_self_nested(call, &mut sibling)?
            } else {
                state.host.dispatch_self(call)?
            };
            let body = fit_reply(state.host, reply_body(&answered.outcome)?)?;
            Ok(answered.guest_json(body).to_string())
        }
    }
}

/// A verb-table call the run answers from its own results: `store`, a
/// `describe` of a result rather than of a task, a `can` that asks whether
/// it may read one rather than whether it may ask, and the facets that read
/// one (`slice`, `search`, `query`, `chunks`), whose input names the result
/// by its `ref`. `None` for any other call.
fn result_call(input: &str) -> Result<Option<JsResultCall>> {
    let Ok(args) = serde_json::from_str::<VerbCall>(input) else {
        return Ok(None);
    };
    if let Some(facet) = ResultFacet::from_name(&args.verb) {
        let Value::Object(mut fields) = args.input else {
            return Err(failure("result ref must be a name, handle or card"));
        };
        let Some(Value::String(reference)) = fields.remove("ref") else {
            return Err(failure("result ref must be a name, handle or card"));
        };
        return Ok(Some(JsResultCall::Read {
            target: JsResultTarget::parse(&reference),
            facet,
            input: Value::Object(fields),
        }));
    }
    Ok(match args.verb.as_str() {
        "store" => {
            let store = decode::<Store>(args.input)?;
            Some(JsResultCall::Store {
                name: store.name,
                sources: store.sources,
                receipt: store.receipt,
            })
        }
        "describe" if secret_handle(&args.input).is_none() => {
            result_ref(args.input).map(JsResultCall::Describe)
        }
        "can" => {
            can_read(args.input)?.map(|(target, child)| JsResultCall::CanRead { target, child })
        }
        _ => None,
    })
}

/// The result a `can` input asks to read, when it asks: `{read: r}`, with
/// `r` a result as `describe` takes one, and whether it asks too whether a
/// reader child could be spawned over it (`child: {}`). Any other `can` is
/// the manifest's ask preflight.
fn can_read(input: Value) -> Result<Option<(JsResultTarget, bool)>> {
    let Value::Object(mut fields) = input else {
        return Ok(None);
    };
    let Some(read) = fields.remove("read") else {
        return Ok(None);
    };
    let child = match fields.remove("child") {
        None => false,
        Some(Value::Object(child)) if child.is_empty() => true,
        Some(_) => return Err(failure("can({read, child}) takes an empty child")),
    };
    if !fields.is_empty() {
        return Err(failure("can({read}) takes only the result to read"));
    }
    result_ref(read)
        .map(|target| Some((target, child)))
        .ok_or_else(|| failure("result ref must be a name, handle or card"))
}

/// The result a `describe` input names, when it names one: a string (a bound
/// name, or a handle, whose colon no name has, either with a range suffix),
/// a result's card by its `ref` or `handle`, or `{name}` with none of a task
/// describe's fields.
fn result_ref(input: Value) -> Option<JsResultTarget> {
    const TASK_FIELDS: [&str; 6] = [
        "task_ref",
        "self",
        "session_id",
        "key",
        "frame_epoch",
        "fold",
    ];
    match input {
        Value::String(text) => Some(JsResultTarget::parse(&text)),
        Value::Object(mut fields) => {
            for key in ["ref", "handle"] {
                if let Some(Value::String(reference)) = fields.remove(key) {
                    return Some(JsResultTarget::parse(&reference));
                }
            }
            if TASK_FIELDS.iter().any(|field| fields.contains_key(*field)) {
                return None;
            }
            match fields.remove("name") {
                Some(Value::String(name)) => Some(JsResultTarget {
                    reference: JsResultRef::Name(name),
                    range: None,
                }),
                _ => None,
            }
        }
        _ => None,
    }
}

/// The secret handle a `describe` input names, when it names one (OF-560):
/// `"sc12"`, `{handle: "sc12"}`, `sc12:ab` or the text form `[secret sc12]`.
/// A secret's handle is read before a result bound under the same name.
fn secret_handle(input: &Value) -> Option<String> {
    let text = match input {
        Value::String(text) => text.as_str(),
        Value::Object(fields) if fields.len() == 1 => fields.get("handle")?.as_str()?,
        _ => return None,
    };
    crate::secret_custody::parse_secret_handle(text)
        .is_ok()
        .then(|| text.to_owned())
}

/// The `WRONG_ROOT` refusal for a verb-table call that names no row but one
/// canonical verb under another root. Answered before any typed call, bridge
/// stamp or receipt exists, so the wrong name has no effect.
fn wrong_root_call(name: &str, input: &str) -> Option<crate::memory::MemoryError> {
    if name != "self.verbs.call" {
        return None;
    }
    let args: VerbCall = serde_json::from_str(input).ok()?;
    crate::task_verb::sdk::wrong_root(&args.verb)
}

fn self_call(name: &str, input: &str, now: u64) -> Result<SelfCall> {
    Ok(match name {
        "self.verbs.call" => {
            let args: VerbCall = parse(input)?;
            // A row the run answers itself is its own typed call, so it keeps
            // the effect, gate and replay row it has always had.
            if let Some(verb) = RunVerb::from_name(&args.verb) {
                return crate::code_run::run_verb_call::run_verb_call(verb, args.input, now);
            }
            let verb =
                AgentVerb::from_name(&args.verb).ok_or_else(|| failure("unknown SDK verb"))?;
            // The bare `ask` and `wait` rows keep the run's coordination calls:
            // an ask binds to the run's own task, and a wait reads the run's
            // replay for the voids it has already seen.
            // A secret's handle is described, and its reveal waited on,
            // through the reveal rows (OF-560): `describe("sc12")` names no
            // result of the run, and `wait({reveal})` no task ask.
            if verb == AgentVerb::Describe
                && let Some(handle) = secret_handle(&args.input)
            {
                return Ok(SelfCall::AgentVerb(crate::code_run::SelfAgentVerbCall {
                    verb: AgentVerb::RevealDescribe,
                    input: json!({ "handle": handle }),
                }));
            }
            if verb == AgentVerb::Wait && args.input.get("reveal").is_some() {
                return Ok(SelfCall::AgentVerb(crate::code_run::SelfAgentVerbCall {
                    verb: AgentVerb::RevealWait,
                    input: args.input,
                }));
            }
            // `describe({fold})` peeks at a fold of this run's own log, which
            // only the run holds: no host door ever sees it.
            if verb == AgentVerb::Describe
                && let Some(fold) = args.input.get("fold").filter(|fold| !fold.is_null())
            {
                let fold = fold
                    .as_str()
                    .ok_or_else(|| failure("invalid fold handle"))?;
                return Ok(SelfCall::Fold(crate::compaction::SelfFoldCall::Describe {
                    fold: crate::compaction::parse_fold_handle(fold)?,
                }));
            }
            if verb == AgentVerb::Ask {
                let request: crate::task_verb::sdk::TaskAskRequest = decode(args.input)?;
                let spec = request
                    .into_spec()
                    .map_err(|_| failure("invalid ask input"))?;
                return Ok(SelfCall::TasksAsk(Box::new(spec)));
            }
            if verb == AgentVerb::Wait {
                let request: crate::task_verb::sdk::TaskWaitRequest = decode(args.input)?;
                return Ok(SelfCall::TasksWait(request.handle));
            }
            // A reader child's finding names one of its own results, which
            // only the run resolves; a bare acknowledgement stays the row's.
            if verb == AgentVerb::TasksUpdate
                && args
                    .input
                    .get("resultRef")
                    .is_some_and(|result| !result.is_null())
            {
                let request: crate::task_verb::sdk::TaskUpdateRequest = decode(args.input)?;
                // A typed report sent beside the result would be dropped
                // here, so the call is refused instead.
                if request.report.is_some()
                    || request.report_key.is_some()
                    || request.attempt.is_some()
                {
                    return Err(failure("task_update_report_conflicts_with_result"));
                }
                let result_ref = request
                    .result_ref
                    .ok_or_else(|| failure("invalid task update"))?;
                return Ok(SelfCall::ReaderReport(
                    crate::code_run::SelfReaderReportCall {
                        task: EntityId::from_hex(&request.task_ref)?,
                        result_ref,
                        bound: None,
                    },
                ));
            }
            SelfCall::AgentVerb(crate::code_run::SelfAgentVerbCall {
                verb,
                input: args.input,
            })
        }
        "vault.agents.put" => {
            let args: AgentPut = parse(input)?;
            SelfCall::AgentsPut(Box::new(crate::code_run::parse_agent_put_request(
                &args.id,
                args.definition,
                now,
            )?))
        }
        "tasks.ask" => SelfCall::TasksAsk(Box::new(parse::<crate::task_verb::TaskAskSpec>(input)?)),
        "tasks.wait" => SelfCall::TasksWait(parse::<crate::task_verb::TaskAskHandle>(input)?),
        "self.report_blocked" => {
            let args: ReportBlocked = parse(input)?;
            let category: BlockedCategory = serde_json::from_value(Value::String(args.category))
                .map_err(|_| failure("invalid blocked category"))?;
            SelfCall::ReportBlocked(SelfReportBlockedCall::new(category, args.detail))
        }
        "ask" => SelfCall::Ask(SelfAskCall::new(parse::<Ask>(input)?.prompt)),
        "self.speak" => SelfCall::Speak(SelfSpeechCall::new(parse::<Speech>(input)?.text)),
        "self.think" => SelfCall::Think(SelfSpeechCall::new(parse::<Speech>(input)?.text)),
        "self.express" => SelfCall::Express(SelfSpeechCall::new(parse::<Speech>(input)?.text)),
        _ => return Err(failure("unlinked self call")),
    })
}

/// Bytes `value` takes as JSON, holding none of them.
fn encoded_len(value: &Value) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    match serde_json::to_writer(&mut count, value) {
        Ok(()) => count.0,
        Err(_) => usize::MAX,
    }
}

/// A reply as the guest gets it: one whose JSON is past
/// `RESULT_REPLY_INLINE_BYTES` is stored as a result of the run, and its
/// card stands under `output` in place of what was stored (the output, or
/// the whole reply when it has none). No answer is refused for its size; a
/// host with no result store sends it as it is, for the message bound to
/// judge.
fn fit_reply(host: &mut dyn JsCodeModeHost, mut body: Value) -> Result<Value> {
    if encoded_len(&body) <= RESULT_REPLY_INLINE_BYTES {
        return Ok(body);
    }
    let has_output = body.get("output").is_some();
    let stored = if has_output { &body["output"] } else { &body };
    if let Some(card) = host.store_reply(stored)? {
        if has_output {
            body["output"] = card;
        } else {
            body = json!({ "output": card });
        }
    }
    Ok(body)
}

#[cfg(test)]
fn response(response: SelfDispatchResponse) -> Result<String> {
    Ok(response
        .guest_json(reply_body(&response.outcome)?)
        .to_string())
}

/// The failure codes a guest's failed reply names under `error`: each a
/// stable word a host door refuses with, which the guest can act on. Any
/// other failure (an internal error's text) answers `{failed: true}` alone,
/// and the replay row keeps the whole error either way.
const GUEST_FAILURE_CODES: &[&str] = &[
    // summarize and reader children (OF-190)
    "summarize_unbound",
    "summarize_unresolved",
    "summarize_invalid_group",
    "summarize_past_cutoff",
    "summarize_unmetered",
    "reader_spawn_unbound",
    "reader_spawn_unresolved",
    "reader_spawn_invalid_intent_key",
    "reader_spawn_past_cutoff",
    "reader_spawn_unmetered",
    "not_reader_task",
    "finding_not_own",
    "finding_tainted",
    "finding_not_json",
    "reader_task_settled",
    "task_wait_unbound",
    "task_wait_invalid",
    "task_wait_changed",
    // the planner, refusals, skills and teams
    "planner_unbound",
    "tasks_refuse_unbound",
    "tasks_refuse_other_task",
    "tasks_refuse_invalid_reason",
    "skills_call_unleased",
    "skills_call_unbound",
    "skills_call_lease_lost",
    "skills_call_no_runtime",
    "skills_call_no_executor",
    "team_unbound",
    "team_off_record",
    "team_start_invalid_agent",
    "team_start_spawn_refused",
    "team_start_unknown_pattern",
    "team_start_solo",
    "team_start_invalid_input",
    "team_start_tournament_not_market",
    "team_start_invalid_tournament",
    "team_start_tournament_unknown",
    "team_start_tournament_foreign",
    "team_start_tournament_unbound",
    "team_record_not_led",
    "team_record_invalid_input",
    "team_record_unknown_member",
    "team_record_member_outside_team",
    "team_record_no_models",
    "team_record_roles",
    "team_record_decider",
    "team_submit_invalid_output",
    "team_submit_unrecorded",
    "team_submit_not_led",
    "team_submit_output_missing",
    "team_submit_id_occupied",
    "team_submit_unreviewed",
    // the bridge
    "host_bridge_halted",
    "task_declined",
    // the facade's error codes a coordination call fails with
    "BAD_REQUEST",
    "NOT_FOUND",
    "FORBIDDEN",
    "INVALID_STATE",
    "LEASE_REQUIRED",
    "IDENTITY_UNSETTLED",
    "BUDGET_SPENT",
    "MODEL_UNAVAILABLE",
    "PENDING_ASK",
];

/// One dispatched call's reply body, before its budget envelope.
fn reply_body(outcome: &SelfDispatchOutcome) -> Result<Value> {
    Ok(match outcome {
        // A row's answer is its output, framed as every verb's is: the type
        // its row names (`output` in `scripts/sdk/agent-verbs.json`).
        SelfDispatchOutcome::MemoryWrite(value) => {
            json!({ "output": crate::code_run::MemoryWriteOutput { id: value.id } })
        }
        SelfDispatchOutcome::MemoryEdgeWrite(value) => json!({
            "output": crate::code_run::MemoryEdgeOutput {
                src: value.src,
                kind: value.kind.name().to_owned(),
                tgt: value.tgt,
            }
        }),
        SelfDispatchOutcome::MemorySearch(value) => json!({
            "output": crate::code_run::MemorySearchOutput {
                results: value
                    .results
                    .iter()
                    .map(|hit| crate::code_run::MemorySearchHit {
                        id: hit.id,
                        score: hit.score,
                    })
                    .collect(),
            }
        }),
        // Any call that parks, and every call past a park, answers the wait.
        SelfDispatchOutcome::DurableWait(value) => json!({"waitId":value.wait_id.to_hex()}),
        SelfDispatchOutcome::TaskRefusal(value) => json!({
            "output": crate::code_run::TaskRefuseOutput {
                task: value.task_ref,
                level: value.level.as_str().to_owned(),
                outcome: value.outcome_word().to_owned(),
                replay: value.replay,
            }
        }),
        SelfDispatchOutcome::AgentVerb(answer) => json!({"output":answer.output}),
        SelfDispatchOutcome::SkillCall(value) => json!({"output":value.output}),
        SelfDispatchOutcome::Denied(value) => {
            json!({"denied":value.outcome,"reasonCodes":value.reason_codes})
        }
        SelfDispatchOutcome::Failed(value) => {
            if GUEST_FAILURE_CODES.contains(&value.error.as_str()) {
                json!({"failed": true, "error": value.error})
            } else {
                json!({"failed": true})
            }
        }
        SelfDispatchOutcome::AgentDefinitionPut(value) => {
            json!({"id":value.id.to_hex(),"disposition":value.disposition.as_str()})
        }
        SelfDispatchOutcome::AgentSpawn(value) => {
            use crate::code_run::{AgentSpawnKind, AgentSpawnOutput, SelfAgentSpawnResult};
            let spawn = match value {
                SelfAgentSpawnResult::Queued { attempt_ref } => AgentSpawnOutput::Queued {
                    kind: AgentSpawnKind::AgentSpawn,
                    attempt: crate::entity_id::bytes_to_hex_lower(attempt_ref.as_bytes()),
                },
                SelfAgentSpawnResult::ProposedWiden { proposal_ref } => {
                    AgentSpawnOutput::ProposedWiden {
                        kind: AgentSpawnKind::AgentSpawn,
                        proposal: proposal_ref.clone(),
                    }
                }
            };
            json!({ "output": spawn })
        }
        // The bare `ask` and `wait` answer their rows' outputs, as their host
        // doors do. A wait that would stay pending parks instead, so it
        // answers `waitId`, never `Pending`.
        SelfDispatchOutcome::TaskAsk(receipt) => json!({ "output": receipt }),
        SelfDispatchOutcome::TaskAskStatus(value) => {
            use crate::task_verb::{TaskAskStatus, TaskAskWait};
            let wait = match value {
                TaskAskStatus::Pending { .. } => {
                    return Err(failure("a code-mode wait parks rather than answer pending"));
                }
                TaskAskStatus::Changed { voided, generation } => TaskAskWait::Changed {
                    voided: voided.clone(),
                    generation: *generation,
                },
                TaskAskStatus::Settled(result) => TaskAskWait::Ready(result.clone()),
            };
            json!({ "output": wait })
        }
        SelfDispatchOutcome::Speech(value) => {
            json!({"order":value.order,"isVisible":value.is_visible})
        }
        SelfDispatchOutcome::ReportBlocked { receipt } => {
            json!({"receipt":receipt.to_hex()})
        }
        SelfDispatchOutcome::InferenceDefaults(json) => json!({"json": json}),
        SelfDispatchOutcome::Fold(json) => {
            let output: Value =
                serde_json::from_str(json).map_err(|_| failure("fold answer is not JSON"))?;
            json!({ "output": output })
        }
        SelfDispatchOutcome::ReaderSpawn(receipt) => json!({ "output": receipt }),
        SelfDispatchOutcome::ReaderReport(receipt) => json!({ "output": receipt }),
        SelfDispatchOutcome::TaskWaitSet(result) => json!({ "output": result }),
        SelfDispatchOutcome::Summarize(reply) => json!({ "output": reply.output() }),
        SelfDispatchOutcome::Leader(json) => {
            let output: Value =
                serde_json::from_str(json).map_err(|_| failure("leader answer is not JSON"))?;
            json!({ "output": output })
        }
        SelfDispatchOutcome::Team(answer) => json!({ "output": answer }),
        SelfDispatchOutcome::TeamSubmitted(answer) => json!({ "output": answer }),
        SelfDispatchOutcome::Context(_) => {
            return Err(failure("context is not a linked component import"));
        }
        SelfDispatchOutcome::WakePolicyWritten(_) => {
            return Err(failure(
                "owner policy actions are not linked component imports",
            ));
        }
    })
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

/// What a step returns beside its streamed result: whether it finished. A
/// component that does not stream may still return its observation and
/// files here.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Output {
    done: bool,
    #[serde(default)]
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

/// Takes one frame of the step's streamed result: into the host's body
/// store, or held for the step's outcome when the host keeps none. A file
/// frame must name a file under `/mnt/outputs`.
pub(super) fn output(bridge: &mut Bridge<'_>, target: StreamTarget, frame: Vec<u8>) -> Result<u64> {
    if frame.len() > bridge.message_bytes {
        return Err(failure("streamed output frame exceeds the message limit"));
    }
    let target = match target {
        StreamTarget::File(path) => {
            let path = SandboxVirtualPath::try_new(&path)?;
            if path.mount() != crate::code_sandbox::SandboxMount::Outputs {
                return Err(failure("component output must be under /mnt/outputs"));
            }
            StreamTarget::File(path.as_str().to_owned())
        }
        other => other,
    };
    let len = frame.len() as u64;
    if !bridge.host.write_output(target.stream(), &frame)? {
        bridge.held.take(target, frame, bridge.held_limit)?;
    }
    Ok(len)
}

pub(super) fn decode_output(output: &str, limit: usize) -> Result<JsCodeModeStepOutcome> {
    if output.len() > limit {
        return Err(crate::Error::InvalidConfig(format!(
            "component output is {} bytes, past the {limit}-byte step message limit \
             (ComponentBudget.message_bytes)",
            output.len()
        )));
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

#[cfg(test)]
#[test]
fn ask_and_wait_bridge_decode_the_engine_spec_without_guest_host_fields() {
    let id = EntityId::now();
    let spec = crate::task_verb::TaskAskSpec::shorthand(
        None,
        crate::task_verb::TaskAskQuestion::new(crate::task_verb::ConsultPayloadRef::Turn(id)),
        Some(100),
        crate::task_verb::TaskAskDefault::Hold,
    );
    let input = serde_json::to_string(&spec).unwrap();
    assert_eq!(
        self_call("tasks.ask", &input, 1).unwrap(),
        SelfCall::TasksAsk(Box::new(spec))
    );
    let handle = crate::task_verb::TaskAskHandle { group_ref: id };
    assert_eq!(
        self_call("tasks.wait", &serde_json::to_string(&handle).unwrap(), 1).unwrap(),
        SelfCall::TasksWait(handle)
    );
    assert!(
        self_call(
            "tasks.wait",
            &json!({"group_ref": id.to_hex(), "step_key": "guest"}).to_string(),
            1
        )
        .is_err()
    );
    let mut forged: Value = serde_json::from_str(&input).unwrap();
    forged["actor"] = Value::from(id.to_hex());
    assert!(self_call("tasks.ask", &forged.to_string(), 1).is_err());
}

#[cfg(test)]
#[test]
fn owner_policy_action_is_unreachable_from_the_guest_imports() {
    assert!(self_call("dreamer.wake_policy.set", "{}", 1).is_err());
    let reply = SelfDispatchResponse {
        outcome: SelfDispatchOutcome::WakePolicyWritten(crate::dreamer_wake::DreamerWakePolicy {
            wake_grain_turns: 1,
            agent_cadence: serde_json::from_str::<crate::dreamer_wake::DreamerWakePolicy>(
                include_str!("../../dreamer_wake/wake_policy_defaults.json"),
            )
            .expect("shipped wake policy")
            .agent_cadence,
            new_records: 50,
            longest_wait_secs: 28_800,
            nightly_secs: 86_400,
            idle_secs: 1,
            quiet_weave_secs: 3_600,
            weave_recipe_priority: crate::dreamer_wake::WeaveRecipePriority::BeforeConnectorEvent,
        }),
        budget: None,
        view: None,
    };
    assert!(response(reply).is_err());
}

#[cfg(test)]
#[test]
fn recoverable_reply_respects_encoded_wire_limit_without_losing_bytes() {
    let source = (0..2048)
        .map(|i| [227_u8, 129, 130][i % 3])
        .collect::<Vec<_>>();
    let path = "/mnt/outputs/.oneiron-context-ref/0/hash/2048/chunk/0";
    let mut restored = Vec::new();
    while restored.len() < source.len() {
        let end = restored
            .len()
            .saturating_add(RECOVERABLE_TEST_CHUNK)
            .min(source.len());
        let reply = bounded_recoverable_reply(path, &source[restored.len()..end], 300)
            .expect("at least one encoded byte fits");
        assert!(reply.len() <= 300, "the whole framed reply fits");
        let body: serde_json::Value = serde_json::from_str(&reply).expect("wire JSON");
        let bytes = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(body["base64"].as_str().expect("base64 field"))
                .expect("base64 bytes")
        };
        assert!(!bytes.is_empty());
        restored.extend(bytes);
    }
    assert_eq!(restored, source);
}

#[cfg(test)]
const RECOVERABLE_TEST_CHUNK: usize = 64 * 1024;
