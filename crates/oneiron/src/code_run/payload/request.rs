//! Canonical request values used by code-run replay.
//! Entry: `self_call_request_value`.
//! Call definitions belong to `code_run::types`; `payload` forwards the entry at its old path.

use super::*;

pub(super) const CODE_RUN_REPLAY_CANONICAL_REQUEST_ACTOR: [u8; 16] = [0x42; 16];

pub(in crate::code_run) fn self_call_request_value(call: &SelfCall) -> Result<Value> {
    Ok(match call {
        SelfCall::AgentsSpawn(call) => super::coordination_codec::spawn_request(call)?,
        SelfCall::AgentsPut(call) => request_map(vec![
            ("id", entity_id_value(call.id)),
            (
                "definition",
                Value::Binary(crate::agent_def::encode_agent_definition(&call.definition)?),
            ),
            ("occurred_start", Value::from(call.occurred.start)),
            ("occurred_end", Value::from(call.occurred.end)),
            ("learned_at", Value::from(call.learned_at)),
        ]),
        SelfCall::TasksAsk(call) => super::coordination_codec::ask_request(call)?,
        SelfCall::TasksWait(handle) => {
            request_map(vec![("handle", entity_id_value(handle.group_ref))])
        }
        SelfCall::TasksRefuse(call) => request_map(vec![
            (
                "task_ref",
                call.task_ref.map_or(Value::Nil, entity_id_value),
            ),
            ("domain", Value::from(call.domain.as_str())),
            ("reason_ref", Value::from(call.reason_ref.as_str())),
            ("at", Value::from(call.at)),
        ]),
        SelfCall::ConsultResult(request) => request_map(vec![(
            "call",
            Value::from(
                serde_json::to_string(request)
                    .map_err(|_| invalid_code_run_replay("consult landing does not encode"))?,
            ),
        )]),
        SelfCall::SkillsCall(call) => request_map(vec![
            ("skill", entity_id_value(call.skill)),
            ("args", Value::from(call.args.to_string())),
        ]),
        SelfCall::AgentVerb(call) => request_map(vec![
            ("verb", Value::from(call.verb.as_str())),
            ("input", Value::from(call.input.to_string())),
        ]),
        SelfCall::ConnectorAnswer(request) => request_map(vec![(
            "call",
            Value::from(
                serde_json::to_string(request)
                    .map_err(|_| invalid_code_run_replay("connector answer does not encode"))?,
            ),
        )]),
        SelfCall::WorldPrivacySet(input) => {
            request_map(vec![(
                "call",
                Value::from(serde_json::to_string(input).map_err(|_| {
                    invalid_code_run_replay("world privacy request does not encode")
                })?),
            )])
        }
        // The closed request, TASK and workflow included; its parent, actor
        // and run are the host's.
        SelfCall::WorkflowDispatch(request) => request_map(vec![(
            "call",
            Value::from(
                serde_json::to_string(request)
                    .map_err(|_| invalid_code_run_replay("workflow dispatch does not encode"))?,
            ),
        )]),
        // The run repo row and its closed input; the binding is the host's.
        SelfCall::Repo(call) => repo_request_value(call)?,
        SelfCall::MemorySearch(call) => request_map(vec![
            ("query", Value::from(call.query.as_str())),
            ("limit", Value::from(call.limit as u64)),
        ]),
        SelfCall::MemoryWriteFixture(call) => request_map(vec![
            ("id", entity_id_value(call.id)),
            ("candidate", claim_candidate_request_value(&call.candidate)?),
            ("occurred_start", Value::from(call.occurred.start)),
            ("occurred_end", Value::from(call.occurred.end)),
            ("learned_at", Value::from(call.learned_at)),
        ]),
        SelfCall::MemoryPutClaim(call) => request_map(vec![
            ("id", entity_id_value(call.id)),
            ("candidate", claim_candidate_request_value(&call.candidate)?),
            ("occurred_start", Value::from(call.occurred.start)),
            ("occurred_end", Value::from(call.occurred.end)),
            ("learned_at", Value::from(call.learned_at)),
        ]),
        SelfCall::MemorySupersedeClaim(call) => request_map(vec![
            ("new_id", entity_id_value(call.new_id)),
            ("old_id", entity_id_value(call.old_id)),
            ("now", Value::from(call.now)),
        ]),
        SelfCall::MemoryPutEdge(call) => request_map(vec![
            ("src", entity_id_value(call.src)),
            ("kind", Value::from(call.kind as u8)),
            ("tgt", entity_id_value(call.tgt)),
            ("weight", Value::F32(call.weight)),
        ]),
        SelfCall::InferenceDefaultsRead => request_map(vec![]),
        SelfCall::Fold(call) => request_map(vec![(
            "call",
            Value::from(
                serde_json::to_string(call)
                    .map_err(|_| invalid_code_run_replay("fold call does not encode"))?,
            ),
        )]),
        SelfCall::InferenceDefaultsReplace(json) => {
            request_map(vec![("json", Value::from(json.as_str()))])
        }
        SelfCall::WakePolicyWrite(call) => request_map(vec![(
            "policy",
            Value::from(
                serde_json::to_string(&call.policy)
                    .map_err(|_| invalid_code_run_replay("wake policy does not encode"))?,
            ),
        )]),
        SelfCall::ReportBlocked(call) => request_map(vec![
            ("category", Value::from(call.category.as_str())),
            ("detail", Value::from(call.detail.as_str())),
            ("order", Value::from(call.order)),
            ("occurred_at", Value::from(call.occurred_at)),
        ]),
        SelfCall::Ask(call) => request_map(vec![("prompt", Value::from(call.prompt.as_str()))]),
        SelfCall::DestructiveFixture(call) | SelfCall::OutboundFixture(call) => {
            request_map(vec![("label", Value::from(call.label.as_str()))])
        }
        SelfCall::Context(call) => {
            request_map(vec![("spec", Value::from(context_spec_json(&call.spec)?))])
        }
        SelfCall::Speak(call) | SelfCall::Think(call) | SelfCall::Express(call) => {
            request_map(vec![
                ("text", Value::from(call.text.as_str())),
                ("order", Value::from(u64::from(call.order))),
                ("occurred_at", Value::from(call.occurred_at)),
            ])
        }
        // The guest's call: the source the host bound to it is not the
        // guest's, and a replay resolves it again.
        SelfCall::ReaderSpawn(call) => request_map(vec![
            ("source", Value::from(call.source.as_str())),
            ("ask", Value::from(call.ask.as_str())),
            ("intent_key", Value::from(call.intent_key.as_str())),
        ]),
        SelfCall::ReaderReport(call) => request_map(vec![
            ("task", entity_id_value(call.task)),
            ("result_ref", Value::from(call.result_ref.as_str())),
        ]),
        SelfCall::Team(call) => request_map(vec![(
            "call",
            Value::from(
                serde_json::to_string(call)
                    .map_err(|_| invalid_code_run_replay("team call does not encode"))?,
            ),
        )]),
        // Its own `verb` key keeps a submit apart from a start or a record
        // under the one Team effect.
        SelfCall::TeamSubmit(input) => request_map(vec![
            ("verb", Value::from("submit")),
            (
                "call",
                Value::from(
                    serde_json::to_string(input)
                        .map_err(|_| invalid_code_run_replay("team submit does not encode"))?,
                ),
            ),
        ]),
        SelfCall::TasksWaitSet(call) => request_map(vec![(
            "call",
            Value::from(
                serde_json::to_string(call)
                    .map_err(|_| invalid_code_run_replay("task wait set does not encode"))?,
            ),
        )]),
        // The guest's call: the members the host bound to it are not the
        // guest's, and a replay resolves them again.
        SelfCall::Summarize(call) => summarize_request_value(call),
        SelfCall::Leader(super::SelfLeaderCall::Advice { top }) => request_map(vec![
            ("verb", Value::from("advice")),
            ("top", top.map_or(Value::Nil, Value::from)),
        ]),
        SelfCall::Leader(super::SelfLeaderCall::Pattern { skill }) => request_map(vec![
            ("verb", Value::from("pattern")),
            ("skill", entity_id_value(*skill)),
        ]),
        SelfCall::Leader(super::SelfLeaderCall::Split { leader, slice }) => {
            leader_split_request_value(leader, slice)?
        }
    })
}

/// The request value of a run repo call: its row and its closed input.
fn repo_request_value(call: &crate::code_run::RepoRunCall) -> Result<Value> {
    Ok(request_map(vec![
        ("row", Value::from(call.effect().as_str())),
        (
            "call",
            Value::from(
                serde_json::to_string(call)
                    .map_err(|_| invalid_code_run_replay("run repo call does not encode"))?,
            ),
        ),
    ]))
}

/// The request value of a summarize call: the guest call alone.
fn summarize_request_value(call: &crate::code_run::SelfSummarizeCall) -> Value {
    request_map(vec![(
        "call",
        Value::from(
            serde_json::json!({
                "ref": call.reference,
                "effort": call.effort.map(super::SummarizeEffort::as_str),
                "group": call.group,
                "defer": call.defer,
            })
            .to_string(),
        ),
    )])
}

/// The request value of a leader split call: its leader and its slice.
fn leader_split_request_value(
    leader: &Option<EntityId>,
    slice: &Option<crate::llm::Scope>,
) -> Result<Value> {
    Ok(request_map(vec![
        ("verb", Value::from("split")),
        ("leader", leader.map_or(Value::Nil, entity_id_value)),
        (
            "slice",
            match slice {
                Some(slice) => Value::from(
                    serde_json::to_string(slice)
                        .map_err(|_| invalid_code_run_replay("split slice does not encode"))?,
                ),
                None => Value::Nil,
            },
        ),
    ]))
}

pub(super) fn claim_candidate_request_value(candidate: &ClaimCandidate) -> Result<Value> {
    let envelope = canonical_replay_request_envelope()?;
    // The request value carries the candidate's own scope, never a stamp.
    let body = (*candidate).clone().into_claim_body(
        &envelope,
        crate::claim::substrate_facet_id(envelope.actor().entity_ref())?,
    )?;
    Ok(Value::Map(vec![
        (
            Value::from("predicate"),
            Value::from(body.predicate.as_str()),
        ),
        (Value::from("subject"), Value::Binary(body.subject.encode())),
        (Value::from("value"), body.value.clone()),
        (Value::from("confidence"), Value::F32(body.confidence)),
        (Value::from("salience"), optional_f32_value(body.salience)),
        (
            Value::from("evidence"),
            optional_value(body.evidence.clone()),
        ),
        (
            Value::from("valid_from"),
            optional_u64_value(body.valid_from),
        ),
        (Value::from("valid_to"), optional_u64_value(body.valid_to)),
        (Value::from("world"), optional_entity_value(body.world)),
        (Value::from("scope"), optional_value(body.scope.clone())),
        (Value::from("stale"), Value::Boolean(body.stale)),
    ]))
}

pub(super) fn canonical_replay_request_envelope() -> Result<WriteEnvelope> {
    let actor = EntityId::from_bytes(CODE_RUN_REPLAY_CANONICAL_REQUEST_ACTOR)
        .map_err(|_| invalid_code_run_replay("canonical replay actor id is invalid"))?;
    Ok(WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Agent),
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![(
            Value::from(SELF_PROVENANCE_SURFACE_KEY),
            Value::from("code_run_replay_request"),
        )]))?,
        ClaimApprovalStatus::Proposed,
    ))
}
