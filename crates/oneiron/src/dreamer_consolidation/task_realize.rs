//! A Dreamer-lane TASK's realization: the one row `tasks.create` queues for
//! a TASK routed to the Dreamer. Its lease took the TASK on the highway at
//! admission. One durable model step answers the TASK's spec and brief with
//! the host's wording, or the catalogue's own (`dreamer.task_realize`); the
//! answer lands as one research NOTE the Dreamer authors, in linked parts
//! past the NOTE body bound, and the row's result names it (its first part).
//! Completing the row then reports the TASK Done, under its brief's own
//! judgment.
//!
//! A briefed TASK's realization is also asked for its confession (OF-544)
//! against the brief's done-means: the answer ends with it, and the wake
//! driver reads it back from the stored answer and seals it once the try
//! has closed.
//!
//! The engine ships the wording, so a Dreamer-lane TASK realizes out of the
//! box; it parks only on a host that lends no Dreamer model.

use super::confession::{confession_ask, parse_confession};
use super::step_charge::StepChargeTally;
use crate::attempt_queue::{AttemptQueue, AttemptRecord, AttemptResultRef, SetAttemptResult};
use crate::dreamer_runner::{
    DREAMER_TASK_REALIZE_ATTEMPT_KIND, DreamerAdmittedAttempt, DreamerParkCause,
};
use crate::dreamer_wake::{
    DREAMER_HARD_CUT_PARK_REASON, DreamerAttemptExecution, WakeAttemptContext,
};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::learning::TypeRef;
use crate::llm::manifest::ModelRole;
use crate::llm::{
    BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart, DurableStepContext,
    DurableStepError, HostInferenceContext, LlmBackend, LlmMessage, LlmMessageRole, LlmRequest,
    LlmResponse, ModelId, ModelTierRef, ResponseFormat, StepOutcome, TierPrecedence,
    call_as_step_checked,
};
use crate::self_heal::audit::AttemptConfession;
use crate::task_verb::QueueTaskBrief;
use crate::{Vault, WriteActor};
use std::collections::BTreeMap;

/// Why a TASK's realization parks on a host that lends no Dreamer model.
pub const TASK_REALIZE_UNLENT_PARK_REASON: &str = "task realization needs a lent Dreamer model";

/// The NOTE kind an answer lands as: vault-readable and durable.
const RESULT_NOTE_KIND: &str = "research";

/// What the host lends a TASK's realization.
pub struct TaskRealizeModel<'a> {
    pub backend: &'a dyn LlmBackend,
    pub guard: &'a BudgetGuard,
    pub model: ModelId,
    pub inference: HostInferenceContext<'a>,
    /// The Dreamer role whose route the step runs on.
    pub role: ModelRole,
    /// The Dreamer, who authors the NOTE.
    pub actor: WriteActor,
    /// The host's wording, else
    /// [`TASK_REALIZE_INSTRUCTION`](crate::llm::decision::catalogue::TASK_REALIZE_INSTRUCTION).
    pub instruction: &'a str,
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("task realization: {reason}"))
}

/// Why a realization's reply is refused: it holds no answer.
const EMPTY_ANSWER: &str = "the model wrote an empty answer";

/// A realization's answer, trimmed. The step's check and the landing read it
/// alike (FIX 7431).
fn realize_answer(response: &LlmResponse) -> std::result::Result<String, &'static str> {
    let answer = super::step_charge::reply_text(response);
    let answer = answer.trim();
    if answer.is_empty() {
        Err(EMPTY_ANSWER)
    } else {
        Ok(answer.to_owned())
    }
}

/// The step's check on a realization's reply (FIX 7431): an empty answer is
/// refused inside the step, paid and never memoized, so its Retry asks again.
fn check_realize_reply(response: &LlmResponse) -> std::result::Result<(), String> {
    realize_answer(response).map(|_| ()).map_err(str::to_owned)
}

/// Realizes one TASK: asks the lent model with the instruction, the TASK's
/// spec and its brief, writes the answer as one research NOTE under the
/// Dreamer's stamp, and names that NOTE as the row's result. An answer past
/// the NOTE body bound lands in ordered parts, each continuation linked
/// `Mentions` to the first, as an imported note's parts are; the result
/// names the first. A brief's objectives are asked for a confession after
/// the answer. A replay after the result was attached writes nothing; a TASK
/// cancelled or settled since it was queued is owed nothing.
pub async fn run_task_realize(
    attempt: &DreamerAdmittedAttempt,
    ctx: &WakeAttemptContext<'_>,
    model: TaskRealizeModel<'_>,
) -> Result<DreamerAttemptExecution> {
    let record = &attempt.status.attempt;
    if record.kind != DREAMER_TASK_REALIZE_ATTEMPT_KIND {
        return Err(invalid("not a TASK realization"));
    }
    if record.result_ref.is_some() {
        return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
    }
    let Some((task, brief)) =
        crate::task_verb::highway_runner::runner_task_brief(ctx.vault, record)?
    else {
        return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
    };
    let spec =
        serde_json::to_string_pretty(&crate::msgpack_value_to_json(&attempt.status.payload.input))
            .map_err(|_| invalid("the spec is not JSON"))?;
    let mut text = format!(
        "Task: {}\n\n## Spec\n\n```json\n{spec}\n```\n",
        task.to_hex()
    );
    let objectives = brief.as_ref().map(brief_objectives).unwrap_or_default();
    if let Some(brief) = brief {
        let brief =
            serde_json::to_string_pretty(&brief).map_err(|_| invalid("the brief is not JSON"))?;
        text.push_str(&format!("\n## Brief\n\n```json\n{brief}\n```\n"));
    }
    let locality = model
        .inference
        .selected_locality()
        .ok_or_else(|| invalid("the host binding names no locality"))?;
    let mut request = LlmRequest {
        model: model.model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: crate::llm::Scope::default(),
            // The TASK's spec and brief leave the vault as an extraction's
            // records do, so they pass the same egress gate.
            purpose: CallPurpose::Extraction,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Extraction,
                ModelTierRef("consolidation".into()),
            ),
            response_format: ResponseFormat::Text,
            locality,
        }
        .with_purpose_defaults(),
        messages: vec![
            LlmMessage {
                role: LlmMessageRole::System,
                content: vec![ContentPart::Text {
                    text: model.instruction.to_owned(),
                }],
            },
            LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text { text }],
            },
        ],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    };
    if !objectives.is_empty() {
        request.messages.push(LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: confession_ask(&objectives),
            }],
        });
    }
    let mut request = ctx
        .vault
        .authorize_model_role(model.role, request, &model.inference)?
        .into_request();
    super::roles::bind_reasoning(ctx.vault, model.backend, &mut request)?;
    let step_hash = request
        .canonical_hash()
        .map_err(|_| invalid("the request did not hash"))?;
    let step_ctx = DurableStepContext {
        vault: ctx.vault,
        attempt_id: record.id,
        run_id: record.run_id.clone(),
        envelope_actor: model.actor,
        subject: task,
        deadline: Some(ctx.deadline),
        now_ms: ctx.now_ms,
    };
    let mut charges = StepChargeTally::default();
    let response = match call_as_step_checked(
        &step_ctx,
        model.backend,
        model.guard,
        request,
        &check_realize_reply,
    )
    .await
    {
        Ok(StepOutcome::Finished { response, .. }) => {
            charges.record_terminal(ctx.vault, record.id, step_hash, &response.usage)?;
            response
        }
        Ok(StepOutcome::Trapped { .. }) => {
            return Ok(DreamerAttemptExecution::Park {
                reason: "durable step trapped for resume".to_owned(),
                cause: DreamerParkCause::Signal,
            });
        }
        Err(DurableStepError::SpentFinalizeRefused { usage }) => {
            charges.record_usage(&usage);
            return Ok(charges.checkpoint());
        }
        Err(DurableStepError::DeadlineHardCut) => {
            return Ok(DreamerAttemptExecution::Park {
                reason: DREAMER_HARD_CUT_PARK_REASON.to_owned(),
                cause: DreamerParkCause::Checkpoint,
            });
        }
        Err(DurableStepError::FinalizeRefused) => {
            return Ok(DreamerAttemptExecution::Park {
                reason: "wake pass finalize window".to_owned(),
                cause: DreamerParkCause::Checkpoint,
            });
        }
        // An empty answer the check refused was paid and never memoized: it
        // is asked again after its retry delay (FIX 7431).
        Err(DurableStepError::SpentSchemaValidation { usage, errors, .. }) => {
            charges.record_usage(&usage);
            return Ok(charges.park_for(&errors.join("; "), DreamerParkCause::Retry));
        }
        Err(DurableStepError::Engine(error)) => return Err(error),
        Err(other) => {
            return Ok(DreamerAttemptExecution::Park {
                reason: other.to_string(),
                cause: DreamerParkCause::of_step(&other),
            });
        }
    };
    if ctx.deadline.expired() {
        return Ok(charges.checkpoint());
    }
    let answer = match realize_answer(&response) {
        Ok(answer) => answer,
        // Only a memo stored before the check can be empty: it goes, and the
        // Retry asks again (FIX 7431, OF-193a).
        Err(reason) => return charges.park_refused_reply(ctx.vault, record.id, step_hash, reason),
    };
    let answer = answer.as_str();
    let mut notes = Vec::new();
    for part in super::note_parts::parts(answer, crate::note::MAX_NOTE_BYTES) {
        notes.push(
            ctx.vault
                .create_note(RESULT_NOTE_KIND, part, model.actor)
                .map_err(|error| invalid(&format!("result note: {error}")))?,
        );
    }
    let (&note, continuations) = notes
        .split_first()
        .ok_or_else(|| invalid("the answer landed no note"))?;
    if !continuations.is_empty() {
        ctx.vault
            .try_with_actor_content_write_txn(model.actor, |content| {
                let mut batch = ctx.vault.batch_in();
                for part in continuations {
                    batch = batch.edge(part, EdgeKind::Mentions, &note, 1.0);
                }
                content.apply_batch(batch)
            })?;
    }
    AttemptQueue::new(ctx.vault).set_result(SetAttemptResult {
        id: record.id,
        lease_owner: record.lease_owner.clone().unwrap_or_default(),
        attempt_count: record.attempt_count,
        result_ref: AttemptResultRef::new(note.to_hex())?,
        now: ctx.now_ms / 1_000,
    })?;
    Ok(DreamerAttemptExecution::Completed {
        completed_units: charges.units,
    })
}

/// The objectives a realization confesses against (OF-544): its brief's
/// done-means, named as every TASK run's are.
fn brief_objectives(brief: &QueueTaskBrief) -> Vec<String> {
    brief.confession_objectives()
}

/// The confession a realization's stored answer makes against its brief's
/// objectives (OF-544), read while its TASK is still open, before Done
/// settles it. The subject is the Dreamer that authored the answer; the type
/// is the brief's placement, as the TASK's lifecycle receipts read it. `None`
/// when `admitted` is no realization with a result, its TASK is no longer
/// the runner's or has no brief, or the answer confesses nothing that
/// parses: a confession is never made up.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn task_realize_confession(
    vault: &Vault,
    admitted: &AttemptRecord,
) -> Result<Option<AttemptConfession>> {
    if admitted.kind != DREAMER_TASK_REALIZE_ATTEMPT_KIND {
        return Ok(None);
    }
    // The admitted row predates its result: read the row as it is now.
    let Some(record) = AttemptQueue::new(vault).get(admitted.id)? else {
        return Ok(None);
    };
    let Some(note) = record
        .result_ref
        .as_ref()
        .and_then(|result| EntityId::from_hex(result.as_str()).ok())
    else {
        return Ok(None);
    };
    let Some((_, Some(brief))) =
        crate::task_verb::highway_runner::runner_task_brief(vault, &record)?
    else {
        return Ok(None);
    };
    let objectives = brief_objectives(&brief);
    if objectives.is_empty() {
        return Ok(None);
    }
    let Some((author, answer)) = stored_answer(vault, note)? else {
        return Ok(None);
    };
    let Some(objectives) = parse_confession(answer.as_bytes(), &objectives) else {
        return Ok(None);
    };
    let Some(type_ref) = brief_type_ref(vault, &brief)? else {
        tracing::warn!(
            attempt = ?record.id,
            "a TASK realization's confession has no placed type; it is not sealed"
        );
        return Ok(None);
    };
    Ok(Some(AttemptConfession {
        attempt: record.id,
        subject: author,
        type_ref,
        objectives,
    }))
}

/// Seals a realization's confession in the write that closes its try
/// (OF-544), after the try is terminal there, so no crash can leave a
/// completed realization unsealed. The seal writes in its own savepoint: a
/// refusal rolls back alone, is logged, and the completed work stands.
///
/// # Errors
///
/// Storage errors opening or committing the savepoint.
pub(crate) fn seal_task_realize_confession_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    confession: &AttemptConfession,
    now: u64,
) -> Result<()> {
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    match vault.record_attempt_confession_in_txn(&mut savepoint, confession, now) {
        Ok(_) => savepoint.commit()?,
        Err(error) => tracing::warn!(
            kind = ?error.kind(),
            attempt = ?confession.attempt,
            "a TASK realization's confession was not sealed"
        ),
    }
    Ok(())
}

/// A realization's answer as it was stored, whole: its result NOTE, then
/// each continuation part its author linked `Mentions` to it, in the order
/// they were written (ids ascend), beside the Dreamer that authored it.
/// `None` when the result is no readable NOTE, or its author was erased: no
/// one is no Dreamer, so no answer is bound to them (FIX 6072).
fn stored_answer(vault: &Vault, note: EntityId) -> Result<Option<(EntityId, String)>> {
    let Some(crate::note::NoteBody {
        kind,
        author_ref,
        markdown: mut answer,
        ..
    }) = vault.read_note(&note)?
    else {
        return Ok(None);
    };
    let Some(author_ref) = author_ref.id() else {
        return Ok(None);
    };
    for part in vault.sources(
        &note,
        EdgeKind::Mentions,
        Some(crate::registry::ENTITY_TYPE_NOTE),
    )? {
        if part <= note {
            continue;
        }
        if let Some(body) = vault.read_note(&part)?
            && body.author_ref.is(author_ref)
            && body.kind == kind
        {
            answer.push_str(&body.markdown);
        }
    }
    Ok(Some((author_ref, answer)))
}

/// The TASK's placement as its lifecycle receipts read it (OF-543): the
/// brief's type node in its project's tree, at the brief's version. `None`
/// when that tree holds no such node.
fn brief_type_ref(vault: &Vault, brief: &QueueTaskBrief) -> Result<Option<TypeRef>> {
    let txn = vault.store.env.read_txn()?;
    let tree = crate::agent_dispatch::load_team_type_tree_in_txn(vault, &txn, brief.project_ref)?;
    Ok(tree.node_by_entity(brief.type_ref.node_id).map(|node| {
        TypeRef::from(&crate::task_type::TaskTypeRef::new(
            node.node_id.clone(),
            brief.type_ref.tree_version,
        ))
    }))
}
