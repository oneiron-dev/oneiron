use rmpv::Value;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::facade::{FACADE_CODE_INVALID_STATE, FacadeError, FacadeResult};
use crate::human_task::HumanTaskError;

use super::consult_payload::{ConsultPayload, ConsultPayloadRef};
use super::consult_result::TaskVerbBody;
use super::create_spec::TaskCreateSpec;
use super::terminal_state::TaskTerminalDisposition;
use super::verb_kind::{TaskAssignee, TaskKind, TaskTtl};
use super::wire_decode::{task_verb_body, task_verb_body_in};
use super::wire_encode::{consult_payload_value, task_assignee_value};

pub(super) fn task_create_proposal_value(spec: &TaskCreateSpec, now: u64) -> Value {
    Value::Map(vec![
        (Value::from("spec"), spec.spec.clone()),
        (
            Value::from("label"),
            spec.label.clone().map_or(Value::Nil, Value::from),
        ),
        (
            Value::from("owner_ref"),
            spec.owner_ref
                .map_or(Value::Nil, |owner| Value::from(owner.to_hex())),
        ),
        // The typed shape travels WITH the proposal: an approved consult
        // proposal must replay as a consult, never silently as a standard task.
        (
            Value::from("kind"),
            spec.kind
                .map_or(Value::Nil, |kind| Value::from(kind.as_str())),
        ),
        (
            Value::from("assignee"),
            spec.assignee.map_or(Value::Nil, task_assignee_value),
        ),
        (
            Value::from("consult"),
            spec.consult
                .as_ref()
                .map_or(Value::Nil, consult_payload_value),
        ),
        (
            Value::from("ttl"),
            spec.ttl.map_or(Value::Nil, |ttl| {
                Value::Map(vec![(
                    Value::from("deadline_at"),
                    Value::from(ttl.deadline_at),
                )])
            }),
        ),
        (Value::from("created_at"), Value::from(now)),
    ])
}

/// The settled typed shape of one `tasks.create`. Producing this value is the
/// only door to a TASK write, so an invalid combination can never reach one.
pub(super) struct ValidatedTaskCreate {
    pub(super) kind: TaskKind,
    pub(super) assignee: Option<TaskAssignee>,
    pub(super) consult: Option<ConsultPayload>,
    pub(super) ttl: Option<TaskTtl>,
    pub(super) spec: Value,
}

/// Settles `(kind, consult, assignee, ttl)` into one legal shape.
///
/// Two branches: a peer-addressed consult with a typed payload, a future
/// deadline and a `Nil` spec (ONE-1699); and a standard task on any routable
/// assignee (ONE-1700). Every assignee binds to a live entity of the right kind
/// HERE, before the write transaction opens, so a dangling or unroutable
/// assignee leaves no partial task behind.
pub(super) fn validate_task_create(
    vault: &Vault,
    spec: &TaskCreateSpec,
    now: u64,
) -> FacadeResult<ValidatedTaskCreate> {
    match (
        spec.kind.unwrap_or(TaskKind::Standard),
        &spec.consult,
        &spec.assignee,
        &spec.ttl,
    ) {
        (
            TaskKind::Consult,
            Some(payload),
            Some(assignee @ TaskAssignee::Peer { .. }),
            Some(ttl),
        ) if spec.spec == Value::Nil => {
            if ttl.deadline_at <= now {
                return Err(FacadeError::bad_request(
                    "a consult deadline must be in the future",
                ));
            }
            payload.validate()?;
            assignee.validate(vault)?;
            for payload_ref in
                std::iter::once(payload.question_ref).chain(payload.context_refs.iter().copied())
            {
                require_resolved_payload_ref(vault, payload_ref)?;
            }
            Ok(ValidatedTaskCreate {
                kind: TaskKind::Consult,
                assignee: Some(*assignee),
                consult: Some(payload.clone()),
                ttl: Some(*ttl),
                spec: Value::Nil,
            })
        }
        (TaskKind::Standard, None, assignee, ttl) => {
            if let Some(assignee) = assignee {
                // A human assignee binds to a live entity HERE like every other
                // lane; whether that person has a NATIVE route is settled
                // inside the create transaction, so a known-but-unreachable
                // person rolls the whole create back instead of leaving a human
                // task nothing is tracking.
                assignee.validate(vault)?;
            }
            Ok(ValidatedTaskCreate {
                kind: TaskKind::Standard,
                assignee: *assignee,
                consult: None,
                ttl: *ttl,
                spec: spec.spec.clone(),
            })
        }
        _ => Err(FacadeError::bad_request("invalid typed task shape")),
    }
}

/// A typed ref must still name a live entity of its declared kind at write
/// time: `ConsultPayloadRef::parse` binds caller strings, but the enum can also
/// be constructed directly.
pub(super) fn require_resolved_payload_ref(
    vault: &Vault,
    payload_ref: ConsultPayloadRef,
) -> FacadeResult<()> {
    if vault.get_entity_type(&payload_ref.entity_ref())? == Some(payload_ref.entity_type()) {
        Ok(())
    } else {
        Err(FacadeError::bad_request(
            "consult ref does not resolve to an entity of its declared kind",
        ))
    }
}

pub(super) fn require_resolved_entity(vault: &Vault, entity_ref: EntityId) -> FacadeResult<()> {
    if vault.get_entity_type(&entity_ref)?.is_some() {
        Ok(())
    } else {
        Err(FacadeError::from(Error::EntityNotFound))
    }
}

/// The one local-realization dedupe key per TASK, shared by both local lanes so
/// a retried route returns the existing attempt instead of minting a second.
pub(super) fn task_route_dedupe_key(task_ref: EntityId) -> String {
    format!("task:{}", task_ref.to_hex())
}

/// Surfaces a native-human routing refusal in its own name. A person the vault
/// knows but cannot currently reach is NOT a missing entity and NOT a reason to
/// fall through to Dreamer realization — the TASK simply does not get created,
/// and the caller is told which of the two it was.
pub(super) fn human_route_refusal(error: HumanTaskError) -> FacadeError {
    match error {
        HumanTaskError::Engine(error) => FacadeError::from(error),
        HumanTaskError::NotAPerson => consult_refusal(
            FACADE_CODE_INVALID_STATE,
            "a human assignee must be a person",
            "Assign the task to the dreamer, an agent definition, or a peer actor.",
        ),
        HumanTaskError::NotNativelyReachable => consult_refusal(
            FACADE_CODE_INVALID_STATE,
            "known person is not currently reachable through a native route",
            "Connect a channel this person is reachable on, then assign the task.",
        ),
        // Belongs to the response half of the module and cannot arise from
        // route resolution; it is still spelled out rather than folded into a
        // neighbouring message that would misreport what happened.
        HumanTaskError::UnboundResponse => consult_refusal(
            FACADE_CODE_INVALID_STATE,
            "human response does not match its wait binding",
            "Signal the response against the binding that names this task, person, and step.",
        ),
    }
}

/// `FacadeError::new` is private to the facade module and no `Error` variant
/// carries these refusals, so the typed shape is built from its public fields.
pub(super) fn consult_refusal(code: &str, message: &str, suggestion: &str) -> FacadeError {
    FacadeError {
        code: code.to_owned(),
        message: message.to_owned(),
        suggestions: vec![suggestion.to_owned()],
        successor_short_id: None,
    }
}

/// Reads one typed TASK body of any kind inside a live transaction.
pub(super) fn task_body_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    task_ref: EntityId,
) -> FacadeResult<TaskVerbBody> {
    task_verb_body_in(vault, rtxn, task_ref)?
        .ok_or_else(|| FacadeError::from(Error::EntityNotFound))
}

/// Reads one NON-consult TASK body inside a live transaction.
///
/// The general result door routes through here so a consult can never settle
/// through it: a consult's terminal record must carry the ONE-1699
/// evidence-or-abstention summary, and the general input has no way to express
/// one. Sending a consult back to its own door keeps that contract the only
/// path to a terminal consult, rather than one of two.
pub(super) fn standard_body_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    task_ref: EntityId,
) -> FacadeResult<TaskVerbBody> {
    let body = task_body_in_txn(vault, rtxn, task_ref)?;
    if body.task_kind() == TaskKind::Consult {
        return Err(consult_refusal(
            FACADE_CODE_INVALID_STATE,
            "a consult settles through the consult result door, not the general one",
            "Land the answer or reasoned abstention with land_consult_result.",
        ));
    }
    Ok(body)
}

/// Reads one TASK body as a consult inside a live transaction.
pub(super) fn consult_body_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    task_ref: EntityId,
) -> FacadeResult<TaskVerbBody> {
    let body = task_body_in_txn(vault, rtxn, task_ref)?;
    if body.task_kind() != TaskKind::Consult {
        return Err(FacadeError::bad_request("target task is not a consult"));
    }
    Ok(body)
}

/// The PERSON one TASK is assigned to, or `None` on every other lane. The
/// follow-up cursor is derived state, so this is how a lost cursor is rebuilt
/// from the authoritative synced fact.
pub(crate) fn task_human_assignee(vault: &Vault, task_ref: EntityId) -> Result<Option<EntityId>> {
    Ok(
        task_verb_body(vault, task_ref)?.and_then(|body| match body.assignee {
            Some(TaskAssignee::Human { actor_ref }) => Some(actor_ref),
            None
            | Some(
                TaskAssignee::Dreamer | TaskAssignee::AgentDef { .. } | TaskAssignee::Peer { .. },
            ) => None,
        }),
    )
}

/// Whether this replica has settled the TASK. The C9 peer-result signal reads
/// it as its no-early-resume guard: a queued or working delegation has nothing
/// to resume on.
pub(crate) fn task_is_terminal(vault: &Vault, task_ref: EntityId) -> Result<bool> {
    Ok(task_verb_body(vault, task_ref)?
        .and_then(|body| body.state)
        .is_some_and(|state| state.terminal().is_some()))
}

/// The ONE-1709 PACKET_AMEND carve-out: a READ-ONLY settled-result query the
/// `contextFrom` validator in `context_projection.rs` consumes. This is the
/// reverse of the pre-settlement window: `land_task_result` /
/// `land_consult_result` resolve the caller-supplied artifact BEFORE the
/// terminal write, so a durable artifact never proved settlement. This query
/// answers the settled question directly — the TASK must be terminal HERE
/// with a terminal `result_ref` — and the consumer additionally requires a
/// `Completed` disposition plus same-parent/run lineage, so nothing unbound
/// is ever admitted. `None` on every other door: a missing row, a non-TASK
/// row, an unsettled TASK, or a terminal TASK without a result ref.
pub(crate) fn settled_task_result_binding(
    vault: &Vault,
    task_ref: EntityId,
) -> Result<Option<(TaskTerminalDisposition, EntityId)>> {
    Ok(task_verb_body(vault, task_ref)?
        .and_then(|body| body.terminal().cloned())
        .and_then(|terminal| {
            terminal
                .result_ref
                .map(|result_ref| (terminal.disposition, result_ref))
        }))
}
