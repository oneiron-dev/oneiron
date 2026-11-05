//! Explicit host-Done objective answers, read from their exact settling receipt.

use crate::attempt_queue::{AttemptRecord, AttemptState};
use crate::learning::TypeRef;
use crate::memory::MemoryResult;
use crate::self_heal::audit::{AttemptConfession, ObjectiveConfession};
use crate::{EntityId, Vault};

use super::highway_accept::{Lane, lane_of};
use super::terminal_state::TaskTerminalDisposition;
use super::verb_kind::TaskKind;
use super::{lifecycle_receipt, wire_decode};

pub(super) const FIELD_CONFESSION_STRUCTURED: &str = "confession_structured";
pub(super) const FIELD_HOST_ATTEMPT_COUNT: &str = "host_attempt_count";

/// The runner's frozen confession context, not answers or a capability.
#[derive(Debug, Clone)]
pub struct HostDoneConfessionContext {
    pub subject: EntityId,
    pub type_ref: TypeRef,
    pub objectives: Vec<String>,
}

/// Read only after the real completion, in that completion's writer. Receipt
/// content supplies answers, never the subject, type, executor or attempt.
pub(crate) fn host_done_confession_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &AttemptRecord,
    attempt_count: u32,
    context: &HostDoneConfessionContext,
) -> MemoryResult<Option<AttemptConfession>> {
    if record.state != AttemptState::Completed
        || record.attempt_count != attempt_count
        || context.objectives.is_empty()
    {
        return Ok(None);
    }
    let Some(task_ref) = record
        .task_ref
        .as_deref()
        .and_then(|hex| EntityId::from_hex(hex).ok())
    else {
        return Ok(None);
    };
    let Some(body) = wire_decode::task_verb_body_in(vault, txn, task_ref)? else {
        return Ok(None);
    };
    if body.task_kind() != TaskKind::Standard || lane_of(body.assignee) != Lane::Runner {
        return Ok(None);
    }
    let Some(terminal) = body.terminal() else {
        return Ok(None);
    };
    if terminal.disposition != TaskTerminalDisposition::Completed {
        return Ok(None);
    }
    let Some(result_ref) = terminal.result_ref else {
        return Ok(None);
    };
    let Some(id) = lifecycle_receipt::settled_in(vault, txn, task_ref, terminal.finished_at)?
    else {
        return Ok(None);
    };
    let Some(receipt) = lifecycle_receipt::kept_in(vault, txn, &id)? else {
        return Ok(None);
    };
    let parent = super::highway::attempt_hex(record.id);
    let generation = attempt_count.to_string();
    let task = task_ref.to_hex();
    let result = result_ref.to_hex();
    if receipt.on_behalf_of.as_deref() != Some(parent.as_str())
        || receipt.trigger_ref.as_deref() != Some(task.as_str())
        || receipt.occurred_at != terminal.finished_at
        || receipt.outcome != "completed"
        || receipt.fields.get("call").map(String::as_str) != Some("report")
        || receipt.fields.get("body").map(String::as_str) != Some("done")
        || receipt.fields.get("criteria_verdict").map(String::as_str) != Some("met")
        || receipt.fields.get("result_ref").map(String::as_str) != Some(result.as_str())
        || receipt
            .fields
            .get(FIELD_HOST_ATTEMPT_COUNT)
            .map(String::as_str)
            != Some(generation.as_str())
    {
        return Ok(None);
    }
    let Some(raw) = receipt.fields.get(FIELD_CONFESSION_STRUCTURED) else {
        return Ok(None);
    };
    let Ok(objectives) = serde_json::from_str::<Vec<ObjectiveConfession>>(raw) else {
        return Ok(None);
    };
    if !objectives
        .iter()
        .map(|answer| answer.objective.as_str())
        .eq(context.objectives.iter().map(String::as_str))
    {
        return Ok(None);
    }
    let confession = AttemptConfession {
        attempt: record.id,
        subject: context.subject,
        type_ref: context.type_ref.clone(),
        objectives,
    };
    Ok(crate::self_heal::audit::validate_confession(&confession)
        .is_ok()
        .then_some(confession))
}
