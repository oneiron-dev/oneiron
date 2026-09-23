//! Replay encoding for the typed coordination calls.
use super::support::{
    bool_value, decode_array, entity_id_value, entity_value, expect_map, invalid_code_run_replay,
    map_get, request_map, str_value,
};
use super::{SelfAgentSpawnCall, SelfAgentSpawnResult};
use crate::Result;
use crate::agent_dispatch::AgentDispatchTarget;
use crate::task_verb::{
    TaskAskHandle, TaskAskHoldReason, TaskAskReceipt, TaskAskSpec, TaskAskStatus,
};
use rmpv::Value;

pub(super) fn spawn_request(call: &SelfAgentSpawnCall) -> Result<Value> {
    let (kind, target) = match call.target {
        AgentDispatchTarget::Custom(id) => ("agent_def", id),
        AgentDispatchTarget::Workflow(id) => ("workflow", id),
    };
    Ok(request_map(vec![
        ("target_kind", Value::from(kind)),
        ("target", entity_id_value(target)),
        ("intent_key", Value::from(call.intent_key.as_str())),
        (
            "context_spec",
            match &call.context.context_spec {
                Some(spec) => Value::from(
                    serde_json::to_string(spec)
                        .map_err(|_| invalid_code_run_replay("spawn context encode"))?,
                ),
                None => Value::Nil,
            },
        ),
        (
            "context_from",
            Value::Array(
                call.context
                    .context_from
                    .iter()
                    .copied()
                    .map(entity_id_value)
                    .collect(),
            ),
        ),
        (
            "depth_remaining",
            call.context.depth_remaining.map_or(Value::Nil, Value::from),
        ),
    ]))
}

pub(super) fn ask_request(call: &TaskAskSpec) -> Result<Value> {
    let bytes =
        rmp_serde::to_vec_named(call).map_err(|_| invalid_code_run_replay("ask request encode"))?;
    rmpv::decode::read_value(&mut bytes.as_slice())
        .map_err(|_| invalid_code_run_replay("ask request encode"))
}

pub(super) fn spawn_value(result: &SelfAgentSpawnResult) -> Value {
    match result {
        SelfAgentSpawnResult::Queued { attempt_ref } => request_map(vec![
            ("kind", Value::from("agent_spawn")),
            ("state", Value::from("queued")),
            (
                "attempt",
                Value::from(crate::entity_id::bytes_to_hex_lower(attempt_ref.as_bytes())),
            ),
        ]),
        SelfAgentSpawnResult::ProposedWiden { proposal_ref } => request_map(vec![
            ("kind", Value::from("agent_spawn")),
            ("state", Value::from("proposed_widen")),
            ("proposal", Value::from(proposal_ref.as_str())),
        ]),
    }
}

pub(super) fn decode_spawn(value: &Value) -> Result<SelfAgentSpawnResult> {
    let m = expect_map(value, "spawn outcome map")?;
    match str_value(map_get(m, "state")?)? {
        "queued" => Ok(SelfAgentSpawnResult::Queued {
            attempt_ref: crate::attempt_queue::AttemptId::from_bytes(
                crate::EntityId::from_hex(str_value(map_get(m, "attempt")?)?)?.as_bytes(),
            )?,
        }),
        "proposed_widen" => Ok(SelfAgentSpawnResult::ProposedWiden {
            proposal_ref: str_value(map_get(m, "proposal")?)?.to_owned(),
        }),
        _ => Err(invalid_code_run_replay("spawn state")),
    }
}

fn hold_value(hold: Option<TaskAskHoldReason>) -> Value {
    match hold {
        None => Value::Nil,
        Some(TaskAskHoldReason::NoLiveRoute) => Value::from("no_live_route"),
    }
}
fn hold_decode(value: &Value) -> Result<Option<TaskAskHoldReason>> {
    match value {
        Value::Nil => Ok(None),
        value if value.as_str() == Some("no_live_route") => {
            Ok(Some(TaskAskHoldReason::NoLiveRoute))
        }
        _ => Err(invalid_code_run_replay("ask hold")),
    }
}
pub(super) fn ask_value(result: &TaskAskReceipt) -> Value {
    request_map(vec![
        ("kind", Value::from("task_ask")),
        ("group", entity_id_value(result.handle.group_ref)),
        (
            "tasks",
            Value::Array(
                result
                    .task_refs
                    .iter()
                    .copied()
                    .map(entity_id_value)
                    .collect(),
            ),
        ),
        ("hold", hold_value(result.hold)),
        ("replay", Value::Boolean(result.idempotent_replay)),
    ])
}
pub(super) fn decode_ask(value: &Value) -> Result<TaskAskReceipt> {
    let m = expect_map(value, "ask outcome map")?;
    Ok(TaskAskReceipt {
        handle: TaskAskHandle {
            group_ref: entity_value(map_get(m, "group")?)?,
        },
        task_refs: decode_array(map_get(m, "tasks")?, entity_value)?,
        hold: hold_decode(map_get(m, "hold")?)?,
        idempotent_replay: bool_value(map_get(m, "replay")?)?,
    })
}
pub(super) fn status_value(result: &TaskAskStatus) -> Result<Value> {
    let bytes = rmp_serde::to_vec_named(result)
        .map_err(|_| invalid_code_run_replay("ask result encode"))?;
    let value = rmpv::decode::read_value(&mut bytes.as_slice())
        .map_err(|_| invalid_code_run_replay("ask result encode"))?;
    Ok(request_map(vec![
        ("kind", Value::from("task_ask_status")),
        ("status", value),
    ]))
}
pub(super) fn decode_status(value: &Value) -> Result<TaskAskStatus> {
    let fields = expect_map(value, "ask status map")?;
    let bytes = rmp_serde::to_vec_named(map_get(fields, "status")?)
        .map_err(|_| invalid_code_run_replay("ask result encode"))?;
    rmp_serde::from_slice(&bytes).map_err(|_| invalid_code_run_replay("ask result decode"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_hold_reason_round_trips() -> Result<()> {
        for hold in [None, Some(TaskAskHoldReason::NoLiveRoute)] {
            let status = TaskAskStatus::Pending { hold };
            assert_eq!(decode_status(&status_value(&status)?)?, status);
        }
        assert!(hold_decode(&Value::from("unknown")).is_err());
        Ok(())
    }
}
