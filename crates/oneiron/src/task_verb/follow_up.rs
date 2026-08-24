use rmpv::Value;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::consts::{PEER_HANDLE_KEY_PREFIX, TASK_FOLLOW_UP_KEY_PREFIX, TASK_FOLLOW_UP_NAMESPACE};
use super::consult_payload::ConsultRecovery;
use super::wire_decode::{decode_entity_ref, task_body_field};
use super::wire_encode::entity_ref_value;

/// Canonical outbound idempotency/dedupe key in the shared task-follow-up
/// namespace. ONE-1708's human follow-up stages key the same way, so one task
/// never double-notifies across follow-up families.
#[must_use]
pub fn task_follow_up_dedupe_key(task_ref: EntityId, stage: &str) -> String {
    format!("{TASK_FOLLOW_UP_NAMESPACE}:{}:{stage}", task_ref.to_hex())
}

pub(super) fn task_follow_up_key(task_ref: EntityId, stage: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        TASK_FOLLOW_UP_KEY_PREFIX.len() + task_ref.as_bytes().len() + 1 + stage.len(),
    );
    key.extend_from_slice(TASK_FOLLOW_UP_KEY_PREFIX);
    key.extend_from_slice(task_ref.as_bytes());
    key.push(0);
    key.extend_from_slice(stage.as_bytes());
    key
}

pub(super) fn task_follow_up_marker(
    vault: &Vault,
    task_ref: EntityId,
    stage: &str,
) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .vault_meta
        .get(&rtxn, task_follow_up_key(task_ref, stage).as_slice())?
        .is_some())
}

pub(super) fn set_task_follow_up_marker_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    stage: &str,
) -> Result<()> {
    vault
        .store
        .vault_meta
        .put(wtxn, task_follow_up_key(task_ref, stage).as_slice(), &[1])?;
    Ok(())
}

pub(super) fn peer_handle_key(actor_ref: EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(PEER_HANDLE_KEY_PREFIX.len() + actor_ref.as_bytes().len());
    key.extend_from_slice(PEER_HANDLE_KEY_PREFIX);
    key.extend_from_slice(actor_ref.as_bytes());
    key
}

/// Transaction-scoped handle read: the only caller is page hydration, which
/// already holds its page's shared read transaction.
pub(super) fn peer_handle_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    actor_ref: EntityId,
) -> Result<Option<String>> {
    let Some(raw) = vault
        .store
        .vault_meta
        .get(rtxn, peer_handle_key(actor_ref).as_slice())?
    else {
        return Ok(None);
    };
    Ok(std::str::from_utf8(raw.as_ref()).ok().map(str::to_owned))
}

/// The durable expiry artifact. It carries TYPED recovery choices — the
/// consuming lens localizes the human sentence, so no product prose lives here.
pub(super) fn consult_expiry_artifact_value(
    task_ref: EntityId,
    deadline_at: u64,
    expired_at: u64,
    recovery: &[ConsultRecovery],
) -> Value {
    Value::Map(vec![
        (Value::from("kind"), Value::from("consult.expiry")),
        (Value::from("task_ref"), entity_ref_value(task_ref)),
        (Value::from("deadline_at"), Value::from(deadline_at)),
        (Value::from("expired_at"), Value::from(expired_at)),
        (
            Value::from("recovery"),
            Value::Array(
                recovery
                    .iter()
                    .copied()
                    .map(|choice| {
                        Value::Map(vec![
                            (Value::from("choice"), Value::from(choice.as_str())),
                            (
                                Value::from("actor_ref"),
                                match choice {
                                    ConsultRecovery::TryPeer(actor_ref) => {
                                        entity_ref_value(actor_ref)
                                    }
                                    ConsultRecovery::RetryAssignee
                                    | ConsultRecovery::NudgeAssignee => Value::Nil,
                                },
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

/// Decodes the typed recovery choices persisted on one expiry artifact.
pub fn decode_consult_expiry_recovery(artifact_body: &[u8]) -> Result<Vec<ConsultRecovery>> {
    let mut cursor = artifact_body;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidTaskBody("tasks.consult.expiry"))?;
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("tasks.consult.expiry"))?;
    task_body_field(entries, "recovery")?
        .as_array()
        .ok_or(Error::InvalidTaskBody("tasks.consult.expiry"))?
        .iter()
        .map(|entry| {
            let entry = entry
                .as_map()
                .ok_or(Error::InvalidTaskBody("tasks.consult.expiry"))?;
            match task_body_field(entry, "choice")?.as_str() {
                Some("retry_assignee") => Ok(ConsultRecovery::RetryAssignee),
                Some("nudge_assignee") => Ok(ConsultRecovery::NudgeAssignee),
                Some("try_peer") => Ok(ConsultRecovery::TryPeer(decode_entity_ref(
                    task_body_field(entry, "actor_ref")?,
                    "tasks.consult.expiry",
                )?)),
                _ => Err(Error::InvalidTaskBody("tasks.consult.expiry")),
            }
        })
        .collect()
}
