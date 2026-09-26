use rmpv::Value;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, SideKey, SideTable};

use super::consts::TASK_FOLLOW_UP_NAMESPACE;
use super::consult_payload::ConsultRecovery;
use super::wire_decode::{decode_entity_ref, task_body_field};
use super::wire_encode::entity_ref_value;
use crate::error::RecordError;

/// Canonical outbound idempotency/dedupe key in the shared task-follow-up
/// namespace. ONE-1708's human follow-up stages key the same way, so one task
/// never double-notifies across follow-up families.
#[must_use]
pub fn task_follow_up_dedupe_key(task_ref: EntityId, stage: &str) -> String {
    format!("{TASK_FOLLOW_UP_NAMESPACE}:{}:{stage}", task_ref.to_hex())
}

/// The bytes after [`side_table::TASK_FOLLOW_UP_MARKER`]'s prefix: the task id,
/// a NUL separator, then the stage name — exactly the shape this row has
/// always spelled.
pub(super) struct TaskFollowUpKey {
    pub(super) task_ref: EntityId,
    pub(super) stage: String,
}

impl SideKey for TaskFollowUpKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.task_ref.as_bytes());
        out.push(0);
        out.extend_from_slice(self.stage.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (id, rest) = bytes.split_at_checked(16)?;
        let (separator, stage) = rest.split_first()?;
        if *separator != 0 {
            return None;
        }
        Some(Self {
            task_ref: EntityId::from_bytes(id.try_into().ok()?).ok()?,
            stage: String::from_utf8(stage.to_vec()).ok()?,
        })
    }
}

pub(super) const TASK_FOLLOW_UP_MARKERS: SideTable<TaskFollowUpKey, [u8; 1], side_table::Raw> =
    SideTable::new(&side_table::TASK_FOLLOW_UP_MARKER);

pub(super) fn task_follow_up_marker(
    vault: &Vault,
    task_ref: EntityId,
    stage: &str,
) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(TASK_FOLLOW_UP_MARKERS
        .get(
            &vault.store,
            &rtxn,
            &TaskFollowUpKey {
                task_ref,
                stage: stage.to_owned(),
            },
        )?
        .is_some())
}

pub(super) fn set_task_follow_up_marker_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    stage: &str,
) -> Result<()> {
    TASK_FOLLOW_UP_MARKERS.put(
        &vault.store,
        wtxn,
        &TaskFollowUpKey {
            task_ref,
            stage: stage.to_owned(),
        },
        &[1],
    )?;
    Ok(())
}

pub(super) const PEER_HANDLES: SideTable<EntityId, Vec<u8>, side_table::Raw> =
    SideTable::new(&side_table::TASK_PEER_HANDLE);

/// Transaction-scoped handle read: the only caller is page hydration, which
/// already holds its page's shared read transaction.
///
/// A non-UTF-8 row is treated as absent rather than an error: display
/// handles are a projection convenience, and every write path only ever
/// stores a validated `&str`, so this defends a corrupted row without adding
/// a new failure mode to a read-only accessor.
pub(super) fn peer_handle_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    actor_ref: EntityId,
) -> Result<Option<String>> {
    let Some(raw) = PEER_HANDLES.get(&vault.store, rtxn, &actor_ref)? else {
        return Ok(None);
    };
    Ok(String::from_utf8(raw).ok())
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
        .map_err(|_| Error::Record(RecordError::InvalidTaskBody("tasks.consult.expiry")))?;
    let entries = value
        .as_map()
        .ok_or(Error::Record(RecordError::InvalidTaskBody(
            "tasks.consult.expiry",
        )))?;
    task_body_field(entries, "recovery")?
        .as_array()
        .ok_or(Error::Record(RecordError::InvalidTaskBody(
            "tasks.consult.expiry",
        )))?
        .iter()
        .map(|entry| {
            let entry = entry
                .as_map()
                .ok_or(Error::Record(RecordError::InvalidTaskBody(
                    "tasks.consult.expiry",
                )))?;
            match task_body_field(entry, "choice")?.as_str() {
                Some("retry_assignee") => Ok(ConsultRecovery::RetryAssignee),
                Some("nudge_assignee") => Ok(ConsultRecovery::NudgeAssignee),
                Some("try_peer") => Ok(ConsultRecovery::TryPeer(decode_entity_ref(
                    task_body_field(entry, "actor_ref")?,
                    "tasks.consult.expiry",
                )?)),
                _ => Err(Error::Record(RecordError::InvalidTaskBody(
                    "tasks.consult.expiry",
                ))),
            }
        })
        .collect()
}
