//! Immediate ask handles, immutable responder sets, and first-answer CAS.
use super::{
    TaskAssignee, TaskCreateRateLimit, TaskExecutionState, TaskKind, TaskTerminalDisposition,
    TaskTerminalRecord,
    create_validation::{ValidatedTaskCreate, task_body_in_txn},
    rate_limit::{record_task_create, task_actor_ceiling},
    wire_encode::{canonical_bytes, encode_task_verb_body},
};
use crate::gate::PolicyApprovalCeiling;
use crate::memory::{Memory, MemoryError, MemoryResult, facade_provenance};
use crate::{EntityId, Error, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
pub(super) const ASKS: &[u8] = b"tasks.ask.v1/";
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAskSpec {
    pub question: serde_json::Value,
    pub holders: BTreeSet<String>,
    pub idempotency_key: String,
    /// Ask-local outcome binding. A standing-question version may be linked
    /// after ONE-2343 lands; this does not fork its question registry.
    pub outcome_binding: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskAskHandle {
    pub task_ref: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskAskReceipt {
    pub handle: TaskAskHandle,
    pub count: u64,
    pub replayed: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskAskAnswer {
    pub task_ref: String,
    pub actor_ref: String,
    pub result_ref: String,
    pub at: u64,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct AskRow {
    pub(super) owner: String,
    pub(super) spec: TaskAskSpec,
    pub(super) answer: Option<TaskAskAnswer>,
    pub(super) count: u64,
}
pub(super) fn ask_key(id: EntityId) -> Vec<u8> {
    [ASKS, id.as_bytes()].concat()
}
pub(super) fn read(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> MemoryResult<AskRow> {
    let raw = vault
        .store
        .vault_meta
        .get(txn, &ask_key(id))?
        .ok_or(Error::EntityNotFound)?;
    serde_json::from_slice(&raw).map_err(|_| MemoryError::bad_request("ask record invalid"))
}
pub(super) fn save(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    row: &AskRow,
) -> MemoryResult<()> {
    vault.store.vault_meta.put(
        txn,
        &ask_key(id),
        &serde_json::to_vec(row).map_err(|_| MemoryError::bad_request("ask encoding"))?,
    )?;
    Ok(())
}
impl Memory<'_> {
    pub fn tasks_ask(&self, spec: &TaskAskSpec) -> MemoryResult<TaskAskReceipt> {
        if spec.idempotency_key.is_empty()
            || spec.idempotency_key.len() > 256
            || spec.holders.is_empty()
            || spec.holders.len() > 256
            || !spec.question.is_object()
            || spec.question.to_string().len() > 64 * 1024
            || spec
                .outcome_binding
                .as_ref()
                .is_some_and(|s| s.len() > 1024)
        {
            return Err(MemoryError::bad_request("invalid ask spec"));
        }
        let now = crate::unix_seconds_now();
        let payload =
            rmp_serde::to_vec_named(spec).map_err(|_| MemoryError::bad_request("ask encoding"))?;
        let spec_value = rmpv::decode::read_value(&mut payload.as_slice())
            .map_err(|_| MemoryError::bad_request("ask encoding"))?;
        self.with_verified_actor_write_txn(|txn| {
            let owner = self.actor().to_hex();
            let dedupe = [
                b"tasks.ask.dedupe.v1/".as_slice(),
                self.actor().as_bytes(),
                blake3::hash(spec.idempotency_key.as_bytes()).as_bytes(),
            ]
            .concat();
            if let Some(raw) = self.vault().store.vault_meta.get(txn, &dedupe)? {
                let id = EntityId::from_bytes(
                    raw.as_ref()
                        .try_into()
                        .map_err(|_| MemoryError::bad_request("ask index"))?,
                )?;
                let row = read(self.vault(), txn, id)?;
                if &row.spec != spec || row.owner != owner {
                    return Err(MemoryError::bad_request("ask idempotency binding changed"));
                }
                task_body_in_txn(self.vault(), txn, id)?;
                return Ok(TaskAskReceipt {
                    handle: TaskAskHandle {
                        task_ref: id.to_hex(),
                    },
                    count: row.count,
                    replayed: true,
                });
            }
            if task_actor_ceiling(self.vault(), txn, self.actor(), self.actor_class())?
                != PolicyApprovalCeiling::Auto
            {
                return Err(MemoryError::bad_request(
                    "ask requires the caller's Auto creation grant",
                ));
            }
            for holder in &spec.holders {
                let id = EntityId::from_hex(holder)?;
                if id.to_hex() != *holder
                    || !matches!(
                        self.vault().get_entity_type_in_txn(txn, &id)?,
                        Some(
                            crate::registry::ENTITY_TYPE_PERSON
                                | crate::registry::ENTITY_TYPE_AGENT_DEF
                        )
                    )
                {
                    return Err(MemoryError::bad_request(
                        "ask holder must be a person or agent",
                    ));
                }
            }
            let count = record_task_create(
                self.vault(),
                txn,
                self.actor(),
                now,
                TaskCreateRateLimit::default(),
            )?;
            let validated = ValidatedTaskCreate {
                kind: TaskKind::Standard,
                assignee: Some(TaskAssignee::AnswerHolders),
                consult: None,
                ttl: None,
                spec: spec_value.clone(),
            };
            let id = self.mint_task_in_txn(
                txn,
                &validated,
                None,
                self.actor(),
                &facade_provenance("tasks.ask"),
                now,
            )?;
            let row = AskRow {
                owner,
                spec: spec.clone(),
                answer: None,
                count,
            };
            save(self.vault(), txn, id, &row)?;
            self.vault()
                .store
                .vault_meta
                .put(txn, &dedupe, id.as_bytes())?;
            Ok(TaskAskReceipt {
                handle: TaskAskHandle {
                    task_ref: id.to_hex(),
                },
                count,
                replayed: false,
            })
        })
    }
    pub fn tasks_answer(
        &self,
        handle: &TaskAskHandle,
        result_ref: EntityId,
    ) -> MemoryResult<TaskAskAnswer> {
        let id = EntityId::from_hex(&handle.task_ref)?;
        let now = crate::unix_seconds_now();
        self.with_verified_actor_write_txn(|txn| {
            let mut row = read(self.vault(), txn, id)?;
            if !row.spec.holders.contains(&self.actor().to_hex()) {
                return Err(MemoryError::bad_request("actor is not an answer holder"));
            }
            if let Some(answer) = row.answer {
                return Ok(answer);
            }
            if self
                .vault()
                .get_entity_type_in_txn(txn, &result_ref)?
                .is_none()
            {
                return Err(Error::EntityNotFound.into());
            }
            let mut body = task_body_in_txn(self.vault(), txn, id)?;
            if body.state.as_ref().is_some_and(|s| s.terminal().is_some())
                || self
                    .vault()
                    .task_authority_state_in(txn, id)?
                    .is_some_and(|s| s.cancelled)
            {
                return Err(MemoryError::bad_request("ask is terminal"));
            }
            let stored: TaskAskSpec = rmp_serde::from_slice(&canonical_bytes(&body.spec))
                .map_err(|_| MemoryError::bad_request("ask body"))?;
            if stored != row.spec || body.assignee != Some(TaskAssignee::AnswerHolders) {
                return Err(MemoryError::bad_request("ask holder binding changed"));
            }
            let answer = TaskAskAnswer {
                task_ref: id.to_hex(),
                actor_ref: self.actor().to_hex(),
                result_ref: result_ref.to_hex(),
                at: now,
            };
            body.state = Some(TaskExecutionState::Terminal(TaskTerminalRecord {
                disposition: TaskTerminalDisposition::Completed,
                result_ref: Some(result_ref),
                summary: None,
                finished_at: now,
                ladder: None,
                counter_task_ref: None,
            }));
            self.put_task_body_in_txn(txn, id, &encode_task_verb_body(body), now)?;
            row.answer = Some(answer.clone());
            save(self.vault(), txn, id, &row)?;
            super::ask_wait::signal_waiters(self.vault(), txn, id, now.saturating_mul(1000))?;
            Ok(answer)
        })
    }
}
