//! Vault-backed, atomic wave plan application through the ordinary TASK doors.
use super::create_validation::ValidatedTaskCreate;
use super::{TaskAssignee, TaskKind};
use crate::edge::EdgeActorClass;
use crate::error::Error;
use crate::gate::PolicyApprovalCeiling;
use crate::linear_sync::{LinearSyncError, WaveResult};
use crate::memory::{MemoryError, facade_provenance};
use crate::wave_orchestration::*;
use crate::{EntityId, Vault};
use std::collections::BTreeMap;

pub struct VaultWaveTaskPort<'a> {
    vault: &'a Vault,
    actor: EntityId,
    actor_class: EdgeActorClass,
    attempt: Option<crate::attempt_queue::AttemptRecord>,
}
impl<'a> VaultWaveTaskPort<'a> {
    pub fn new(vault: &'a Vault, actor: EntityId, actor_class: EdgeActorClass) -> Self {
        Self {
            vault,
            actor,
            actor_class,
            attempt: None,
        }
    }
}
fn engine_error(error: MemoryError) -> LinearSyncError {
    Error::InvalidConfig(format!("{}: {}", error.code, error.message)).into()
}
fn index_key(plan: &str, local: &str) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(&(plan.len() as u64).to_be_bytes());
    hash.update(plan.as_bytes());
    hash.update(local.as_bytes());
    [b"wave.task.v1/".as_slice(), hash.finalize().as_bytes()].concat()
}
fn fingerprint(plan: &ValidatedWavePlan) -> Vec<u8> {
    let tasks: Vec<_> = plan
        .tasks
        .values()
        .map(|task| {
            serde_json::json!({
                "key": task.local_key, "label": task.label, "spec": task.spec,
                "assignee": task.assignee_ref.map(|id| id.to_hex()), "blocked_by": task.blocked_by
            })
        })
        .collect();
    serde_json::json!({"epic": plan.epic_task_ref.to_hex(), "tasks": tasks})
        .to_string()
        .into_bytes()
}
impl WaveTaskPort for VaultWaveTaskPort<'_> {
    fn apply_validated_plan(
        &mut self,
        plan: &ValidatedWavePlan,
        now: u64,
    ) -> WaveResult<Vec<WaveTaskWrite>> {
        // The carrier has public fields. Revalidate rather than trusting a
        // caller-constructed value to have passed the orchestrator.
        let checked = WaveOrchestrator::<Self>::validate(WavePlan {
            schema_version: WAVE_PLAN_SCHEMA_VERSION,
            plan_ref: plan.plan_ref.clone(),
            epic_task_ref: plan.epic_task_ref,
            tasks: plan.tasks.values().cloned().collect(),
        })?;
        if &checked != plan {
            return Err(Error::InvariantViolation("unvalidated wave ordering").into());
        }
        let memory = self.vault.memory(self.actor, self.actor_class);
        memory
            .with_verified_actor_write_txn(|txn| {
                if let Some(attempt) = &self.attempt {
                    let current = crate::attempt_queue::AttemptQueue::new(self.vault)
                        .get_in_write_txn(txn, attempt.id)?;
                    if current.as_ref().is_none_or(|current| {
                        current.state != crate::attempt_queue::AttemptState::Leased
                            || current.lease_owner != attempt.lease_owner
                            || current.attempt_count != attempt.attempt_count
                    }) {
                        return Err(MemoryError::bad_request(
                            "wave planner lease is no longer current",
                        ));
                    }
                }
                if super::rate_limit::task_actor_ceiling(
                    self.vault,
                    txn,
                    self.actor,
                    self.actor_class,
                )? != PolicyApprovalCeiling::Auto
                {
                    return Err(MemoryError::bad_request(
                        "wave plan requires task-create authority",
                    ));
                }
                if self
                    .vault
                    .get_entity_type_in_txn(txn, &plan.epic_task_ref)?
                    != Some(crate::registry::ENTITY_TYPE_TASK)
                {
                    return Err(MemoryError::bad_request("wave epic must be a TASK"));
                }
                let seal_key = index_key(&plan.plan_ref, "");
                let fingerprint = fingerprint(plan);
                if self
                    .vault
                    .store
                    .vault_meta
                    .get(txn, &seal_key)?
                    .is_some_and(|raw| raw.as_ref() != fingerprint.as_slice())
                {
                    return Err(MemoryError::bad_request(
                        "wave plan_ref reused for a different cut",
                    ));
                }
                let mut ids = BTreeMap::new();
                for local in &plan.topological_order {
                    let task = &plan.tasks[local];
                    let key = index_key(&plan.plan_ref, local);
                    let id = if let Some(raw) = self.vault.store.vault_meta.get(txn, &key)? {
                        let id = EntityId::from_bytes(
                            raw.as_ref()
                                .try_into()
                                .map_err(|_| Error::CorruptedIndex("wave task index"))?,
                        )?;
                        if self.vault.get_entity_type_in_txn(txn, &id)?
                            != Some(crate::registry::ENTITY_TYPE_TASK)
                        {
                            return Err(Error::EntityNotFound.into());
                        }
                        id
                    } else {
                        let assignee = match task.assignee_ref {
                            None => None,
                            Some(actor_ref) => {
                                Some(match self.vault.get_entity_type_in_txn(txn, &actor_ref)? {
                                    Some(crate::registry::ENTITY_TYPE_PERSON) => {
                                        TaskAssignee::Peer { actor_ref }
                                    }
                                    Some(crate::registry::ENTITY_TYPE_AGENT_DEF) => {
                                        TaskAssignee::AgentDef {
                                            agent_def_ref: actor_ref,
                                        }
                                    }
                                    _ => {
                                        return Err(MemoryError::bad_request(
                                            "wave assignee must be an actor or agent definition",
                                        ));
                                    }
                                })
                            }
                        };
                        let encoded = rmp_serde::to_vec_named(&task.spec)
                            .map_err(|_| Error::InvariantViolation("wave spec encoding"))?;
                        let spec = rmpv::decode::read_value(&mut encoded.as_slice())
                            .map_err(|_| Error::InvariantViolation("wave spec decoding"))?;
                        let validated = ValidatedTaskCreate {
                            kind: TaskKind::Standard,
                            assignee,
                            consult: None,
                            ttl: None,
                            spec,
                        };
                        super::rate_limit::record_task_create(
                            self.vault,
                            txn,
                            self.actor,
                            crate::unix_seconds_now(),
                            super::TaskCreateRateLimit::default(),
                        )?;
                        let id = memory.mint_task_in_txn(
                            txn,
                            &validated,
                            Some(task.label.clone()),
                            self.actor,
                            &facade_provenance(WAVE_PLAN_ATTEMPT_KIND),
                            now,
                        )?;
                        memory.route_created_task_in_txn(txn, id, &validated, now)?;
                        self.vault.store.vault_meta.put(txn, &key, id.as_bytes())?;
                        id
                    };
                    ids.insert(local.clone(), id);
                }
                let mut writes = Vec::new();
                for local in &plan.topological_order {
                    let task = &plan.tasks[local];
                    let id = ids[local];
                    let blockers = task
                        .blocked_by
                        .iter()
                        .map(|local| ids[local])
                        .collect::<Vec<_>>();
                    for blocker in &blockers {
                        let edge = blocked_by_edge_write(
                            id,
                            self.vault
                                .get_entity_type_in_txn(txn, &id)?
                                .ok_or(Error::EntityNotFound)?,
                            *blocker,
                            self.vault
                                .get_entity_type_in_txn(txn, blocker)?
                                .ok_or(Error::EntityNotFound)?,
                        )
                        .map_err(|e| MemoryError::bad_request(e.to_string()))?;
                        self.vault
                            .batch_in()
                            .edge(&edge.dependent, edge.kind(), &edge.blocker, 1.0)
                            .apply(txn)?;
                    }
                    writes.push(WaveTaskWrite {
                        local_key: local.clone(),
                        task_ref: id,
                        label: task.label.clone(),
                        assignee_ref: task.assignee_ref,
                        blocker_refs: blockers,
                    });
                }
                self.vault
                    .store
                    .vault_meta
                    .put(txn, &seal_key, &fingerprint)?;
                Ok(writes)
            })
            .map_err(engine_error)
    }

    fn task_terminal_success(&self, task: EntityId) -> WaveResult<bool> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        Ok(super::terminal_success_in_store(
            &self.vault.store,
            &txn,
            task,
        )?)
    }
    fn blockers(&self, task: EntityId) -> WaveResult<Vec<EntityId>> {
        // Do not type-filter away a deleted blocker: missing is not success.
        Ok(self
            .vault
            .targets(&task, crate::edge::EdgeKind::BlockedBy, None)?)
    }
}

impl Vault {
    /// Queue a planning attempt. Planning itself remains host/agent code.
    pub fn enqueue_wave_plan(
        &self,
        epic: EntityId,
        objective: &str,
        constraints: serde_json::Value,
        now: u64,
    ) -> crate::Result<crate::attempt_queue::EnqueueOutcome> {
        let payload = serde_json::to_vec(&serde_json::json!({"epic": epic.to_hex(), "objective": objective, "constraints": constraints}))
            .map_err(|_| Error::InvariantViolation("wave request encoding"))?;
        crate::attempt_queue::AttemptQueue::new(self).enqueue(
            crate::attempt_queue::EnqueueAttempt {
                kind: WAVE_PLAN_ATTEMPT_KIND.to_owned(),
                dedupe_key: Some(format!("wave.plan:{}", blake3::hash(&payload).to_hex())),
                payload,
                run_id: None,
                now,
            },
        )
    }

    /// Apply a host-produced cut against the current planning lease. Retries
    /// recover the same TASK ids through the plan index. Completing the attempt
    /// remains the executor's existing queue operation.
    pub fn apply_wave_plan_attempt(
        &self,
        actor: EntityId,
        actor_class: EdgeActorClass,
        attempt: &crate::attempt_queue::AttemptRecord,
        plan: WavePlan,
        now: u64,
    ) -> WaveResult<WavePlanReceipt> {
        let payload: serde_json::Value = serde_json::from_slice(&attempt.payload)
            .map_err(|_| Error::InvalidConfig("invalid wave request".to_owned()))?;
        if attempt.kind != WAVE_PLAN_ATTEMPT_KIND
            || attempt.state != crate::attempt_queue::AttemptState::Leased
            || payload.get("epic").and_then(serde_json::Value::as_str)
                != Some(plan.epic_task_ref.to_hex().as_str())
        {
            return Err(Error::InvalidConfig(
                "wave cut is not bound to its planning attempt".to_owned(),
            )
            .into());
        }
        let mut port = VaultWaveTaskPort::new(self, actor, actor_class);
        port.attempt = Some(attempt.clone());
        let validated = WaveOrchestrator::<VaultWaveTaskPort<'_>>::validate(plan)?;
        WaveOrchestrator::new(port).apply(validated, now)
    }
}
