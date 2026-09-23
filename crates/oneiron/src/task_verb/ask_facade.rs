//! Async scope-authority asks over existing consult TASKs.
use super::ask_record::{self, AskGroup, AskMember};
use super::ask_types::*;
use super::create_validation::{consult_refusal, validate_task_create_in};
use super::{ConsultPayload, TaskAssignee, TaskCreateSpec, TaskKind, TaskTtl};
use crate::code_run::peer_result_wait;
use crate::entity_id::EntityId;
use crate::gate::PolicyApprovalCeiling;
use crate::memory::{Memory, MemoryError, MemoryResult, facade_provenance, verify_actor_binding};

impl Memory<'_> {
    /// Returns at admission. This does not open a trap, lease a run, or wait.
    /// A question answer never stands in for an authenticated consent receipt.
    pub fn tasks_ask(&self, input: &TaskAskSpec) -> MemoryResult<TaskAskReceipt> {
        if input.intent_key.trim().is_empty() || input.intent_key.len() > 256 {
            return Err(MemoryError::bad_request(
                "ask intent key must contain 1..=256 bytes",
            ));
        }
        let digest = ask_request_digest(input)?;
        self.with_verified_actor_write_txn(|txn| {
            let now = self.vault().store.clock.now_recorded_at();
            let group_ref =
                ask_record::group_id(self.vault(), txn, self.actor(), &input.intent_key)?;
            if let Some(group) = ask_record::read_group(self.vault(), txn, group_ref)? {
                return replay_receipt(group_ref, group, self.actor(), &digest);
            }
            // Revocation and admission observe the SAME snapshot.
            let holders = match &input.who {
                Some(TaskAskTarget::Authority(scope)) => self
                    .vault()
                    .ask_authority_holders_in_txn(txn, &scope.class, &scope.envelope)?,
                Some(TaskAskTarget::Responder(assignee)) => {
                    vec![assignee.entity_ref().unwrap_or(self.actor())]
                }
                Some(TaskAskTarget::People(people)) => people.iter().copied().collect(),
                None => vec![self.actor()],
            };
            let context_class = self.ask_class_in_txn(txn, input.task_ref)?;
            let effective = input.effective(
                &holders.iter().copied().collect(),
                now,
                context_class.clone(),
            )?;
            if super::rate_limit::task_actor_ceiling(
                self.vault(),
                txn,
                self.actor(),
                self.actor_class(),
            )? != PolicyApprovalCeiling::Auto
            {
                return Err(consult_refusal(
                    crate::memory::MEMORY_CODE_FORBIDDEN,
                    "scope ask requires an own auto-ceiling actor",
                    "Propose the ask through the authority surface.",
                ));
            }
            let mut no_live_route = true;
            let mut validated = Vec::with_capacity(holders.len());
            for actor in &holders {
                let kind = self.vault().get_entity_type_in_txn(txn, actor)?;
                if !matches!(
                    kind,
                    Some(
                        crate::registry::ENTITY_TYPE_PERSON
                            | crate::registry::ENTITY_TYPE_AGENT_DEF
                            | crate::registry::ENTITY_TYPE_MACHINE
                    )
                ) {
                    return Err(MemoryError::bad_request("ask recipient is not an actor"));
                }
                let assignee = match &effective.who {
                    Some(TaskAskTarget::Responder(assignee)) => *assignee,
                    _ if kind == Some(crate::registry::ENTITY_TYPE_PERSON) => {
                        TaskAssignee::Human { actor_ref: *actor }
                    }
                    _ => TaskAssignee::Peer { actor_ref: *actor },
                };
                // No contact route is required to QUEUE a question. Human followup
                // is registered only where the native route actually resolves.
                let reachable = match assignee {
                    TaskAssignee::Human { actor_ref } => {
                        crate::human_task::resolve_native_human_route_in(
                            self.vault(),
                            txn,
                            actor_ref,
                        )
                        .is_ok()
                    }
                    TaskAssignee::Dreamer | TaskAssignee::Child { .. } => true,
                    TaskAssignee::Peer { .. } | TaskAssignee::AgentDef { .. } => false,
                };
                no_live_route &= !reachable;
                for reference in std::iter::once(effective.what.reference)
                    .chain(effective.what.context_refs.iter().copied())
                {
                    crate::llm::decision::questions::validate_task_answer_unit(
                        self.vault(),
                        txn,
                        self.actor(),
                        *actor,
                        reference.entity_ref(),
                    )?;
                }
                let spec =
                    TaskCreateSpec::new(
                        rmpv::Value::Nil,
                        effective.what.label.clone(),
                        None,
                        Some(now),
                    )
                    .with_kind(TaskKind::Consult)
                    .with_consult(ConsultPayload::question(
                        effective.what.reference,
                        effective.what.context_refs.clone(),
                        group_ref,
                    ))
                    .with_assignee(assignee)
                    .with_ttl(TaskTtl::at(effective.until.ok_or_else(|| {
                        MemoryError::bad_request("missing effective ask deadline")
                    })?));
                validated.push((
                    validate_task_create_in(self.vault(), txn, &spec, now)?,
                    reachable,
                ));
            }
            let question_digest =
                super::ask_settlement::question_digest(self.vault(), txn, &effective.what)?
                    .ok_or(crate::Error::EntityNotFound)?;
            let mut members = Vec::with_capacity(holders.len());
            for (actor, (entry, reachable)) in holders.iter().zip(&validated) {
                let task_ref = self.mint_task_at_in_txn(
                    txn,
                    (ask_record::member_id(group_ref, *actor)?, self.actor()),
                    entry,
                    effective.what.label.clone(),
                    &facade_provenance("tasks.ask"),
                    now,
                )?;
                // Local executors use the SAME exhaustive TASK route; remote
                // mailboxes do not create a local worker. Unknown human routes
                // stay queued on the asks list rather than aborting the run.
                if !matches!(entry.assignee, Some(TaskAssignee::Human { .. })) && *reachable {
                    self.route_created_task_in_txn(txn, task_ref, entry, now)?;
                }
                members.push(AskMember {
                    task: task_ref.to_hex(),
                    actor: actor.to_hex(),
                });
            }
            let group = AskGroup {
                base_policy_version: 1,
                owner: self.actor().to_hex(),
                request_digest: digest.clone(),
                requested: input.clone(),
                effective,
                context_class,
                question_digest,
                members,
                no_live_route,
                created_at: now,
            };
            ask_record::put_group(self.vault(), txn, group_ref, &group)?;
            for (member, (entry, _)) in group.members.iter().zip(&validated) {
                if matches!(entry.assignee, Some(TaskAssignee::Human { .. })) {
                    crate::human_task::register_human_followup_in_txn(
                        self.vault(),
                        txn,
                        ask_record::entity(&member.task)?,
                        ask_record::entity(&member.actor)?,
                        now,
                    )?;
                }
            }
            let mut receipt = replay_receipt(group_ref, group, self.actor(), &digest)?;
            receipt.idempotent_replay = false;
            Ok(receipt)
        })
    }

    fn ask_class_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        task: Option<EntityId>,
    ) -> MemoryResult<Option<TaskAskClass>> {
        let task = match task {
            Some(task) => task,
            None => match self.governed_task_in_txn(txn)? {
                Some(task) => task,
                None => return Ok(None),
            },
        };
        let body = super::create_validation::task_body_in_txn(self.vault(), txn, task)?;
        let authority = self
            .vault()
            .task_authority_state_in(txn, task)?
            .ok_or_else(|| MemoryError::bad_request("ask task has no owner proof"))?;
        if authority.cancelled
            || authority.owner_ref.to_hex() != body.owner_ref
            || (authority.owner_ref != self.actor()
                && body.assignee.and_then(TaskAssignee::entity_ref) != Some(self.actor()))
        {
            return Err(MemoryError::bad_request(
                "ask task context is not owned or addressed to this actor",
            ));
        }
        let Some(fields) = body.spec.as_map() else {
            return Ok(None);
        };
        let mut rows = fields
            .iter()
            .filter(|(key, _)| key.as_str() == Some("ask_class"));
        let Some((_, value)) = rows.next() else {
            return Ok(None);
        };
        if rows.next().is_some() {
            return Err(MemoryError::bad_request("duplicate ask class binding"));
        }
        let bytes = rmp_serde::to_vec_named(value)
            .map_err(|_| MemoryError::bad_request("invalid task ask class binding"))?;
        rmp_serde::from_slice(&bytes)
            .map(Some)
            .map_err(|_| MemoryError::bad_request("invalid task ask class binding"))
    }

    /// The task context of an ask that omits `task_ref`: the one live TASK
    /// assigned to this actor whose spec binds an `ask_class`.
    ///
    /// A walk the scan cap stops before the TASK index ends cannot prove that
    /// no governed task exists, so the omission is refused, never admitted.
    fn governed_task_in_txn(&self, txn: &heed::RoTxn<'_>) -> MemoryResult<Option<EntityId>> {
        let name_the_task = |message: &str| {
            MemoryError::bad_request_with(message, &["Name the governing task in task_ref."])
        };
        let scan = super::presence_scan::scan_task_entity_pages(
            super::presence_scan::TASK_PRESENCE_PAGE_SIZE,
            super::presence_scan::TASK_PRESENCE_SCAN_CAP,
            |after, limit| {
                crate::ports::EntityStoreRead::port_entity_ids_by_type(
                    &self.vault().store,
                    txn,
                    crate::registry::ENTITY_TYPE_TASK,
                    after.copied(),
                )?
                .take(limit)
                .collect()
            },
        )?;
        if !scan.source_exhausted {
            return Err(name_the_task(
                "too many tasks to find this ask's task context",
            ));
        }
        let mut found = None;
        for task in scan.pages.into_iter().flatten() {
            let Ok(Some(body)) = super::wire_decode::task_verb_body_in(self.vault(), txn, task)
            else {
                continue;
            };
            if body.assignee.and_then(TaskAssignee::entity_ref) != Some(self.actor())
                || body.terminal().is_some()
                || !body.spec.as_map().is_some_and(|fields| {
                    fields
                        .iter()
                        .any(|(key, _)| key.as_str() == Some("ask_class"))
                })
                || self
                    .vault()
                    .task_authority_state_in(txn, task)?
                    .is_some_and(|authority| authority.cancelled)
            {
                continue;
            }
            if found.replace(task).is_some() {
                return Err(name_the_task(
                    "more than one governed task could bind this ask",
                ));
            }
        }
        Ok(found)
    }

    /// Owner and admitted responders see the same winner, including its actor.
    pub fn tasks_ask_status(&self, handle: TaskAskHandle) -> MemoryResult<TaskAskStatus> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let group = ask_record::read_group(self.vault(), &txn, handle.group_ref)?
            .ok_or_else(|| MemoryError::bad_request("unknown ask handle"))?;
        if group.owner != self.actor().to_hex()
            && !group
                .members
                .iter()
                .any(|m| m.actor == self.actor().to_hex())
        {
            return Err(consult_refusal(
                crate::memory::MEMORY_CODE_FORBIDDEN,
                "ask handle is not addressed to this actor",
                "Read an ask you own or answer.",
            ));
        }
        drop(txn);
        self.with_verified_actor_write_txn(|txn| {
            super::ask_settlement::settle_in(
                self.vault(),
                txn,
                handle.group_ref,
                self.vault().store.clock.now_recorded_at(),
            )?;
            Ok(ask_record::status_in(
                self.vault(),
                txn,
                handle.group_ref,
                &group,
            )?)
        })
    }

    /// Projects a sibling's group winner without replacing that sibling's
    /// terminal evidence. An arbitrary matching correlation is not membership.
    pub fn tasks_ask_status_for_task(
        &self,
        task_ref: EntityId,
    ) -> MemoryResult<Option<TaskAskStatus>> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let body = super::create_validation::task_body_in_txn(self.vault(), &txn, task_ref)?;
        let Some(consult) = body.consult else {
            return Ok(None);
        };
        let Some(group) = ask_record::read_group(self.vault(), &txn, consult.correlation_ref)?
        else {
            return Ok(None);
        };
        if !group
            .members
            .iter()
            .any(|member| member.task == task_ref.to_hex())
        {
            return Ok(None);
        }
        if group.owner != self.actor().to_hex()
            && !group
                .members
                .iter()
                .any(|member| member.actor == self.actor().to_hex())
        {
            return Err(consult_refusal(
                crate::memory::MEMORY_CODE_FORBIDDEN,
                "ask handle is not addressed to this actor",
                "Read an ask you own or answer.",
            ));
        }
        drop(txn);
        self.with_verified_actor_write_txn(|txn| {
            super::ask_settlement::settle_in(
                self.vault(),
                txn,
                consult.correlation_ref,
                self.vault().store.clock.now_recorded_at(),
            )?;
            Ok(Some(ask_record::status_in(
                self.vault(),
                txn,
                consult.correlation_ref,
                &group,
            )?))
        })
    }

    /// Call only when this step has no other work. A host without an engine
    /// step supplies its stable key; code mode consumes the returned C9 park.
    pub fn tasks_wait(
        &self,
        handle: TaskAskHandle,
        step_key: Option<&str>,
    ) -> MemoryResult<TaskAskWait> {
        if step_key.is_some_and(|key| key.is_empty() || key.len() > 256) {
            return Err(MemoryError::bad_request("invalid wait step key"));
        }
        self.with_verified_actor_write_txn(|txn| {
            let group = ask_record::read_group(self.vault(), txn, handle.group_ref)?
                .ok_or_else(|| MemoryError::bad_request("unknown ask handle"))?;
            if group.owner != self.actor().to_hex() {
                return Err(MemoryError::bad_request("only the asking actor may wait"));
            }
            super::ask_settlement::settle_in(
                self.vault(),
                txn,
                handle.group_ref,
                self.vault().store.clock.now_recorded_at(),
            )?;
            let status = ask_record::status_in(self.vault(), txn, handle.group_ref, &group)?;
            let Some(step_key) = step_key else {
                return Ok(match status {
                    TaskAskStatus::Pending { .. } => {
                        let mut wait = peer_result_wait(handle.group_ref);
                        wait.effect = crate::code_run::SelfEffect::TasksWait;
                        TaskAskWait::Park(wait)
                    }
                    TaskAskStatus::Settled(result) => TaskAskWait::Ready(result),
                });
            };
            self.bind_external_wait(txn, handle, step_key, status)
        })
    }
}

fn replay_receipt(
    id: EntityId,
    group: AskGroup,
    actor: EntityId,
    digest: &str,
) -> MemoryResult<TaskAskReceipt> {
    if group.owner != actor.to_hex() || group.request_digest != digest {
        return Err(MemoryError::bad_request(
            "ask intent key was used for different arguments",
        ));
    }
    Ok(TaskAskReceipt {
        handle: TaskAskHandle { group_ref: id },
        task_refs: group
            .members
            .iter()
            .map(|m| ask_record::entity(&m.task))
            .collect::<crate::Result<Vec<_>>>()?,
        hold: group
            .no_live_route
            .then_some(TaskAskHoldReason::NoLiveRoute),
        idempotent_replay: true,
    })
}

fn ask_request_digest(input: &TaskAskSpec) -> MemoryResult<String> {
    let bytes = rmp_serde::to_vec_named(input)
        .map_err(|_| MemoryError::bad_request("ask request encoding"))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

impl Memory<'_> {
    /// Owner-scoped calibration pairs. The outcome reader rechecks current
    /// fact fields, lifecycle and privacy; the ask id is never a read grant.
    pub fn tasks_ask_outcomes(
        &self,
        handle: &TaskAskHandle,
    ) -> MemoryResult<Vec<crate::llm::decision::questions::CalibrationPair>> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let group = ask_record::read_group(self.vault(), &txn, handle.group_ref)?
            .ok_or_else(|| MemoryError::bad_request("unknown ask handle"))?;
        if group.owner != self.actor().to_hex() {
            return Err(MemoryError::bad_request(
                "only the asking actor may read outcomes",
            ));
        }
        drop(txn);
        Ok(crate::llm::decision::questions::calibration_pairs(
            self.vault(),
            self.actor(),
            handle.group_ref,
        )?)
    }
}

const WAITS: &[u8] = b"tasks.wait/";
const MAX_WAITS_PER_ASK: usize = 64;

#[derive(serde::Serialize, serde::Deserialize)]
struct WaitRow {
    trap_ref: Option<EntityId>,
    step_hash: [u8; 32],
    actor: EntityId,
    consumed: bool,
}

fn wait_prefix(id: EntityId) -> Vec<u8> {
    [WAITS, id.as_bytes()].concat()
}

pub(super) fn signal_waiters(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    group: EntityId,
    now: u64,
) -> MemoryResult<()> {
    let rows = vault
        .store
        .vault_meta
        .prefix_iter(txn, &wait_prefix(group))?
        .map(|row| row.map(|(_, value)| value.to_vec()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for raw in rows {
        let row: WaitRow =
            rmp_serde::from_slice(&raw).map_err(|_| MemoryError::bad_request("wait record"))?;
        if !row.consumed {
            let trap = crate::llm::TrapRef {
                trap_claim_id: row
                    .trap_ref
                    .ok_or_else(|| MemoryError::bad_request("pending wait has no trap"))?,
                kind: crate::llm::DreamerTrapKind::HumanResponse,
                step_hash: row.step_hash,
            };
            crate::llm::signal_step_wait_in_txn(vault, txn, &trap, now)?;
        }
    }
    Ok(())
}

impl Memory<'_> {
    fn bind_external_wait(
        &self,
        txn: &mut heed::RwTxn<'_>,
        handle: TaskAskHandle,
        step_key: &str,
        status: TaskAskStatus,
    ) -> MemoryResult<TaskAskWait> {
        let mut hash = blake3::Hasher::new();
        hash.update(WAITS);
        hash.update(self.actor().as_bytes());
        hash.update(handle.group_ref.as_bytes());
        hash.update(step_key.as_bytes());
        let step_hash = *hash.finalize().as_bytes();
        let key = [
            wait_prefix(handle.group_ref).as_slice(),
            step_hash.as_slice(),
        ]
        .concat();
        let now_ms = self
            .vault()
            .store
            .clock
            .now_recorded_at()
            .saturating_mul(1000);
        let mut row = if let Some(raw) = self.vault().store.vault_meta.get(txn, &key)? {
            rmp_serde::from_slice::<WaitRow>(&raw)
                .map_err(|_| MemoryError::bad_request("wait record"))?
        } else {
            let count = self
                .vault()
                .store
                .vault_meta
                .prefix_iter(txn, &wait_prefix(handle.group_ref))?
                .take(MAX_WAITS_PER_ASK)
                .try_fold(0, |count, row| row.map(|_| count + 1))?;
            if count >= MAX_WAITS_PER_ASK {
                return Err(MemoryError::bad_request("ask waiter limit reached"));
            }
            // Answer-before-wait needs only bounded exactly-once bookkeeping.
            // Do not mint a detached step or a trap for a completed answer.
            let trap_ref = if matches!(status, TaskAskStatus::Pending { .. }) {
                let ctx = crate::llm::DurableStepContext {
                    vault: self.vault(),
                    attempt_id: crate::attempt_queue::AttemptId::from_bytes(
                        step_hash
                            .get(..16)
                            .ok_or_else(|| MemoryError::bad_request("wait identity"))?,
                    )?,
                    run_id: None,
                    envelope_actor: crate::WriteActor::new(self.actor(), self.actor_class()),
                    subject: self.actor(),
                    deadline: None,
                    now_ms,
                };
                crate::llm::register_detached_step_in_txn(self.vault(), txn, &ctx, step_hash)?;
                Some(
                    crate::llm::open_step_wait_in_txn(self.vault(), txn, &ctx, step_hash)?
                        .trap_claim_id,
                )
            } else {
                None
            };
            WaitRow {
                trap_ref,
                step_hash,
                actor: self.actor(),
                consumed: false,
            }
        };
        if row.actor != self.actor() || row.step_hash != step_hash {
            return Err(MemoryError::bad_request("wait binding changed"));
        }
        let outcome = match status {
            TaskAskStatus::Pending { .. } => TaskAskWait::Pending {
                trap_ref: row
                    .trap_ref
                    .ok_or_else(|| MemoryError::bad_request("pending wait has no trap"))?
                    .to_hex(),
            },
            TaskAskStatus::Settled(result) => {
                if let Some(trap_claim_id) = row.trap_ref
                    && !row.consumed
                {
                    let trap = crate::llm::TrapRef {
                        trap_claim_id,
                        kind: crate::llm::DreamerTrapKind::HumanResponse,
                        step_hash,
                    };
                    crate::llm::signal_step_wait_in_txn(self.vault(), txn, &trap, now_ms)?;
                    if !crate::llm::consume_step_wait_in_txn(self.vault(), txn, &trap, now_ms)? {
                        return Err(MemoryError::bad_request("wait signal was not consumable"));
                    }
                }
                row.consumed = true;
                TaskAskWait::Ready(result)
            }
        };
        self.vault().store.vault_meta.put(
            txn,
            &key,
            &rmp_serde::to_vec_named(&row)
                .map_err(|_| MemoryError::bad_request("wait encoding"))?,
        )?;
        Ok(outcome)
    }
}

impl Memory<'_> {
    /// Live evidence includes late words, without rewriting the cutoff receipt.
    pub fn tasks_ask_evidence(&self, handle: TaskAskHandle) -> MemoryResult<Vec<TaskAskEvidence>> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        let group = ask_record::read_group(self.vault(), &txn, handle.group_ref)?
            .ok_or_else(|| MemoryError::bad_request("unknown ask handle"))?;
        if group.owner != self.actor().to_hex()
            && !group
                .members
                .iter()
                .any(|member| member.actor == self.actor().to_hex())
        {
            return Err(MemoryError::bad_request(
                "ask evidence is not addressed to this actor",
            ));
        }
        Ok(super::ask_settlement::evidence(
            self.vault(),
            &txn,
            handle.group_ref,
            &group,
        )?)
    }
}

pub(crate) fn settle_waiting_asks(vault: &crate::Vault) -> crate::Result<()> {
    let txn = vault.store.env.read_txn()?;
    let mut groups = std::collections::BTreeSet::new();
    for row in vault.store.vault_meta.prefix_iter(&txn, WAITS)? {
        let (key, value) = row?;
        let row: WaitRow = rmp_serde::from_slice(&value).map_err(|_| ask_record::invalid())?;
        if !row.consumed {
            let group = key
                .get(WAITS.len()..WAITS.len() + 16)
                .ok_or_else(ask_record::invalid)?;
            groups.insert(EntityId::from_bytes(
                group.try_into().map_err(|_| ask_record::invalid())?,
            )?);
        }
    }
    drop(txn);
    for group in groups {
        super::ask_settlement::settle_ask_if_due(vault, group)?;
    }
    Ok(())
}
