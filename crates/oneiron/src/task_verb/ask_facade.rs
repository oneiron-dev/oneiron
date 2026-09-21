//! Async scope-authority asks over existing consult TASKs.
use super::ask_record::{self, AskGroup, AskMember};
use super::ask_types::*;
use super::create_validation::{consult_refusal, validate_task_create};
use super::{ConsultPayload, TaskAssignee, TaskCreateSpec, TaskKind, TaskTtl};
use crate::code_run::peer_result_wait;
use crate::consent::{ActorBound, GrantBound};
use crate::entity_id::EntityId;
use crate::gate::PolicyApprovalCeiling;
use crate::memory::{Memory, MemoryError, MemoryResult, facade_provenance, verify_actor_binding};

impl Memory<'_> {
    /// Returns at admission. This does not open a trap, lease a run, or wait.
    /// A question answer never stands in for an authenticated consent receipt.
    pub(super) fn tasks_ask_scope(&self, input: &TaskAskSpec) -> MemoryResult<TaskAskReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        if input.intent_key.trim().is_empty() || input.intent_key.len() > 256 {
            return Err(MemoryError::bad_request(
                "ask intent key must contain 1..=256 bytes",
            ));
        }
        let now = crate::unix_seconds_now();
        let group_ref = ask_record::group_id(self.vault(), self.actor(), &input.intent_key)?;
        let digest = ask_request_digest(self.actor(), input)?;
        let holders = {
            let txn = self
                .vault()
                .store
                .env
                .read_txn()
                .map_err(crate::Error::from)?;
            if let Some(group) = ask_record::read_group(self.vault(), &txn, group_ref)? {
                return replay_receipt(group_ref, group, self.actor(), &digest);
            }
            match &input.target {
                TaskAskTarget::Authority(scope) => self.vault().ask_authority_holders_in_txn(
                    &txn,
                    &scope.class,
                    &scope.envelope,
                )?,
                TaskAskTarget::Responder(assignee) => {
                    vec![assignee.entity_ref().unwrap_or(self.actor())]
                }
            }
        };
        if holders.is_empty() || holders.len() > 64 {
            return Err(MemoryError::bad_request(
                "ask requires 1..=64 live scope authority holders",
            ));
        }
        let mut no_live_route = true;
        let mut validated = Vec::with_capacity(holders.len());
        for actor in &holders {
            // No contact route is required to QUEUE a question. Human followup
            // is registered only where the native route actually resolves.
            let human =
                self.vault().get_entity_type(actor)? == Some(crate::registry::ENTITY_TYPE_PERSON);
            let assignee = match &input.target {
                TaskAskTarget::Responder(assignee) => *assignee,
                TaskAskTarget::Authority(_) if human => TaskAssignee::Human { actor_ref: *actor },
                TaskAskTarget::Authority(_) => TaskAssignee::Peer { actor_ref: *actor },
            };
            let reachable = match assignee {
                TaskAssignee::AnswerHolders => {
                    return Err(MemoryError::bad_request(
                        "scope ask requires a routable responder",
                    ));
                }
                TaskAssignee::Human { actor_ref } => {
                    crate::human_task::resolve_native_human_route(self.vault(), actor_ref).is_ok()
                }
                TaskAssignee::Dreamer | TaskAssignee::Child { .. } => true,
                TaskAssignee::Peer { .. } | TaskAssignee::AgentDef { .. } => false,
            };
            no_live_route &= !reachable;
            let spec = TaskCreateSpec::new(rmpv::Value::Nil, input.label.clone(), None, Some(now))
                .with_kind(TaskKind::Consult)
                .with_consult(ConsultPayload::question(
                    input.question_ref,
                    input.context_refs.clone(),
                    group_ref,
                ))
                .with_assignee(assignee)
                .with_ttl(TaskTtl::at(input.deadline_at));
            validated.push((validate_task_create(self.vault(), &spec, now)?, reachable));
        }
        self.with_verified_actor_write_txn(|txn| {
            if let Some(group) = ask_record::read_group(self.vault(), &*txn, group_ref)? {
                return replay_receipt(group_ref, group, self.actor(), &digest);
            }
            // Revocation and admission observe the SAME snapshot. The outside
            // pass only binds payload entities and discovers native routes.
            if let TaskAskTarget::Authority(scope) = &input.target {
                let live = self.vault().ask_authority_holders_in_txn(
                    &*txn,
                    &scope.class,
                    &scope.envelope,
                )?;
                if live != holders {
                    return Err(MemoryError::bad_request(
                        "ask authority changed; retry admission",
                    ));
                }
            }
            if super::rate_limit::task_actor_ceiling(
                self.vault(),
                &*txn,
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
            let mut members = Vec::with_capacity(holders.len());
            for (actor, (entry, reachable)) in holders.iter().zip(&validated) {
                let task_ref = self.mint_task_at_in_txn(
                    txn,
                    (ask_record::member_id(group_ref, *actor)?, self.actor()),
                    entry,
                    input.label.clone(),
                    &facade_provenance("tasks.ask"),
                    now,
                )?;
                // Local executors use the SAME exhaustive TASK route; remote
                // mailboxes do not create a local worker. Unknown human routes
                // stay queued on the asks list rather than aborting the run.
                if matches!(entry.assignee, Some(TaskAssignee::Human { .. })) {
                    crate::human_task::register_human_followup_in_txn(
                        self.vault(),
                        txn,
                        task_ref,
                        *actor,
                        now,
                    )?;
                } else if *reachable {
                    self.route_created_task_in_txn(txn, task_ref, entry, now)?;
                }
                members.push(AskMember {
                    task: task_ref.to_hex(),
                    actor: actor.to_hex(),
                });
            }
            let group = AskGroup {
                owner: self.actor().to_hex(),
                request_digest: digest.clone(),
                question: input.question_ref.short_ref(),
                members,
                no_live_route,
                created_at: now,
            };
            ask_record::put_group(self.vault(), txn, group_ref, &group)?;
            let mut receipt = replay_receipt(group_ref, group, self.actor(), &digest)?;
            receipt.idempotent_replay = false;
            Ok(receipt)
        })
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
        Ok(ask_record::status_in(
            self.vault(),
            &txn,
            handle.group_ref,
            &group,
        )?)
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
        Ok(Some(ask_record::status_in(
            self.vault(),
            &txn,
            consult.correlation_ref,
            &group,
        )?))
    }

    /// Host-side idle adapter. Opens a real durable C9 trap and parks only
    /// `ctx.attempt_id`. A ready answer does not open or park anything.
    pub fn tasks_wait_step(
        &self,
        handle: TaskAskHandle,
        ctx: &crate::llm::DurableStepContext<'_>,
        step_hash: [u8; 32],
    ) -> MemoryResult<Option<crate::llm::TrapRef>> {
        if !std::ptr::eq(self.vault(), ctx.vault)
            || ctx.envelope_actor.entity_ref() != self.actor()
            || ctx.envelope_actor.actor_class() != self.actor_class()
        {
            return Err(MemoryError::bad_request("ask wait host binding mismatch"));
        }
        match self.tasks_wait(handle)? {
            TaskAskWait::Ready(_) => Ok(None),
            TaskAskWait::Park(_) => Ok(Some(crate::llm::park_peer_result_step(
                ctx,
                handle.group_ref,
                step_hash,
            )?)),
        }
    }

    /// Call only when this step has no other work. `Park` is consumed by the
    /// host's C9 trap adapter, not a promise that reading this method waits.
    pub fn tasks_wait(&self, handle: TaskAskHandle) -> MemoryResult<TaskAskWait> {
        match self.tasks_ask_status(handle)? {
            TaskAskStatus::Pending { .. } => {
                let mut wait = peer_result_wait(handle.group_ref);
                wait.effect = crate::code_run::SelfEffect::TasksWait;
                Ok(TaskAskWait::Park(wait))
            }
            status => Ok(TaskAskWait::Ready(status)),
        }
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

fn ask_request_digest(actor: EntityId, input: &TaskAskSpec) -> MemoryResult<String> {
    let target = match &input.target {
        TaskAskTarget::Authority(scope) => {
            let bound = GrantBound::action(
                ActorBound::new(actor.to_hex())?,
                scope.class.clone(),
                scope.envelope.clone(),
            )?;
            rmpv::Value::Array(vec![
                rmpv::Value::from("authority"),
                rmpv::Value::from(bound.digest().to_hex()),
            ])
        }
        TaskAskTarget::Responder(assignee) => rmpv::Value::Array(vec![
            rmpv::Value::from(assignee.as_str()),
            assignee
                .entity_ref()
                .map_or(rmpv::Value::Nil, |id| rmpv::Value::from(id.to_hex())),
        ]),
    };
    let mut fields = vec![
        target,
        rmpv::Value::from(input.question_ref.short_ref()),
        rmpv::Value::Array(
            input
                .context_refs
                .iter()
                .map(|r| rmpv::Value::from(r.short_ref()))
                .collect(),
        ),
        rmpv::Value::from(input.deadline_at),
    ];
    fields.push(
        input
            .label
            .as_ref()
            .map_or(rmpv::Value::Nil, |v| rmpv::Value::from(v.as_str())),
    );
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &rmpv::Value::Array(fields))
        .map_err(|_| MemoryError::bad_request("ask request encoding"))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}
