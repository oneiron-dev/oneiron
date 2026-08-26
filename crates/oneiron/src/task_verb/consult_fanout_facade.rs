use rmpv::Value;

use crate::entity_id::EntityId;
use crate::gate::PolicyApprovalCeiling;
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult,
    OutboundDraftInput, facade_provenance, verify_actor_binding,
};
use crate::registry::{ENTITY_TYPE_TASK, ENTITY_TYPE_TURN};
use crate::temporal::TimeRange;
use crate::unix_seconds_now;

use super::consts::{CONSULT_SETTLE_PAGE, TASK_FOLLOW_UP_STAGE_CONSULT_EXPIRED};
use super::consult_payload::{ConsultPayload, ConsultRecovery};
use super::consult_result::{
    ConsultDigestRoute, ConsultExpiryReport, ConsultFanOutReceipt, ConsultFanOutSpec,
};
use super::create_spec::{TaskCreateRateLimit, TaskCreateSpec};
use super::create_validation::{
    consult_body_in_txn, consult_refusal, require_resolved_entity, validate_task_create,
};
use super::follow_up::{
    consult_expiry_artifact_value, set_task_follow_up_marker_in_txn, task_follow_up_dedupe_key,
    task_follow_up_marker,
};
use super::rate_limit::{consume_create_rate_slot, task_actor_ceiling, task_verb_contract};
use super::terminal_state::{TaskExecutionState, TaskTerminalDisposition, TaskTerminalRecord};
use super::verb_kind::{TaskAssignee, TaskKind, TaskTtl, TasksVerb};
use super::wire_decode::task_verb_body;
use super::wire_encode::{canonical_bytes, encode_task_verb_body};

impl Memory<'_> {
    /// Fans one question out to N distinct peer actors as N independent consult
    /// TASKs sharing one correlation ref. Each task has its own assignee,
    /// deadline, terminal state, and result. There is no consult budget: a
    /// missing budget never blocks consult creation.
    pub fn fan_out_consults(
        &self,
        input: &ConsultFanOutSpec,
    ) -> MemoryResult<ConsultFanOutReceipt> {
        let verb = task_verb_contract(TasksVerb::Create);
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let now = input.now.unwrap_or_else(unix_seconds_now);
        let provenance = facade_provenance(verb);
        if input.assignees.is_empty() {
            return Err(MemoryError::bad_request(
                "a fan-out addresses at least one peer actor",
            ));
        }
        // Deterministic assignee order, and duplicates REFUSED rather than
        // collapsed: asking one peer twice under one correlation is a caller
        // bug whose silent de-duplication would return fewer tasks than asked.
        let mut assignees = input.assignees.clone();
        assignees.sort_unstable();
        if assignees.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(MemoryError::bad_request(
                "fan-out assignees must be distinct peer actors",
            ));
        }
        let correlation_ref = EntityId::now();
        let validated = assignees
            .iter()
            .map(|actor_ref| {
                validate_task_create(
                    self.vault(),
                    &TaskCreateSpec::new(Value::Nil, input.label.clone(), None, Some(now))
                        .with_kind(TaskKind::Consult)
                        .with_consult(ConsultPayload::question(
                            input.question_ref,
                            input.context_refs.clone(),
                            correlation_ref,
                        ))
                        .with_assignee(TaskAssignee::Peer {
                            actor_ref: *actor_ref,
                        })
                        .with_ttl(TaskTtl::at(input.deadline_at)),
                    now,
                )
            })
            .collect::<MemoryResult<Vec<_>>>()?;

        let rate_now = unix_seconds_now();
        let task_refs = self.with_verified_actor_write_txn(|wtxn| {
            let ceiling =
                task_actor_ceiling(self.vault(), &*wtxn, self.actor(), self.actor_class())?;
            if ceiling != PolicyApprovalCeiling::Auto {
                return Err(consult_refusal(
                    MEMORY_CODE_FORBIDDEN,
                    "fan-out requires an auto-ceiling actor",
                    "Create the consults individually so each surfaces its own proposal.",
                ));
            }
            let mut task_refs = Vec::with_capacity(validated.len());
            for entry in &validated {
                // All-or-nothing: a quota refusal mid-fan-out aborts the whole
                // transaction rather than minting a silent subset.
                if !consume_create_rate_slot(
                    self.vault(),
                    wtxn,
                    self.actor(),
                    rate_now,
                    TaskCreateRateLimit::default(),
                )? {
                    return Err(consult_refusal(
                        MEMORY_CODE_INVALID_STATE,
                        "fan-out exceeds the actor's create quota for this window",
                        "Retry the whole fan-out in the next window.",
                    ));
                }
                task_refs.push(self.mint_task_in_txn(
                    wtxn,
                    entry,
                    input.label.clone(),
                    self.actor(),
                    &provenance,
                    now,
                )?);
            }
            Ok(task_refs)
        })?;

        Ok(ConsultFanOutReceipt {
            correlation_ref,
            task_refs,
        })
    }

    /// Reconciles consults whose absolute deadline has passed: local
    /// compare-and-set to terminal `Expired` with a durable expiry artifact,
    /// then ONE ARCH-0046 digest per task through the existing outbound facade.
    ///
    /// Engine-owned; it never enters `TASKS_VERBS`. It walks TASK ids through
    /// the bounded `entities_by_type_page` primitive rather than adding another
    /// unpaged TASK scan, and it re-drives an already-expired task whose digest
    /// marker is absent — closing the crash window between terminalization and
    /// outbound scheduling.
    pub fn settle_due_consults(
        &self,
        now: u64,
        digest_route: &ConsultDigestRoute,
    ) -> MemoryResult<ConsultExpiryReport> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        // ARCH-0046 O3: a degrade is receipted WITH a way forward. A digest
        // carrying no recovery choice is a dead end, so it is refused here
        // rather than delivered as one.
        if digest_route.recovery.is_empty() {
            return Err(MemoryError::bad_request(
                "an expiry digest must carry at least one typed recovery choice",
            ));
        }
        for choice in &digest_route.recovery {
            if let ConsultRecovery::TryPeer(actor_ref) = choice {
                require_resolved_entity(self.vault(), *actor_ref)?;
            }
        }

        let mut report = ConsultExpiryReport {
            expired_task_refs: Vec::new(),
            digest_intent_refs: Vec::new(),
            already_settled: 0,
        };
        let mut undigested: Vec<(EntityId, EntityId)> = Vec::new();
        let mut cursor: Option<EntityId> = None;
        loop {
            let page = self.vault().entities_by_type_page(
                ENTITY_TYPE_TASK,
                cursor.as_ref(),
                CONSULT_SETTLE_PAGE,
            )?;
            let exhausted = page.len() < CONSULT_SETTLE_PAGE;
            cursor = page.last().copied();
            for task_ref in page {
                // One malformed body must not wedge the sweep for every other
                // consult — the same degrade `tasks.check` already applies.
                let Ok(Some(body)) = task_verb_body(self.vault(), task_ref) else {
                    continue;
                };
                if body.task_kind() != TaskKind::Consult {
                    continue;
                }
                let Some(ttl) = body.ttl else {
                    continue;
                };
                if ttl.deadline_at >= now {
                    continue;
                }
                match body.terminal() {
                    // Answered (or otherwise settled) before the deadline swept
                    // it: nothing is due.
                    Some(record) if record.disposition != TaskTerminalDisposition::Expired => {
                        continue;
                    }
                    Some(record) => {
                        let Some(result_ref) = record.result_ref else {
                            continue;
                        };
                        if task_follow_up_marker(
                            self.vault(),
                            task_ref,
                            TASK_FOLLOW_UP_STAGE_CONSULT_EXPIRED,
                        )? {
                            report.already_settled += 1;
                        } else {
                            undigested.push((task_ref, result_ref));
                        }
                    }
                    // Settled on the OTHER axis: a deferring ladder terminal
                    // handed the case to a follow-on and left the TASK row live
                    // on purpose. That consult is answered, so the deadline has
                    // nothing to expire and nothing to digest. The write door
                    // asks the same question again inside its own transaction,
                    // which is the half that holds against an escalation
                    // landing after this page was read.
                    None if body.settled_ladder_disposition().is_some() => continue,
                    None => {
                        if let Some(result_ref) =
                            self.expire_consult_in_txn(task_ref, now, digest_route)?
                        {
                            report.expired_task_refs.push(task_ref);
                            undigested.push((task_ref, result_ref));
                        }
                    }
                }
            }
            if exhausted {
                break;
            }
        }

        for (task_ref, result_ref) in undigested {
            let key = task_follow_up_dedupe_key(task_ref, TASK_FOLLOW_UP_STAGE_CONSULT_EXPIRED);
            let receipt = self.schedule_outbound(&OutboundDraftInput {
                verb: digest_route.verb.clone(),
                channel: digest_route.channel.clone(),
                target: digest_route.target.clone(),
                on_behalf_of: digest_route.on_behalf_of.clone(),
                // Outbound copy renders from typed state, never from prose
                // assembled here.
                content_ref: Some(result_ref.to_hex()),
                idempotency_key: Some(key.clone()),
                dedupe_key: Some(key),
                trigger: "gap_queue".to_owned(),
                trigger_ref: task_ref.to_hex(),
                job_ref: None,
                occurred_at: Some(now),
            })?;
            report.digest_intent_refs.push(receipt.intent_ref);
            // The marker lands AFTER the schedule, deliberately: a crash in
            // between leaves a marker-less expired task that the next sweep
            // re-drives, and the outbound idempotency key coalesces the retry.
            self.with_verified_actor_write_txn(|wtxn| {
                set_task_follow_up_marker_in_txn(
                    self.vault(),
                    wtxn,
                    task_ref,
                    TASK_FOLLOW_UP_STAGE_CONSULT_EXPIRED,
                )
                .map_err(MemoryError::from)
            })?;
        }
        Ok(report)
    }

    /// Compare-and-set one unanswered consult to terminal `Expired` and mint
    /// its durable expiry artifact in the same transaction. Returns `None` when
    /// the task settled between the page read and this write.
    ///
    /// "Settled" is asked on BOTH axes, and the ladder half is asked HERE
    /// rather than only at the sweep: the page read happens outside this
    /// transaction, so an escalation that lands in that gap is only visible to
    /// the re-read. Overwriting it would replace an immutable settled ladder
    /// with a bare `Expired` record, and no adversary is needed for it — only
    /// a deadline.
    fn expire_consult_in_txn(
        &self,
        task_ref: EntityId,
        now: u64,
        digest_route: &ConsultDigestRoute,
    ) -> MemoryResult<Option<EntityId>> {
        self.with_verified_actor_write_txn(|wtxn| {
            let mut body = consult_body_in_txn(self.vault(), &*wtxn, task_ref)?;
            if body.terminal().is_some() || body.settled_ladder_disposition().is_some() {
                return Ok(None);
            }
            let result_ref = EntityId::now();
            let artifact = canonical_bytes(&consult_expiry_artifact_value(
                task_ref,
                body.ttl.map_or(now, |ttl| ttl.deadline_at),
                now,
                &digest_route.recovery,
            ));
            let occurred = TimeRange {
                start: now,
                end: now,
            };
            self.vault()
                .batch_in()
                .put(&result_ref, ENTITY_TYPE_TURN, occurred, now, &artifact)
                .apply(wtxn)?;
            body.state = Some(TaskExecutionState::Terminal(TaskTerminalRecord {
                disposition: TaskTerminalDisposition::Expired,
                result_ref: Some(result_ref),
                summary: None,
                finished_at: now,
                ladder: None,
                counter_task_ref: None,
            }));
            let encoded = encode_task_verb_body(body);
            self.put_task_body_in_txn(wtxn, task_ref, &encoded, now)?;
            // ONE-1702 SEAM (own-task settlement → WAKE/CARRIER): second
            // producer call site for `mint_own_task_event` → `route_event`.
            // See `land_consult_result` for why it is not called on this base.
            Ok(Some(result_ref))
        })
    }
}
