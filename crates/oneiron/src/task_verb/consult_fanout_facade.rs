use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::memory::{MemoryResult, OutboundDraftInput};
use crate::registry::{ENTITY_TYPE_TASK, ENTITY_TYPE_TURN};
use crate::temporal::TimeRange;

use super::consts::{CONSULT_SETTLE_PAGE, TASK_FOLLOW_UP_STAGE_CONSULT_EXPIRED};
use super::consult_assignee_wait::waits_for_assignee_fact;
use super::consult_result::{CONSULT_EXPIRY_RECOVERY, ConsultDigestRoute, ConsultExpiryReport};
use super::create_validation::consult_body_in_txn;
use super::follow_up::{
    consult_expiry_artifact_value, set_task_follow_up_marker_in_txn, task_follow_up_dedupe_key,
    task_follow_up_marker,
};
use super::rate_limit::task_create_owner;
use super::terminal_state::{
    TaskExecutionState, TaskLapseCause, TaskTerminalDisposition, TaskTerminalRecord,
};
use super::verb_kind::TaskKind;
use super::wire_decode::task_verb_body;
use super::wire_encode::{canonical_bytes, encode_task_verb_body};

impl Vault {
    /// Reconciles consults whose absolute deadline has passed: local
    /// compare-and-set to terminal `Expired` with a durable expiry artifact,
    /// then ONE ARCH-0046 digest per task, addressed to that task's own asker.
    ///
    /// The expiry is an engine-caused lapse (`ConsultDeadlineElapsed`, or
    /// `ConsultAssigneeMissing` for a consult whose ConsultAssignee fact never
    /// landed): the deadline the asker set has passed, so the clock enacts the
    /// asker's own will and no actor or authority is taken for it. Every
    /// expiry is committed before any digest work starts, so a digest that
    /// cannot be routed or scheduled never holds one back and never undoes
    /// one.
    ///
    /// `resolve_digest` is the host's native route to one asker. A task whose
    /// asker has no route, or is not the task's create owner, keeps its digest
    /// marker absent and the next pass retries it. A routed digest is
    /// scheduled as the create owner, the way ONE-1708's human follow-ups send.
    ///
    /// Engine-owned; it never enters the task catalog. It walks TASK ids through
    /// the paged `entities_by_type_page` primitive to exhaustion rather than
    /// adding another unpaged TASK scan, and it re-drives an already-expired
    /// task whose digest marker is absent — closing the crash window between
    /// terminalization and outbound scheduling.
    pub fn settle_due_consults(
        &self,
        now: u64,
        resolve_digest: &dyn Fn(EntityId) -> MemoryResult<Option<ConsultDigestRoute>>,
    ) -> MemoryResult<ConsultExpiryReport> {
        let mut report = ConsultExpiryReport {
            expired_task_refs: Vec::new(),
            digest_intent_refs: Vec::new(),
            already_settled: 0,
        };
        // Each undigested expiry keeps the asker its digest is addressed to.
        let mut undigested: Vec<(EntityId, EntityId, String)> = Vec::new();
        let mut cursor: Option<EntityId> = None;
        loop {
            let page =
                self.entities_by_type_page(ENTITY_TYPE_TASK, cursor.as_ref(), CONSULT_SETTLE_PAGE)?;
            let exhausted = page.len() < CONSULT_SETTLE_PAGE;
            cursor = page.last().copied();
            for task_ref in page {
                // One malformed body must not wedge the sweep for every other
                // consult — the same degrade `describe` already applies.
                let Ok(Some(body)) = task_verb_body(self, task_ref) else {
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
                            self,
                            task_ref,
                            TASK_FOLLOW_UP_STAGE_CONSULT_EXPIRED,
                        )? {
                            report.already_settled += 1;
                        } else {
                            undigested.push((task_ref, result_ref, body.owner_ref));
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
                        if let Some(result_ref) = self.expire_consult_in_txn(task_ref, now)? {
                            report.expired_task_refs.push(task_ref);
                            undigested.push((task_ref, result_ref, body.owner_ref));
                        }
                    }
                }
            }
            if exhausted {
                break;
            }
        }

        // Every expiry above has committed; nothing below can undo one.
        for (task_ref, result_ref, owner_ref) in undigested {
            let Ok(asker) = EntityId::from_hex(&owner_ref) else {
                continue;
            };
            // The digest is sent AS the task's create owner, so it goes only
            // to that owner: body addressing never borrows another owner's
            // sending face.
            if task_create_owner(self, task_ref)? != Some(asker) {
                continue;
            }
            let Some(route) = resolve_digest(asker)? else {
                continue;
            };
            let key = task_follow_up_dedupe_key(task_ref, TASK_FOLLOW_UP_STAGE_CONSULT_EXPIRED);
            let draft = OutboundDraftInput {
                verb: route.verb,
                channel: route.channel,
                target: route.target,
                on_behalf_of: None,
                // Outbound copy renders from typed state, never from prose
                // assembled here.
                content_ref: Some(result_ref.to_hex()),
                idempotency_key: Some(key.clone()),
                dedupe_key: Some(key),
                trigger: "gap_queue".to_owned(),
                trigger_ref: task_ref.to_hex(),
                job_ref: None,
                occurred_at: Some(now),
                mention: None,
            };
            let scheduled = self
                .memory(asker, EdgeActorClass::Agent)
                .schedule_outbound(&draft);
            // One unschedulable digest must not wedge every other asker's.
            let receipt = match scheduled {
                Ok(receipt) => receipt,
                Err(error) => {
                    tracing::debug!(
                        task_ref = %task_ref.to_hex(),
                        code = %error.code,
                        "consult expiry digest not scheduled; the next pass retries"
                    );
                    continue;
                }
            };
            report.digest_intent_refs.push(receipt.intent_ref);
            // The marker lands AFTER the schedule, deliberately: a crash in
            // between leaves a marker-less expired task that the next sweep
            // re-drives, and the outbound idempotency key coalesces the retry.
            self.with_write_txn_grouped(|wtxn| {
                set_task_follow_up_marker_in_txn(
                    self,
                    wtxn,
                    task_ref,
                    TASK_FOLLOW_UP_STAGE_CONSULT_EXPIRED,
                )
            })?;
        }
        crate::llm::reconcile_peer_result_signals(self, now)?;
        Ok(report)
    }

    /// Compare-and-set one unanswered consult to terminal `Expired` and mint
    /// its durable expiry artifact in the same transaction. Returns `None` when
    /// the task settled between the page read and this write.
    ///
    /// An engine-caused deadline lapse, written actor-free the way the trial
    /// and ask lapses write: no actor is verified or stamped, so the TASK
    /// keeps no Linear writer for it. The artifact names the cause with the
    /// deadline the asker set, re-read here with everything else.
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
    ) -> MemoryResult<Option<EntityId>> {
        self.try_with_write_txn_grouped(|wtxn| -> MemoryResult<_> {
            let mut body = consult_body_in_txn(self, &*wtxn, task_ref)?;
            if body.terminal().is_some() || body.settled_ladder_disposition().is_some() {
                return Ok(None);
            }
            let Some(ttl) = body.ttl.filter(|ttl| ttl.deadline_at < now) else {
                return Ok(None);
            };
            // A consult still waiting for its ConsultAssignee fact lapses
            // with that cause; a fold that does not read is not a missing
            // fact.
            let missing = self
                .task_authority_facts_in(&*wtxn, task_ref)
                .is_ok_and(|facts| waits_for_assignee_fact(&body, &facts));
            let cause = if missing {
                TaskLapseCause::ConsultAssigneeMissing {
                    deadline_at: ttl.deadline_at,
                }
            } else {
                TaskLapseCause::ConsultDeadlineElapsed {
                    deadline_at: ttl.deadline_at,
                }
            };
            let result_ref = self.store.clock.entity_id()?;
            let artifact = canonical_bytes(&consult_expiry_artifact_value(
                task_ref,
                cause,
                now,
                &CONSULT_EXPIRY_RECOVERY,
            ));
            let occurred = TimeRange {
                start: now,
                end: now,
            };
            self.batch_in()
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
            // The INTERNAL door: the body carries the deadline that has just
            // passed, which the public door's born-expired check refuses.
            self.batch_in()
                .put_internal(&task_ref, ENTITY_TYPE_TASK, occurred, now, &encoded)
                .apply(wtxn)?;
            // Announced after commit like every TASK put; the board
            // publisher routes the expiry to the asker.
            Ok(Some(result_ref))
        })
    }
}
