//! The highway's Status arm (OF-220): any handle's status, and a poll.
//!
//! Computed per read from the rows that hold the truth (the pending tray,
//! the TASK, the ATTEMPT, the ask group); nothing stores a status twin. A
//! poll passes the last observation digest back as `after` and gets
//! `Unchanged` when nothing moved. A read takes no lease and writes nothing,
//! and an actor the facts do not name gets the not-found shape.

use crate::attempt_queue::{AttemptQueue, AttemptRecord};
use crate::claim::{CallerLocality, ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::memory::{Memory, MemoryResult};

use super::ask_types::{TaskAskHandle, TaskAskStatus};
use super::consts::{
    TASK_BRIEF_PROPOSAL_PREDICATE, TASK_CREATE_PROPOSAL_PREDICATE, TASK_EXTERNAL_ATTEMPT_KIND,
    TASK_REALIZE_ATTEMPT_KIND, TASK_SETTLE_ID_DOMAIN,
};
use super::create_validation::task_route_dedupe_key;
use super::highway::{attempt_hex, lease_owner_for, not_found, phase_of};
use super::highway_accept::{Lane, lane_of};
use super::highway_types::{
    AttemptHandle, AttemptView, TaskCallReceipt, TaskHandle, TaskOutcome, TaskPhase,
    TaskStatusQuery, TaskStatusView,
};
use super::terminal_state::TaskExecutionState;
use super::wire_decode::task_verb_body_in;

/// Domain of a status view's observation digest.
const OBSERVED_DOMAIN: &[u8] = b"oneiron.tasks.status.observed.v1";

/// What one status read found.
enum StatusRead {
    View(TaskStatusView, Vec<TaskHandle>),
    Rejected,
    WrongNode,
}

/// A view with its observation digest stamped over everything else in it.
fn observed(mut view: TaskStatusView) -> TaskStatusView {
    view.observed = [0; 32];
    let bytes = rmp_serde::to_vec_named(&view).unwrap_or_default();
    let mut hasher = blake3::Hasher::new();
    hasher.update(OBSERVED_DOMAIN);
    hasher.update(&bytes);
    view.observed = *hasher.finalize().as_bytes();
    view
}

impl Memory<'_> {
    pub(super) fn highway_status(&self, query: TaskStatusQuery) -> MemoryResult<TaskCallReceipt> {
        let read = match query.handle {
            TaskHandle::Proposed { proposal_ref } => {
                self.proposal_status(query.handle, proposal_ref)?
            }
            TaskHandle::Task { task_ref } => self.task_status(query.handle, task_ref, None)?,
            TaskHandle::Attempt(handle) => {
                self.task_status(query.handle, handle.task_ref, Some(handle))?
            }
            TaskHandle::Ask { group_ref } => self.ask_group_status(query.handle, group_ref)?,
        };
        let (outcome, related) = match read {
            StatusRead::View(view, related) => {
                let view = observed(view);
                if query.after == Some(view.observed) {
                    (TaskOutcome::Unchanged, related)
                } else {
                    (TaskOutcome::Snapshot(Box::new(view)), related)
                }
            }
            StatusRead::Rejected => (TaskOutcome::Rejected { decision_ref: None }, Vec::new()),
            StatusRead::WrongNode => (TaskOutcome::WrongNode, Vec::new()),
        };
        Ok(TaskCallReceipt {
            handle: query.handle,
            related,
            outcome,
            receipt_ref: None,
            lifecycle: None,
            idempotent_replay: false,
        })
    }

    /// A proposal's status: the TASK it landed as, once it landed;
    /// otherwise pending in the tray, or rejected. Readable by its proposer
    /// and the vault owner.
    fn proposal_status(
        &self,
        handle: TaskHandle,
        proposal_ref: EntityId,
    ) -> MemoryResult<StatusRead> {
        let (landed, pending, rejected) = {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            let Some(claim) = self.vault().get_claim_in_txn(&txn, &proposal_ref)? else {
                return Err(not_found());
            };
            if claim.predicate != TASK_CREATE_PROPOSAL_PREDICATE
                && claim.predicate != TASK_BRIEF_PROPOSAL_PREDICATE
            {
                return Err(not_found());
            }
            let proposer = crate::claim::session_claim_producer(&claim);
            if proposer != Some(self.actor()) && self.verify_owner_in_txn(&txn).is_err() {
                return Err(not_found());
            }
            let landed = if claim.predicate == TASK_CREATE_PROPOSAL_PREDICATE {
                let task_ref = EntityId::derive(TASK_SETTLE_ID_DOMAIN, &[proposal_ref.as_bytes()])?;
                task_verb_body_in(self.vault(), &txn, task_ref)?.map(|_| task_ref)
            } else {
                None
            };
            let pending = self
                .vault()
                .store
                .pending_gate_consent_in_txn(&txn, &proposal_ref)?
                .is_some();
            let rejected = claim.approval == ClaimApprovalStatus::Rejected
                || claim.lifecycle == ClaimLifecycleStatus::Retracted;
            (landed, pending, rejected)
        };
        if let Some(task_ref) = landed {
            return Ok(match self.task_status(handle, task_ref, None)? {
                StatusRead::View(view, mut related) => {
                    related.push(TaskHandle::Task { task_ref });
                    StatusRead::View(view, related)
                }
                other => other,
            });
        }
        if rejected {
            return Ok(StatusRead::Rejected);
        }
        // An off-device caller sees no device-local pending row, the filter
        // `pending_writes` applies.
        let pending = pending
            && !(self.locality() == CallerLocality::OffDevice
                && self.vault().device_local_keeps(&proposal_ref)?);
        Ok(StatusRead::View(
            TaskStatusView {
                handle,
                task_ref: None,
                phase: TaskPhase::Proposed { pending },
                brief_current: None,
                brief_running: None,
                attempt: None,
                pending,
                asks: Vec::new(),
                last_receipt: None,
                observed: [0; 32],
            },
            Vec::new(),
        ))
    }

    /// A TASK's status, and its live try's. Readable by its owner and by the
    /// actors its assignment and acceptance facts name.
    fn task_status(
        &self,
        handle: TaskHandle,
        task_ref: EntityId,
        attempt: Option<AttemptHandle>,
    ) -> MemoryResult<StatusRead> {
        if self.credential_withholds(task_ref)? {
            return Err(not_found());
        }
        let (body, generation) = {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            let Some(body) = task_verb_body_in(self.vault(), &txn, task_ref)? else {
                return Err(not_found());
            };
            let standing = self
                .vault()
                .task_standing_in(&txn, task_ref)?
                .ok_or_else(not_found)?;
            let actor = self.actor();
            let readable = standing.owner == actor
                || standing.assignee == Some(actor)
                || standing.taker.is_some_and(|taker| taker.actor == actor);
            if !readable {
                return Err(not_found());
            }
            let generation = self.vault().actor_binding_generation_in_txn(&txn, actor)?;
            (body, generation)
        };
        let queue = AttemptQueue::new(self.vault());
        let live: Option<AttemptRecord> = match attempt {
            Some(handle) => match queue.get(handle.attempt_ref)? {
                Some(record) if record.task_ref.as_deref() == Some(task_ref.to_hex().as_str()) => {
                    Some(record)
                }
                Some(_) => return Err(not_found()),
                None => return Ok(StatusRead::WrongNode),
            },
            None => {
                let dedupe = task_route_dedupe_key(task_ref);
                match (lane_of(body.assignee), body.assignee) {
                    (Lane::External, _) => {
                        queue.pending_task_route(TASK_EXTERNAL_ATTEMPT_KIND, &dedupe, task_ref)?
                    }
                    (Lane::Runner, None | Some(super::verb_kind::TaskAssignee::Dreamer)) => {
                        queue.pending_task_route(TASK_REALIZE_ATTEMPT_KIND, &dedupe, task_ref)?
                    }
                    _ => None,
                }
            }
        };
        let mine = lease_owner_for(self.actor(), generation.as_ref());
        let brief_running = live
            .as_ref()
            .filter(|record| record.kind == TASK_EXTERNAL_ATTEMPT_KIND)
            .map(|record| super::external_attempt::decode(&record.payload))
            .transpose()?
            .and_then(|input| input.brief);
        let attempt_view = live.as_ref().map(|record| AttemptView {
            attempt_ref: attempt_hex(record.id),
            state: record.state.as_str().to_owned(),
            attempt_count: record.attempt_count,
            yours: record.lease_owner.as_deref() == Some(mine.as_str()),
            claimed_at: record.claimed_at,
            backoff_until: record.scheduled_at,
        });
        let mut asks = Vec::new();
        if let Some(TaskExecutionState::Blocked { on, .. }) = &body.state {
            for wait in on {
                let group = TaskAskHandle { group_ref: *wait };
                if let Ok(status) = self.tasks_ask_status(group) {
                    asks.push((group, status));
                }
            }
        }
        Ok(StatusRead::View(
            TaskStatusView {
                handle,
                task_ref: Some(task_ref),
                phase: phase_of(&body),
                brief_current: body.brief.as_ref().map(super::brief::StoredBrief::stamp),
                brief_running,
                attempt: attempt_view,
                pending: false,
                asks,
                last_receipt: None,
                observed: [0; 32],
            },
            Vec::new(),
        ))
    }

    /// An ask group's status, through the ask door's own reader checks.
    fn ask_group_status(
        &self,
        handle: TaskHandle,
        group_ref: EntityId,
    ) -> MemoryResult<StatusRead> {
        let group = TaskAskHandle { group_ref };
        let status = self.tasks_ask_status(group)?;
        let settled = matches!(status, TaskAskStatus::Settled(_));
        Ok(StatusRead::View(
            TaskStatusView {
                handle,
                task_ref: None,
                phase: TaskPhase::Asked { settled },
                brief_current: None,
                brief_running: None,
                attempt: None,
                pending: !settled,
                asks: vec![(group, status)],
                last_receipt: None,
                observed: [0; 32],
            },
            Vec::new(),
        ))
    }
}
