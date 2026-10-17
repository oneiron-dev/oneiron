//! The highway's Accept arm (OF-220): take a TASK addressed to you.
//!
//! Accept splits by route lane, because the human lane executes nothing
//! and an attempt is one try on one seat. A peer or child takes an external
//! try on its own node under a lease owner the engine derives from its
//! actor and binding generation; a person records the Accepted fact alone;
//! the Dreamer and agent-definition runners keep leasing their own tries
//! and accept through their host binding. The queue stays plumbing no agent
//! touches: only a named TASK's own try is ever leased here.

use crate::Vault;
use crate::attempt_queue::{
    AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome, EnqueueAttempt,
    EnqueueOutcome,
};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::task_authority::{
    BindingGeneration, TaskAuthorityFact, TaskAuthorityFactKind, TaskStanding,
    put_task_authority_fact_in_txn,
};

use super::brief::StoredBrief;
use super::consts::TASK_EXTERNAL_ATTEMPT_KIND;
use super::create_validation::{task_body_in_txn, task_route_dedupe_key};
use super::highway::{
    attempt_handle, attempt_hex, forbidden, generation_digest, invalid_state, lease_owner_for,
    local_node_in, not_found, qualified_key, stamp_fields,
};
use super::highway_types::{
    HostBinding, TaskAccept, TaskCallReceipt, TaskHandle, TaskOutcome, TaskVia,
};
use super::terminal_state::TaskExecutionState;
use super::verb_kind::{TaskAssignee, TaskKind};

/// How one TASK's work is taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Lane {
    /// Dreamer and agent-definition work: the engine's runner leases its
    /// own try and reaches the highway through its host binding.
    Runner,
    /// Peer and child work: an external try on the taker's node.
    External,
    /// A person: the Accepted fact is the fence.
    Human,
}

pub(super) const fn lane_of(assignee: Option<TaskAssignee>) -> Lane {
    match assignee {
        None | Some(TaskAssignee::Dreamer | TaskAssignee::AgentDef { .. }) => Lane::Runner,
        Some(TaskAssignee::Peer { .. } | TaskAssignee::Child { .. }) => Lane::External,
        Some(TaskAssignee::Human { .. }) => Lane::Human,
    }
}

/// A host binding checked against the try realizing one TASK.
pub(super) enum HostFence {
    Held(AttemptRecord),
    Stale,
    Missing,
}

/// Under `Host` the fence is the runner's own lease: the parent attempt
/// must realize this TASK and still be held by the binding's owner and
/// generation.
pub(super) fn host_fence_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    binding: &HostBinding,
    task_hex: &str,
) -> MemoryResult<HostFence> {
    let Some(record) = AttemptQueue::new(vault).get_in_txn(txn, binding.parent())? else {
        return Ok(HostFence::Missing);
    };
    if record.task_ref.as_deref() != Some(task_hex) {
        return Err(forbidden(
            "this host's attempt does not realize the task",
            "Report against the task your own attempt realizes.",
        ));
    }
    Ok(
        if record.state.is_running()
            && record.lease_owner.as_deref() == Some(binding.lease_owner())
            && record.attempt_count == binding.attempt_count()
        {
            HostFence::Held(record)
        } else {
            HostFence::Stale
        },
    )
}

/// The checks every Accept and Report runs on the TASK itself: a live
/// standard task, not an ask, not cancelled.
pub(super) fn require_live_standard(
    body: &super::consult_result::TaskVerbBody,
    standing: &TaskStanding,
) -> MemoryResult<()> {
    if body.task_kind() != TaskKind::Standard {
        return Err(invalid_state(
            "a consult or reconciliation task settles through its own door",
            "Use the consult or reconciliation verbs for this task.",
        ));
    }
    if body.terminal().is_some() || body.settled_ladder_disposition().is_some() {
        return Err(invalid_state(
            "task is already terminal",
            "Read the settled terminal record; a terminal task takes no more work.",
        ));
    }
    if standing.cancelled {
        return Err(invalid_state(
            "task was cancelled",
            "A cancelled task takes no more work.",
        ));
    }
    Ok(())
}

/// The addressed-lane proof: the immutable facts name this actor. The owner
/// is told why; anyone else gets the not-found shape.
pub(super) fn require_assignee(
    standing: &TaskStanding,
    actor: crate::EntityId,
) -> MemoryResult<()> {
    if standing.assignee == Some(actor) {
        Ok(())
    } else if standing.owner == actor {
        Err(forbidden(
            "only the actor this task is assigned to takes it",
            "The assignee accepts and reports; the owner reads its status.",
        ))
    } else {
        Err(not_found())
    }
}

enum Accepted {
    Taken {
        attempt: Option<AttemptRecord>,
        replay: bool,
        lease_owner: Option<String>,
    },
    HeldByOther {
        since: u64,
    },
    Stale,
    WrongNode,
}

/// What one Accept's transaction did, for its receipt.
struct AcceptStep {
    accepted: Accepted,
    brief: Option<StoredBrief>,
    node: Option<crate::EntityId>,
    generation: Option<BindingGeneration>,
}

impl Memory<'_> {
    pub(super) fn highway_accept(
        &self,
        via: &TaskVia,
        accept: TaskAccept,
    ) -> MemoryResult<TaskCallReceipt> {
        let key = qualified_key(via, &accept.intent_key, "intent key")?;
        let task_ref = accept.task_ref;
        if self.credential_withholds(task_ref)? {
            return Err(not_found());
        }
        if super::ask_record::ask_is_terminal(self.vault(), task_ref)?.is_some() {
            return Err(invalid_state(
                "an ask is answered with tasks.answer, not accepted",
                "Answer the ask through its handle.",
            ));
        }
        let now = self.vault().now_recorded_at();
        let step = self
            .with_verified_actor_write_txn(|wtxn| self.accept_in_txn(wtxn, via, task_ref, now))?;
        let receipt = self.accept_receipt(via, task_ref, key, step, now)?;
        if matches!(receipt.outcome, TaskOutcome::Accepted { .. }) && !receipt.idempotent_replay {
            self.vault().store.notify_attempt_observers();
            self.vault().store.notify_task_updates([task_ref]);
        }
        Ok(receipt)
    }

    /// Accept inside a write transaction the caller holds and verified: a
    /// runner takes its TASK in the commit that leases its try (R1). The
    /// caller's commit announces it.
    pub(super) fn accept_in_runner_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        via: &TaskVia,
        task_ref: crate::EntityId,
        key: String,
    ) -> MemoryResult<TaskCallReceipt> {
        let now = self.vault().now_recorded_at();
        let step = self.accept_in_txn(wtxn, via, task_ref, now)?;
        self.accept_receipt(via, task_ref, key, step, now)
    }

    /// One Accept's transaction: the lane's proof, the take, and on a new
    /// take the Working body and the Accepted fact.
    fn accept_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        via: &TaskVia,
        task_ref: crate::EntityId,
        now: u64,
    ) -> MemoryResult<AcceptStep> {
        let task_hex = task_ref.to_hex();
        let queue = AttemptQueue::new(self.vault());
        let mut body = task_body_in_txn(self.vault(), &*wtxn, task_ref)?;
        let standing = self
            .vault()
            .task_standing_in(&*wtxn, task_ref)?
            .ok_or_else(not_found)?;
        let lane = lane_of(body.assignee);
        if lane != Lane::Runner {
            require_assignee(&standing, self.actor())?;
        }
        require_live_standard(&body, &standing)?;
        let generation = self
            .vault()
            .actor_binding_generation_in_txn(&*wtxn, self.actor())?;
        let node = local_node_in(self.vault(), &*wtxn)?;
        // A replay is the same taker, under the same bindings, on a TASK
        // still taken: after a release the next accept is a new take.
        let taken_before = standing
            .taker
            .is_some_and(|taker| taker.actor == self.actor() && taker.generation == generation)
            && matches!(
                body.state,
                Some(TaskExecutionState::Working { .. } | TaskExecutionState::Blocked { .. })
            );
        let accepted = match (lane, via) {
            (Lane::Runner, TaskVia::Wire) => {
                return Err(invalid_state(
                    "the engine's runner takes this task; it is not addressed to an external taker",
                    "Address the task to a peer, child or person to take it over the wire.",
                ));
            }
            (Lane::Runner, TaskVia::Host(binding)) => {
                match host_fence_in(self.vault(), &*wtxn, binding, &task_hex)? {
                    HostFence::Held(record) => Accepted::Taken {
                        attempt: Some(record),
                        replay: taken_before,
                        lease_owner: Some(binding.lease_owner().to_owned()),
                    },
                    HostFence::Stale => Accepted::Stale,
                    HostFence::Missing => Accepted::WrongNode,
                }
            }
            (Lane::Human, _) => Accepted::Taken {
                attempt: None,
                replay: taken_before,
                lease_owner: None,
            },
            (Lane::External, _) => {
                let lease_owner = lease_owner_for(self.actor(), generation.as_ref());
                // The try freezes the brief revision and the TASK's team run;
                // an existing try keeps the payload it was enqueued with.
                let payload = super::external_attempt::encode(
                    body.brief.as_ref().map(StoredBrief::stamp),
                    body.team.clone(),
                )?;
                let enqueued = queue.enqueue_with_task_ref_and_dedupe_actor_in_txn(
                    wtxn,
                    EnqueueAttempt {
                        kind: TASK_EXTERNAL_ATTEMPT_KIND.to_owned(),
                        payload,
                        dedupe_key: Some(task_route_dedupe_key(task_ref)),
                        run_id: None,
                        now,
                    },
                    Some(task_hex.clone()),
                    None,
                )?;
                let (EnqueueOutcome::Enqueued(record) | EnqueueOutcome::Existing(record)) =
                    enqueued;
                match record.state {
                    AttemptState::Leased | AttemptState::Landing => {
                        if record.lease_owner.as_deref() == Some(lease_owner.as_str()) {
                            Accepted::Taken {
                                attempt: Some(record),
                                replay: true,
                                lease_owner: Some(lease_owner),
                            }
                        } else {
                            Accepted::HeldByOther {
                                since: record.claimed_at.unwrap_or(record.updated_at),
                            }
                        }
                    }
                    AttemptState::Queued | AttemptState::Scheduled => {
                        match queue.claim_for_task_in_txn(
                            wtxn,
                            record.id,
                            &task_hex,
                            TASK_EXTERNAL_ATTEMPT_KIND,
                            ClaimAttempt {
                                lease_owner: lease_owner.clone(),
                                now,
                            },
                        )? {
                            ClaimOutcome::Claimed(record) => Accepted::Taken {
                                attempt: Some(record),
                                replay: false,
                                lease_owner: Some(lease_owner),
                            },
                            ClaimOutcome::Empty => {
                                // OF-368: a TASK answering an unattached
                                // comment waits, so the claim held its try
                                // instead of leasing it. The refusal rolls
                                // the accept back with that pause.
                                if self
                                    .vault()
                                    .annotation_task_hold_in_txn(&*wtxn, &task_ref)?
                                    .is_some()
                                {
                                    return Err(invalid_state(
                                        "this task waits while its comment is unattached",
                                        "Accept again once the comment is reattached.",
                                    ));
                                }
                                return Err(invalid_state(
                                    "this task's next try is not ready yet",
                                    "Accept again once its backoff has passed.",
                                ));
                            }
                        }
                    }
                    _ => {
                        return Err(invalid_state(
                            "this task's try is paused or already settled",
                            "Read the task's status, then accept again.",
                        ));
                    }
                }
            }
        };
        let brief = body.brief.clone();
        if let Accepted::Taken { replay: false, .. } = &accepted {
            if matches!(body.state, None | Some(TaskExecutionState::Queued)) {
                body.state = Some(TaskExecutionState::Working { started_at: now });
                self.rewrite_task_in_txn(wtxn, task_ref, body, now)?;
            }
            put_task_authority_fact_in_txn(
                self.vault(),
                wtxn,
                TaskAuthorityFact {
                    task_ref,
                    kind: TaskAuthorityFactKind::Accepted,
                    actor_ref: self.actor(),
                    assigned_ref: None,
                    actor_generation: generation,
                    assigned_generation: None,
                    occurred_at: now,
                },
            )
            .map_err(MemoryError::from)?;
        }
        Ok(AcceptStep {
            accepted,
            brief,
            node,
            generation,
        })
    }

    /// The receipt one Accept owes.
    fn accept_receipt(
        &self,
        via: &TaskVia,
        task_ref: crate::EntityId,
        key: String,
        step: AcceptStep,
        now: u64,
    ) -> MemoryResult<TaskCallReceipt> {
        let AcceptStep {
            accepted,
            brief,
            node,
            generation,
        } = step;
        let mut lifecycle =
            self.lifecycle_record(via, "accept", "accepted", Some(task_ref), None, now);
        stamp_fields(&mut lifecycle.fields, brief.as_ref());
        lifecycle.fields.insert("intent_key".to_owned(), key);
        lifecycle.fields.insert(
            "actor_generation".to_owned(),
            generation_digest(generation.as_ref()),
        );
        let task = TaskHandle::Task { task_ref };
        let (handle, related, outcome, replay) = match accepted {
            Accepted::Taken {
                attempt,
                replay,
                lease_owner,
            } => {
                let handle = attempt
                    .as_ref()
                    .map(|record| attempt_handle(task_ref, record, node));
                if let Some(record) = &attempt {
                    lifecycle.job_ref = Some(attempt_hex(record.id));
                    lifecycle
                        .fields
                        .insert("attempt_count".to_owned(), record.attempt_count.to_string());
                    if let Some(retry_of) = record.retry_of {
                        lifecycle
                            .fields
                            .insert("retry_of".to_owned(), attempt_hex(retry_of));
                    }
                    // OF-540: the realizing attempt's frozen team run, never
                    // the project's current pattern.
                    if let Some(team) = crate::agent_dispatch::attempt_team_stamp(record)? {
                        crate::receipt::append_team_receipt_fields(&mut lifecycle.fields, &team);
                    }
                }
                if let Some(lease_owner) = lease_owner {
                    lifecycle
                        .fields
                        .insert("lease_owner".to_owned(), lease_owner);
                }
                if let Some(node) = node {
                    lifecycle.fields.insert("node".to_owned(), node.to_hex());
                }
                (
                    handle.map_or(task, TaskHandle::Attempt),
                    if handle.is_some() {
                        vec![task]
                    } else {
                        Vec::new()
                    },
                    TaskOutcome::Accepted { attempt: handle },
                    replay,
                )
            }
            Accepted::HeldByOther { since } => {
                lifecycle.outcome = "held_by_other".to_owned();
                (task, Vec::new(), TaskOutcome::HeldByOther { since }, false)
            }
            Accepted::Stale => {
                lifecycle.outcome = "stale_fence".to_owned();
                (task, Vec::new(), TaskOutcome::StaleFence, false)
            }
            Accepted::WrongNode => {
                lifecycle.outcome = "wrong_node".to_owned();
                (task, Vec::new(), TaskOutcome::WrongNode, false)
            }
        };
        Ok(TaskCallReceipt {
            handle,
            related,
            outcome,
            receipt_ref: None,
            lifecycle: Some(lifecycle),
            idempotent_replay: replay,
        })
    }
}
