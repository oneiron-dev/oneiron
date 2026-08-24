use rmpv::Value;

use crate::claim::ClaimApprovalStatus;
use crate::consult_ladder::{
    ConsultLadderState, ConsultLineage, ConsultLineageRelation, EntityDeltaArtifact,
    LadderTerminalDisposition, LadderTransition, LadderTransitionError, transition_ladder,
};
use crate::entity_id::EntityId;
use crate::facade::{
    FACADE_CODE_FORBIDDEN, FACADE_CODE_INVALID_STATE, FacadeError, FacadeResult, MemoryFacade,
    facade_provenance, verify_actor_binding,
};
use crate::gate::PolicyApprovalCeiling;
use crate::registry::ENTITY_TYPE_TURN;
use crate::temporal::TimeRange;
use crate::unix_seconds_now;

use super::consult_result::TaskVerbBody;
use super::create_spec::{TaskCreateRateLimit, TaskCreateSpec};
use super::create_validation::{
    consult_body_in_txn, consult_refusal, require_resolved_entity, validate_task_create,
};
use super::entity_delta_facade::counter_lineage_artifact_value;
use super::follow_up::peer_handle_key;
use super::rate_limit::{consume_create_rate_slot, task_actor_ceiling, task_verb_contract};
use super::route_receipts::TaskCreateReceipt;
use super::terminal_state::{TaskExecutionState, TaskTerminalDisposition, TaskTerminalRecord};
use super::verb_kind::{TaskAssignee, TaskKind, TaskTtl, TasksVerb};
use super::wire_encode::{canonical_bytes, encode_task_verb_body};

impl MemoryFacade<'_> {
    /// Registers the DISPLAY handle for one peer actor. Board projections
    /// resolve handles through this table; TASK storage stays actor-addressed,
    /// so a renamed harness never rewrites a single consult row.
    pub fn register_peer_handle(&self, actor_ref: EntityId, handle: &str) -> FacadeResult<()> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        require_resolved_entity(self.vault(), actor_ref)?;
        self.with_verified_actor_write_txn(|wtxn| {
            self.vault()
                .store
                .vault_meta
                .put(
                    wtxn,
                    peer_handle_key(actor_ref).as_slice(),
                    handle.as_bytes(),
                )
                .map_err(FacadeError::from)
        })
    }

    // ── consult ladder (ONE-1888) ───────────────────────────────────────

    /// Compare-and-set one consult ladder step onto ONE-1699's TASK body.
    ///
    /// The pure [`transition_ladder`] decides; this only checks that the
    /// caller's `expected` ladder state still PROJECTS onto what is persisted,
    /// then writes the new projection as the same single register ONE-1699
    /// minted. The ladder never becomes a second durable record: everything
    /// here is the TASK body.
    ///
    /// Terminal immutability is enforced twice over — once against the STORED
    /// ladder disposition, which refuses every move off a settled row whatever
    /// the caller expected, and once by the pure transition. The projection
    /// check between them decides staleness, not immutability: a deferring
    /// terminal persists on the live `Interrupted` register, so the projection
    /// alone cannot tell a settled ladder from a resumable interruption.
    pub fn compare_and_set_consult_ladder(
        &self,
        task_ref: EntityId,
        expected: &ConsultLadderState,
        transition: LadderTransition,
    ) -> FacadeResult<LadderTransitionReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let expected_state = project_consult_ladder_state(expected);
        let (ladder_state, task_state) = self.with_verified_actor_write_txn(|wtxn| {
            let mut body = consult_body_in_txn(self.vault(), &*wtxn, task_ref)?;
            if body.settled_ladder_disposition().is_some() {
                return Err(ladder_refusal(LadderTransitionError::TerminalImmutable));
            }
            if body.state.as_ref() != Some(&expected_state) {
                return Err(consult_refusal(
                    FACADE_CODE_INVALID_STATE,
                    "consult ladder state moved since it was read",
                    "Re-read the TASK body and retry the transition against its current state.",
                ));
            }
            let next = transition_ladder(expected, transition).map_err(ladder_refusal)?;
            let next_state = project_consult_ladder_state(&next);
            body.state = Some(next_state.clone());
            let encoded = encode_task_verb_body(body);
            self.put_task_body_in_txn(wtxn, task_ref, &encoded, now_for_ladder(&next))?;
            Ok((next, next_state))
        })?;
        Ok(LadderTransitionReceipt {
            task_ref,
            ladder_state,
            task_state,
        })
    }

    /// Mints one counter TASK, and — when the original is still open —
    /// terminalizes it as rejected-with-counter-lineage in the SAME
    /// transaction.
    ///
    /// A counter is never an edit. The original keeps its own terminal row
    /// forever; an ALREADY-terminal original is left byte-identical and only
    /// the new task is written.
    pub fn mint_counter_task(
        &self,
        parent_task_ref: EntityId,
        counter_delta: EntityDeltaArtifact,
        deadline_at: u64,
        now: u64,
    ) -> FacadeResult<TaskCreateReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let provenance = facade_provenance(task_verb_contract(TasksVerb::Create));
        // A counter is a fresh cross-actor consult, so it answers to exactly
        // the same attribution and ownership laws as the original ask.
        let owning_actor_ref = self.resolve_cross_actor_owner(&counter_delta)?;
        let payload = self
            .entity_delta_payload(counter_delta)?
            .with_lineage(ConsultLineage {
                relation: ConsultLineageRelation::Counter,
                parent_task_ref,
            });
        let spec = TaskCreateSpec::new(Value::Nil, None, None, Some(now))
            .with_kind(TaskKind::Consult)
            .with_consult(payload)
            .with_assignee(TaskAssignee::Peer {
                actor_ref: owning_actor_ref,
            })
            .with_ttl(TaskTtl::at(deadline_at));
        let validated = validate_task_create(self.vault(), &spec, now)?;
        let rate_now = unix_seconds_now();
        let (task_ref, route) = self.with_verified_actor_write_txn(|wtxn| {
            let parent = consult_body_in_txn(self.vault(), &*wtxn, parent_task_ref)?;
            self.require_auto_ceiling_in_txn(&*wtxn)?;
            if !consume_create_rate_slot(
                self.vault(),
                wtxn,
                self.actor(),
                rate_now,
                TaskCreateRateLimit::default(),
            )? {
                return Err(consult_refusal(
                    FACADE_CODE_INVALID_STATE,
                    "counter exceeds the actor's create quota for this window",
                    "Retry the counter in the next window.",
                ));
            }
            let task_ref =
                self.mint_task_in_txn(wtxn, &validated, None, self.actor(), &provenance, now)?;
            // A counter routes through the same one door as any other create,
            // so a peer-addressed counter mints zero local attempts here too.
            let route = self.route_created_task_in_txn(wtxn, task_ref, &validated, now)?;
            // "Already terminal" is asked on BOTH axes: an escalated ladder
            // settled without settling the TASK, and rewriting it here would
            // reopen a decision the ladder calls immutable.
            let parent_settled =
                parent.terminal().is_some() || parent.settled_ladder_disposition().is_some();
            if !parent_settled {
                self.terminalize_countered_parent_in_txn(
                    wtxn,
                    parent_task_ref,
                    parent,
                    task_ref,
                    now,
                )?;
            }
            Ok((task_ref, route))
        })?;
        Ok(TaskCreateReceipt {
            task_ref: Some(task_ref),
            proposal_ref: None,
            approval: ClaimApprovalStatus::Auto,
            effected: true,
            route: Some(route),
        })
    }

    /// Writes the OLD task's terminal row: rejected on the ONE-1699 axis,
    /// `Countered` on the ladder axis, with a durable counter-lineage artifact
    /// as its `result_ref`.
    fn terminalize_countered_parent_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        parent_ref: EntityId,
        mut parent: TaskVerbBody,
        counter_task_ref: EntityId,
        now: u64,
    ) -> FacadeResult<()> {
        let result_ref = EntityId::now();
        let artifact = canonical_bytes(&counter_lineage_artifact_value(
            parent_ref,
            counter_task_ref,
            now,
        ));
        let occurred = TimeRange {
            start: now,
            end: now,
        };
        self.vault()
            .batch_in()
            .put(&result_ref, ENTITY_TYPE_TURN, occurred, now, &artifact)
            .apply(wtxn)?;
        parent.state = Some(TaskExecutionState::Terminal(TaskTerminalRecord {
            disposition: TaskTerminalDisposition::Rejected,
            result_ref: Some(result_ref),
            summary: None,
            finished_at: now,
            ladder: Some(LadderTerminalDisposition::Countered),
            counter_task_ref: Some(counter_task_ref),
        }));
        let encoded = encode_task_verb_body(parent);
        self.put_task_body_in_txn(wtxn, parent_ref, &encoded, now)
    }

    fn require_auto_ceiling_in_txn(&self, txn: &heed::RoTxn<'_>) -> FacadeResult<()> {
        let ceiling = task_actor_ceiling(self.vault(), txn, self.actor(), self.actor_class())?;
        if ceiling == PolicyApprovalCeiling::Auto {
            Ok(())
        } else {
            Err(consult_refusal(
                FACADE_CODE_FORBIDDEN,
                "this ladder write requires an auto-ceiling actor",
                "Create the consult through `tasks.create` so it surfaces its own proposal.",
            ))
        }
    }
}

// ── consult ladder durable bridge (ONE-1888) ────────────────────────────

/// Where one cross-actor entity-delta write went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossActorRoute {
    /// The writer owns the target: the existing typed write path applies.
    AutoOwn,
    /// A graduated pair on an already-receipted shape: the existing standing
    /// grant applies, with no NEW owner-agent consult.
    AutoViaStandingGrant { standing_grant_ref: EntityId },
    /// The owning actor is the first adjudicator.
    ConsultOwner { receipt: TaskCreateReceipt },
}

/// One landed ladder step, in both vocabularies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LadderTransitionReceipt {
    pub task_ref: EntityId,
    pub ladder_state: ConsultLadderState,
    pub task_state: TaskExecutionState,
}

/// Projects the pure ladder state onto the fields ONE-1699 already persists.
///
/// `Escalated` is deliberately NOT a terminal record: the case is waiting on
/// the follow-on assignee named in its escalation receipt, so it persists as
/// `Interrupted`. `Approved`/`Overridden` both persist as `Completed` and
/// `Countered` as `Rejected` — the finer ladder vocabulary rides inside the
/// same single terminal register rather than widening the ONE-1699 axis.
#[must_use]
pub fn project_consult_ladder_state(state: &ConsultLadderState) -> TaskExecutionState {
    match state {
        ConsultLadderState::Working(working) => TaskExecutionState::Working {
            started_at: working.started_at,
        },
        ConsultLadderState::Interrupted(_) => TaskExecutionState::Interrupted { ladder: None },
        ConsultLadderState::Terminal(terminal) => {
            if terminal.disposition.defers_to_follow_on() {
                // The deferring terminal rides INSIDE the interrupted register
                // rather than beside it: the ONE-1699 axis stays live for the
                // follow-on, and the settled ladder stays distinguishable from
                // an ordinary interruption that may still move.
                return TaskExecutionState::Interrupted {
                    ladder: Some(*terminal),
                };
            }
            TaskExecutionState::Terminal(TaskTerminalRecord {
                disposition: task_disposition_for_ladder(terminal.disposition),
                result_ref: Some(terminal.result_ref),
                summary: None,
                finished_at: terminal.finished_at,
                ladder: Some(terminal.disposition),
                counter_task_ref: terminal.counter_task_ref,
            })
        }
    }
}

/// The ONE-1699 disposition each non-deferring ladder outcome persists as.
const fn task_disposition_for_ladder(
    disposition: LadderTerminalDisposition,
) -> TaskTerminalDisposition {
    match disposition {
        LadderTerminalDisposition::Approved | LadderTerminalDisposition::Overridden => {
            TaskTerminalDisposition::Completed
        }
        // A counter is a rejection that named its successor. It is never
        // `Failed`: the owner decided, the machine did not break.
        LadderTerminalDisposition::Rejected | LadderTerminalDisposition::Countered => {
            TaskTerminalDisposition::Rejected
        }
        LadderTerminalDisposition::Failed => TaskTerminalDisposition::Failed,
        LadderTerminalDisposition::Abandoned => TaskTerminalDisposition::Abandoned,
        // Unreachable for `Escalated`, which never reaches a terminal record.
        LadderTerminalDisposition::Escalated => TaskTerminalDisposition::Failed,
    }
}

/// The ladder reading of a pre-ONE-1888 terminal row. `Completed` reads as
/// `Approved` and `Expired`/`Cancelled` as `Abandoned`: an unstamped row
/// carries no finer outcome, and inventing one would be worse than widening.
pub(super) const fn ladder_disposition_for_task(
    disposition: TaskTerminalDisposition,
) -> LadderTerminalDisposition {
    match disposition {
        TaskTerminalDisposition::Completed => LadderTerminalDisposition::Approved,
        TaskTerminalDisposition::Rejected => LadderTerminalDisposition::Rejected,
        TaskTerminalDisposition::Failed => LadderTerminalDisposition::Failed,
        TaskTerminalDisposition::Expired
        | TaskTerminalDisposition::Abandoned
        | TaskTerminalDisposition::Cancelled => LadderTerminalDisposition::Abandoned,
    }
}

/// The instant one ladder state settled on, for the entity envelope.
const fn now_for_ladder(state: &ConsultLadderState) -> u64 {
    match state {
        ConsultLadderState::Working(working) => working.started_at,
        ConsultLadderState::Interrupted(interrupted) => interrupted.interrupted_at,
        ConsultLadderState::Terminal(terminal) => terminal.finished_at,
    }
}

fn ladder_refusal(error: LadderTransitionError) -> FacadeError {
    match error {
        LadderTransitionError::TerminalImmutable => consult_refusal(
            FACADE_CODE_INVALID_STATE,
            "a terminal consult is immutable",
            "Mint a counter, appeal, or escalation task with lineage instead of reopening this one.",
        ),
        LadderTransitionError::ConsentRequired => consult_refusal(
            FACADE_CODE_FORBIDDEN,
            "this interruption resumes only through a human verdict",
            "Apply the typed human verdict, then finish the ladder.",
        ),
        LadderTransitionError::InvalidTransition => consult_refusal(
            FACADE_CODE_INVALID_STATE,
            "the requested ladder transition has no meaning from this state",
            "Read the current ladder state and choose a transition it admits.",
        ),
        LadderTransitionError::MissingResultRef => consult_refusal(
            FACADE_CODE_INVALID_STATE,
            "the persisted terminal record carries no result ref",
            "Terminal ladder states require a durable result; settle through the ladder path.",
        ),
    }
}
