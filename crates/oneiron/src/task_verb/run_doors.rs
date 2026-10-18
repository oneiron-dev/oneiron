//! The owner's run doors over one TASK's branches (DOOR-100, ARCH-0026
//! `#run-tree`): `vault.tasks.cancel_force`, canon's `cancel.force`, the
//! vault owner's unrefusable stop of every live branch, and
//! `vault.runs.branches.get`, the owner's read of every branch as the queue
//! holds it; and `vault.consults.get` (DOOR-063, ARCH-0067), the owner's
//! read of one consult TASK's deadline and terminal register.
//!
//! The force is the hard rung only. It reaches any TASK in the vault, not
//! only one its owner's actor created, and asks no gate and opens no
//! proposal: the owner's proof, rechecked in the writing transaction, is the
//! authority. The soft `cancel` and the actor-bound
//! [`Memory::cancel_force`](crate::Memory::cancel_force) keep their own rights.
//!
//! A branch reads exactly as its attempt row stores it: lifecycle state,
//! the pure [`AgentRunStatus`] projection of that state, result, typed asks
//! and signals, and the whole cancel protocol evidence (landing, resume
//! point, terminal cancellation, receipts). Nothing here invents progress,
//! a next breakpoint or a wait class.
//!
//! A consult reads exactly as its terminal register stores it: refs only,
//! never a result body. Landing an answer or abstention stays the addressed
//! peer's; the owner inspects it. The peer's run lands it through the run
//! row `tasks.consult.result` (DOOR-063), as the run's own actor.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::ask_types::TaskAskOptionId;
use super::consult_payload::ConsultPayloadRef;
use super::consult_result::{
    ConsultMeasuredSpend, ConsultResultInput, ConsultResultKind, TaskResultReceipt,
};
use super::create_validation::consult_body_in_txn;
use super::presence_scan::{attempt_hex, superseded_attempt_ids};
use super::terminal_state::{ConsultResultSummary, TaskTerminalDisposition, TaskTerminalRecord};
use crate::agent_run_status::{AgentRunStatus, project_agent_run_status};
use crate::attempt_queue::{
    AttemptCancelState, AttemptId, AttemptQueue, AttemptRecord, AttemptResultRef, AttemptState,
    ForceAttemptCancel, ForceCancelAuthority, ForceCancelOutcome, validate_signal_cancel,
};
use crate::code_run::JS_SAFE_INTEGER;
use crate::consent::AuthenticatedOwner;
use crate::context_board::cancel_task_in_txn;
use crate::error::Error;
use crate::llm::run_admission::LeaseUnit;
use crate::memory::{MEMORY_CODE_NOT_FOUND, MemoryError, MemoryResult};
use crate::registry::ENTITY_TYPE_TASK;
use crate::run_tree::{RunAsk, RunBranchSignal, RunTreeStatus};
use crate::{EntityId, Vault};

/// What a door that names no TASK should name instead.
const TASK_FIX: &str =
    "Name a TASK ref; a spawned agent reads by its attempt through vault.agents.spawn.get.";

/// The owner's force: every live branch of `task_ref` stops, for `reason`
/// when one is given.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CancelForceRequest {
    pub task_ref: EntityId,
    /// Kept on each terminal cancellation receipt the force writes.
    #[serde(default)]
    pub reason: Option<String>,
}

/// What the force did: whether it stopped anything, how many branches this
/// call cancelled, and every branch of the TASK after it. A repeat on
/// settled branches stops nothing, writes nothing and reads them as stored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CancelForceReceipt {
    pub task_ref: EntityId,
    pub effected: bool,
    pub forced: u32,
    pub branches: Vec<RunBranchView>,
}

/// The owner's read of every branch of one TASK.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunBranchesRequest {
    pub task_ref: EntityId,
}

/// Every branch of the TASK, in the order the queue created them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunBranchesView {
    pub task_ref: EntityId,
    pub branches: Vec<RunBranchView>,
}

/// One branch: one attempt row realizing the TASK, as stored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunBranchView {
    /// The attempt id, as `steer` names its branch.
    pub branch: String,
    #[serde(default)]
    pub run_id: Option<String>,
    pub state: AttemptState,
    /// The projection of `state` every run-tree viewer reads. A cancelled
    /// branch reads `failed` here; its cause is `cancel_state`'s.
    pub agent_status: AgentRunStatus,
    /// The lease generation within this try.
    pub attempt_count: u32,
    /// The artifact version the branch's durable output lives in.
    #[serde(default)]
    pub result_ref: Option<String>,
    #[serde(default)]
    pub last_error: Option<String>,
    /// Durable ask handles, partial answers included.
    pub asks: Vec<RunAsk>,
    /// The branch's control inbox and settled replay receipts.
    pub signals: Vec<RunBranchSignal>,
    /// Landing, resume point (the saved partial result a successor reads
    /// first), terminal cancellation and every cancel receipt.
    pub cancel_state: AttemptCancelState,
}

/// The owner's read of one consult TASK.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsultReadRequest {
    pub task_ref: EntityId,
}

/// One consult TASK as its owner inspects it: its deadline, when it has one,
/// and its terminal register. `terminal` is `None` while nothing has settled
/// the consult: no answer, abstention, expiry or ladder outcome yet.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsultInspection {
    pub task_ref: EntityId,
    #[serde(default)]
    pub deadline_at: Option<u64>,
    #[serde(default)]
    pub terminal: Option<ConsultTerminalView>,
}

/// A consult's one terminal register, as stored: refs, never result bodies.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsultTerminalView {
    pub disposition: ConsultDisposition,
    /// The result the settlement wrote.
    #[serde(default)]
    pub result_ref: Option<EntityId>,
    /// The evidence an answer cites or the reason an abstention gives.
    #[serde(default)]
    pub summary: Option<ConsultSummaryView>,
    pub finished_at: u64,
    /// The consult ladder's finer outcome (`approved`, `overridden`,
    /// `rejected`, `failed`, `escalated`, `countered` or `abandoned`), when a
    /// ladder settled it.
    #[serde(default)]
    pub ladder: Option<String>,
    /// The TASK a countered ladder outcome created in the same transaction.
    #[serde(default)]
    pub counter_task_ref: Option<EntityId>,
}

/// How a consult ended. `expired` (its deadline passed) and `abandoned` (its
/// executor went away) stay distinct causes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConsultDisposition {
    Completed,
    Rejected,
    Failed,
    Expired,
    Abandoned,
    Cancelled,
}

/// An answer's evidence, or an abstention's reason, by ref.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConsultSummaryView {
    Answer {
        evidence_refs: Vec<ConsultPayloadRef>,
    },
    Abstained {
        reason_ref: ConsultPayloadRef,
    },
}

/// `tasks.consult.result`: the addressed peer's run lands its answer to, or
/// its abstention from, one consult TASK. The actor is the run's own, from
/// its live lease; nothing here names one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsultLandRequest {
    pub task_ref: EntityId,
    pub kind: ConsultLandKind,
    /// When the peer finished, unix seconds: its word, refused when later
    /// than the engine's clock.
    #[schemars(range(max = "JS_SAFE_INTEGER"))]
    pub completed_at: u64,
    /// What the consult cost the peer, measured; absent when unknown. Only a
    /// first landing folds it into the peer's consult calibration.
    #[serde(default)]
    pub measured_spend: Option<ConsultLandSpend>,
}

/// An answer, citing its evidence, or an abstention, giving its reason.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConsultLandKind {
    Answer {
        /// The result the peer stored.
        result_ref: EntityId,
        /// The option the answer picks, when the consult offered options.
        #[serde(default)]
        option: Option<TaskAskOptionId>,
        /// At least one, each distinct.
        evidence_refs: Vec<ConsultPayloadRef>,
    },
    Abstain {
        /// The result the peer stored.
        result_ref: EntityId,
        reason_ref: ConsultPayloadRef,
    },
}

/// What one consult cost its peer, measured, in one unit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConsultLandSpend {
    /// A budget line's unit: `tokens`, or one a pack row names.
    pub unit: LeaseUnit,
    #[schemars(range(max = "JS_SAFE_INTEGER"))]
    pub units: u64,
}

/// What the landing came to: the consult's terminal register as stored, and
/// whether this call replayed an identical earlier landing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConsultLandReply {
    pub task_ref: EntityId,
    pub terminal: ConsultTerminalView,
    pub idempotent_replay: bool,
}

impl ConsultLandRequest {
    /// The engine's landing input, the TASK it lands on, and every ref the
    /// run's read lane must read first: the TASK, the result and each
    /// evidence or reason ref, each once. Times and units are JavaScript safe
    /// integers, as on every run row, and a unit is one a budget line could
    /// name.
    ///
    /// # Errors
    ///
    /// `InvalidClaimBody` for a time or a unit count past the safe range, or
    /// a unit no budget line names.
    pub(crate) fn into_engine(
        self,
    ) -> crate::Result<(EntityId, ConsultResultInput, Vec<EntityId>)> {
        let Self {
            task_ref,
            kind,
            completed_at,
            measured_spend,
        } = self;
        if completed_at > JS_SAFE_INTEGER {
            return Err(Error::InvalidClaimBody("invalid unix time"));
        }
        let measured_spend = measured_spend
            .map(|spend| {
                if spend.units > JS_SAFE_INTEGER {
                    return Err(Error::InvalidClaimBody("invalid consult spend units"));
                }
                let unit = LeaseUnit::new(spend.unit.as_str())
                    .map_err(|_| Error::InvalidClaimBody("invalid consult spend unit"))?;
                Ok(ConsultMeasuredSpend {
                    unit,
                    units: spend.units,
                })
            })
            .transpose()?;
        let (kind, result_ref, carried) = match kind {
            ConsultLandKind::Answer {
                result_ref,
                option,
                evidence_refs,
            } => {
                let carried: Vec<_> = evidence_refs
                    .iter()
                    .copied()
                    .map(ConsultPayloadRef::entity_ref)
                    .collect();
                let kind = ConsultResultKind::Answer {
                    result_ref,
                    option,
                    evidence_refs,
                };
                (kind, result_ref, carried)
            }
            ConsultLandKind::Abstain {
                result_ref,
                reason_ref,
            } => {
                let kind = ConsultResultKind::Abstain {
                    result_ref,
                    reason_ref,
                };
                (kind, result_ref, vec![reason_ref.entity_ref()])
            }
        };
        // Deduped for the reads only: the evidence the engine checks is the
        // peer's as given.
        let mut seen = HashSet::new();
        let reads: Vec<EntityId> = [task_ref, result_ref]
            .into_iter()
            .chain(carried)
            .filter(|id| seen.insert(*id))
            .collect();
        let input = ConsultResultInput {
            kind,
            completed_at,
            measured_spend,
        };
        Ok((task_ref, input, reads))
    }
}

impl From<TaskResultReceipt> for ConsultLandReply {
    fn from(receipt: TaskResultReceipt) -> Self {
        Self {
            task_ref: receipt.task_ref,
            terminal: terminal_view(&receipt.terminal),
            idempotent_replay: receipt.idempotent_replay,
        }
    }
}

/// Stops, as the vault owner and unrefusably, every live branch of
/// `input.task_ref`: in one write transaction the owner is rechecked, each
/// branch no later try replaces and not yet terminal is force-cancelled on
/// the owner's grounds, and the TASK records its cancellation once one
/// really stopped. Each stopped branch's running step stops after commit.
///
/// # Errors
///
/// `NOT_FOUND` for a ref that names nothing, or a TASK no attempt realizes;
/// `BAD_REQUEST` for a ref that is not a TASK; a reason the cancel receipt
/// refuses; a stale owner proof; storage errors.
pub fn cancel_force_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: CancelForceRequest,
) -> MemoryResult<CancelForceReceipt> {
    let CancelForceRequest { task_ref, reason } = input;
    let queue = AttemptQueue::new(vault);
    let now = vault.store.clock.now_recorded_at();
    let (records, stopped) = vault.try_with_write_txn_grouped(|wtxn| {
        let actor = owner.revalidate_in_txn(vault, wtxn)?;
        let authority = ForceCancelAuthority::owner(actor.to_hex().as_str())?;
        // The actor and reason checks every cancel receipt takes, before a
        // row changes: a repeat that stops nothing refuses a bad reason too.
        validate_signal_cancel(authority.actor(), reason.as_deref())?;
        let task = task_in(vault, &*wtxn, task_ref)?;
        let mut records = branches(&task, queue.list_task_in_write_txn(&*wtxn, &task)?)?;
        let superseded = superseded_attempt_ids(&records);
        let mut stopped: Vec<(AttemptId, u32)> = Vec::new();
        for record in &mut records {
            if superseded.contains(&record.id) || record.state.is_terminal() {
                continue;
            }
            let outcome = queue.force_cancel_in_txn(
                wtxn,
                ForceAttemptCancel {
                    id: record.id,
                    authority: authority.clone(),
                    reason: reason.clone(),
                    now,
                },
            )?;
            *record = match outcome {
                ForceCancelOutcome::Cancelled(after) => {
                    stopped.push((after.id, after.attempt_count));
                    after
                }
                ForceCancelOutcome::AlreadyCancelled(after)
                | ForceCancelOutcome::AlreadySettled(after) => after,
            };
        }
        // Only a force that really stopped a branch records the TASK's
        // cancellation: the fact is a stop that happened.
        if !stopped.is_empty() {
            cancel_task_in_txn(vault, wtxn, task_ref, actor, now)?;
        }
        Ok::<_, MemoryError>((records, stopped))
    })?;
    if !stopped.is_empty() {
        vault.store.notify_attempt_observers();
        // Committed: the step each stopped lease was running stops (FIX 600).
        for (id, generation) in &stopped {
            crate::engine_executor::stop_attempt_step(Some(vault), *id, *generation);
        }
    }
    Ok(CancelForceReceipt {
        task_ref,
        effected: !stopped.is_empty(),
        forced: u32::try_from(stopped.len()).unwrap_or(u32::MAX),
        branches: records.into_iter().map(branch_view).collect(),
    })
}

/// Reads, as the vault owner, every branch of `input.task_ref` in one read
/// transaction: each attempt row realizing the TASK, archived ones too, as
/// stored.
///
/// # Errors
///
/// `NOT_FOUND` for a ref that names nothing, or a TASK no attempt realizes;
/// `BAD_REQUEST` for a ref that is not a TASK; a stale owner proof; storage
/// errors.
pub fn read_branches_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: RunBranchesRequest,
) -> MemoryResult<RunBranchesView> {
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    owner.revalidate_in_txn(vault, &txn)?;
    let task = task_in(vault, &txn, input.task_ref)?;
    let records = branches(
        &task,
        AttemptQueue::new(vault).list_task_in_txn(&txn, &task)?,
    )?;
    Ok(RunBranchesView {
        task_ref: input.task_ref,
        branches: records.into_iter().map(branch_view).collect(),
    })
}

/// Reads, as the vault owner, one consult TASK in one read transaction: its
/// deadline and its terminal register (disposition, result ref, evidence or
/// abstention refs, ladder outcome and counter TASK), as stored.
///
/// # Errors
///
/// `NOT_FOUND` for a ref that names nothing; `BAD_REQUEST` for a ref that is
/// not a TASK, or a TASK that is not a consult; a stale owner proof; storage
/// errors.
pub fn read_consult_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: ConsultReadRequest,
) -> MemoryResult<ConsultInspection> {
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    owner.revalidate_in_txn(vault, &txn)?;
    task_in(vault, &txn, input.task_ref)?;
    let body = consult_body_in_txn(vault, &txn, input.task_ref)?;
    Ok(ConsultInspection {
        task_ref: input.task_ref,
        deadline_at: body.ttl.map(|ttl| ttl.deadline_at),
        terminal: body.terminal().map(terminal_view),
    })
}

/// The hex of `task_ref`, refused unless it names a TASK.
fn task_in(vault: &Vault, txn: &heed::RoTxn<'_>, task_ref: EntityId) -> MemoryResult<String> {
    let hex = task_ref.to_hex();
    match vault.get_entity_type_in_txn(txn, &task_ref)? {
        Some(ENTITY_TYPE_TASK) => Ok(hex),
        Some(_) => Err(MemoryError::bad_request_with(
            format!("{hex} is not a TASK"),
            &[TASK_FIX],
        )),
        None => Err(MemoryError::not_found(format!(
            "no TASK {hex} is in this vault"
        ))),
    }
}

/// The TASK's attempt rows, refused when there are none: a TASK nothing has
/// run has no branch.
fn branches(task: &str, records: Vec<AttemptRecord>) -> MemoryResult<Vec<AttemptRecord>> {
    if records.is_empty() {
        return Err(MemoryError::new(
            MEMORY_CODE_NOT_FOUND,
            format!("no attempt realizes TASK {task}: it has no branch"),
            &[
                "A TASK nothing has run yet has no branch to read or stop; cancel stops the TASK itself.",
            ],
        ));
    }
    Ok(records)
}

/// One attempt row as its branch view: every field as stored, the agent
/// status projected from the stored state alone.
fn branch_view(record: AttemptRecord) -> RunBranchView {
    RunBranchView {
        branch: attempt_hex(record.id),
        run_id: record.run_id,
        state: record.state,
        agent_status: project_agent_run_status(RunTreeStatus::from(record.state)),
        attempt_count: record.attempt_count,
        result_ref: record.result_ref.map(AttemptResultRef::into_string),
        last_error: record.last_error,
        asks: record.asks,
        signals: record.signals,
        cancel_state: record.cancel_state,
    }
}

/// A consult's terminal register as its view: every field as stored.
fn terminal_view(record: &TaskTerminalRecord) -> ConsultTerminalView {
    ConsultTerminalView {
        disposition: match record.disposition {
            TaskTerminalDisposition::Completed => ConsultDisposition::Completed,
            TaskTerminalDisposition::Rejected => ConsultDisposition::Rejected,
            TaskTerminalDisposition::Failed => ConsultDisposition::Failed,
            TaskTerminalDisposition::Expired => ConsultDisposition::Expired,
            TaskTerminalDisposition::Abandoned => ConsultDisposition::Abandoned,
            TaskTerminalDisposition::Cancelled => ConsultDisposition::Cancelled,
        },
        result_ref: record.result_ref,
        summary: record.summary.as_ref().map(|summary| match summary {
            ConsultResultSummary::Answer { evidence_refs } => ConsultSummaryView::Answer {
                evidence_refs: evidence_refs.clone(),
            },
            ConsultResultSummary::Abstained { reason_ref } => ConsultSummaryView::Abstained {
                reason_ref: *reason_ref,
            },
        }),
        finished_at: record.finished_at,
        ladder: record.ladder.map(|ladder| ladder.as_str().to_owned()),
        counter_task_ref: record.counter_task_ref,
    }
}
