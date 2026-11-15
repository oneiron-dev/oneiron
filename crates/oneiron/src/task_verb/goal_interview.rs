//! The goal-intake interview's TASK (OF-501; Engine RULING
//! GOAL-INTAKE-DRAFT-RUN = A, 14 Nov). When the host opens a minted
//! project's interview thread, the engine mints one TASK for the project's
//! leader and binds it to that thread; holding it is what lets the leader
//! speak there (ARCH-0006a). The TASK is never routed: the engine dispatches
//! each of the leader's intake runs itself, and none is the TASK's try. The
//! owner's confirmation that commits the goal settles it.

use rmpv::Value;

use super::create_validation::ValidatedTaskCreate;
use super::terminal_state::{TaskExecutionState, TaskTerminalDisposition, TaskTerminalRecord};
use super::verb_kind::{TaskAssignee, TaskKind};
use super::wire_decode::task_verb_body_in;
use super::wire_encode::encode_task_verb_body;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::memory::{Memory, MemoryResult};

/// The interview TASK's label on the board.
const GOAL_INTERVIEW_TASK_LABEL: &str = "goal interview";

/// The provenance source the interview TASK names.
const GOAL_INTERVIEW_TASK_SOURCE: &str = "project.goal_intake";

/// Mints the interview TASK of `project` in the caller's write: Standard,
/// assigned to the project's `leader` AGENT_DEF, owned by the vault `owner`
/// whose tap opened the interview, with no TTL and no route. `memory` is the
/// owner's.
pub(crate) fn mint_goal_interview_task_in_txn(
    memory: &Memory<'_>,
    txn: &mut heed::RwTxn<'_>,
    project: EntityId,
    leader: EntityId,
    owner: EntityId,
    now: u64,
) -> MemoryResult<EntityId> {
    let validated = ValidatedTaskCreate::engine_internal(
        TaskKind::Standard,
        Some(TaskAssignee::AgentDef {
            agent_def_ref: leader,
        }),
        Value::Map(vec![(
            Value::from("goal_interview"),
            Value::from(project.to_hex()),
        )]),
        crate::task_type::TaskTypeRef::seeded_root(),
    );
    let provenance = Value::Map(vec![
        (
            Value::from("source"),
            Value::from(GOAL_INTERVIEW_TASK_SOURCE),
        ),
        (Value::from("project"), Value::from(project.to_hex())),
    ]);
    memory.mint_task_in_txn(
        txn,
        &validated,
        Some(GOAL_INTERVIEW_TASK_LABEL.to_owned()),
        owner,
        &provenance,
        now,
    )
}

/// Settles the interview TASK `task` Completed in the write that commits
/// the goal claim `goal`, which is its result. The write is the engine's
/// own, through the internal TASK body door, as a watch TASK's settle is. A
/// TASK already settled or cancelled, or gone, is left alone.
pub(crate) fn settle_goal_interview_task_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    task: EntityId,
    goal: EntityId,
    now: u64,
) -> Result<()> {
    let Some(mut body) = task_verb_body_in(vault, &*txn, task)? else {
        return Ok(());
    };
    if body.terminal().is_some()
        || body.settled_ladder_disposition().is_some()
        || vault.task_authority_facts_in(&*txn, task)?.cancelled
    {
        return Ok(());
    }
    body.state = Some(TaskExecutionState::Terminal(TaskTerminalRecord {
        disposition: TaskTerminalDisposition::Completed,
        result_ref: Some(goal),
        summary: None,
        finished_at: now,
        ladder: None,
        counter_task_ref: None,
    }));
    vault
        .batch_in()
        .put_internal(
            &task,
            crate::registry::ENTITY_TYPE_TASK,
            crate::TimeRange {
                start: now,
                end: now,
            },
            now,
            &encode_task_verb_body(body),
        )
        .apply(txn)?;
    // As every settlement does: a review the owner accepted before the TASK
    // settled anchors it, and the routing folds count it.
    super::settlement_anchor::anchor_kept_review_in_txn(vault, txn, task, None)?;
    crate::edit_distance::routing::refold_task_outcomes_in_txn(vault, txn, task);
    Ok(())
}
