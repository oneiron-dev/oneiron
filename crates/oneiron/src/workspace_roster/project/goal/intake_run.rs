//! A minted project's goal-intake interview thread (OF-501; Engine RULINGS
//! ARM05-GOAL-INTAKE = A and GOAL-INTAKE-DRAFT-RUN = A, 14 Nov 2026).
//!
//! The owner's tap that mints a project from a card opens the interview in
//! the new home room, in one write: the card's turn lands as the owner's
//! thread root on the room's header, the engine mints the leader's
//! interview TASK and binds it to that root, and the leader's first intake
//! run is dispatched. Holding that TASK is what lets the leader claim and
//! answer the thread's turns; who may speak is unchanged (ARCH-0006a). Each
//! later turn of the thread that wakes the TASK's holder dispatches the
//! leader's next intake run in the write that stages the wake. The thread
//! holds the project's own goal, so no turn of it asks the house mind's
//! project question that other threads of the room ask. The context
//! names the last run that loaded the goal-intake skill, and the owner's
//! confirmation that commits the goal settles the TASK and ends the
//! interview.

use crate::agent_dispatch::{AgentDispatchOutcome, AgentDispatcher};
use crate::attempt_queue::AttemptId;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Error, Result, Vault};
use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

/// The message type of the interview's thread root: the card's turn, which
/// names the card and copies none of its words.
pub(crate) const GOAL_INTERVIEW_MESSAGE_TYPE: &str = "project_goal_interview";

/// One project's goal-intake interview, as the host opened it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GoalInterviewRow {
    /// The card whose tap minted the project: its goal-intake entry admits
    /// each of the leader's intake runs.
    card: String,
    /// The interview's thread root in the home room.
    pub(super) thread: EntityId,
    /// The open interview TASK the leader holds; `None` once the goal the
    /// interview confirmed committed.
    pub(super) task: Option<EntityId>,
    /// The last intake run that loaded the goal-intake skill.
    pub(super) attempt: Option<AttemptId>,
}

/// One project's goal-intake interview. Key: id16 (project).
const INTERVIEWS: SideTable<EntityId, GoalInterviewRow, Named> =
    SideTable::new(&side_table::PROJECT_GOAL_INTAKE_RUN);
/// The project whose interview a thread root opens. Key: id16 (thread root).
const THREADS: SideTable<EntityId, EntityId, Raw> =
    SideTable::new(&side_table::PROJECT_GOAL_INTAKE_THREAD);

/// `project`'s goal-intake interview, if the host opened one.
pub(super) fn interview_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    project: EntityId,
) -> Result<Option<GoalInterviewRow>> {
    INTERVIEWS.get(store, txn, &project)
}

/// Ends `project`'s open interview in the write that commits the goal
/// claim `goal` it confirmed: the interview TASK settles with the claim as
/// its result and leaves the row, so no later turn of the thread wakes a
/// run. The thread root and the last run stay on record.
pub(super) fn close_interview_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    project: EntityId,
    goal: EntityId,
    now: u64,
) -> Result<()> {
    let Some(mut row) = INTERVIEWS.get(&vault.store, txn, &project)? else {
        return Ok(());
    };
    let Some(task) = row.task.take() else {
        return Ok(());
    };
    crate::task_verb::settle_goal_interview_task_in_txn(vault, txn, task, goal, now)?;
    INTERVIEWS.put(&vault.store, txn, &project, &row)?;
    Ok(())
}

impl Vault {
    /// Opens `project`'s goal-intake interview, as the authenticated
    /// `owner`'s act, for the stored `card` that minted it with `leader`:
    /// in one write, the card's turn lands as the owner's thread root on the
    /// home room's header, the engine mints the leader's interview TASK,
    /// binds it to that root with the owner as binder (the home room's
    /// roster rule), records the interview and dispatches the leader's
    /// first intake run. Any failure lands none of it. `None` when the home
    /// room has no owner-authored trunk turn to open the thread on, as a
    /// converted project's: its interview opens no thread.
    pub(crate) fn open_project_goal_interview(
        &self,
        owner: &AuthenticatedOwner,
        card: &str,
        project: EntityId,
        home_room: EntityId,
        leader: EntityId,
        now: u64,
    ) -> Result<Option<AgentDispatchOutcome>> {
        let actor = {
            let txn = self.store.env.read_txn()?;
            if INTERVIEWS.get(&self.store, &txn, &project)?.is_some() {
                return Err(Error::InvalidConfig(
                    "this project's goal interview is already open".into(),
                ));
            }
            owner.revalidate_in_txn(self, &txn)?
        };
        let memory = self.memory(actor, EdgeActorClass::Human);
        // The header the owner's tap witnessed when the project was born.
        let anchor = memory
            .rooms_messages(home_room)
            .map_err(|error| Error::InvalidConfig(error.to_string()))?
            .into_iter()
            .filter(|turn| {
                turn.thread_of.is_none() && turn.reply_to.is_none() && turn.actor == actor.to_hex()
            })
            .min_by_key(|turn| turn.at);
        let Some(anchor) = anchor else {
            return Ok(None);
        };
        let root = WitnessTurn {
            conversation_ref: home_room.to_hex(),
            turn_ref: Some(EntityId::now().to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::User,
                message_type: GOAL_INTERVIEW_MESSAGE_TYPE.into(),
                // The card is named, never copied.
                content: String::new(),
                parts: None,
                metadata: Some(serde_json::json!({
                    "room_thread_of": anchor.turn_id,
                    "project_goal_interview": card,
                })),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: now,
            assertions: Default::default(),
        };
        let mut opened = None;
        memory
            .witness_linked_with_room_birth(
                &root,
                |_| Ok(()),
                |txn, landed| {
                    let thread = landed.turn_id;
                    let task = crate::task_verb::mint_goal_interview_task_in_txn(
                        &memory, txn, project, leader, actor, now,
                    )?;
                    self.bind_room_thread_task_in_txn(txn, actor, home_room, thread, task)?;
                    INTERVIEWS.put(
                        &self.store,
                        txn,
                        &project,
                        &GoalInterviewRow {
                            card: card.to_owned(),
                            thread,
                            task: Some(task),
                            attempt: None,
                        },
                    )?;
                    THREADS.put(&self.store, txn, &thread, &project)?;
                    let outcome = AgentDispatcher::new(self).dispatch_goal_intake_in_txn(
                        txn,
                        card,
                        project,
                        home_room,
                        Some(thread),
                        None,
                        now,
                    )?;
                    opened = Some((thread, outcome));
                    Ok(())
                },
            )
            .map_err(|error| Error::InvalidConfig(error.to_string()))?;
        let (thread, outcome) = opened.ok_or(Error::InvariantViolation(
            "a goal interview opens in its witness write",
        ))?;
        self.store.notify_attempt_observers();
        // The bound root reaches the room's live window after commit.
        #[cfg(feature = "sync")]
        self.refresh_room_turn_in_live_window(&thread);
        #[cfg(not(feature = "sync"))]
        let _ = thread;
        Ok(Some(outcome))
    }

    /// The thread root of `project`'s goal-intake interview, open or ended,
    /// read in `txn`; `None` when the host opened none.
    pub(crate) fn project_goal_interview_thread_in_txn(
        &self,
        txn: &RoTxn<'_>,
        project: EntityId,
    ) -> Result<Option<EntityId>> {
        Ok(interview_in_txn(&self.store, txn, project)?.map(|row| row.thread))
    }

    /// Whether `thread` is the root of a goal-intake interview, open or
    /// ended, read in `txn`.
    pub(crate) fn is_goal_interview_thread_in_txn(
        &self,
        txn: &RoTxn<'_>,
        thread: EntityId,
    ) -> Result<bool> {
        THREADS.contains(&self.store, txn, &thread)
    }

    /// Records `attempt`, an intake run of `project` that just loaded the
    /// goal-intake skill, as the interview's run: the attempt its context
    /// names. Nothing for a project with no open interview thread.
    pub(crate) fn record_project_goal_interview_attempt(
        &self,
        project: EntityId,
        attempt: AttemptId,
    ) -> Result<()> {
        self.with_write_txn(|txn| {
            let Some(mut row) = INTERVIEWS.get(&self.store, txn, &project)? else {
                return Ok(());
            };
            if row.task.is_none() || row.attempt == Some(attempt) {
                return Ok(());
            }
            row.attempt = Some(attempt);
            INTERVIEWS.put(&self.store, txn, &project, &row)?;
            Ok(())
        })
    }

    /// RULING GOAL-INTAKE-DRAFT-RUN = A: in the write that stages `agent`'s
    /// wake for the room turn `turn` of the thread `thread`, when `agent`
    /// holds a project's open interview TASK and `thread` is that
    /// interview's, the engine dispatches the leader's next intake run,
    /// once per turn. Only the interview TASK does this; any other TASK
    /// holder's wake is left to its consumers. A run that does not dispatch
    /// (its leader changed since the card, a refused admission) is logged
    /// and lands nothing, and the turn stands.
    pub(crate) fn continue_project_goal_interview_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        thread: Option<EntityId>,
        turn: EntityId,
        agent: EntityId,
        now: u64,
    ) -> Result<()> {
        let Some(thread) = thread else {
            return Ok(());
        };
        let Some(project) = THREADS.get(&self.store, txn, &thread)? else {
            return Ok(());
        };
        let Some(row) = INTERVIEWS.get(&self.store, txn, &project)? else {
            return Ok(());
        };
        let Some(task) = row.task.filter(|_| row.thread == thread) else {
            return Ok(());
        };
        match crate::task_verb::open_thread_task_holder_in(
            self,
            txn,
            task,
            crate::gate::TaskHolderFallback::AssigneeOnly,
        ) {
            Ok(Some(holder)) if holder == agent => {}
            Ok(_) | Err(Error::EntityNotFound) => return Ok(()),
            Err(error) => return Err(error),
        }
        let home_room = super::super::home_room_id(project)?;
        let mut savepoint = self.store.env.nested_write_txn(txn)?;
        match AgentDispatcher::new(self).dispatch_goal_intake_in_txn(
            &mut savepoint,
            &row.card,
            project,
            home_room,
            Some(thread),
            Some(turn),
            now,
        ) {
            Ok(_) => savepoint.commit()?,
            Err(error) => {
                savepoint.abort();
                tracing::warn!(
                    project = %project.to_hex(),
                    turn = %turn.to_hex(),
                    %error,
                    "goal interview: the leader's next intake run was not dispatched"
                );
            }
        }
        Ok(())
    }
}
