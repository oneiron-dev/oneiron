//! The own-task producer: committed TASK writes become routed board events.
//!
//! Every committed TASK write is announced after its commit
//! ([`crate::Vault::subscribe_task_updates`]). The host reads what the TASK now
//! is with [`CommittedTaskBoardState::read`], outside any lock, and hands it to
//! [`BoardStreamRegistry::publish_task_state`]. The event, its recipient and its
//! line all come from the committed TASK, never from a caller's claim. The
//! engine only publishes: the queued wakes wait for a host-side adapter
//! (ARCH-0067 "where the wake ladder lives"), and done deltas ride the next tool
//! result as CARRIER frames.

use std::collections::VecDeque;

use super::events::{BoardEvent, RouteObservation};
use super::frames::DeltaRow;
use super::provenance::VerifiedOwnTaskEvent;
use super::registry::BoardStreamRegistry;
use crate::context_board::TaskBoardStatus;
use crate::{EntityId, Result, Vault};

/// How many TASKs the registry remembers having routed. An older task that
/// changes again after it is forgotten routes again, so the bound costs a
/// repeated event, never a lost one.
const PUBLISHED_TASKS_CAP: usize = 4096;

/// One committed TASK as the board STREAM sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedTaskBoardState {
    task_ref: String,
    owner_ref: String,
    /// The actor an open consult addresses.
    consultee_ref: Option<String>,
    status: TaskBoardStatus,
    line: String,
}

impl CommittedTaskBoardState {
    /// Reads one committed TASK. `None` when the board does not show it: not a
    /// task-verb TASK, cancelled, or with no proven owner.
    pub fn read(vault: &Vault, task: EntityId) -> Result<Option<Self>> {
        let Some((presence, consultee)) = crate::task_verb::board_task_for_id(vault, task)? else {
            return Ok(None);
        };
        let Some(authority) = vault.task_authority_state(task)? else {
            return Ok(None);
        };
        Ok(Some(Self {
            task_ref: task.to_hex(),
            owner_ref: authority.owner_ref.to_hex(),
            consultee_ref: consultee.map(|actor| actor.to_hex()),
            status: presence.status,
            line: crate::context_board::tasks::intent_row(&presence).line,
        }))
    }
}

/// The last status this registry routed per TASK.
#[derive(Debug, Default)]
pub(super) struct PublishedTasks {
    status: std::collections::HashMap<String, TaskBoardStatus>,
    order: VecDeque<String>,
}

impl PublishedTasks {
    fn swap(&mut self, task: &str, status: TaskBoardStatus) -> Option<TaskBoardStatus> {
        let previous = self.status.insert(task.to_owned(), status);
        if previous.is_none() {
            self.order.push_back(task.to_owned());
            while self.order.len() > PUBLISHED_TASKS_CAP {
                if let Some(oldest) = self.order.pop_front() {
                    self.status.remove(&oldest);
                }
            }
        }
        previous
    }
}

impl BoardStreamRegistry {
    /// Routes what changed since this registry last routed the TASK.
    ///
    /// A TASK that reaches `done` sends its owner a CARRIER delta; one that
    /// reaches `failed` sends its owner a WAKE. A consult first seen while
    /// still queued wakes the actor it addresses. A write that leaves the
    /// board status where it was routes nothing.
    pub fn publish_task_state(&mut self, state: CommittedTaskBoardState) -> RouteObservation {
        let previous = self.published_tasks.swap(&state.task_ref, state.status);
        if previous == Some(state.status) {
            return RouteObservation::default();
        }
        let event = |actor_ref: &str, what: &str| VerifiedOwnTaskEvent {
            task_ref: state.task_ref.clone(),
            actor_ref: actor_ref.to_owned(),
            event_ref: format!("{}:{what}", state.task_ref),
        };
        match state.status {
            TaskBoardStatus::Done => self.route_event(BoardEvent::OwnTaskDone {
                event: event(&state.owner_ref, "done"),
                delta: DeltaRow {
                    key: format!("tasks:{}", state.task_ref),
                    line: state.line.clone(),
                },
            }),
            TaskBoardStatus::Failed => self.route_event(BoardEvent::OwnTaskFailed {
                event: event(&state.owner_ref, "failed"),
                line: state.line.clone(),
            }),
            TaskBoardStatus::Queued if previous.is_none() => match &state.consultee_ref {
                Some(consultee) => self.route_event(BoardEvent::ConsultArrived {
                    event: event(consultee, "arrived"),
                    line: state.line.clone(),
                }),
                None => RouteObservation::default(),
            },
            _ => RouteObservation::default(),
        }
    }
}

impl Vault {
    /// Committed TASK ids, each sent once its write commits. Subscribe before
    /// the first read so no commit falls between them. A lagged receiver has
    /// lost ids; the board's refresh stays the correctness floor.
    #[cfg(feature = "sync")]
    pub fn subscribe_task_updates(&self) -> tokio::sync::broadcast::Receiver<EntityId> {
        self.store.task_updates.subscribe()
    }
}
