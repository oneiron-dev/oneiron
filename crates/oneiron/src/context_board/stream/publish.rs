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

use super::events::{BoardEvent, RouteObservation, SubscriptionScope};
use super::frames::DeltaRow;
use super::provenance::VerifiedOwnTaskEvent;
use super::registry::{BoardStreamRegistry, StreamConnectionState};
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
    /// task-verb TASK, cancelled, an acknowledged failure, or with no proven
    /// owner.
    pub fn read(vault: &Vault, task: EntityId) -> Result<Option<Self>> {
        let Some((presence, consultee)) = crate::task_verb::board_task_for_id(vault, task)? else {
            return Ok(None);
        };
        // An acknowledged failure is off the board; nothing may revive it.
        if presence.is_acked_failure() {
            return Ok(None);
        }
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

/// What this registry last routed for one TASK.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Routed {
    status: TaskBoardStatus,
    line: String,
    consultee_ref: Option<String>,
}

/// The last state this registry routed per TASK.
#[derive(Debug, Default)]
pub(super) struct PublishedTasks {
    routed: std::collections::HashMap<String, Routed>,
    order: VecDeque<String>,
}

impl PublishedTasks {
    fn swap(&mut self, task: &str, now: Routed) -> Option<Routed> {
        let previous = self.routed.insert(task.to_owned(), now);
        if previous.is_none() {
            self.order.push_back(task.to_owned());
            while self.order.len() > PUBLISHED_TASKS_CAP {
                if let Some(oldest) = self.order.pop_front() {
                    self.routed.remove(&oldest);
                }
            }
        }
        previous
    }
}

impl BoardStreamRegistry {
    /// Routes what changed since this registry last routed the TASK.
    ///
    /// A TASK that reaches `done`, or whose done row changes, sends its owner
    /// a CARRIER delta; one that reaches `failed` sends its owner a WAKE. A
    /// queued consult wakes the actor it addresses the first time it
    /// addresses them. Anything else routes nothing.
    ///
    /// Only connections whose ceiling spans the vault hear these events: the
    /// row is not projected through a world or facet ceiling, so a narrowed
    /// connection hears none, as the carrier drain already delivers it none.
    pub fn publish_task_state(&mut self, state: CommittedTaskBoardState) -> RouteObservation {
        let previous = self.published_tasks.swap(
            &state.task_ref,
            Routed {
                status: state.status,
                line: state.line.clone(),
                consultee_ref: state.consultee_ref.clone(),
            },
        );
        let changed_status = previous.as_ref().map(|p| p.status) != Some(state.status);
        let event = |actor_ref: &str, what: &str| VerifiedOwnTaskEvent {
            task_ref: state.task_ref.clone(),
            actor_ref: actor_ref.to_owned(),
            event_ref: format!("{}:{what}", state.task_ref),
        };
        let vault_wide = |st: &StreamConnectionState| {
            SubscriptionScope::ALL
                .iter()
                .all(|scope| st.allowed.contains(scope))
        };
        match state.status {
            TaskBoardStatus::Done
                if changed_status || previous.as_ref().is_some_and(|p| p.line != state.line) =>
            {
                self.route_event_where(
                    BoardEvent::OwnTaskDone {
                        event: event(&state.owner_ref, "done"),
                        delta: DeltaRow {
                            key: format!("tasks:{}", state.task_ref),
                            line: state.line.clone(),
                        },
                    },
                    vault_wide,
                )
            }
            TaskBoardStatus::Failed if changed_status => self.route_event_where(
                BoardEvent::OwnTaskFailed {
                    event: event(&state.owner_ref, "failed"),
                    line: state.line.clone(),
                },
                vault_wide,
            ),
            TaskBoardStatus::Queued
                if previous.as_ref().map(|p| &p.consultee_ref) != Some(&state.consultee_ref) =>
            {
                match &state.consultee_ref {
                    Some(consultee) => self.route_event_where(
                        BoardEvent::ConsultArrived {
                            event: event(consultee, "arrived"),
                            line: state.line.clone(),
                        },
                        vault_wide,
                    ),
                    None => RouteObservation::default(),
                }
            }
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
