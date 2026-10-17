//! The own-task producer: committed TASK writes become routed board events.
//!
//! Every committed TASK write is announced after its commit
//! ([`crate::Vault::subscribe_task_updates`]). The host reads what the TASK now
//! is with [`CommittedTaskBoardState::read`], outside any lock, decides which
//! of the recipients' connections may read that TASK now, and hands both to
//! [`BoardStreamRegistry::publish_task_state`]. The event, its recipient and its
//! line all come from the committed TASK, never from a caller's claim. The
//! engine only publishes: the queued wakes wait for a host-side adapter, which
//! takes them with [`BoardStreamRegistry::drain_wakes`] (ARCH-0067 "where the
//! wake ladder lives"), and done deltas ride the next tool result as CARRIER
//! frames.

use std::collections::VecDeque;

use super::events::{BoardEvent, RouteObservation};
use super::frames::{DeltaRow, StreamConnectionId};
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
    /// The committed TASK state this was read from (ARCH-0067
    /// `#wake-envelope-id`).
    revision: String,
    /// The failed attempt heads its status folds from, sorted.
    failed_attempts: Vec<String>,
}

impl CommittedTaskBoardState {
    /// Reads one committed TASK. `None` when the board does not show it: not a
    /// task-verb TASK, cancelled, an acknowledged failure, or with no proven
    /// owner.
    pub fn read(vault: &Vault, task: EntityId) -> Result<Option<Self>> {
        let Some(board) = crate::task_verb::board_task_for_id(vault, task)? else {
            return Ok(None);
        };
        let presence = board.presence;
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
            consultee_ref: board.addressee.map(|actor| actor.to_hex()),
            status: presence.status,
            line: crate::context_board::tasks::intent_row(&presence).line,
            revision: revision(board.body_revision, &presence),
            failed_attempts: failed_attempts(&presence),
        }))
    }

    /// The current TASK row for a STREAM delta. A host must admit this TASK
    /// under the recipient's current read before delivering the row.
    pub fn delta_row(&self) -> DeltaRow {
        DeltaRow {
            key: format!("tasks:{}", self.task_ref),
            line: self.line.clone(),
        }
    }

    /// The actors an event about this TASK can reach: its owner, and the
    /// actor an open consult addresses.
    pub fn recipients(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.owner_ref.as_str()).chain(self.consultee_ref.as_deref())
    }
}

/// The TASK revision an event names: a digest of the committed state the
/// board reads, its durable body revision and status, and each attempt head
/// the status folds from. The body revision alone stays put when a retried
/// attempt fails, since that writes attempt rows only; the heads tell those
/// two failures apart. Re-reading an unchanged TASK gives the same revision.
fn revision(body_revision: u64, presence: &crate::context_board::TaskIntentPresence) -> String {
    let mut heads = presence
        .realizing_jobs
        .iter()
        .map(|job| (job.id.as_str(), job.status.as_str()))
        .collect::<Vec<_>>();
    heads.sort_unstable();
    let mut digest = blake3::Hasher::new();
    digest.update(&body_revision.to_be_bytes());
    digest.update(presence.status.as_str().as_bytes());
    for (id, status) in heads {
        digest.update(&[0]);
        digest.update(id.as_bytes());
        digest.update(&[0]);
        digest.update(status.as_bytes());
    }
    digest.finalize().to_hex()[..16].to_owned()
}

fn failed_attempts(presence: &crate::context_board::TaskIntentPresence) -> Vec<String> {
    let mut failed = presence
        .realizing_jobs
        .iter()
        .filter(|job| job.status == TaskBoardStatus::Failed)
        .map(|job| job.id.clone())
        .collect::<Vec<_>>();
    failed.sort_unstable();
    failed
}

/// What this registry last routed for one TASK.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Routed {
    status: TaskBoardStatus,
    line: String,
    consultee_ref: Option<String>,
    failed_attempts: Vec<String>,
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
    /// a CARRIER delta. A TASK that reaches `failed` sends its owner a WAKE,
    /// and so does each further attempt head that fails: a retry that fails
    /// again wakes its owner even when no state between the two failures was
    /// announced, under a new envelope id. A queued consult wakes
    /// the actor it addresses the first time it addresses them. Anything else
    /// routes nothing.
    ///
    /// Only the connections `reads` admits hear an event: a subscription is
    /// to a category of events, never a grant to read the TASK behind one, so
    /// the host answers with each connection's own live read of the TASK,
    /// projected through that connection's world and facet ceiling.
    pub fn publish_task_state(
        &mut self,
        state: CommittedTaskBoardState,
        reads: impl Fn(&StreamConnectionId) -> bool,
    ) -> RouteObservation {
        let previous = self.published_tasks.swap(
            &state.task_ref,
            Routed {
                status: state.status,
                line: state.line.clone(),
                consultee_ref: state.consultee_ref.clone(),
                failed_attempts: state.failed_attempts.clone(),
            },
        );
        let changed_status = previous.as_ref().map(|p| p.status) != Some(state.status);
        // A failed attempt head this registry has not routed yet.
        let failed_again = previous.as_ref().is_some_and(|p| {
            state
                .failed_attempts
                .iter()
                .any(|attempt| !p.failed_attempts.contains(attempt))
        });
        let event = |actor_ref: &str, what: &str| VerifiedOwnTaskEvent {
            task_ref: state.task_ref.clone(),
            actor_ref: actor_ref.to_owned(),
            event_ref: format!("{}:{what}:{}", state.task_ref, state.revision),
        };
        let admitted = |c: &StreamConnectionId, _: &StreamConnectionState| reads(c);
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
                    admitted,
                )
            }
            TaskBoardStatus::Failed if changed_status || failed_again => self.route_event_where(
                BoardEvent::OwnTaskFailed {
                    event: event(&state.owner_ref, "failed"),
                    line: state.line.clone(),
                },
                admitted,
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
                        admitted,
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
