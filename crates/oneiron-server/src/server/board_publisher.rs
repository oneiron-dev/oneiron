//! The board publisher: committed TASK writes reach STREAM subscribers.
//!
//! The engine announces every committed TASK write and decides what it means
//! to the board (`oneiron::context_board::CommittedTaskBoardState`). This loop
//! is the host half: it carries each announcement into the process-local
//! stream registry the MCP gateway owns. A recipient's connection hears the
//! event only if its bound credential may read the TASK now, by the same
//! predicate the board door filters TASK rows with. Done deltas then ride the
//! subscriber's next tool result, read again there; wakes wait in the
//! registry for a host-side adapter. The reads run on a blocking thread,
//! outside the registry lock.
//!
//! Beside it, every commit and every attached connection starts a pass over
//! the pending diary-read reviews (`oneiron::context_board::PendingDiaryReview`,
//! FIX 2879, FIX 6957): each review wakes its reviewed agent's own
//! connections, naming the review and nothing of it. That loop runs
//! alongside the TASK loop and never inside it.

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::attempt_queue::AttemptQueue;
use oneiron::context_board::{CommittedTaskBoardState, PendingDiaryReview};
use tokio::sync::broadcast::error::{RecvError, TryRecvError};

use super::core::SyncServer;

/// A serve loop's background tasks: the lifecycle scheduler, then the board
/// publisher. Stopped together, in that order, once serving ends.
pub(crate) struct ServeBackground {
    lifecycle: super::lifecycle::LifecycleScheduler,
    board: tokio::task::JoinHandle<()>,
}

impl ServeBackground {
    /// Stops the scheduler, waiting out a housekeeping pass in flight, then
    /// aborts the publisher and waits for it to end.
    pub(crate) async fn stop(self) {
        self.lifecycle.stop().await;
        self.board.abort();
        let _ = self.board.await;
    }
}

impl SyncServer {
    /// Starts the lifecycle scheduler, its housekeeping passes admitted
    /// through `admit`, and the board publisher.
    pub(crate) fn spawn_serve_background(
        self: &Arc<Self>,
        admit: super::HousekeepingAdmission,
    ) -> ServeBackground {
        ServeBackground {
            lifecycle: self.spawn_lifecycle_scheduler(admit),
            board: self.spawn_board_publisher(),
        }
    }

    /// Starts the publisher. It subscribes before it returns, so no TASK
    /// committed after this call is missed, and a review opened after it is
    /// read at the latest by the pass its commit starts. A connection that
    /// attaches is read for by the pass its attach starts.
    pub(crate) fn spawn_board_publisher(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let updates = self.vault().subscribe_task_updates();
        let commits = AttemptQueue::new(self.vault()).subscribe();
        let server = Arc::clone(self);
        tokio::spawn(async move {
            tokio::join!(
                Arc::clone(&server).publish_board_forever(updates),
                server.publish_reviews_forever(commits),
            );
        })
    }

    /// One pass over the pending reviews first, then one per commit
    /// announcement or connection attach. Signals queued meanwhile, or lost
    /// to lag, fold into the next pass, which reads the whole pending set
    /// fresh. A failed pass is logged and retried at the next commit or
    /// attach; it never reaches the write that opened the review.
    async fn publish_reviews_forever(
        self: Arc<Self>,
        mut commits: tokio::sync::broadcast::Receiver<()>,
    ) {
        let attached = self
            .mcp_registry
            .lock()
            .await
            .streams_mut()
            .attach_notifier();
        loop {
            self.publish_pending_reviews().await;
            tokio::select! {
                commit = commits.recv() => match commit {
                    Ok(()) | Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => return,
                },
                () = attached.notified() => {}
            }
            while matches!(commits.try_recv(), Ok(()) | Err(TryRecvError::Lagged(_))) {}
        }
    }

    async fn publish_pending_reviews(&self) {
        let vault = Arc::clone(self.vault());
        let pending =
            tokio::task::spawn_blocking(move || PendingDiaryReview::read_all(&vault)).await;
        match pending {
            Ok(Ok(pending)) => {
                self.mcp_registry
                    .lock()
                    .await
                    .streams_mut()
                    .publish_diary_reviews(pending);
            }
            Ok(Err(error)) => {
                tracing::warn!(kind = ?error.kind(), "board publisher could not read pending diary reviews; it reads them again at the next commit or attach");
            }
            Err(error) => {
                tracing::warn!(
                    panicked = error.is_panic(),
                    "board publisher review read did not finish"
                );
            }
        }
    }

    async fn publish_board_forever(
        self: Arc<Self>,
        mut updates: tokio::sync::broadcast::Receiver<oneiron::EntityId>,
    ) {
        loop {
            let task = match updates.recv().await {
                Ok(task) => task,
                Err(RecvError::Lagged(missed)) => {
                    tracing::warn!(
                        missed,
                        "board publisher fell behind; those TASK changes reach subscribers at their next board refresh"
                    );
                    continue;
                }
                Err(RecvError::Closed) => return,
            };
            let vault = Arc::clone(self.vault());
            let state =
                tokio::task::spawn_blocking(move || CommittedTaskBoardState::read(&vault, task))
                    .await;
            match state {
                Ok(Ok(Some(state))) => {
                    let (readers, runs) = {
                        let registry = self.mcp_registry.lock().await;
                        let recipients = state.recipients().collect::<Vec<_>>();
                        (
                            registry.stream_readers_for(&recipients),
                            registry.run_readers_for(&recipients),
                        )
                    };
                    let vault = Arc::clone(self.vault());
                    let admitted = tokio::task::spawn_blocking(move || {
                        readers
                            .into_iter()
                            .filter(|reader| {
                                crate::api::mcp_stream_reads_task(&vault, reader, &task)
                            })
                            .map(|reader| reader.stream_connection)
                            .chain(
                                runs.into_iter()
                                    .filter(|(_, reader)| run_reads_task(&vault, reader, &task))
                                    .map(|(connection, _)| connection),
                            )
                            .collect::<BTreeSet<_>>()
                    })
                    .await;
                    let Ok(admitted) = admitted else {
                        tracing::warn!(task = %task.to_hex(), "board publisher admission did not finish");
                        continue;
                    };
                    let mut registry = self.mcp_registry.lock().await;
                    registry
                        .streams_mut()
                        .publish_task_state(state, |connection| admitted.contains(connection));
                }
                Ok(Ok(None)) => {}
                Ok(Err(error)) => {
                    tracing::warn!(kind = ?error.kind(), task = %task.to_hex(), "board publisher could not read a committed TASK");
                }
                Err(error) => {
                    tracing::warn!(panicked = error.is_panic(), task = %task.to_hex(), "board publisher read did not finish");
                }
            }
        }
    }
}

/// Whether a pumped run's own board reader may be told about `task` now
/// (FIX 4888): the TASK still stands on the board and the run's own key
/// reads it, as its board's TASK rows are read. Any failure to decide is a
/// no.
fn run_reads_task(
    vault: &oneiron::Vault,
    reader: &oneiron::claim::ScopedReadActorKey,
    task: &oneiron::EntityId,
) -> bool {
    matches!(
        oneiron::context_board::CommittedTaskBoardState::read(vault, *task),
        Ok(Some(_))
    ) && vault
        .scoped_read(reader.clone())
        .is_ref_readable(task)
        .unwrap_or(false)
}
