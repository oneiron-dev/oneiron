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
//!
//! The same pass reads the staged room wakes
//! (`oneiron::context_board::PendingRoomWake`, FIX 15647): a room turn that
//! addresses an agent no resident pump runs wakes that agent's own
//! connections, naming the room and the turn and nothing of the turn. A wake
//! handed to a connection, or no longer live, is settled; one whose agent has
//! no connection waits for one.
//!
//! The TASK loop also stages each wake a committed TASK owes
//! (`oneiron::context_board::PendingTaskWake`, census L2-38): a failed TASK's
//! to its owner, a queued consult's to its addressee. A third loop runs on
//! each attach and each connection's first bound reader. It offers every
//! staged wake that is still live to each of its recipient's connections that
//! may read the TASK and was not offered it yet, so a wake outlives a restart
//! and reaches a connection that attaches later. It settles a staged wake once
//! its TASK no longer owes it.
//!
//! The review pass also takes the child ends the settle writes staged
//! (`oneiron::context_board::ChildDone`, census L2-38): each AGENT child's try
//! that ended done, failed or abandoned rides its spawner's next tool result as
//! a `children:<attempt id>` CARRIER line, naming the child and its end.

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::attempt_queue::AttemptQueue;
use oneiron::context_board::{
    ChildDone, CommittedTaskBoardState, PendingDiaryReview, PendingRoomWake, PendingTaskWake,
    StreamConnectionId,
};
use tokio::sync::broadcast::error::{RecvError, TryRecvError};

use super::core::{BroadcastPayload, SyncServer};

/// A serve loop's background tasks: the lifecycle scheduler, the board
/// publisher, and the cloud erase watch. Stopped together, in that order,
/// once serving ends.
pub(crate) struct ServeBackground {
    lifecycle: super::lifecycle::LifecycleScheduler,
    board: tokio::task::JoinHandle<()>,
    cloud_erase_watch: tokio::task::JoinHandle<()>,
}

impl ServeBackground {
    /// Stops the scheduler, waiting out a housekeeping pass in flight, then
    /// aborts the publisher and the erase watch and waits for both to end.
    pub(crate) async fn stop(self) {
        self.lifecycle.stop().await;
        self.board.abort();
        let _ = self.board.await;
        self.cloud_erase_watch.abort();
        let _ = self.cloud_erase_watch.await;
    }
}

impl SyncServer {
    /// Starts the lifecycle scheduler, its housekeeping passes admitted
    /// through `admit`, the board publisher, and the cloud erase watch.
    pub(crate) fn spawn_serve_background(
        self: &Arc<Self>,
        admit: super::HousekeepingAdmission,
    ) -> ServeBackground {
        ServeBackground {
            lifecycle: self.spawn_lifecycle_scheduler(admit),
            board: self.spawn_board_publisher(),
            cloud_erase_watch: self.spawn_cloud_erase_watch(),
        }
    }

    /// Starts the publisher. It subscribes before it returns, so no TASK
    /// committed after this call is missed, and a review opened after it is
    /// read at the latest by the pass its commit starts. A connection that
    /// attaches is read for by the pass its attach starts, and the staged
    /// TASK wakes by the pass its attach or its first bound reader starts.
    pub(crate) fn spawn_board_publisher(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let updates = self.vault().subscribe_task_updates();
        let commits = AttemptQueue::new(self.vault()).subscribe();
        let server = Arc::clone(self);
        tokio::spawn(async move {
            tokio::join!(
                Arc::clone(&server).publish_board_forever(updates),
                Arc::clone(&server).publish_reviews_forever(commits),
                server.publish_task_wakes_forever(),
            );
        })
    }

    /// Starts the cloud device-flow erase watch (FIX 10947 S1): a pending
    /// flow whose owner's PERSON hard-erase committed ends on the next
    /// wake instead of staying for a dead owner. It subscribes before it
    /// returns, so no erase committed after this call is missed, and its
    /// first pass revalidates only flows held now. Only exact
    /// handle-plus-actor pairs take, never the global cancel. Owned like
    /// the board publisher: aborted in [`ServeBackground::stop`].
    pub(crate) fn spawn_cloud_erase_watch(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let mut inbox = self.broadcast_tx.subscribe();
        let server = Arc::downgrade(self);
        tokio::spawn(async move {
            if !revalidate_cloud_flows(&server, None).await {
                return;
            }
            loop {
                match inbox.recv().await {
                    Ok(BroadcastPayload::LocalDocs(entities)) => {
                        if !revalidate_cloud_flows(&server, Some(entities)).await {
                            return;
                        }
                    }
                    Ok(BroadcastPayload::Resync { .. }) => {
                        if !revalidate_cloud_flows(&server, None).await {
                            return;
                        }
                    }
                    Ok(BroadcastPayload::Frame(..)) => {}
                    Err(RecvError::Lagged(_)) => {
                        if !revalidate_cloud_flows(&server, None).await {
                            return;
                        }
                    }
                    Err(RecvError::Closed) => return,
                }
            }
        })
    }

    /// One pass over the pending reviews and the staged room wakes first,
    /// then one per commit announcement or connection attach. Signals queued
    /// meanwhile, or lost to lag, fold into the next pass, which reads the
    /// whole pending set fresh. A failed pass is logged and retried at the
    /// next commit or attach; it never reaches the write that opened the
    /// review or minted the room turn.
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
            self.publish_staged_room_wakes().await;
            self.publish_children_done().await;
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

    /// One pass over the staged room wakes (FIX 15647): each live wake of an
    /// agent no resident pump runs reaches that agent's subscribed
    /// connections, and each one handed over, or no longer live, is settled.
    /// A wake whose agent has no connection stays staged for a later pass.
    async fn publish_staged_room_wakes(&self) {
        let vault = Arc::clone(self.vault());
        let read = tokio::task::spawn_blocking(move || PendingRoomWake::read_all(&vault)).await;
        let read = match read {
            Ok(Ok(read)) => read,
            Ok(Err(error)) => {
                tracing::warn!(kind = ?error.kind(), "board publisher could not read staged room wakes; it reads them again at the next commit or attach");
                return;
            }
            Err(error) => {
                tracing::warn!(
                    panicked = error.is_panic(),
                    "board publisher room wake read did not finish"
                );
                return;
            }
        };
        // A live wake stays staged however many queues it reached, so a
        // connection that attaches later (the bridge's own instance) still
        // hears it; only a wake no longer live is settled (FIX 15647).
        let settle = read.spent;
        self.mcp_registry
            .lock()
            .await
            .streams_mut()
            .publish_room_wakes(read.pending);
        if settle.is_empty() {
            return;
        }
        let vault = Arc::clone(self.vault());
        let settled = tokio::task::spawn_blocking(move || {
            let now = vault.now_recorded_at();
            vault.settle_room_wakes(&settle, now)
        })
        .await;
        match settled {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(kind = ?error.kind(), "board publisher could not settle room wakes; the next pass hands them over again");
            }
            Err(error) => {
                tracing::warn!(
                    panicked = error.is_panic(),
                    "board publisher room wake settle did not finish"
                );
            }
        }
    }

    /// One pass over the child ends the settle writes staged (census L2-38):
    /// each is taken, and sent to its spawner's connections that subscribe to
    /// their children. A connection with no keyframe yet takes nothing; the
    /// board's refresh stays the floor.
    async fn publish_children_done(&self) {
        let vault = Arc::clone(self.vault());
        let taken = tokio::task::spawn_blocking(move || ChildDone::take_all(&vault)).await;
        match taken {
            Ok(Ok(done)) if done.is_empty() => {}
            Ok(Ok(done)) => {
                self.mcp_registry
                    .lock()
                    .await
                    .streams_mut()
                    .publish_children_done(done);
            }
            Ok(Err(error)) => {
                tracing::warn!(kind = ?error.kind(), "board publisher could not take staged child ends; it takes them at the next commit");
            }
            Err(error) => {
                tracing::warn!(
                    panicked = error.is_panic(),
                    "board publisher child end take did not finish"
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
            let state = tokio::task::spawn_blocking(move || {
                let state = CommittedTaskBoardState::read(&vault, task)?;
                // A wake the TASK owes is staged before it is routed, so it
                // outlives the queues it lands in (census L2-38).
                if let Err(error) = vault.stage_task_wakes(task, state.as_ref()) {
                    tracing::warn!(kind = ?error.kind(), task = %task.to_hex(), "board publisher could not stage a TASK's wakes; its next write stages them");
                }
                Ok::<_, oneiron::Error>(state)
            })
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
                Ok(Ok(None)) => {
                    self.mcp_registry
                        .lock()
                        .await
                        .streams_mut()
                        .forget_task_wakes(task);
                }
                Ok(Err(error)) => {
                    tracing::warn!(kind = ?error.kind(), task = %task.to_hex(), "board publisher could not read a committed TASK");
                }
                Err(error) => {
                    tracing::warn!(panicked = error.is_panic(), task = %task.to_hex(), "board publisher read did not finish");
                }
            }
        }
    }

    /// One pass over the staged TASK wakes first, then one per attach or
    /// first bound reader. Signals sent meanwhile fold into the next pass,
    /// which reads the whole staged set fresh. A failed pass is logged and
    /// retried at the next signal.
    async fn publish_task_wakes_forever(self: Arc<Self>) {
        let replay = self
            .mcp_registry
            .lock()
            .await
            .streams_mut()
            .task_wake_replay_notifier();
        loop {
            self.publish_staged_task_wakes().await;
            replay.notified().await;
        }
    }

    /// One pass over the staged TASK wakes (census L2-38): each live wake
    /// reaches every subscribed connection of its recipient that was not
    /// offered it yet and whose bound reader may read the TASK now, by the
    /// predicate a live route uses. A connection with no bound reader waits
    /// for its first bind. A staged wake its TASK no longer owes is settled.
    async fn publish_staged_task_wakes(&self) {
        let vault = Arc::clone(self.vault());
        let read = tokio::task::spawn_blocking(move || PendingTaskWake::read_all(&vault)).await;
        let read = match read {
            Ok(Ok(read)) => read,
            Ok(Err(error)) => {
                tracing::warn!(kind = ?error.kind(), "board publisher could not read staged TASK wakes; it reads them again at the next attach");
                return;
            }
            Err(error) => {
                tracing::warn!(
                    panicked = error.is_panic(),
                    "board publisher TASK wake read did not finish"
                );
                return;
            }
        };
        let candidates = {
            let registry = self.mcp_registry.lock().await;
            let mut candidates = Vec::new();
            for wake in &read.pending {
                for connection in registry.streams().task_wake_candidates(wake) {
                    let reader = match registry.stream_reader(&connection) {
                        Some(reader) => Some(TaskWakeReader::Credential(reader)),
                        None => registry.run_reader(&connection).map(TaskWakeReader::Run),
                    };
                    if let Some(reader) = reader {
                        candidates.push((wake.task(), connection, reader));
                    }
                }
            }
            candidates
        };
        let vault = Arc::clone(self.vault());
        let admitted = tokio::task::spawn_blocking(move || {
            candidates
                .into_iter()
                .filter(|(task, _, reader)| match reader {
                    TaskWakeReader::Credential(reader) => {
                        crate::api::mcp_stream_reads_task(&vault, reader, task)
                    }
                    TaskWakeReader::Run(reader) => run_reads_task(&vault, reader, task),
                })
                .map(|(task, connection, _)| (task, connection))
                .collect::<BTreeSet<(oneiron::EntityId, StreamConnectionId)>>()
        })
        .await;
        let Ok(admitted) = admitted else {
            tracing::warn!("board publisher TASK wake admission did not finish");
            return;
        };
        let spent = read.spent;
        {
            let mut registry = self.mcp_registry.lock().await;
            let streams = registry.streams_mut();
            streams.forget_spent_task_wakes(&spent);
            streams.publish_task_wakes(read.pending, |connection, wake| {
                admitted.contains(&(wake.task(), connection.clone()))
            });
        }
        if spent.is_empty() {
            return;
        }
        let vault = Arc::clone(self.vault());
        let settled = tokio::task::spawn_blocking(move || vault.settle_task_wakes(&spent)).await;
        match settled {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(kind = ?error.kind(), "board publisher could not settle spent TASK wakes; the next pass finds them spent again");
            }
            Err(error) => {
                tracing::warn!(
                    panicked = error.is_panic(),
                    "board publisher TASK wake settle did not finish"
                );
            }
        }
    }
}

/// The reader a staged TASK wake is admitted under: a credential connection's
/// bound reader, or a pumped run's.
enum TaskWakeReader {
    Credential(crate::mcp::McpResolvedActor),
    Run(oneiron::claim::ScopedReadActorKey),
}

/// One cloud erase-watch pass over this server's held device flows:
/// `None` revalidates every held flow (startup, lag, resync); `Some`
/// intersects the held actors with the woken entities first. The
/// snapshot, the committed-marker probes and the exact takes all run on
/// the blocking pool: never the flows guard across a vault read, and
/// never sync LMDB work on an async worker. `false` means the server is
/// gone and the watch ends.
async fn revalidate_cloud_flows(
    server: &std::sync::Weak<SyncServer>,
    filter: Option<Vec<oneiron::EntityId>>,
) -> bool {
    let Some(server) = server.upgrade() else {
        return false;
    };
    let outcome = tokio::task::spawn_blocking(move || {
        let held = server.cloud_registration.snapshot_held_flows();
        for (handle, actor) in held {
            if let Some(want) = &filter {
                if !want.contains(&actor) {
                    continue;
                }
            }
            server
                .cloud_registration
                .take_flow_if_owner_erased(server.vault(), &handle, &actor);
        }
    })
    .await;
    if let Err(error) = outcome {
        tracing::warn!(
            panicked = error.is_panic(),
            "cloud erase watch pass did not finish"
        );
    }
    true
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
