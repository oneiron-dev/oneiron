//! The run's board carrier (FIX 2135): the frame its own board connection
//! queued rides each successful answer of the run's door, as a typed
//! observation beside the verb's output, which stays exactly as it was.
//! The queue is drained, never waited on. A connection the run never
//! attached queues nothing, and a refresh's own frame already drained what
//! it superseded.

use oneiron::code_run::RunObservation;
use oneiron::context_board::{BoardStreamFrame, CommittedTaskBoardState, FrameKind};

use super::{
    AgentVerb, AgentVerbAnswer, AgentVerbRefusal, Arc, EntityId, RunHostDoor, ScopedRead,
    StreamConnectionId, SyncServer, WriteActor, agent_lane,
};

impl RunHostDoor {
    /// `verb`'s `answered`, with the frame the run's board connection queued
    /// beside it when it is an answer the run reads as it stands, its rows
    /// known. Every other outcome leaves the queue for the next such answer:
    /// a refusal or a stop; an answer whose rows are not known, which the
    /// frame's own rows could not be released beside; and a reply the run
    /// may still turn into a wait ([`holds_reply`]), which keeps no frame.
    pub(super) fn observed(
        &self,
        verb: AgentVerb,
        answered: oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>>,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        match answered {
            Ok(Ok(mut answer)) if answer.rows.is_some() && !holds_reply(verb) => {
                answer.observations = self.take_observations();
                Ok(Ok(answer))
            }
            other => other,
        }
    }

    /// The one frame queued on the run's board connection, as an
    /// observation; none when nothing is queued. The run's thread waits for
    /// the server's blocking thread that takes it, never for a frame.
    fn take_observations(&self) -> Vec<RunObservation> {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let server = Arc::clone(&self.server);
        let (actor, board) = (self.actor, self.board.clone());
        self.runtime.spawn_blocking(move || {
            let handle = tokio::runtime::Handle::current();
            let _ = sender.send(handle.block_on(take_run_frame(&server, actor, &board)));
        });
        receiver.recv().ok().flatten().into_iter().collect()
    }
}

/// Whether the run may turn `verb`'s answer into a durable wait: a
/// `connector.call` reply, or a `self.use` one, that holds or retries its
/// connector call parks the run on it, and the wait keeps no frame.
fn holds_reply(verb: AgentVerb) -> bool {
    matches!(verb, AgentVerb::ConnectorCall | AgentVerb::SelfUse)
}

/// Takes exactly one pending coalesced payload of the run's board
/// connection, as a connector's next successful result does (ONE-1704 M7):
/// a remainder the coalescer keeps rides the run's next answer. Each queued
/// TASK line is read again under the agent's own lane before it rides; one
/// whose TASK is gone, or that the lane no longer reads, is dropped, and a
/// delta left with no line rides nothing. The session's changed line rides
/// the frame. The observation keeps the rows the frame was derived from:
/// its TASK lines', its child lines' (where each child works) and the
/// changed line's.
async fn take_run_frame(
    server: &Arc<SyncServer>,
    actor: WriteActor,
    board: &StreamConnectionId,
) -> Option<RunObservation> {
    let queued = server.mcp_registry.lock().await.next_carrier_frame(board)?;
    let (live, child_rows) = live_task_lines(server, actor, queued)?;
    let (frame, mut rows) = crate::api::ride_run_carrier(server, actor, board, live).await;
    rows.extend(task_rows(&frame));
    rows.extend(child_rows);
    Some(RunObservation {
        connection: board.0.clone(),
        frame,
        rows,
    })
}

/// `frame` less every TASK line the agent may not be told about now: its
/// TASK no longer stands on the board, or the agent's lane does not read
/// it; and less every child line whose child the agent did not spawn, or
/// whose child's placement does not read (census L2-38), with the rows the
/// kept child lines are derived from. Any failure to decide is a no. `None`
/// when a delta keeps no line.
fn live_task_lines(
    server: &SyncServer,
    actor: WriteActor,
    mut frame: BoardStreamFrame,
) -> Option<(BoardStreamFrame, Vec<EntityId>)> {
    let mut child_rows = Vec::new();
    let FrameKind::Delta(rows) = &mut frame.kind else {
        return Some((frame, child_rows));
    };
    let lane = agent_lane(server, actor).ok()?;
    let spawner = actor.entity_ref();
    rows.retain(|row| {
        if let Some(task) = row.key.strip_prefix("tasks:") {
            return EntityId::from_hex(task).is_ok_and(|task| tells_task(server, &lane, task));
        }
        row.key
            .strip_prefix(oneiron::context_board::CHILD_DONE_KEY_PREFIX)
            .is_none_or(|child| tells_child(server, spawner, child, &mut child_rows))
    });
    (!rows.is_empty()).then_some((frame, child_rows))
}

/// Whether `spawner` spawned `child` and where the child works reads: the
/// TASK its try realizes and the worlds its dispatch names, which join
/// `child_rows`, so the run's answer that carries the line is released by
/// them too.
fn tells_child(
    server: &SyncServer,
    spawner: EntityId,
    child: &str,
    child_rows: &mut Vec<EntityId>,
) -> bool {
    let spawned = oneiron::context_board::child_spawner(server.vault(), child)
        .is_ok_and(|child_spawner| child_spawner == Some(spawner));
    if !spawned {
        return false;
    }
    match oneiron::context_board::child_release_rows(server.vault(), child) {
        Ok(Some(rows)) => {
            child_rows.extend(rows);
            true
        }
        Ok(None) | Err(_) => false,
    }
}

/// Whether `task` still stands on the board and `lane` reads it.
fn tells_task(server: &SyncServer, lane: &ScopedRead<'_>, task: EntityId) -> bool {
    let stands = matches!(
        CommittedTaskBoardState::read(server.vault(), task),
        Ok(Some(_))
    );
    stands && lane.is_entity_readable(&task).unwrap_or(false)
}

/// The TASK rows a frame's delta lines name.
fn task_rows(frame: &BoardStreamFrame) -> Vec<EntityId> {
    match &frame.kind {
        FrameKind::Delta(rows) => rows
            .iter()
            .filter_map(|row| row.key.strip_prefix("tasks:"))
            .filter_map(|task| EntityId::from_hex(task).ok())
            .collect(),
        FrameKind::Keyframe(_) => Vec::new(),
    }
}
