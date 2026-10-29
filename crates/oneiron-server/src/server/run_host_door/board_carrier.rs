//! The run's board carrier (FIX 2135): the frame its own board connection
//! queued rides each successful answer of the run's door, as a typed
//! observation beside the verb's output, which stays exactly as it was.
//! The queue is drained, never waited on. A connection the run never
//! attached queues nothing, and a refresh's own frame already drained what
//! it superseded.

use oneiron::code_run::RunObservation;
use oneiron::context_board::{BoardStreamFrame, CommittedTaskBoardState, FrameKind};

use super::{
    AgentVerbAnswer, AgentVerbRefusal, Arc, EntityId, RunHostDoor, ScopedRead, StreamConnectionId,
    SyncServer, WriteActor, agent_lane,
};

impl RunHostDoor {
    /// `answered`, with the frame the run's board connection queued beside
    /// it when it is an answer: a refusal or a stop carries none, and leaves
    /// the queue for the next answer.
    pub(super) fn observed(
        &self,
        answered: oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>>,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        match answered {
            Ok(Ok(mut answer)) => {
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

/// Takes exactly one pending coalesced payload of the run's board
/// connection, as a connector's next successful result does (ONE-1704 M7):
/// a remainder the coalescer keeps rides the run's next answer. Each queued
/// TASK line is read again under the agent's own lane before it rides; one
/// whose TASK is gone, or that the lane no longer reads, is dropped, and a
/// delta left with no line rides nothing. The session's changed line rides
/// the frame. The observation keeps the rows the frame was derived from:
/// its TASK lines' and the changed line's.
async fn take_run_frame(
    server: &Arc<SyncServer>,
    actor: WriteActor,
    board: &StreamConnectionId,
) -> Option<RunObservation> {
    let queued = server.mcp_registry.lock().await.next_carrier_frame(board)?;
    let live = live_task_lines(server, actor, queued)?;
    let (frame, mut rows) = crate::api::ride_run_carrier(server, actor, board, live).await;
    rows.extend(task_rows(&frame));
    Some(RunObservation {
        connection: board.0.clone(),
        frame,
        rows,
    })
}

/// `frame` less every TASK line the agent may not be told about now: its
/// TASK no longer stands on the board, or the agent's lane does not read
/// it. Any failure to decide is a no. `None` when a delta keeps no line.
fn live_task_lines(
    server: &SyncServer,
    actor: WriteActor,
    mut frame: BoardStreamFrame,
) -> Option<BoardStreamFrame> {
    let FrameKind::Delta(rows) = &mut frame.kind else {
        return Some(frame);
    };
    let lane = agent_lane(server, actor).ok()?;
    rows.retain(|row| {
        row.key.strip_prefix("tasks:").is_none_or(|task| {
            EntityId::from_hex(task).is_ok_and(|task| tells_task(server, &lane, task))
        })
    });
    (!rows.is_empty()).then_some(frame)
}

/// Whether `task` still stands on the board and `lane` reads it.
fn tells_task(server: &SyncServer, lane: &ScopedRead<'_>, task: EntityId) -> bool {
    let stands = matches!(CommittedTaskBoardState::read(server.vault(), task), Ok(Some(_)));
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
