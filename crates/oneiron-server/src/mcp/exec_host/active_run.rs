//! Single flight for each durable code-mode run (FIX 9505): an entry of a
//! run whose earlier entry still runs waits behind it, in arrival order, and
//! enters the run once that entry's worker ends, instead of being refused.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use oneiron::EntityId;
use oneiron::work_line::{LinePermit, WorkLine};

use super::McpCodeExecutionError;

/// Each run's own line, one entry at a time. A line that no entry holds or
/// waits in is dropped at the next entry of any run.
pub(super) struct ActiveRuns {
    /// How long an entry waits for its run's turn: the host's configured
    /// queue wait, the deadline its fair permit queue keeps too.
    wait: Duration,
    lines: Mutex<HashMap<EntityId, WorkLine<()>>>,
}

impl ActiveRuns {
    pub(super) fn new(wait: Duration) -> Self {
        Self {
            wait,
            lines: Mutex::new(HashMap::new()),
        }
    }

    /// The run's single flight: now, or once every earlier entry of the run
    /// has ended. The entry takes its place in the run's line under the
    /// registry's lock, so no line is dropped while an entry holds it or
    /// waits in it. A caller who hangs up while waiting leaves the line;
    /// past the wait the entry starts nothing and answers
    /// [`McpCodeExecutionError::RunWaitedOut`]. A retry is a later entry of
    /// the same run: it enters the run's replay record once its turn comes.
    pub(super) async fn acquire(
        &self,
        run_id: EntityId,
    ) -> Result<ActiveRun, McpCodeExecutionError> {
        let turn = {
            let mut lines = self
                .lines
                .lock()
                .map_err(|_| McpCodeExecutionError::RunBinding("run registry poisoned".into()))?;
            lines.retain(|_, line| !line.is_idle());
            lines
                .entry(run_id)
                .or_insert_with(|| WorkLine::exclusive(self.wait))
                .admit_in_line(())
        };
        let permit = turn
            .await
            .map_err(|_| McpCodeExecutionError::RunWaitedOut)?;
        Ok(ActiveRun { _turn: permit })
    }
}

/// One entry's hold on its run. It moves into the entry's worker, so a
/// disconnected caller cannot release single flight while its worker writes;
/// dropping it lets the run's next entry in.
pub(super) struct ActiveRun {
    _turn: LinePermit,
}
