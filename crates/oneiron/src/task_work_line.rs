//! The vault's task-work line: the inherent `Vault` methods that admit task
//! work through the line in [`crate::work_line`] (defined in `oneiron-base`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::work_line::{LineCrossing, LineObserver, TaskWorkTurn, WaitTimedOut};
use crate::{EntityId, Vault};

impl Vault {
    /// Sets this vault's task-work line: `bound` pieces at once, waits that
    /// end at `wait`, its crossings said to `crossing`. A host sets it once
    /// it holds the vault; the line and the work in it stay.
    pub fn set_task_work(
        &self,
        bound: usize,
        wait: Duration,
        crossing: Option<Arc<dyn LineCrossing>>,
    ) {
        self.task_work.configure(bound, wait, crossing);
    }

    /// `caller`'s turn to run one piece of task work on this vault (`can`,
    /// `ask`, `wait`, `tasks.answer`; Rule 5): at once while fewer than the
    /// bound run, else in a fair line, one caller's work after another's,
    /// each caller's oldest first. Work is never refused: it keeps its place
    /// until its turn comes, however long, and never runs without one (FIX
    /// 10015). Hold the turn until the work ends; take it before the engine
    /// opens a transaction, and only where no turn is held for the same work
    /// already.
    pub fn admit_task_work(
        &self,
        caller: EntityId,
    ) -> impl Future<Output = TaskWorkTurn> + Send + 'static {
        self.admit_task_work_observed(caller, None)
    }

    /// The same task-work turn, reporting its wait to the serving call's
    /// durable admission receipt when it has one.
    pub fn admit_task_work_observed(
        &self,
        caller: EntityId,
        observer: Option<Arc<dyn LineObserver>>,
    ) -> impl Future<Output = TaskWorkTurn> + Send + 'static {
        let permit = self.task_work.admit_in_line_untimed(caller, observer);
        async move {
            TaskWorkTurn {
                _permit: permit.await,
            }
        }
    }

    /// [`Self::admit_task_work_observed`] for work that carries a request
    /// deadline of its own: in the same line, until `deadline`. Past it with
    /// no turn, the work leaves the line and [`WaitTimedOut`] says nothing
    /// was started; a deadline already past starts nothing.
    pub fn admit_task_work_until(
        &self,
        caller: EntityId,
        deadline: Instant,
        observer: Option<Arc<dyn LineObserver>>,
    ) -> impl Future<Output = Result<TaskWorkTurn, WaitTimedOut>> + Send + 'static {
        let permit = self
            .task_work
            .admit_in_line_until(caller, deadline, observer);
        async move {
            Ok(TaskWorkTurn {
                _permit: permit.await?,
            })
        }
    }

    /// [`Self::admit_task_work`] on this thread: for the embedded SDK, a
    /// code run's own calls and other work off the runtime.
    pub fn admit_task_work_blocking(&self, caller: EntityId) -> TaskWorkTurn {
        TaskWorkTurn {
            _permit: self.task_work.admit_blocking_untimed(caller),
        }
    }

    /// [`Self::admit_task_work_until`] on this thread.
    pub fn admit_task_work_blocking_until(
        &self,
        caller: EntityId,
        deadline: Instant,
    ) -> Result<TaskWorkTurn, WaitTimedOut> {
        Ok(TaskWorkTurn {
            _permit: self.task_work.admit_blocking_until(caller, deadline)?,
        })
    }
}
