//! The saved-workflow pump: runs each open workflow's ready step on the
//! generative seat and advances it, without anyone calling a route.
//!
//! It wakes on the vault's post-commit attempt signal and once at start
//! (recovery). A step whose leaf is scheduled or backing off has no signal
//! of its own, so while any workflow is open but waiting the pump also
//! re-checks on a slow timer; with nothing open it only waits for a signal.
use std::sync::Arc;
use std::time::Duration;

use oneiron::Vault;
use oneiron::agent_dispatch::{AgentDispatcher, WorkflowProgress};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, FailAttempt, RetryAttempt};
use tokio::sync::{broadcast, watch};

use super::status::{IdleReason, StatusCell, WorkState, WorkStatus};
use super::step::StepRunner;

const LEASE_OWNER: &str = "oneiron-server-workflows";
/// How often an open-but-waiting workflow is looked at again.
const WAITING_RECHECK: Duration = Duration::from_secs(30);
/// Tries of one step before its workflow stops.
const MAX_STEP_TRIES: u32 = 5;
/// Backoff before a failed step's next try, times the tries so far.
const STEP_RETRY_SECS: u64 = 30;

pub(super) struct WorkflowPump {
    stop: watch::Sender<bool>,
    thread: std::thread::JoinHandle<()>,
}

impl WorkflowPump {
    pub(super) fn spawn(
        vault: Arc<Vault>,
        runner: StepRunner,
        status: Arc<StatusCell>,
    ) -> std::io::Result<Self> {
        let (stop, stopped) = watch::channel(false);
        // Waiting from the moment the pump exists, so a status read right
        // after start never sees the pre-start state.
        status.update(|status| status.workflows = WorkStatus::waiting());
        let thread = std::thread::Builder::new()
            .name("oneiron-workflows".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        tracing::error!(%error, "workflow pump runtime failed to start");
                        status.update(|status| {
                            status.workflows = WorkStatus::idle(IdleReason::StartFailed);
                        });
                        return;
                    }
                };
                pump(&runtime, &vault, &runner, &status, stopped);
            })?;
        Ok(Self { stop, thread })
    }

    /// Asks the pump to stop between steps, without waiting.
    pub(super) fn signal_stop(&self) {
        let _ = self.stop.send(true);
    }

    /// Stops between steps; a step in flight finishes first.
    pub(super) async fn stop(self) {
        self.signal_stop();
        let _ = tokio::task::spawn_blocking(move || self.thread.join()).await;
    }
}

fn pump(
    runtime: &tokio::runtime::Runtime,
    vault: &Vault,
    runner: &StepRunner,
    status: &StatusCell,
    mut stopped: watch::Receiver<bool>,
) {
    let mut signals = AttemptQueue::new(vault).subscribe();
    loop {
        if *stopped.borrow() {
            return;
        }
        let open = match pump_once(runtime, vault, runner, status, &stopped) {
            Ok(open) => open,
            Err(error) => {
                tracing::error!(%error, "workflow pump pass failed");
                status.update(|status| status.workflows.last_error = Some(error.to_string()));
                true
            }
        };
        let woke = runtime.block_on(async {
            tokio::select! {
                biased;
                _ = stopped.wait_for(|stop| *stop) => false,
                signal = signals.recv() => !matches!(signal, Err(broadcast::error::RecvError::Closed)),
                () = tokio::time::sleep(WAITING_RECHECK), if open => true,
            }
        });
        if !woke {
            return;
        }
        // Drain the burst our own commits (and any concurrent ones) caused.
        while let Ok(()) | Err(broadcast::error::TryRecvError::Lagged(_)) = signals.try_recv() {}
    }
}

/// Runs every open workflow as far as it will go. Returns whether any
/// workflow is still open (and so may need a timed re-check).
fn pump_once(
    runtime: &tokio::runtime::Runtime,
    vault: &Vault,
    runner: &StepRunner,
    status: &StatusCell,
    stopped: &watch::Receiver<bool>,
) -> oneiron::Result<bool> {
    let dispatcher = AgentDispatcher::new(vault);
    let roots = dispatcher.open_workflow_roots()?;
    for root in &roots {
        loop {
            if *stopped.borrow() {
                return Ok(true);
            }
            let mut claimed: Option<(AttemptId, u32)> = None;
            let progress = dispatcher.run_workflow_step_output(
                *root,
                LEASE_OWNER,
                now_secs(),
                |step, context| {
                    claimed = Some((step.attempt.id, step.attempt.attempt_count));
                    status.update(|status| {
                        status.workflows.state = WorkState::Working;
                        status.workflows.started += 1;
                    });
                    runner.run(runtime, vault, step, context)
                },
            );
            status.update(|status| {
                status.workflows.state = WorkState::Waiting;
                match &progress {
                    Ok(_) if claimed.is_some() => status.workflows.completed += 1,
                    Ok(_) => {}
                    Err(error) => {
                        status.workflows.failed += u64::from(claimed.is_some());
                        status.workflows.last_error = Some(error.to_string());
                    }
                }
            });
            match progress {
                Ok(WorkflowProgress::Advanced(_)) => continue,
                Ok(_) => break,
                Err(error) => {
                    tracing::warn!(%error, ?root, "workflow step did not complete");
                    if let Some((leaf, tries)) = claimed
                        && let Err(release) = give_back(vault, leaf, tries, &error)
                    {
                        tracing::error!(%release, ?leaf, "failed step's lease was not given back");
                    }
                    break;
                }
            }
        }
    }
    Ok(!dispatcher.open_workflow_roots()?.is_empty())
}

/// Releases a failed step's lease this pump holds: a later try with backoff,
/// or a failed leaf (and so a stopped workflow) once the tries are spent.
fn give_back(
    vault: &Vault,
    leaf: AttemptId,
    tries: u32,
    error: &oneiron::Error,
) -> oneiron::Result<()> {
    let queue = AttemptQueue::new(vault);
    let now = now_secs();
    if tries >= MAX_STEP_TRIES {
        queue.fail(FailAttempt {
            id: leaf,
            lease_owner: LEASE_OWNER.to_owned(),
            attempt_count: tries,
            reason: "workflow_step_failed".to_owned(),
            now,
        })?;
    } else {
        queue.retry(RetryAttempt {
            id: leaf,
            lease_owner: LEASE_OWNER.to_owned(),
            attempt_count: tries,
            backoff_until: now
                .saturating_add(STEP_RETRY_SECS.saturating_mul(u64::from(tries.max(1)))),
            last_error: Some(error.to_string()),
            now,
        })?;
    }
    Ok(())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
