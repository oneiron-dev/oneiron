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
use oneiron::attempt_queue::{AttemptQueue, CleanupAttemptLeases};
use tokio::sync::{broadcast, watch};

use super::status::{StatusCell, WorkState};
use super::step::StepRunner;

const LEASE_OWNER: &str = "oneiron-server-workflows";
/// How often an open-but-waiting workflow is looked at again.
const WAITING_RECHECK: Duration = Duration::from_secs(30);
/// A leaf lease older than this belongs to a step that died mid-call.
const STUCK_LEASE_SECS: u64 = 15 * 60;

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
                        return;
                    }
                };
                pump(&runtime, &vault, &runner, &status, stopped);
            })?;
        Ok(Self { stop, thread })
    }

    /// Stops between steps; a step in flight finishes first.
    pub(super) async fn stop(self) {
        let _ = self.stop.send(true);
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
    status.update(|status| status.workflows.state = WorkState::Waiting);
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
    let now = now_secs();
    AttemptQueue::new(vault).cleanup_leases(CleanupAttemptLeases {
        now,
        lease_timeout_secs: STUCK_LEASE_SECS,
    })?;
    let dispatcher = AgentDispatcher::new(vault);
    let roots = dispatcher.open_workflow_roots()?;
    for root in &roots {
        loop {
            if *stopped.borrow() {
                return Ok(true);
            }
            let mut ran = false;
            let progress = dispatcher.run_workflow_step_output(
                *root,
                LEASE_OWNER,
                now_secs(),
                |step, context| {
                    ran = true;
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
                    Ok(_) if ran => status.workflows.completed += 1,
                    Ok(_) => {}
                    Err(error) => {
                        status.workflows.failed += u64::from(ran);
                        status.workflows.last_error = Some(error.to_string());
                    }
                }
            });
            match progress {
                Ok(WorkflowProgress::Advanced(_)) => continue,
                Ok(_) => break,
                Err(error) => {
                    tracing::warn!(%error, ?root, "workflow step did not complete");
                    break;
                }
            }
        }
    }
    Ok(!dispatcher.open_workflow_roots()?.is_empty())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
