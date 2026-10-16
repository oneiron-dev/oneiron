//! The saved-workflow pump: runs each open workflow's ready step on the
//! generative seat and advances it, without anyone calling a route.
//!
//! It wakes on the vault's post-commit attempt signal and once at start
//! (recovery). A step whose leaf is scheduled or backing off has no signal
//! of its own, so while any workflow is open but waiting the pump also
//! re-checks on a slow timer; with nothing open it only waits for a signal.
//! Each pass also resumes a TASK's attempts held while its comment was
//! unattached, once the comment is back (OF-368); a reattach signals no
//! attempt, so while any is held the timer runs too.
//! A failed step goes to the engine's failure ladder ([`super::step_failure`]).
//! A metered leaf with no spend left under its lease's cap stops before its
//! model call (OF-532); the engine pump settles each leaf's lease.
//!
//! On the same signal it asks each queued project question (OF-501): a
//! person's turn queued it by reference, and it runs here, off that turn, on
//! the host's typed ladder once the host installed one.
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use oneiron::Vault;
use oneiron::agent_dispatch::{
    AgentDispatcher, ProjectDetection, ProjectDetectionRun, WorkflowProgress,
};
use oneiron::attempt_queue::{AttemptId, AttemptQueue};
use oneiron::failure_ladder::FailureLadderOutcome;
use tokio::sync::{broadcast, watch};

use super::status::{IdleReason, StatusCell, WorkState, WorkStatus};
use super::step::StepRunner;
use super::step_failure::{FailedStep, held_leases, settle};

const LEASE_OWNER: &str = "oneiron-server-workflows";
/// Project questions lease apart from workflow steps, so a failed step's
/// settlement never reads one as its own.
const DETECTION_LEASE_OWNER: &str = "oneiron-server-project-detection";
/// How often an open-but-waiting workflow is looked at again.
const WAITING_RECHECK: Duration = Duration::from_secs(30);

pub(super) struct WorkflowPump {
    stop: watch::Sender<bool>,
    thread: std::thread::JoinHandle<()>,
    /// The host's typed project question, once the host holds a ladder for it.
    detection: Arc<OnceLock<ProjectDetection>>,
}

impl WorkflowPump {
    pub(super) fn spawn(
        vault: Arc<Vault>,
        runner: StepRunner,
        status: Arc<StatusCell>,
    ) -> std::io::Result<Self> {
        let (stop, stopped) = watch::channel(false);
        let detection = Arc::new(OnceLock::new());
        let questions = Arc::clone(&detection);
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
                pump(&runtime, &vault, &runner, &status, &questions, stopped);
            })?;
        Ok(Self {
            stop,
            thread,
            detection,
        })
    }

    /// Installs the host's typed project question, the way a code-mode
    /// provider takes its seat decisions: from the next pass on, each queued
    /// question runs on it. Until then the questions wait queued. `false`
    /// when one is installed already.
    #[allow(dead_code)] // No in-tree host builds the project question's ladder yet.
    pub(super) fn with_project_detection(&self, detection: ProjectDetection) -> bool {
        self.detection.set(detection).is_ok()
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
    detection: &OnceLock<ProjectDetection>,
    mut stopped: watch::Receiver<bool>,
) {
    let mut signals = AttemptQueue::new(vault).subscribe();
    loop {
        if *stopped.borrow() {
            return;
        }
        ask_project_questions(vault, detection, &stopped);
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
/// workflow is still open, a wave plan is pending, or any attempt is still
/// held for an unattached comment (and so may need a timed re-check).
fn pump_once(
    runtime: &tokio::runtime::Runtime,
    vault: &Vault,
    runner: &StepRunner,
    status: &StatusCell,
    stopped: &watch::Receiver<bool>,
) -> oneiron::Result<bool> {
    let held = match vault.release_annotation_holds() {
        Ok(sweep) => sweep.held > 0,
        Err(error) => {
            tracing::warn!(%error, "annotation hold release failed");
            true
        }
    };
    if !*stopped.borrow() {
        super::waves::run_once(runtime, vault, runner, status)?;
    }
    let dispatcher = AgentDispatcher::new(vault);
    let roots = dispatcher.open_workflow_roots()?;
    for root in &roots {
        loop {
            if *stopped.borrow() {
                return Ok(true);
            }
            let mut claimed: Option<(AttemptId, u32)> = None;
            let mut retryable = false;
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
                    // OF-532: a metered leaf runs under its spend lease. With
                    // nothing left under the cap it stops here, before any
                    // model call, and is not retried; the steps already done
                    // keep their saved results.
                    if let Some(scope) = dispatcher.spend_scope_for_attempt(step.attempt.id)? {
                        let guard = dispatcher.guard_for_scope(&scope)?;
                        if guard.read().remaining_units == 0 {
                            return Err(oneiron::Error::InvalidConfig(format!(
                                "workflow step spend cap reached under scope {scope}"
                            )));
                        }
                    }
                    runner.run(runtime, vault, step, context).map_err(|fault| {
                        retryable = fault.retryable;
                        fault.error
                    })
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
                    tracing::warn!(kind = ?error.kind(), ?root, "workflow step did not complete");
                    // The claim may have committed before the step's context
                    // failed to resolve: then the callback never ran, and the
                    // lease is found by owner. Nothing else runs on this pump.
                    let failed = match claimed {
                        Some((leaf, lease_count)) => vec![FailedStep {
                            leaf,
                            lease_count,
                            retryable,
                        }],
                        None => held_leases(vault, LEASE_OWNER).unwrap_or_else(|list| {
                            tracing::error!(%list, "held workflow leases could not be listed");
                            Vec::new()
                        }),
                    };
                    let mut released = !failed.is_empty();
                    for step in &failed {
                        let backoff = runner.retry_backoff_secs;
                        match settle(vault, *root, step, LEASE_OWNER, backoff, now_secs()) {
                            Ok(FailureLadderOutcome::Retried { .. }) => {}
                            Ok(_) => {
                                runner.forget(step.leaf);
                                tracing::warn!(?root, "a workflow step ended; its workflow stops");
                            }
                            Err(settlement) => {
                                tracing::error!(kind = ?settlement.kind(), leaf = ?step.leaf, "failed step was not settled");
                                released = false;
                            }
                        }
                    }
                    // Look at the workflow again now: a retry due at once runs,
                    // a spent leaf stops it. A later retry reads as Waiting.
                    if released {
                        continue;
                    }
                    break;
                }
            }
        }
    }
    let wave_pending = AttemptQueue::new(vault).list()?.iter().any(|attempt| {
        attempt.kind == oneiron::wave_orchestration::WAVE_PLAN_ATTEMPT_KIND
            && matches!(
                attempt.state,
                oneiron::attempt_queue::AttemptState::Queued
                    | oneiron::attempt_queue::AttemptState::Scheduled
                    | oneiron::attempt_queue::AttemptState::Leased
            )
    });
    Ok(held || wave_pending || !dispatcher.open_workflow_roots()?.is_empty())
}

/// Asks every queued project question on the host's ladder; with none
/// installed they wait queued. A question that fails is logged and ends its
/// attempt: the conversation's next person turn asks again.
fn ask_project_questions(
    vault: &Vault,
    detection: &OnceLock<ProjectDetection>,
    stopped: &watch::Receiver<bool>,
) {
    let Some(detection) = detection.get() else {
        return;
    };
    let dispatcher = AgentDispatcher::new(vault);
    while !*stopped.borrow() {
        match dispatcher.run_project_detection(detection, DETECTION_LEASE_OWNER, now_secs()) {
            Ok(ProjectDetectionRun::Idle) => return,
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "a project question did not complete");
                return;
            }
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
