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
//! A metered leaf near its cap sends the run's other running agents the
//! wrap-up warning; with no spend left it is held before its model call, its
//! saved results kept and its checkpoint recorded, resumable and never failed
//! (OF-532, OF-541); the engine pump settles each leaf's lease.
//! A leaf that ran binds its execution context while its lease still holds,
//! on the host's decision ladder once the host installed one, so its pack
//! receipt closes attributed (OF-540).
//!
//! A wave cut's fan-out under the vault's `auto` mode is ruled on through the
//! host's decision ladder once the host installed it (FIX 939).
//!
//! A leaf that confessed (OF-544) is sealed with its confession once it has
//! completed: the seal pins its result and executor and opens a directed
//! check for each flaw or doubt it names. A leaf that gave none is sealed
//! with none.
//!
//! On the same signal it asks each queued project question (OF-501): a
//! person's turn queued it by reference, and it runs here, off that turn, on
//! the host's typed ladder once the host installed one.
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use oneiron::Vault;
use oneiron::agent_dispatch::{
    AgentDispatcher, BudgetHoldLease, ProjectDetection, ProjectDetectionRun, SpendSignal,
    WorkflowProgress,
};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptResumePoint};
use oneiron::failure_ladder::FailureLadderOutcome;
use oneiron::learning::TypeRef;
use oneiron::llm::decision::HeldLadder;
use oneiron::self_heal::audit::AttemptConfession;
use tokio::sync::{broadcast, watch};

use super::status::{IdleReason, StatusCell, WorkState, WorkStatus};
use super::step::{StepRunner, deliver_hold_notice};
use super::step_failure::{FailedStep, held_leases, settle};
use crate::decision_host::DecisionHost;

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
    /// The host's decision ladder, whose judge a leaf's attribution names.
    attribution: Arc<OnceLock<HeldLadder>>,
}

impl WorkflowPump {
    /// `decisions` is the host's decision host, shared with the Dreamer: the
    /// host installs it once it staffs its ladder, and from the next wave cut
    /// on its fan-out is ruled on through it.
    pub(super) fn spawn(
        vault: Arc<Vault>,
        runner: StepRunner,
        status: Arc<StatusCell>,
        decisions: Arc<OnceLock<DecisionHost>>,
    ) -> std::io::Result<Self> {
        let (stop, stopped) = watch::channel(false);
        let detection = Arc::new(OnceLock::new());
        let questions = Arc::clone(&detection);
        let attribution = Arc::new(OnceLock::new());
        let judges = Arc::clone(&attribution);
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
                pump(
                    &runtime, &vault, &runner, &status, &questions, &judges, &decisions, stopped,
                );
            })?;
        Ok(Self {
            stop,
            thread,
            detection,
            attribution,
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

    /// Installs the host's decision ladder for leaf attribution: from the next
    /// leaf on, each one that ran binds its execution context, judged on it.
    /// Until then leaves close unattributed. `false` when one is installed
    /// already.
    #[allow(dead_code)] // The host's attach installs it once it staffs its ladder.
    pub(super) fn with_attribution_ladder(&self, judges: HeldLadder) -> bool {
        self.attribution.set(judges).is_ok()
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

#[expect(
    clippy::too_many_arguments,
    reason = "the pump's one thread holds each hook the host installs"
)]
fn pump(
    runtime: &tokio::runtime::Runtime,
    vault: &Vault,
    runner: &StepRunner,
    status: &StatusCell,
    detection: &OnceLock<ProjectDetection>,
    attribution: &OnceLock<HeldLadder>,
    decisions: &OnceLock<DecisionHost>,
    mut stopped: watch::Receiver<bool>,
) {
    let mut signals = AttemptQueue::new(vault).subscribe();
    loop {
        if *stopped.borrow() {
            return;
        }
        ask_project_questions(vault, detection, &stopped);
        let open = match pump_once(
            runtime,
            vault,
            runner,
            status,
            attribution,
            decisions.get(),
            &stopped,
        ) {
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
    attribution: &OnceLock<HeldLadder>,
    decisions: Option<&DecisionHost>,
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
        super::waves::run_once(runtime, vault, runner, status, decisions)?;
    }
    let dispatcher = AgentDispatcher::new(vault);
    let roots = dispatcher.open_workflow_roots()?;
    for root in &roots {
        // A notice a crash or a refusal left owed goes out first.
        deliver_hold_notice(&dispatcher, *root, now_secs());
        loop {
            if *stopped.borrow() {
                return Ok(true);
            }
            let mut claimed: Option<(AttemptId, u32)> = None;
            let mut retryable = false;
            let mut held = None;
            let mut confession = None;
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
                    // OF-532/OF-541: a metered leaf runs under its spend lease.
                    // Near the cap the run's other agents get the wrap-up
                    // warning. With nothing left the leaf is held here, before
                    // any model call: paused with its checkpoint, the steps
                    // already done keep their saved results, and the owner is
                    // owed a notice. A hold is not a failure and not retried.
                    if let Some(scope) = dispatcher.spend_scope_for_attempt(step.attempt.id)? {
                        let read = dispatcher.spend_read(&scope)?;
                        let now = now_secs();
                        let reason = format!("workflow spend cap under scope {scope}");
                        dispatcher.budget_signal(
                            *root,
                            &read,
                            Some(step.attempt.id),
                            &reason,
                            now,
                        )?;
                        if matches!(read.signal, Some(SpendSignal::AtCap { .. })) {
                            let hold = dispatcher.hold_for_budget(
                                *root,
                                BudgetHoldLease {
                                    attempt: step.attempt.id,
                                    lease_owner: LEASE_OWNER.to_owned(),
                                    attempt_count: step.attempt.attempt_count,
                                    resume_point: AttemptResumePoint::new(
                                        "workflow-step:before-model-call",
                                        now,
                                    ),
                                },
                                None,
                                &reason,
                                now,
                            )?;
                            held = Some(hold);
                            return Err(oneiron::Error::InvalidConfig(format!(
                                "workflow step held at the spend cap under scope {scope}"
                            )));
                        }
                    }
                    let ran = runner.run(runtime, vault, step, context);
                    // OF-540: bound before the engine completes the leaf or
                    // its failure is settled, while the lease still holds.
                    bind_attribution(vault, step.attempt.id, attribution);
                    match ran {
                        Ok(output) => {
                            // The seal measures the agent that ran, on the
                            // type the spawn was placed under.
                            confession = output.confession.and_then(|objectives| {
                                Some(AttemptConfession {
                                    attempt: step.attempt.id,
                                    subject: step.input.target.agent_definition_ref().ok()?,
                                    type_ref: TypeRef::from(&step.input.type_ref),
                                    objectives,
                                })
                            });
                            Ok(output.bytes)
                        }
                        // The meter ran out inside the model call: held as
                        // at the boundary, from the checkpoint before the
                        // call it could not pay for.
                        Err(fault) if fault.exhausted => {
                            let now = now_secs();
                            held = Some(dispatcher.hold_for_budget(
                                *root,
                                BudgetHoldLease {
                                    attempt: step.attempt.id,
                                    lease_owner: LEASE_OWNER.to_owned(),
                                    attempt_count: step.attempt.attempt_count,
                                    resume_point: AttemptResumePoint::new(
                                        "workflow-step:before-model-call",
                                        now,
                                    ),
                                },
                                None,
                                "workflow step budget ran out during its model call",
                                now,
                            )?);
                            Err(fault.error)
                        }
                        Err(fault) => {
                            retryable = fault.retryable;
                            Err(fault.error)
                        }
                    }
                },
            );
            status.update(|status| {
                status.workflows.state = WorkState::Waiting;
                match &progress {
                    Ok(_) if claimed.is_some() => status.workflows.completed += 1,
                    Ok(_) => {}
                    Err(_) if held.is_some() => {}
                    Err(error) => {
                        status.workflows.failed += u64::from(claimed.is_some());
                        status.workflows.last_error = Some(error.to_string());
                    }
                }
            });
            if progress.is_ok()
                && let Some(confession) = confession
            {
                seal(vault, &confession);
            }
            // The held leaf waits paused; its workflow waits with it until
            // the owner resumes the hold. The notice rides the hold, and
            // goes to the owners now.
            if held.is_some() {
                tracing::info!(?root, "a workflow is held at its spend cap");
                deliver_hold_notice(&dispatcher, *root, now_secs());
                break;
            }
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

/// Seals the leaf that just completed with its confession. A refusal (the
/// leaf did not settle with a result and an executor, or the confession
/// does not hold) is logged; the completed work stands.
fn seal(vault: &Vault, confession: &AttemptConfession) {
    if let Err(error) = vault.record_attempt_confession(confession, now_secs()) {
        tracing::warn!(kind = ?error.kind(), attempt = ?confession.attempt, "a workflow leaf's confession was not sealed");
    }
}

/// Binds the execution context of the leaf `attempt` that just ran. One that
/// cannot bind leaves the leaf to close unattributed; its work stands.
fn bind_attribution(vault: &Vault, attempt: AttemptId, attribution: &OnceLock<HeldLadder>) {
    static UNINSTALLED: std::sync::Once = std::sync::Once::new();
    let Some(judges) = attribution.get() else {
        UNINSTALLED.call_once(|| {
            tracing::warn!(
                "a workflow leaf ran before the host installed its decision ladder; it closes unattributed"
            );
        });
        return;
    };
    if let Err(error) =
        oneiron::skill_attribution::bind_agent_run_attribution(vault, attempt, LEASE_OWNER, judges)
    {
        tracing::warn!(%error, ?attempt, "a workflow leaf's pack attribution did not bind");
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
