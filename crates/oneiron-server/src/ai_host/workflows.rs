//! The saved-workflow pump: runs each open workflow's ready step on the
//! generative seat and advances it, without anyone calling a route.
//!
//! It wakes on the vault's post-commit attempt signal and once at start
//! (recovery). A step whose leaf is scheduled or backing off has no signal
//! of its own, so the pump sleeps until the earliest such instant, once
//! (FIX 9467). A held human budget resumes on its owner's act and an
//! unattached comment's attempts on its reattach, both of which signal
//! attempts. Only waiting work no change signals keeps the slow recheck,
//! while it lasts: a payer park (a funding change has no signal), an owed
//! hold notice, a TASK that did not settle, a wave plan with no instant, or
//! a pass that failed. With none of these it only waits for a signal.
//! Each pass also resumes a TASK's attempts held while its comment was
//! unattached, once the comment is back (OF-368).
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
//!
//! Each pass, at start and on every wake, also settles the TASK each ended
//! run that realizes one still owes it (FIX 4391), a run that ended in this
//! pass included: in a writer of its own per run, a completed run's
//! done-means judged on the host's ladder outside it. A run that does not
//! settle is logged, and the timer looks again.
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use oneiron::Vault;
use oneiron::agent_dispatch::{
    AgentDispatcher, BudgetHoldLease, ProjectDetection, ProjectDetectionRun, SpendSignal,
    WorkflowProgress,
};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptResumePoint, AttemptState};
use oneiron::failure_ladder::FailureLadderOutcome;
use oneiron::learning::TypeRef;
use oneiron::self_heal::audit::{AttemptConfession, ObjectiveConfession};
use oneiron::task_verb::RunnerDoneAnswer;
use tokio::sync::{Notify, broadcast, watch};

use super::status::{IdleReason, StatusCell, WorkState, WorkStatus};
use super::step::{StepFault, StepRunner, deliver_hold_notice};
use super::step_failure::{FailedStep, held_leases, settle};
use crate::decision_host::DecisionHost;

const LEASE_OWNER: &str = "oneiron-server-workflows";
/// Project questions lease apart from workflow steps, so a failed step's
/// settlement never reads one as its own.
const DETECTION_LEASE_OWNER: &str = "oneiron-server-project-detection";
/// How often waiting work no change signals is looked at again.
const WAITING_RECHECK: Duration = Duration::from_secs(30);

/// What the pump waits for after a pass, beside the attempt signal (FIX
/// 9467): the next real scheduled or backoff instant, and whether some
/// waiting work has no signal that wakes it, which keeps the slow recheck
/// while it lasts.
#[derive(Debug, Clone, Copy, Default)]
struct PumpWake {
    /// A payer park, an owed hold notice, an unsettled TASK, a wave plan
    /// with no instant, or a failed sweep or pass.
    recheck: bool,
    /// The earliest future `scheduled_at` or `backoff_until` of a waiting
    /// attempt, in Unix seconds.
    due: Option<u64>,
}

pub(super) struct WorkflowPump {
    stop: watch::Sender<bool>,
    thread: std::thread::JoinHandle<()>,
    /// The host's typed project question, once the host holds a ladder for it.
    detection: Arc<OnceLock<ProjectDetection>>,
    /// Wakes the pump once the host installs its project question, so
    /// questions queued before it run then (FIX 9467).
    ready: Arc<Notify>,
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
        let ready = Arc::new(Notify::new());
        let installed = Arc::clone(&ready);
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
                    &runtime, &vault, &runner, &status, &questions, &decisions, &installed, stopped,
                );
            })?;
        Ok(Self {
            stop,
            thread,
            detection,
            ready,
        })
    }

    /// Installs the host's typed project question, the way a code-mode
    /// provider takes its seat decisions: from the next pass on, each queued
    /// question runs on it. Until then the questions wait queued. `false`
    /// when one is installed already.
    pub(super) fn with_project_detection(&self, detection: ProjectDetection) -> bool {
        let installed = self.detection.set(detection).is_ok();
        if installed {
            self.ready.notify_one();
        }
        installed
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
    decisions: &OnceLock<DecisionHost>,
    ready: &Notify,
    mut stopped: watch::Receiver<bool>,
) {
    let mut signals = AttemptQueue::new(vault).subscribe();
    loop {
        if *stopped.borrow() {
            return;
        }
        ask_project_questions(vault, detection, &stopped);
        let wake = match pump_once(runtime, vault, runner, status, decisions.get(), &stopped) {
            Ok(wake) => wake,
            Err(error) => {
                tracing::error!(%error, "workflow pump pass failed");
                status.update(|status| status.workflows.last_error = Some(error.to_string()));
                PumpWake {
                    recheck: true,
                    due: None,
                }
            }
        };
        // One sleep to the next real instant, armed anew after every pass.
        let until_due = wake
            .due
            .map(|due| Duration::from_secs(due.saturating_sub(now_secs())));
        let woke = runtime.block_on(async {
            tokio::select! {
                biased;
                _ = stopped.wait_for(|stop| *stop) => false,
                signal = signals.recv() => !matches!(signal, Err(broadcast::error::RecvError::Closed)),
                () = ready.notified() => true,
                () = tokio::time::sleep(until_due.unwrap_or_default()), if until_due.is_some() => true,
                () = tokio::time::sleep(WAITING_RECHECK), if wake.recheck => true,
            }
        });
        if !woke {
            return;
        }
        // Drain the burst our own commits (and any concurrent ones) caused.
        while let Ok(()) | Err(broadcast::error::TryRecvError::Lagged(_)) = signals.try_recv() {}
    }
}

/// Runs every open workflow as far as it will go. Returns what the pump
/// waits for next: the earliest scheduled or backoff instant of a waiting
/// attempt, and whether waiting work no change signals is left (FIX 9467).
fn pump_once(
    runtime: &tokio::runtime::Runtime,
    vault: &Vault,
    runner: &StepRunner,
    status: &StatusCell,
    decisions: Option<&DecisionHost>,
    stopped: &watch::Receiver<bool>,
) -> oneiron::Result<PumpWake> {
    // A held comment's attempts resume on its reattach, which signals; a
    // sweep that failed is looked at again on the recheck.
    let mut recheck = match vault.release_annotation_holds() {
        Ok(_) => false,
        Err(error) => {
            tracing::warn!(%error, "annotation hold release failed");
            true
        }
    };
    if !*stopped.borrow() {
        super::waves::run_once(runtime, vault, runner, status, decisions)?;
    }
    // A step parked on its payer goes on once the owners said yes (FIX 805);
    // a funding change no commit signals is caught on the recheck.
    recheck |= super::payer_funding::resume_payer_parks(vault, LEASE_OWNER, now_secs(), Some(&runner.spent))
        > 0;
    let dispatcher = AgentDispatcher::new(vault);
    let roots = dispatcher.open_workflow_roots()?;
    for root in &roots {
        // A notice a crash or a refusal left owed goes out first.
        recheck |= deliver_hold_notice(&dispatcher, *root, now_secs());
        loop {
            if *stopped.borrow() {
                return Ok(PumpWake {
                    recheck: true,
                    due: None,
                });
            }
            let mut claimed: Option<(AttemptId, u32)> = None;
            let mut retryable = false;
            let mut held = None;
            let mut parked = false;
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
                    bind_attribution(vault, step.attempt.id);
                    match ran {
                        Ok(output) => {
                            // The seal measures the agent that ran, on the
                            // type the spawn was placed under. A step asked
                            // to confess is sealed whether or not its
                            // confession parsed (FIX 9466): each objective
                            // it gave no answer for is recorded as none.
                            let objectives = match output.confession {
                                Some(confessed) => confessed,
                                None => output.objectives.into_iter().map(unanswered).collect(),
                            };
                            confession = step
                                .input
                                .target
                                .agent_definition_ref()
                                .ok()
                                .filter(|_| !objectives.is_empty())
                                .map(|subject| AttemptConfession {
                                    attempt: step.attempt.id,
                                    subject,
                                    type_ref: TypeRef::from(&step.input.type_ref),
                                    objectives,
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
                        // Its payer waits on the owners' payer-needed ask
                        // (FIX 805): the step parks as this try, its lease
                        // and spend scope held, neither failed nor retried.
                        Err(StepFault {
                            payer: Some(fault),
                            error,
                            ..
                        }) => {
                            super::payer_funding::park_for_payer(
                                vault,
                                step.attempt.id,
                                LEASE_OWNER,
                                &fault,
                                runner
                                    .spent
                                    .lock()
                                    .expect("step spend mutex poisoned")
                                    .get(&step.attempt.id)
                                    .copied(),
                                now_secs(),
                            )?;
                            parked = true;
                            Err(error)
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
                    Err(_) if held.is_some() || parked => {}
                    Err(error) => {
                        status.workflows.failed += u64::from(claimed.is_some());
                        status.workflows.last_error = Some(error.to_string());
                    }
                }
            });
            // A leaf that completed durably is sealed, and so stays in the
            // random-audit pool, even when advancing its wrapper did not
            // (FIX 9466).
            if let Some(confession) = confession
                && leaf_completed(vault, confession.attempt)
            {
                seal(vault, &confession);
            }
            // The held leaf waits paused; its workflow waits with it until
            // the owner resumes the hold. The notice rides the hold, and
            // goes to the owners now.
            if held.is_some() {
                tracing::info!(?root, "a workflow is held at its spend cap");
                recheck |= deliver_hold_notice(&dispatcher, *root, now_secs());
                break;
            }
            // The parked step's workflow waits with it; the owners' ask is
            // its notice.
            if parked {
                tracing::info!(?root, "a workflow waits on its payer");
                break;
            }
            match progress {
                Ok(WorkflowProgress::Advanced(_)) => continue,
                // A successor whose release was refused (FIX 10602) waits on
                // a definition change no commit signals: looked at again on
                // the recheck, for as long as it waits.
                Ok(WorkflowProgress::Waiting(_)) => {
                    recheck |= !dispatcher
                        .workflow_status(*root)
                        .is_ok_and(|status| status.release_refusal.is_none());
                    break;
                }
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
                            recheck = true;
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
                                // An unsettled lease is looked at again.
                                recheck = true;
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
    recheck |= settle_workflow_tasks(vault, decisions);
    let attempts = AttemptQueue::new(vault).list()?;
    let now = now_secs();
    // A scheduled or backing-off try wakes the pump at its own instant, the
    // readiness instant its claim reads.
    let instant = |attempt: &oneiron::attempt_queue::AttemptRecord| {
        if !matches!(
            attempt.state,
            oneiron::attempt_queue::AttemptState::Queued
                | oneiron::attempt_queue::AttemptState::Scheduled
        ) {
            return None;
        }
        attempt
            .scheduled_at
            .or(attempt.backoff_until)
            .filter(|due| *due > now)
    };
    let due = attempts.iter().filter_map(instant).min();
    // A wave plan with no instant of its own (queued or leased) keeps the
    // recheck, as it did.
    recheck |= attempts.iter().any(|attempt| {
        attempt.kind == oneiron::wave_orchestration::WAVE_PLAN_ATTEMPT_KIND
            && matches!(
                attempt.state,
                oneiron::attempt_queue::AttemptState::Queued
                    | oneiron::attempt_queue::AttemptState::Scheduled
                    | oneiron::attempt_queue::AttemptState::Leased
            )
            && instant(attempt).is_none()
    });
    Ok(PumpWake { recheck, due })
}

/// Settles the TASK each ended run that realizes one still owes it, one
/// writer per run (FIX 4391). A completed run's done-means is judged here,
/// outside that writer, on the host's ladder once the host installed one;
/// until then its Done asks up. `true` while any run still owes it: one
/// that failed to settle is logged and tried again on the next pass.
fn settle_workflow_tasks(vault: &Vault, decisions: Option<&DecisionHost>) -> bool {
    let dispatcher = AgentDispatcher::new(vault);
    let roots = match dispatcher.unsettled_workflow_tasks() {
        Ok(roots) => roots,
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "ended workflows that realize a TASK could not be listed");
            return true;
        }
    };
    let mut owed = false;
    for root in roots {
        let judged = judge_workflow_done(&dispatcher, root, decisions);
        if let Err(error) = dispatcher.settle_workflow_task(root, judged, now_secs()) {
            owed = true;
            tracing::warn!(kind = ?error.kind(), ?root, "a workflow's TASK did not settle; the next pass tries again");
        }
    }
    owed
}

/// A completed run's "Done means met?", answered on the host's ladder. With
/// no question owed, no ladder installed yet, or questions that do not hold,
/// there is no answer and the Done asks up.
fn judge_workflow_done(
    dispatcher: &AgentDispatcher<'_>,
    root: AttemptId,
    decisions: Option<&DecisionHost>,
) -> Option<RunnerDoneAnswer> {
    let question = match dispatcher.workflow_done_question(root) {
        Ok(question) => question?,
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), ?root, "a workflow's Done question could not be read; its Done asks up");
            return None;
        }
    };
    match decisions?.task_decisions() {
        Ok(decisions) => Some(question.decide(&decisions)),
        Err(error) => {
            tracing::warn!(%error, "the task surface's questions are invalid; Done asks up");
            None
        }
    }
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

/// An objective a step was asked to confess against and gave no answer for:
/// recorded as none, never filled in (FIX 9466).
fn unanswered(objective: String) -> ObjectiveConfession {
    ObjectiveConfession {
        objective,
        met: None,
        flaw: None,
        uncertainty: None,
    }
}

/// Whether the leaf `attempt` settled Completed, read now. One that does not
/// read is logged and left unsealed; its work stands.
fn leaf_completed(vault: &Vault, attempt: AttemptId) -> bool {
    match AttemptQueue::new(vault).get(attempt) {
        Ok(record) => record.is_some_and(|record| record.state == AttemptState::Completed),
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), ?attempt, "a workflow leaf's state did not read; it is not sealed");
            false
        }
    }
}

/// Binds the execution context of the leaf `attempt` that just ran, its
/// judge unknown until the model whose answer to its Done stands is recorded
/// (FIX 1877). One that cannot bind leaves the leaf to close unattributed;
/// its work stands.
fn bind_attribution(vault: &Vault, attempt: AttemptId) {
    if let Err(error) =
        oneiron::skill_attribution::bind_agent_run_attribution(vault, attempt, LEASE_OWNER)
    {
        tracing::warn!(%error, ?attempt, "a workflow leaf's pack attribution did not bind");
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
