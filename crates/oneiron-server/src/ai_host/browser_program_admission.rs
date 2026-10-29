//! The browser program admission worker (CUA E8b; DESIGN-2 "The Coach",
//! row E8): it runs each program the Coach proposed, as the source caller
//! the program was induced from, through the library's own propose door.
//! The Coach never admits its own work; this worker admits nothing on its
//! own say-so either: the library's page check, fresh no-model replay and
//! filing are the only admission, placed by rule alone.
//!
//! It claims `browser.program.admit` jobs, one per pass the vault admits,
//! each pass held through the job's blocking browser work. It wakes on the
//! vault's post-commit attempt signal, once at start, and on the recheck
//! tick, which only retries a pass the vault's freeze refused. No model seat
//! gates it: the job makes no model call.
//!
//! A job runs once. One claimed a second time was cut off when the process
//! stopped under it: its receipt names what a filing in its run filed, and
//! it is failed, never run again. Each job's receipt keeps its typed
//! outcome; its end drops the signed binding each of its sources kept.

use std::sync::{Arc, Weak};
use std::time::Duration;

use oneiron::attempt_queue::{
    AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, CompleteAttempt, FailAttempt,
};
use oneiron::browser_library::{
    PROGRAM_ADMISSION_KIND, ProgramAdmissionJob, ProgramAdmissionOutcome, admission_sources,
    program_admission_job_id, record_program_admission, record_undecodable_program_admission,
};
use tokio::sync::broadcast;

use crate::api::RunGuests;
use crate::server::{HousekeepingAdmission, SyncServer};

const LEASE_OWNER: &str = "oneiron-server-browser-program-admission";
/// How long a pass the vault's freeze refused waits before it is tried
/// again, when no queue signal wakes the worker first (CUA E8b, CALLS row
/// "wake"): the Coach host's own poll cadence. Queued jobs wake it at once.
const ADMISSION_RECHECK: Duration = Duration::from_secs(60);
/// Recorded on an attempt whose reason does not fit the queue's bound.
const FAILED: &str = "the browser program admission failed";

/// Starts the worker. Each job runs on a blocking thread, under the pass
/// `admit` returned for it; a pass `admit` refuses waits for the next wake.
pub(crate) fn spawn(
    server: &Arc<SyncServer>,
    admit: HousekeepingAdmission,
) -> tokio::task::JoinHandle<()> {
    let weak = Arc::downgrade(server);
    let mut signals = AttemptQueue::new(&server.vault).subscribe();
    tokio::spawn(async move {
        let mut recheck = tokio::time::interval(ADMISSION_RECHECK);
        recheck.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            if !drain(&weak, &admit).await {
                return;
            }
            tokio::select! {
                biased;
                signal = signals.recv() => {
                    if matches!(signal, Err(broadcast::error::RecvError::Closed)) {
                        return;
                    }
                }
                _ = recheck.tick() => {}
            }
            // Drain the burst our own commits (and any concurrent ones) caused.
            while let Ok(()) | Err(broadcast::error::TryRecvError::Lagged(_)) = signals.try_recv() {
            }
        }
    })
}

/// Runs queued jobs, one per admitted pass, until none is queued or a pass
/// is refused. False once the server is gone.
async fn drain(weak: &Weak<SyncServer>, admit: &HousekeepingAdmission) -> bool {
    loop {
        let Some(server) = weak.upgrade() else {
            return false;
        };
        let Some(pass) = admit() else {
            return true;
        };
        let runtime = tokio::runtime::Handle::current();
        let ran = tokio::task::spawn_blocking(move || {
            let _pass = pass;
            round(&server, &runtime)
        })
        .await;
        match ran {
            Ok(true) => {}
            Ok(false) => return true,
            // A stopped pass logs a static code, never its payload.
            Err(error) => {
                let code = if error.is_panic() {
                    "browser_program_admission_panicked"
                } else {
                    "browser_program_admission_cancelled"
                };
                tracing::warn!(code, "a browser program admission pass stopped");
                return true;
            }
        }
    }
}

/// Claims one job and runs it to its end. Whether one was claimed.
fn round(server: &Arc<SyncServer>, runtime: &tokio::runtime::Handle) -> bool {
    let vault = &server.vault;
    let claimed = AttemptQueue::new(vault).claim_kind(
        PROGRAM_ADMISSION_KIND,
        ClaimAttempt {
            lease_owner: LEASE_OWNER.to_owned(),
            now: vault.now_recorded_at(),
        },
    );
    let attempt = match claimed {
        Ok(ClaimOutcome::Claimed(attempt)) => attempt,
        Ok(_) => return false,
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "browser program admission claim failed");
            return false;
        }
    };
    let result = run(server, runtime, &attempt);
    settle(vault, &attempt, result);
    true
}

/// Runs one claimed job and records its receipt: `Ok` once a job that ran
/// is recorded, the reason the attempt fails otherwise.
fn run(
    server: &Arc<SyncServer>,
    runtime: &tokio::runtime::Handle,
    attempt: &AttemptRecord,
) -> Result<(), String> {
    let job = match ProgramAdmissionJob::decode(attempt) {
        Ok(job) => job,
        Err(error) => return run_undecodable(server, attempt, error.to_string()),
    };
    let job_id = program_admission_job_id(attempt).map_err(|error| error.to_string())?;
    let outcome = if attempt.attempt_count > 1 {
        ProgramAdmissionOutcome::Interrupted { filed: None }
    } else {
        job_outcome(server, runtime, attempt, job_id, &job)
    };
    let now = server.vault.now_recorded_at();
    let receipt = record_program_admission(&server.vault, job_id, &job, &outcome, now)
        .map_err(|error| error.to_string())?;
    tracing::info!(job = %job_id.to_hex(), outcome = ?receipt.outcome, "browser program admission ended");
    if matches!(outcome, ProgramAdmissionOutcome::Interrupted { .. }) {
        return Err("cut off when the process stopped; not run again".into());
    }
    Ok(())
}

/// Records a job whose payload does not decode and fails its attempt
/// (FIX 10716): a receipt with the undecodable outcome, and its sources'
/// kept bindings dropped. A job id that itself fails keeps today's
/// fail-only path: no receipt key exists.
fn run_undecodable(
    server: &Arc<SyncServer>,
    attempt: &AttemptRecord,
    reason: String,
) -> Result<(), String> {
    let job_id = program_admission_job_id(attempt).map_err(|error| error.to_string())?;
    let sources = undecodable_sources(attempt);
    let now = server.vault.now_recorded_at();
    let receipt = record_undecodable_program_admission(&server.vault, job_id, &sources, now)
        .map_err(|error| error.to_string())?;
    tracing::info!(job = %job_id.to_hex(), outcome = ?receipt.outcome, "browser program admission ended");
    Err(reason)
}

/// The source evidence ids a payload that does not decode still names
/// (FIX 10716): `source_evidence` hex ids only; anything else is unread.
fn undecodable_sources(attempt: &AttemptRecord) -> Vec<oneiron::EntityId> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&attempt.payload) else {
        return Vec::new();
    };
    let Some(list) = value
        .get("source_evidence")
        .and_then(serde_json::Value::as_array)
    else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|id| {
            id.as_str()
                .and_then(|hex| oneiron::EntityId::from_hex(hex).ok())
        })
        .collect()
}

/// What job `job` comes to: its sources and their caller as they stand
/// now, then its run as that caller, which judges the proposal's
/// readiness once the caller stands.
fn job_outcome(
    server: &Arc<SyncServer>,
    runtime: &tokio::runtime::Handle,
    attempt: &AttemptRecord,
    job_id: oneiron::EntityId,
    job: &ProgramAdmissionJob,
) -> ProgramAdmissionOutcome {
    let sources = match admission_sources(&server.vault, job_id, job) {
        Ok(Ok(sources)) => sources,
        Ok(Err(cause)) => return ProgramAdmissionOutcome::SourceUnavailable { cause },
        // By kind only: an engine error can quote the vault.
        Err(error) => {
            return ProgramAdmissionOutcome::Failed {
                kind: format!("{:?}", error.kind()),
            };
        }
    };
    RunGuests::admit_program(
        server,
        runtime,
        attempt,
        job_id,
        job,
        &sources.caller,
        &sources.evidence,
    )
}

/// Completes or fails the attempt; either is terminal.
fn settle(vault: &oneiron::Vault, attempt: &AttemptRecord, result: Result<(), String>) {
    let queue = AttemptQueue::new(vault);
    let now = vault.now_recorded_at();
    let fail = |reason: String| {
        queue.fail(FailAttempt {
            id: attempt.id,
            lease_owner: LEASE_OWNER.to_owned(),
            attempt_count: attempt.attempt_count,
            reason,
            now,
        })
    };
    let settled = match result {
        Ok(()) => queue
            .complete(CompleteAttempt {
                id: attempt.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: attempt.attempt_count,
                now,
            })
            .map(drop),
        // The reason is recorded on the attempt, not logged: it can quote
        // the vault.
        Err(reason) => fail(reason).or_else(|_| fail(FAILED.to_owned())).map(drop),
    };
    if let Err(error) = settled {
        tracing::warn!(kind = ?error.kind(), attempt = ?attempt.id, "browser program admission was not settled");
    }
}
