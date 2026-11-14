//! `oneiron serve`'s rescans of every attached folder, Files sources
//! included (OF-554, FIX 6942): the one reconciliation they all share, never
//! a watcher of their own. They are durable jobs on the vault's attempt
//! queue (FIX 7778): the timer only enqueues one rescan per attached folder,
//! and the worker claims, runs and settles each, so a rescan still queued
//! when the host stopped runs after it starts again.
//!
//! A Drive source is stepped again when its last step says
//! (`DriveStepReport::next_step_at`, L3-16-COPY-PACE = A, as the mail
//! worker paces a Gmail copy): once its quota window opens after a step
//! that ran out of it, at once after one that read on to its budget's end.
//! So a whole Drive copies at its share of the provider's quota, not one
//! step per pass. `vault.files.drive.attach` wakes it at once.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use oneiron::attempt_queue::{
    AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, CleanupAttemptLeases, CompleteAttempt,
    EnqueueAttempt, FailAttempt,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::note::FolderSource;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use super::ImportWarning;
use crate::mail_host::{sleep_until_unix, unix_seconds_now};
use crate::server::SyncServer;

/// How often `oneiron serve` enqueues a rescan of each attached folder.
const RESCAN_TICK: Duration = Duration::from_secs(5 * 60);

/// The attempt kind of one queued rescan of one attached folder.
const FOLDER_RESCAN_ATTEMPT_KIND: &str = "files_intake.folder_rescan";

/// Whom the worker claims queued rescans as.
const FOLDER_RESCAN_LEASE_OWNER: &str = "oneiron-serve.folder-rescan";

/// What one queued rescan names: the attached folder, as its source names it.
#[derive(Serialize, Deserialize)]
struct FolderRescanJob {
    folder: String,
}

/// The Drive sources the worker steps before its next pass, by folder, and
/// when (Unix seconds): one just attached at once, and one whose last step
/// named its next step then.
#[derive(Default)]
pub(crate) struct DriveSourceWakes {
    scheduled: Mutex<BTreeMap<String, u64>>,
    notify: Notify,
}

impl DriveSourceWakes {
    /// Steps the Drive source attached as `folder` at once.
    pub(crate) fn wake(&self, folder: &str) {
        self.schedule(folder, Some(unix_seconds_now()));
        self.notify.notify_one();
    }

    /// Keeps the next step of `folder` at `next`, as its last step named
    /// it; none once it named none.
    fn schedule(&self, folder: &str, next: Option<u64>) {
        let mut scheduled = self
            .scheduled
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match next {
            Some(at) => {
                scheduled.insert(folder.to_owned(), at);
            }
            None => {
                scheduled.remove(folder);
            }
        }
    }

    /// The earliest next step kept.
    fn next_scheduled(&self) -> Option<u64> {
        self.scheduled
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .min()
            .copied()
    }

    /// Takes each folder whose next step has come by `now`.
    fn take_due(&self, now: u64) -> Vec<String> {
        let mut scheduled = self
            .scheduled
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let due: Vec<String> = scheduled
            .iter()
            .filter(|(_, at)| **at <= now)
            .map(|(folder, _)| folder.clone())
            .collect();
        for folder in &due {
            scheduled.remove(folder);
        }
        due
    }
}

/// What a worker pass enqueues.
#[derive(Clone, Copy)]
enum Pass {
    /// A rescan of every attached folder.
    Every,
    /// A step of each Drive source whose next step has come.
    Due,
}

/// Enqueues a rescan of every attached folder from `oneiron serve` at start
/// and every [`RESCAN_TICK`], then runs what the queue holds, one rescan at
/// a time, off the async runtime, on every posture: attaching a folder is
/// the owner's standing act for it and detaching ends it, so the folders the
/// vault records are the whole policy. A rescan lands as the vault's local
/// owner; a managed vault starts none, since it keeps no standing import
/// authority yet. A folder that is not there now is said each pass and
/// retracts nothing. At start, a rescan the last host claimed and never
/// settled goes back to the queue first. Between passes, a Drive source is
/// stepped when its last step or its attach named.
pub(crate) fn spawn_rescans(server: Arc<SyncServer>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(RESCAN_TICK);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut recovered = false;
        loop {
            let next_step = server.drive_source_wakes.next_scheduled();
            let kind = tokio::select! {
                _ = interval.tick() => Pass::Every,
                () = sleep_until_unix(next_step) => Pass::Due,
                () = server.drive_source_wakes.notify.notified() => Pass::Due,
            };
            let server = Arc::clone(&server);
            let recover = !std::mem::replace(&mut recovered, true);
            let pass = tokio::task::spawn_blocking(move || {
                let vault = server.vault();
                let wakes = &server.drive_source_wakes;
                if recover {
                    recover_rescans(vault)?;
                }
                match kind {
                    Pass::Every => enqueue_rescans(vault)?,
                    Pass::Due => {
                        for folder in wakes.take_due(unix_seconds_now()) {
                            enqueue_rescan(vault, &folder)?;
                        }
                    }
                }
                run_queued_rescans(vault, wakes)
            })
            .await;
            let error = match pass {
                Ok(Ok(())) => continue,
                Ok(Err(error)) => format!("{error:#}"),
                Err(error) => error.to_string(),
            };
            tracing::warn!(error = %error, "folder source rescan failed");
        }
    })
}

/// Returns to the queue every rescan a host claimed and never settled: this
/// worker is the kind's only one and has claimed none yet, so each such
/// lease is a stopped host's.
fn recover_rescans(vault: &oneiron::Vault) -> anyhow::Result<()> {
    AttemptQueue::new(vault).cleanup_kind_leases(
        FOLDER_RESCAN_ATTEMPT_KIND,
        CleanupAttemptLeases {
            now: vault.now_recorded_at(),
            lease_timeout_secs: 1,
        },
    )?;
    Ok(())
}

/// One queued rescan per attached folder. A folder whose rescan is still
/// queued or running gets no second one: the queue's dedupe key names the
/// folder, and it holds only while that rescan is pending.
fn enqueue_rescans(vault: &oneiron::Vault) -> anyhow::Result<()> {
    for source in vault.folder_sources()? {
        enqueue_rescan(vault, &source.folder)?;
    }
    Ok(())
}

/// One queued rescan of `folder`, unless one is queued or running already.
fn enqueue_rescan(vault: &oneiron::Vault, folder: &str) -> anyhow::Result<()> {
    AttemptQueue::new(vault).enqueue(EnqueueAttempt {
        kind: FOLDER_RESCAN_ATTEMPT_KIND.to_owned(),
        payload: serde_json::to_vec(&FolderRescanJob {
            folder: folder.to_owned(),
        })?,
        dedupe_key: Some(rescan_dedupe_key(folder)),
        run_id: None,
        now: vault.now_recorded_at(),
    })?;
    Ok(())
}

/// The dedupe key of `folder`'s queued rescan: its path's hash, so a path
/// of any length makes one.
fn rescan_dedupe_key(folder: &str) -> String {
    format!("folder_rescan:{}", blake3::hash(folder.as_bytes()).to_hex())
}

/// Claims, runs and settles every queued rescan, one at a time, until the
/// queue holds none; each Drive step keeps its next step in `wakes`.
fn run_queued_rescans(vault: &oneiron::Vault, wakes: &DriveSourceWakes) -> anyhow::Result<()> {
    let queue = AttemptQueue::new(vault);
    let Some(mut attempt) = claim_rescan(&queue, vault)? else {
        return Ok(());
    };
    let owner = crate::owner::local_owner(vault);
    loop {
        let ran = match &owner {
            Ok(owner) => run_rescan(vault, owner, wakes, &attempt),
            Err(error) => Err(anyhow::anyhow!("no local owner to rescan as: {error:#}")),
        };
        match ran {
            Ok(()) => {
                queue.complete(CompleteAttempt {
                    id: attempt.id,
                    lease_owner: FOLDER_RESCAN_LEASE_OWNER.to_owned(),
                    attempt_count: attempt.attempt_count,
                    now: vault.now_recorded_at(),
                })?;
            }
            Err(error) => {
                let reason = format!("{error:#}");
                tracing::warn!(error = %reason, "folder source rescan failed");
                queue.fail(FailAttempt {
                    id: attempt.id,
                    lease_owner: FOLDER_RESCAN_LEASE_OWNER.to_owned(),
                    attempt_count: attempt.attempt_count,
                    reason,
                    now: vault.now_recorded_at(),
                })?;
            }
        }
        match claim_rescan(&queue, vault)? {
            Some(next) => attempt = next,
            None => return Ok(()),
        }
    }
}

/// The oldest queued rescan, claimed by this worker; `None` when the queue
/// holds none.
fn claim_rescan(
    queue: &AttemptQueue<'_>,
    vault: &oneiron::Vault,
) -> anyhow::Result<Option<AttemptRecord>> {
    let claimed = queue.claim_kind(
        FOLDER_RESCAN_ATTEMPT_KIND,
        ClaimAttempt {
            lease_owner: FOLDER_RESCAN_LEASE_OWNER.to_owned(),
            now: vault.now_recorded_at(),
        },
    )?;
    Ok(match claimed {
        ClaimOutcome::Claimed(attempt) => Some(attempt),
        _ => None,
    })
}

/// One claimed rescan. The folder must still be attached when it runs: one
/// detached after it was queued is not read, and the job settles as done.
/// A Drive source's step keeps its next step in `wakes`; a failed one
/// waits for the next pass.
fn run_rescan(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    wakes: &DriveSourceWakes,
    attempt: &AttemptRecord,
) -> anyhow::Result<()> {
    let job: FolderRescanJob = serde_json::from_slice(&attempt.payload)?;
    let Some(source) = vault.folder_source(&job.folder)? else {
        wakes.schedule(&job.folder, None);
        return Ok(());
    };
    let next_step = rescan_one(vault, owner, &source);
    wakes.schedule(&job.folder, next_step.as_ref().ok().copied().flatten());
    next_step.map(|_| ())
}

/// One rescan of `source`, its outcome said in the host's log; for a Drive
/// source, when its next step is.
fn rescan_one(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    source: &FolderSource,
) -> anyhow::Result<Option<u64>> {
    let (report, warnings, next_step) = if source.drive.is_some() {
        let step = super::source::drive_step(vault, owner, source)?;
        (step.rescan, Vec::new(), step.next_step_at)
    } else {
        let (report, warnings) = super::source::rescan(vault, owner, source)?;
        (report, warnings, None)
    };
    for warning in &warnings {
        match warning {
            ImportWarning::LimitCrossed {
                row,
                limit,
                observed,
            } => tracing::warn!(
                folder = %source.folder,
                row = *row,
                limit = *limit,
                observed = *observed,
                "folder source read past a [limits] row; read whole, and the row asks"
            ),
            ImportWarning::OriginalsUnkept { files, first_error } => tracing::warn!(
                folder = %source.folder,
                files = *files,
                error = %first_error,
                "folder source kept no original for some files; their text landed"
            ),
            ImportWarning::HardLinked { .. } => {}
        }
    }
    let moved = report.landed
        + report.superseded
        + report.proposed
        + report.retracted
        + report.restored
        + report.name_only
        + report.failed;
    if moved > 0 {
        tracing::info!(
            folder = %source.folder,
            landed = report.landed,
            superseded = report.superseded,
            proposed = report.proposed,
            retracted = report.retracted,
            restored = report.restored,
            name_only = report.name_only,
            failed = report.failed,
            "folder source rescanned"
        );
    }
    Ok(next_step)
}
