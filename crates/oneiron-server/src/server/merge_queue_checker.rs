//! The standalone merge queue checker drain (FIX 6868). Each lifecycle
//! tick, the first at once, runs the owner-requested queue checks
//! ([`oneiron::Vault::pending_queue_checks`]) on a blocking thread, off the
//! request path and with no model seat, in plain and managed serve alike.
//! It shares the owner work drain's custody: the host's write gate admits
//! each unit and is held through its dispatch, result write and teardown;
//! a managed freeze admits none; the host's stop ends the running check as
//! held and lets its result commit before the pass joins.
//!
//! A pass starts by queueing again any check an executor left running: a
//! pass never starts while another runs. Queued checks run oldest request
//! first, one unit per repository, and distinct repositories run at once
//! up to the host's parallelism (FIX 7232). One repository runs at most
//! `[merge_queue].queue_check_concurrency` checks at once; the next waits.
//! Log lines carry counts and an error's kind, never a row's text.
//!
//! The same drain drives every enrolled queue (G2 PR2): before it runs
//! checks it takes each queue's next steps (`MergeQueue::pending_work`,
//! `drive_one`), each a unit under an admission of its own, then runs the
//! checks those steps asked for, and repeats until nothing moves. A step is
//! taken at most once a pass. A committed queue write wakes this drain
//! alone ([`SyncServer::wake_merge_queue_checker`]); only the lifecycle
//! tick asks a held check or landing again.

mod executor;
mod received;
mod tree;

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use oneiron::merge_queue::{QueueDrivePass, QueueWork};

use super::core::SyncServer;
use super::housekeeping::HousekeepingAdmission;
use super::lifecycle::LifecycleJobKind;
use crate::config::MergeQueueCheckerConfig;

/// The lease owner a checker attempt is claimed under.
const QUEUE_CHECK_LEASE_OWNER: &str = "merge_queue_checker";

/// One repository's queued check keys, oldest request first.
type QueueCheckUnits = Mutex<std::vec::IntoIter<VecDeque<String>>>;

impl SyncServer {
    /// Starts one checker pass on a task of its own, held for the host's
    /// stop, unless the last pass is still running, the host is stopping,
    /// or the host's gate refused the tick.
    pub(super) async fn start_merge_queue_checker(self: &Arc<Self>, admit: &HousekeepingAdmission) {
        self.start_queue_checker_pass(admit, true).await;
    }

    /// The same pass, woken by a committed queue write rather than the
    /// tick: it never asks a held check or landing again.
    pub(super) async fn wake_merge_queue_checker(self: &Arc<Self>, admit: &HousekeepingAdmission) {
        self.start_queue_checker_pass(admit, false).await;
    }

    async fn start_queue_checker_pass(self: &Arc<Self>, admit: &HousekeepingAdmission, tick: bool) {
        if self.housekeeping_passes.stopping()
            || !self
                .begin_lifecycle_job(LifecycleJobKind::MergeQueueChecks)
                .await
        {
            return;
        }
        let Some(admission) = admit() else {
            self.end_lifecycle_job(LifecycleJobKind::MergeQueueChecks)
                .await;
            return;
        };
        let server = Arc::clone(self);
        let admit = Arc::clone(admit);
        let run = tokio::spawn(async move {
            let drain = Arc::clone(&server);
            match tokio::task::spawn_blocking(move || {
                drain.drain_queue_checks(admission, &admit, tick)
            })
            .await
            {
                Ok(Ok(ran)) => {
                    if ran > 0 {
                        tracing::info!(ran, "queue checks ran");
                    }
                }
                Ok(Err(error)) => {
                    tracing::warn!(kind = ?error.kind(), "queue checker pass failed");
                }
                Err(error) => {
                    tracing::warn!(panicked = error.is_panic(), "queue checker task failed");
                }
            }
            server
                .end_lifecycle_job(LifecycleJobKind::MergeQueueChecks)
                .await;
        });
        self.housekeeping_passes.hold(run);
    }

    /// One pass: the enrolled queues' next steps, then every queued check
    /// this host may claim, one unit per repository, each check under an
    /// admission of its own, again until nothing moves. A check its
    /// repository's active one holds back waits for a later pass.
    fn drain_queue_checks(
        &self,
        first: Box<dyn Send>,
        admit: &HousekeepingAdmission,
        tick: bool,
    ) -> oneiron::Result<usize> {
        let vault = self.vault();
        // A guest a stopped host left is ended by name before its work is
        // queued again (FIX 7233).
        let guests = vault.queue_check_guest_dir()?;
        resolve_left_guests(&guests);
        // A served queue source whose import custody now withholds a file
        // is erased each pass (FIX 7708).
        match vault.erase_withheld_queue_sources() {
            Ok(0) => {}
            Ok(erased) => tracing::info!(erased, "withheld queue source copies were erased"),
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "withheld queue sources could not be erased");
            }
        }
        let requeued = vault.requeue_interrupted_queue_checks()?;
        if requeued > 0 {
            tracing::info!(requeued, "interrupted queue checks queued again");
        }
        let config = self.config.merge_queue.clone().unwrap_or_default();
        let concurrency = config.queue_check_concurrency();
        let pass = QueueDrivePass {
            tick,
            first: !self.queue_driver_started.swap(true, Ordering::SeqCst),
        };
        let mut admission = Some(first);
        let mut driven = Vec::new();
        let mut intaken = Vec::new();
        let mut ran = 0_usize;
        loop {
            let Some(moved) = self.drive_queues(&mut admission, admit, pass, &mut driven)? else {
                break;
            };
            // Accepted pushes become Proposed bundles after the queues'
            // own steps, before their checks, once a drain (G4 PR2).
            let Some(proposed) =
                self.intake_received_candidates(&mut admission, admit, &mut intaken)?
            else {
                break;
            };
            let moved = moved + proposed;
            let (checked, ended) =
                self.run_queue_checks(&mut admission, admit, &config, concurrency)?;
            ran += checked;
            if ended {
                return Ok(ran);
            }
            if moved == 0 && checked == 0 {
                break;
            }
        }
        Ok(ran)
    }

    /// Every queued check this host may claim, oldest request first, as one
    /// unit per repository (FIX 7232): distinct repositories run at once, up
    /// to the host's parallelism, and one repository's checks run in turn
    /// under its `concurrency`. Each check runs under an admission of its
    /// own. How many ran, and whether the pass ends: the host stops or its
    /// gate refused.
    fn run_queue_checks(
        &self,
        admission: &mut Option<Box<dyn Send>>,
        admit: &HousekeepingAdmission,
        config: &MergeQueueCheckerConfig,
        concurrency: u32,
    ) -> oneiron::Result<(usize, bool)> {
        let mut units: Vec<VecDeque<String>> = Vec::new();
        let mut unit_of: HashMap<String, usize> = HashMap::new();
        for key in self.vault().pending_queue_checks()? {
            let store = key.split_once(':').map_or(key.as_str(), |(store, _)| store);
            let index = *unit_of.entry(store.to_owned()).or_insert_with(|| {
                units.push(VecDeque::new());
                units.len() - 1
            });
            units[index].push_back(key);
        }
        if units.is_empty() {
            return Ok((0, false));
        }
        let workers = std::thread::available_parallelism()
            .map_or(1, std::num::NonZeroUsize::get)
            .min(units.len());
        let units: QueueCheckUnits = Mutex::new(units.into_iter());
        let spare = Mutex::new(admission.take());
        let checked = AtomicUsize::new(0);
        let ended = AtomicBool::new(false);
        let failed = Mutex::new(None);
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| {
                    while let Some(keys) = next_unit(&units) {
                        for key in keys {
                            if ended.load(Ordering::SeqCst) || self.housekeeping_passes.stopping() {
                                ended.store(true, Ordering::SeqCst);
                                return;
                            }
                            let kept = lock(&spare).take();
                            let Some(held) = kept.or_else(|| admit()) else {
                                ended.store(true, Ordering::SeqCst);
                                return;
                            };
                            match self.run_one_queue_check(&key, config, concurrency) {
                                Ok(None) => {
                                    let mut slot = lock(&spare);
                                    if slot.is_none() {
                                        *slot = Some(held);
                                    }
                                }
                                Ok(Some(settled)) => {
                                    checked.fetch_add(usize::from(settled), Ordering::SeqCst);
                                    drop(held);
                                }
                                Err(error) => {
                                    let mut first = lock(&failed);
                                    if first.is_none() {
                                        *first = Some(error);
                                    }
                                    ended.store(true, Ordering::SeqCst);
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });
        *admission = spare.into_inner().unwrap_or_else(PoisonError::into_inner);
        if let Some(error) = failed.into_inner().unwrap_or_else(PoisonError::into_inner) {
            return Err(error);
        }
        Ok((checked.into_inner(), ended.into_inner()))
    }

    /// Claims queued check `key` and runs it: `None` when it waits, else
    /// whether it settled.
    fn run_one_queue_check(
        &self,
        key: &str,
        config: &MergeQueueCheckerConfig,
        concurrency: u32,
    ) -> oneiron::Result<Option<bool>> {
        let vault = self.vault();
        let Some(work) = vault.claim_queue_check(key, QUEUE_CHECK_LEASE_OWNER, concurrency)? else {
            return Ok(None);
        };
        let mut host = executor::QueueCheckExecutor::new(config.clone())
            .with_guest_records(vault.queue_check_guest_dir()?);
        let stop = || self.housekeeping_passes.stopping();
        Ok(Some(match vault.run_queue_check(&work, &mut host, &stop) {
            Ok(_) => true,
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "queue check did not settle");
                false
            }
        }))
    }

    /// Every enrolled queue's next steps, each step at most once a pass and
    /// each under an admission of its own; how many moved, or `None` when
    /// the host stops or its gate refuses.
    fn drive_queues(
        &self,
        admission: &mut Option<Box<dyn Send>>,
        admit: &HousekeepingAdmission,
        pass: QueueDrivePass,
        driven: &mut Vec<(String, QueueWork)>,
    ) -> oneiron::Result<Option<usize>> {
        let vault = self.vault();
        let mut moved = 0_usize;
        for config in vault.queue_driver_configurations()? {
            let works = match vault
                .queue_driver_open(&config)
                .and_then(|queue| Ok((queue.pending_work(pass)?, queue)))
            {
                Ok(found) => found,
                Err(error) => {
                    tracing::warn!(kind = ?error.kind(), "merge queue driver could not read a queue");
                    continue;
                }
            };
            let (works, queue) = works;
            for work in works {
                if self.housekeeping_passes.stopping() {
                    return Ok(None);
                }
                let key = (config.store.clone(), work);
                if driven.contains(&key) {
                    continue;
                }
                let Some(held) = admission.take().or_else(|| admit()) else {
                    return Ok(None);
                };
                match queue.drive_one(&config, &key.1, pass) {
                    Ok(outcome) => moved += usize::from(outcome.moved()),
                    Err(error) => {
                        tracing::warn!(kind = ?error.kind(), "merge queue drive step did not settle");
                    }
                }
                drop(held);
                driven.push(key);
            }
        }
        Ok(Some(moved))
    }
}

/// Ends every guest a record under `dir` names, by name, and removes its
/// record (FIX 7233). A container backend's guest is removed through its
/// runtime; a record that cannot be resolved is kept for the next pass, and
/// the work is queued again all the same.
fn resolve_left_guests(dir: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut resolved = 0_usize;
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(record) = serde_json::from_slice::<executor::GuestRecord>(&bytes) else {
            let _removed = std::fs::remove_file(&path);
            continue;
        };
        // A forced removal ends the container or finds it gone; only a
        // runtime that does not run keeps the record.
        let ended = match record.backend.as_str() {
            "container-cli" | "landlock-container"
                if std::path::Path::new(&record.runtime).is_absolute() =>
            {
                let name = executor::guest_container_name(&record.generation);
                let mut command = oneiron_spawn::command(&record.runtime);
                command
                    .args(["rm", "--force", name.as_str()])
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin");
                oneiron_container::apply_cli_env_to_command(&mut command);
                command
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .is_ok()
            }
            // A VM backend's guest is a child of the stopped host and ended
            // with it.
            _ => true,
        };
        if ended {
            let _removed = std::fs::remove_file(&path);
            resolved += 1;
        }
    }
    if resolved > 0 {
        tracing::info!(
            resolved,
            "queue check guests a stopped host left were ended"
        );
    }
}

/// The next repository's unit, its lock released before the unit runs.
fn next_unit(units: &QueueCheckUnits) -> Option<VecDeque<String>> {
    lock(units).next()
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
