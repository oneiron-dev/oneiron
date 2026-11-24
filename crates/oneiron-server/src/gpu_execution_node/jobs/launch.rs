//! Staging and the launch commit (design pass 33, 7.4 and 7.5).
//!
//! Staging runs outside the admission lock, on a worker of its own, after a
//! submit is accepted. The launch commit is one critical section under the
//! lock, and the only place a job can start:
//! 1. the key is `Staging`, its staging completed within the staging limit
//!    (read again under the lock, so a wait for the lock counts), and it is
//!    not closed;
//! 2. the local policy, read now: enabled, not paused, not drained, the
//!    template's digest unchanged, and the launch scope meets the minimum
//!    contract (it kills the whole tree, enforces the cutoff with the engine
//!    stopped, and tells when the tree is empty);
//! 3. the authority, read now: the node's fold holds the position the
//!    issuer signed the submit at (EM-11 = B; the worker waits for it up to
//!    the staging limit), and the grants and the issuer's standing are live;
//! 4. the device and the memory, both or neither: a device lease confirmed
//!    with no compute process on it, and the memory floor;
//! 5. `launch.json`, then the `launching` record, synced. Occupancy starts
//!    at this record: its clock is read after both leases are taken, so the
//!    lock wait and the device probe are not occupancy;
//! 6. the unit's start.
//!
//! A no at 1 to 4 ends the key as `LaunchRefused`, not started, with nothing
//! left held. A device that is busy now refuses: no card was held before the
//! commit.

use std::time::{Duration, Instant};

use super::admission::{log_write_error, memory_bytes, slot_request};
use super::job_unit::{LAUNCH_FILE_NAME, LaunchFile, write_file_synced};
use super::journal::{JournalEvent, NodeKey};
use super::node_parts::{GpuSlotRefusal, StageFailure, StageOrder};
use super::{JobKeyId, NodeBook, NodeGate, NodeJobs};
use crate::gpu_execution_node::wire::{JobEnd, JobState, NetworkMode, SignedJobSubmit};

const NANOS_PER_SEC: u64 = 1_000_000_000;

/// How often the staging worker looks at the node's fold while it waits for
/// the submit's authority position.
const AUTHORITY_POLL: Duration = Duration::from_millis(500);

/// One key's staging, as the worker takes it from the journal.
struct StagingRun {
    order: StageOrder,
    authority_heads: Vec<String>,
    deadline: Instant,
}

fn launch_refused(reason: impl Into<String>) -> JournalEvent {
    JournalEvent::Ended {
        end: JobEnd::LaunchRefused {
            reason: reason.into(),
        },
        end_boot_ns: None,
    }
}

impl NodeJobs {
    /// Starts the key's staging worker, unless one runs. A worker that
    /// cannot be started leaves the key where it is; the next tick starts it
    /// again.
    pub(super) fn start_staging(&self, key: String) {
        if !self.lock().staging.insert(key.clone()) {
            return;
        }
        let jobs = self.clone();
        let worker_key = key.clone();
        let spawned = std::thread::Builder::new()
            .name("oneiron-job-stage".to_owned())
            .spawn(move || {
                jobs.stage_and_launch(&worker_key);
                jobs.lock().staging.remove(&worker_key);
            });
        if let Err(error) = spawned {
            tracing::warn!(key, %error, "job staging worker not started; the next tick starts it again");
            self.lock().staging.remove(&key);
        }
    }

    fn stage_and_launch(&self, key: &str) {
        let Some(run) = self.begin_staging(key) else {
            return;
        };
        let deadline = run.deadline;
        let closed = || self.key_closed(key) || Instant::now() >= deadline;
        let staged = self.parts().stager.stage(&run.order, &closed);
        let failure = match staged {
            Ok(()) => None,
            Err(StageFailure::Closed) if self.key_closed(key) => return,
            Err(StageFailure::Closed) => Some("staging_limit".to_owned()),
            Err(StageFailure::Refused(reason)) => Some(reason),
        };
        let fresh =
            failure.is_none() && self.wait_for_authority(key, &run.authority_heads, deadline);
        self.launch_commit(key, failure, fresh, deadline);
    }

    /// Records that staging began (an `accepted` key) or takes up a key
    /// whose staging began before a restart, and gives the worker its order.
    fn begin_staging(&self, key: &str) -> Option<StagingRun> {
        let now = self.now();
        let mut book = self.lock();
        if book.gate != NodeGate::Open {
            return None;
        }
        let journal = book.journal.as_mut()?;
        if journal.is_poisoned() {
            return None;
        }
        let known = journal.table().get(key)?.clone();
        match known.state {
            JobState::Accepted => {
                if let Err(error) = journal.record(
                    key,
                    known.issuer,
                    &now.boot_id,
                    now.wall_ms,
                    JournalEvent::Staged,
                ) {
                    log_write_error(key, &error);
                    return None;
                }
            }
            JobState::Staging => {}
            _ => return None,
        }
        let reserve = known.reserve?;
        let submit = known.submit?;
        let limit = Duration::from_secs(self.parts().admission.job_settings().staging_limit_secs);
        Some(StagingRun {
            order: StageOrder {
                key: key.to_owned(),
                id: known.id.clone(),
                pin: reserve.pin,
                payload_dir: known.id.payload_dir(&self.paths().work_dir),
            },
            authority_heads: submit.submit.authority_heads,
            deadline: Instant::now() + limit,
        })
    }

    /// Whether the key is closed (or the node's history is lost).
    pub(super) fn key_closed(&self, key: &str) -> bool {
        let book = self.lock();
        book.journal
            .as_ref()
            .and_then(|journal| journal.table().get(key))
            .is_none_or(NodeKey::is_ended)
    }

    /// Waits until the node's fold holds every one of `heads`, the key is
    /// closed, or `deadline` passes. Answers whether the fold holds them.
    fn wait_for_authority(&self, key: &str, heads: &[String], deadline: Instant) -> bool {
        loop {
            if self.parts().authority.folded(heads) {
                return true;
            }
            let now = Instant::now();
            if now >= deadline || self.key_closed(key) {
                return false;
            }
            std::thread::sleep(AUTHORITY_POLL.min(deadline - now));
        }
    }

    /// The launch commit, under the admission lock.
    fn launch_commit(
        &self,
        key: &str,
        staging_failure: Option<String>,
        authority_fresh: bool,
        deadline: Instant,
    ) {
        let mut guard = self.lock();
        let now = self.now();
        let book: &mut NodeBook = &mut guard;
        if book.gate != NodeGate::Open {
            return;
        }
        let Some(journal) = book.journal.as_mut() else {
            return;
        };
        let Some(known) = journal.table().get(key).cloned() else {
            return;
        };
        let (JobState::Staging, Some(reserve), Some(signed)) =
            (known.state, known.reserve.clone(), known.submit.clone())
        else {
            return;
        };
        let refusal = staging_failure
            .or_else(|| (Instant::now() >= deadline).then(|| "staging_limit".to_owned()))
            .or_else(|| self.launch_policy_refusal(&known, &signed, authority_fresh));
        if let Some(reason) = refusal {
            if let Err(error) = journal.record(
                key,
                known.issuer,
                &now.boot_id,
                now.wall_ms,
                launch_refused(reason),
            ) {
                log_write_error(key, &error);
            }
            return;
        }
        let pin = &reserve.pin;
        let request = slot_request(key, pin, &reserve.slot);
        let lease = match self.parts().devices.lease_for_launch(&request) {
            Ok(lease) => lease,
            Err(refusal) => {
                let reason = match refusal {
                    GpuSlotRefusal::Busy { .. } => "device_busy".to_owned(),
                    other => format!("device_refused: {other}"),
                };
                if let Err(error) = journal.record(
                    key,
                    known.issuer,
                    &now.boot_id,
                    now.wall_ms,
                    launch_refused(reason),
                ) {
                    log_write_error(key, &error);
                }
                return;
            }
        };
        let floor = match self.parts().floor.try_lease(memory_bytes(pin)) {
            Ok(Some(floor)) => floor,
            Ok(None) | Err(_) => {
                drop(lease);
                if let Err(error) = journal.record(
                    key,
                    known.issuer,
                    &now.boot_id,
                    now.wall_ms,
                    launch_refused("memory_busy"),
                ) {
                    log_write_error(key, &error);
                }
                return;
            }
        };
        // Occupancy starts here, with both leases taken.
        let now = self.now();
        let device_id = lease.grant().device.device_id.clone();
        let maximum_secs = signed.submit.maximum_secs;
        let cutoff_boot_ns = now
            .boot_ns
            .saturating_add(maximum_secs.saturating_mul(NANOS_PER_SEC));
        let launch_file = LaunchFile {
            key: key.to_owned(),
            template: pin.template.clone(),
            template_digest: pin.template_digest.clone(),
            commit: pin.commit.clone(),
            entry: pin.entry.clone(),
            args: pin.args.clone(),
            network: match pin.network {
                NetworkMode::None => "none".to_owned(),
                NetworkMode::Host => "host".to_owned(),
            },
            device_id: device_id.clone(),
            memory_mib: pin.request.memory_mib,
            disk_mib: pin.request.disk_mib,
            maximum_secs,
            boot_id: now.boot_id.clone(),
            launch_boot_ns: now.boot_ns,
        };
        let control_dir = known.id.control_dir(&self.paths().state_dir);
        let written = serde_json::to_vec_pretty(&launch_file)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
            .and_then(|bytes| write_file_synced(&control_dir.join(LAUNCH_FILE_NAME), &bytes));
        if let Err(error) = written {
            drop((lease, floor));
            let reason = format!("control_file: {error}");
            if let Err(error) = journal.record(
                key,
                known.issuer,
                &now.boot_id,
                now.wall_ms,
                launch_refused(reason),
            ) {
                log_write_error(key, &error);
            }
            return;
        }
        let event = JournalEvent::Launching {
            device_id,
            launch_boot_ns: now.boot_ns,
            cutoff_boot_ns,
            memory_mib: pin.request.memory_mib,
        };
        if let Err(error) = journal.record(key, known.issuer, &now.boot_id, now.wall_ms, event) {
            // Nothing is journaled: the device and the memory go back as the
            // leases drop, and the key stays `Staging` for the next tick.
            log_write_error(key, &error);
            return;
        }
        let _kept = lease.keep();
        book.floors.insert(key.to_owned(), floor);
        if let Err(error) = self.parts().units.start(&JobKeyId::for_key(key)) {
            tracing::warn!(key, %error, "job unit start not taken; the end handling reads what remains");
        }
    }

    /// Steps 2 and 3 of the launch commit: the reason the key may not
    /// launch now, or `None`.
    fn launch_policy_refusal(
        &self,
        known: &NodeKey,
        signed: &SignedJobSubmit,
        authority_fresh: bool,
    ) -> Option<String> {
        let admission = &self.parts().admission;
        if let Some(reason) = admission.controls().refusal() {
            return Some(reason);
        }
        let pin = &signed.submit.pin;
        if admission.template_digest(&pin.template).as_deref() != Some(pin.template_digest.as_str())
        {
            return Some("template_changed".to_owned());
        }
        let missing = self.parts().units.probe().minimum_contract_missing();
        if !missing.is_empty() {
            return Some(format!("no_scope: {}", missing.join(", ")));
        }
        if !authority_fresh
            || !self
                .parts()
                .authority
                .folded(&signed.submit.authority_heads)
        {
            return Some("authority_stale".to_owned());
        }
        admission
            .issuer_live(known.issuer)
            .err()
            .map(|not_live| not_live.reason)
    }
}
