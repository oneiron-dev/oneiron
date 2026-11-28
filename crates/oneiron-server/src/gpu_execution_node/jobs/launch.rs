//! Staging and the launch commit (design pass 33, 7.4 and 7.5).
//!
//! Staging runs outside the admission lock, on a worker of its own, after a
//! submit is accepted. The launch commit is one critical section under the
//! lock, and the only place a job can start:
//! 1. the key is `Staging`, its staging completed within the staging limit
//!    (read again under the lock, so a wait for the lock counts), it is not
//!    closed, and the server still serves the service ([`NodeJobs::close`]:
//!    after the close a staging key stays where it is, for the next
//!    opening);
//! 2. the local policy, read now: enabled, not paused, not drained, the
//!    template's digest unchanged, and the launch scope meets the minimum
//!    contract (it kills the whole tree, enforces the cutoff with the engine
//!    stopped, and tells when the tree is empty) and gives every bound the
//!    template requires (pass 34 section 2.2; else `no_scope: <names>`);
//! 3. the authority, read now: the node's fold holds the position the
//!    issuer signed the submit at (EM-11 = B; the worker waits for it up to
//!    the staging limit), and the grants and the issuer's standing are live;
//! 4. every lease of the request, or none (pass 34 9.2 (a)): the request's
//!    device claims placed on a fresh reading of the devices
//!    (`ResourceRequest::place_devices`; none for a request with no device
//!    claim), each placed device leased and confirmed with no compute
//!    process on it, then the placement's host memory from the floor (the
//!    request's memory plus each unified device's claim memory);
//! 5. `launch.json`, then the `launching` record, synced. Occupancy starts
//!    at this record: its clock is read after every lease is taken, so the
//!    lock wait and the device probe are not occupancy;
//! 6. the unit's start.
//!
//! A no at 1 to 4 ends the key as `LaunchRefused`, not started, with nothing
//! left held. A device that is busy now refuses: no card was held before the
//! commit.

use std::time::{Duration, Instant};

use super::admission::{Placing, device_slot_request, log_write_error, mib_bytes, placement};
use super::job_unit::{LAUNCH_FILE_NAME, LaunchFile, scope_missing, write_file_synced};
use super::journal::{JournalEvent, NodeKey};
use super::node_parts::{GpuSlotRefusal, StageFailure, StageOrder};
use super::{JobKeyId, NodeBook, NodeGate, NodeJobs};
use crate::gpu_execution_node::wire::{JobEnd, JobState, SignedJobSubmit};

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
        if self.service_closed() || !self.lock().staging.insert(key.clone()) {
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
        let closed = || self.key_closed(key) || self.service_closed() || Instant::now() >= deadline;
        let staged = self.parts().stager.stage(&run.order, &closed);
        // The server stopped serving: the key stays where it is, and the
        // next opening takes up its staging again (7.7).
        if self.service_closed() {
            return;
        }
        // Staging that ran past the limit, and a fold that did not reach the
        // submit's heads by the limit, end the key with their own reasons.
        let failure = match staged {
            Ok(()) if Instant::now() >= deadline => Some("staging_limit".to_owned()),
            Ok(()) => {
                let folded = self.wait_for_authority(key, &run.authority_heads, deadline);
                if self.service_closed() {
                    return;
                }
                (!folded).then(|| "authority_stale".to_owned())
            }
            Err(StageFailure::Closed) if self.key_closed(key) => return,
            Err(StageFailure::Closed) => Some("staging_limit".to_owned()),
            Err(StageFailure::Refused(reason)) => Some(reason),
        };
        // A key that will not launch keeps no code on the node's disk: it is
        // removed before the key's end is recorded, while its disk is still
        // booked.
        let refused = failure.is_some();
        if refused {
            self.parts().stager.unstage(key, &run.order.payload_dir);
        }
        self.launch_commit(key, failure, deadline);
        // A refusal of the launch commit itself (a device, the memory, the
        // control file) ended the key after its code was staged. A commit
        // the service's close skipped left the key staging: its code stays
        // for the next opening.
        if !refused && !self.key_launched(key) && !self.service_closed() {
            self.parts().stager.unstage(key, &run.order.payload_dir);
        }
    }

    /// Records that staging began (an `accepted` key) or takes up a key
    /// whose staging began before a restart, and gives the worker its order.
    fn begin_staging(&self, key: &str) -> Option<StagingRun> {
        let now = self.now();
        let mut book = self.lock();
        if book.gate != NodeGate::Open || self.service_closed() {
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
                warm: submit.submit.warm,
            },
            authority_heads: submit.submit.authority_heads,
            deadline: Instant::now() + limit,
        })
    }

    /// Whether the key's launch commit is journaled.
    fn key_launched(&self, key: &str) -> bool {
        let book = self.lock();
        book.journal
            .as_ref()
            .and_then(|journal| journal.table().get(key))
            .is_some_and(|known| known.launch.is_some())
    }

    /// Whether the key is closed (or the node's history is lost).
    pub(super) fn key_closed(&self, key: &str) -> bool {
        let book = self.lock();
        book.journal
            .as_ref()
            .and_then(|journal| journal.table().get(key))
            .is_none_or(NodeKey::is_ended)
    }

    /// Waits until the node's fold holds every one of `heads`, the key or
    /// the service is closed, or `deadline` passes. Answers whether the fold
    /// holds them.
    fn wait_for_authority(&self, key: &str, heads: &[String], deadline: Instant) -> bool {
        loop {
            if self.parts().authority.folded(heads) {
                return true;
            }
            let now = Instant::now();
            if now >= deadline || self.key_closed(key) || self.service_closed() {
                return false;
            }
            std::thread::sleep(AUTHORITY_POLL.min(deadline - now));
        }
    }

    /// The launch commit, under the admission lock.
    fn launch_commit(&self, key: &str, staging_failure: Option<String>, deadline: Instant) {
        let mut guard = self.lock();
        let now = self.now();
        let book: &mut NodeBook = &mut guard;
        // Read under the lock: a close that came first stops the commit
        // before anything is leased or written.
        if book.gate != NodeGate::Open || self.service_closed() {
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
            .or_else(|| self.launch_policy_refusal(&known, &signed));
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
        let held_mib = journal.table().held_host_memory_mib();
        // Step 4: every lease of the request, or none (pass 34 9.2 (a)): the
        // placement from a fresh reading, each placed device leased and
        // confirmed, then the host memory. A request with no device claim
        // takes no device lease.
        let leased = placement(self.parts().devices.as_ref(), &reserve, Placing::AtLaunch)
            .map_err(|reason| format!("device_refused: {reason}"))
            .and_then(|placed| {
                // The sum rule against the template's memory ceiling, before
                // any lease.
                self.parts()
                    .admission
                    .admit_placement(pin, &placed, held_mib)?;
                let mut leases = Vec::with_capacity(placed.devices.len());
                for device in &placed.devices {
                    let Some(claim) = pin.request.devices.get(device.claim) else {
                        return Err(format!("device_refused: no claim {}", device.claim));
                    };
                    let request = device_slot_request(key, device, claim);
                    match self.parts().devices.lease_for_launch(&request) {
                        Ok(lease) => leases.push(lease),
                        // The leases taken so far drop here: their devices go
                        // back.
                        Err(GpuSlotRefusal::Busy { .. }) => return Err("device_busy".to_owned()),
                        Err(other) => return Err(format!("device_refused: {other}")),
                    }
                }
                Ok((placed, leases))
            });
        let (placed, leases) = match leased {
            Ok(leased) => leased,
            Err(reason) => {
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
        let floor = match self
            .parts()
            .floor
            .try_lease(mib_bytes(placed.host_memory_mib))
        {
            Ok(Some(floor)) => floor,
            Ok(None) | Err(_) => {
                drop(leases);
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
        // Occupancy starts here, with every lease taken.
        let now = self.now();
        let maximum_secs = signed.submit.maximum_secs;
        let cutoff_boot_ns = now
            .boot_ns
            .saturating_add(maximum_secs.saturating_mul(NANOS_PER_SEC));
        // The template's job cache (FLEET-TOOL-PARITY row 5): kept when no other live key
        // holds it, else cold; never a wait.
        let cache = self
            .parts()
            .admission
            .template_job_cache(&pin.template)
            .map(|target| super::job_cache::launch_cache(&target, journal.table().iter(), key));
        let launch_file = LaunchFile {
            key: key.to_owned(),
            pin: pin.clone(),
            devices: placed.devices.clone(),
            host_memory_mib: placed.host_memory_mib,
            maximum_secs,
            boot_id: now.boot_id.clone(),
            launch_boot_ns: now.boot_ns,
            cache: cache.clone(),
        };
        let control_dir = known.id.control_dir(&self.paths().state_dir);
        let written = serde_json::to_vec_pretty(&launch_file)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
            .and_then(|bytes| write_file_synced(&control_dir.join(LAUNCH_FILE_NAME), &bytes));
        if let Err(error) = written {
            drop((leases, floor));
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
            devices: placed.devices,
            launch_boot_ns: now.boot_ns,
            cutoff_boot_ns,
            host_memory_mib: placed.host_memory_mib,
            cache,
        };
        if let Err(error) = journal.record(key, known.issuer, &now.boot_id, now.wall_ms, event) {
            // Nothing is journaled: the devices and the memory go back as
            // the leases drop, and the key stays `Staging` for the next tick.
            log_write_error(key, &error);
            return;
        }
        for lease in leases {
            let _kept = lease.keep();
        }
        book.floors.insert(key.to_owned(), floor);
        if let Err(error) = self.parts().units.start(&JobKeyId::for_key(key)) {
            tracing::warn!(key, %error, "job unit start not taken; the end handling reads what remains");
        }
    }

    /// Steps 2 and 3 of the launch commit: the reason the key may not
    /// launch now, or `None`.
    fn launch_policy_refusal(&self, known: &NodeKey, signed: &SignedJobSubmit) -> Option<String> {
        let admission = &self.parts().admission;
        if let Some(reason) = admission.controls().refusal() {
            return Some(reason);
        }
        let pin = &signed.submit.pin;
        if admission.template_digest(&pin.template).as_deref() != Some(pin.template_digest.as_str())
        {
            return Some("template_changed".to_owned());
        }
        let Some(required) = admission.template_requires(&pin.template) else {
            return Some("template_changed".to_owned());
        };
        let missing = scope_missing(&self.parts().units.probe(), &required);
        if !missing.is_empty() {
            return Some(format!("no_scope: {}", missing.join(", ")));
        }
        if !self
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
