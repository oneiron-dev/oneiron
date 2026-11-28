//! The node's tick and the end of a launched key (design pass 33, 7.6 "The
//! engine's end handling"). It is level-triggered: at every tick the engine
//! reads the unit's state and its end record, and never relies on having
//! seen the moment of the exit.
//! 1. An end record whose unit's control group was empty ends the key; the
//!    end of occupancy is the end step's boot-clock time. A record that says
//!    a process remained keeps the key `Ending` and quarantines the device:
//!    nothing settles until a reboot ends it as `Lost` or the owner writes
//!    it off.
//!    With no end record, a unit that is inactive with a process left is
//!    the same unconfirmed kill; only an inactive, empty unit whose end
//!    record is still missing when read again ends as `Lost`.
//! 2. The release check: the unit is inactive with its control group gone,
//!    and the device probe answers with every compute entry named by a
//!    process id (none is the unit's: its control group is gone). Then the
//!    staged code goes (`unstage`; `out/` and `log/` stay), `released` is
//!    journaled, and the device and the memory go back. A probe that fails,
//!    cannot answer, or lists an entry with no process id quarantines the
//!    device: it is never read as an empty device. A later clean probe
//!    releases it.
//! 3. The declared outputs are hashed after the release, never before:
//!    regular files opened beneath `out/` without following a link, each
//!    within the key's disk request, within 60 s in all ([`super::outputs`]).
//! 4. The terminal receipt is signed and kept in the control directory.
//!
//! The tick also closes a `Held` key past its `not_after_ms`, restarts a
//! staging worker that is not running, and writes each running key's tick
//! file, the last boot-clock time a host reset can be dated by, and its
//! breadcrumb line (pass 34 row Q4, [`super::breadcrumb`]). Last, it runs
//! the machine's readiness step ([`super::readiness`]). While the history
//! is lost, each tick asks the service manager again to stop every job
//! unit.

use super::admission::{log_write_error, withdrawn};
use super::job_unit::{
    EndRecord, JobUnitPhase, RECEIPT_FILE_NAME, TICK_FILE_NAME, read_end_record, write_file_synced,
};
use super::journal::{EndingCause, JournalEvent, NodeKey};
use super::node_parts::{GpuDeviceProcesses, GpuLeaseEnd};
use super::outputs::hash_outputs;
use super::receipt::{receipt_of, sign_receipt};
use super::{NodeBook, NodeGate, NodeJobs};
use crate::gpu_execution_node::wire::{DeviceRelease, JobEnd, JobState, OutputsState, WorkloadPin};

/// What the tick does with one launched key after reading it under the lock.
enum KeyFollowUp {
    Nothing,
    /// Look for a complete checkpoint while the unit runs (pass 34 row C1).
    ScanCheckpoint {
        pin: Box<WorkloadPin>,
    },
    /// Hash the outputs, outside the lock.
    HashOutputs {
        pin: Box<WorkloadPin>,
    },
}

/// The end a key's end record names. The cutoff and the memory limit win;
/// then the cause the engine journaled before it stopped the unit; then the
/// workload's own exit.
#[must_use]
pub(super) fn end_of(record: &EndRecord, cause: Option<EndingCause>) -> JobEnd {
    if !record.workload_started {
        return JobEnd::LaunchRefused {
            reason: record.refusal.clone().unwrap_or_else(|| "unit".to_owned()),
        };
    }
    // The unit's end step says whether the cutoff ended the run; the service
    // manager's `timeout` alone is also a stop grace that ran out.
    if record.cutoff_fired {
        return JobEnd::TimeLimit;
    }
    if record.service_result == "oom-kill" {
        return JobEnd::MemoryLimit;
    }
    if let Some(end) = cause.and_then(EndingCause::end) {
        return end;
    }
    let status = record.exit_status.as_deref().unwrap_or_default();
    match record.exit_code.as_deref() {
        Some("killed" | "dumped") => JobEnd::Signalled {
            signal: signal_number(status),
        },
        // `exited`, or a service manager that named no exit: the workload's
        // own status, -1 when it gave none.
        _ => JobEnd::Exited {
            code: status.parse().unwrap_or(-1),
        },
    }
}

/// The Linux signal number the service manager's `EXIT_STATUS` names, by
/// number or by name; -1, which no signal has, for a name it does not know.
fn signal_number(status: &str) -> i32 {
    if let Ok(number) = status.parse() {
        return number;
    }
    let name = status.trim_start_matches("SIG");
    [
        ("HUP", 1),
        ("INT", 2),
        ("QUIT", 3),
        ("ILL", 4),
        ("TRAP", 5),
        ("ABRT", 6),
        ("BUS", 7),
        ("FPE", 8),
        ("KILL", 9),
        ("USR1", 10),
        ("SEGV", 11),
        ("USR2", 12),
        ("PIPE", 13),
        ("ALRM", 14),
        ("TERM", 15),
        ("STKFLT", 16),
        ("CHLD", 17),
        ("CONT", 18),
        ("STOP", 19),
        ("TSTP", 20),
        ("TTIN", 21),
        ("TTOU", 22),
        ("URG", 23),
        ("XCPU", 24),
        ("XFSZ", 25),
        ("VTALRM", 26),
        ("PROF", 27),
        ("WINCH", 28),
        ("IO", 29),
        ("POLL", 29),
        ("PWR", 30),
        ("SYS", 31),
    ]
    .iter()
    .find(|(known, _)| *known == name)
    .map_or(-1, |(_, number)| *number)
}

/// How a key's end counts for the machine's drain guard (design 7.9): a
/// cause that is the machine's counts, a caller's stop neither counts nor
/// resets, a run past `fast_exit_secs` resets.
#[must_use]
pub(super) fn drain_end(key: &NodeKey, fast_exit_secs: u64) -> GpuLeaseEnd {
    let occupied_ns = key.launch.as_ref().and_then(|launch| {
        key.end_boot_ns
            .map(|end| end.saturating_sub(launch.launch_boot_ns))
    });
    match &key.end {
        Some(JobEnd::Stopped | JobEnd::Revoked | JobEnd::Withdrawn) => GpuLeaseEnd::Cancelled,
        Some(JobEnd::Lost { reason, .. }) => GpuLeaseEnd::Failed {
            reason: format!("lost: {reason}"),
        },
        Some(JobEnd::LaunchRefused { reason } | JobEnd::Refused { reason }) => {
            GpuLeaseEnd::Failed {
                reason: reason.clone(),
            }
        }
        _ if occupied_ns.is_none_or(|ns| ns < fast_exit_secs.saturating_mul(1_000_000_000)) => {
            GpuLeaseEnd::Failed {
                reason: format!("ended_within_{fast_exit_secs}_s"),
            }
        }
        _ => GpuLeaseEnd::Succeeded,
    }
}

impl NodeJobs {
    /// One pass of the node's tick. The node's service tick calls it (every
    /// 30 s); tests call it to step the node.
    pub fn tick(&self) {
        if self.gate() == NodeGate::Recovering {
            self.recover();
        }
        match self.gate() {
            NodeGate::Open => {}
            NodeGate::HistoryLost { .. } => {
                self.stop_every_unit();
                return;
            }
            NodeGate::Recovering => return,
        }
        self.close_expired_held_keys();
        for key in self.keys_without_staging_worker() {
            self.start_staging(key);
        }
        let launched: Vec<String> = self
            .keys()
            .into_iter()
            .filter(|key| key.launch.is_some() && key.outputs == OutputsState::Pending)
            .map(|key| key.key)
            .collect();
        for key in launched {
            match self.settle_launched(&key) {
                KeyFollowUp::Nothing => {}
                KeyFollowUp::ScanCheckpoint { pin } => {
                    self.follow_checkpoint(&key, pin, JobState::Running);
                }
                KeyFollowUp::HashOutputs { pin } => {
                    self.follow_checkpoint(&key, pin, JobState::Ended);
                }
            }
        }
        self.rearm_renewed_cutoffs();
        self.keep_missing_terminal_receipts();
        self.clean_acknowledged_payloads();
        self.write_breadcrumbs();
        self.readiness_tick();
    }

    /// Asks the scope again for each live renewed session run whose cutoff
    /// the journal moved and the scope has not taken (row W1): a renewal
    /// whose ask failed, or any renewed run after a start. The scope's
    /// renewal moves a cutoff only forward, so asking twice changes nothing.
    /// The armed cutoff of a run that no longer runs is forgotten.
    fn rearm_renewed_cutoffs(&self) {
        let pending: Vec<(String, u64)> = {
            let mut guard = self.lock();
            let book = &mut *guard;
            let Some(journal) = book.journal.as_ref() else {
                return;
            };
            // A run that no longer runs needs no armed cutoff kept.
            book.armed_cutoffs.retain(|key, _| {
                journal.table().get(key).is_some_and(|known| {
                    matches!(known.state, JobState::Launching | JobState::Running)
                })
            });
            journal
                .table()
                .iter()
                .filter(|known| {
                    !known.renewals.is_empty()
                        && matches!(known.state, JobState::Launching | JobState::Running)
                })
                .filter_map(|known| {
                    let cutoff = known.launch.as_ref()?.cutoff_boot_ns;
                    (book.armed_cutoffs.get(&known.key) != Some(&cutoff))
                        .then(|| (known.key.clone(), cutoff))
                })
                .collect()
        };
        for (key, cutoff_boot_ns) in pending {
            self.arm_renewed_cutoff(&key, cutoff_boot_ns);
        }
    }

    /// Writes the signed terminal receipt again for each sealed key whose
    /// control directory lacks it: an engine that stopped between the
    /// `hashed` record and the file, or a write that failed, leaves it
    /// missing, and the journal alone rebuilds it.
    fn keep_missing_terminal_receipts(&self) {
        let now = self.now();
        let (sealed, epoch): (Vec<NodeKey>, _) = {
            let book = self.lock();
            let Some(journal) = book.journal.as_ref() else {
                return;
            };
            let sealed = journal
                .table()
                .iter()
                .filter(|key| {
                    key.launch.is_some()
                        && key.outputs != OutputsState::Pending
                        && !book.checkpoint_in_flight(&key.key)
                })
                .cloned()
                .collect();
            (sealed, journal.epoch())
        };
        for key in &sealed {
            let file = key
                .id
                .control_dir(&self.paths().state_dir)
                .join(RECEIPT_FILE_NAME);
            if !file.exists() {
                self.keep_terminal_receipt(key, epoch, &now);
            }
        }
    }

    /// Signs the sealed key's terminal receipt and keeps it in the key's
    /// control directory, synced. For a renewed session (row W1) it is the
    /// whole run's, under its first key; the issuer reads each chunk's slice
    /// from the status answers.
    fn keep_terminal_receipt(
        &self,
        sealed: &NodeKey,
        epoch: super::JournalEpoch,
        now: &super::ReceiptClock,
    ) {
        let parts = self.parts();
        let mut receipt = receipt_of(sealed, parts.machine, epoch, now);
        receipt.scope = parts.units.scope_facts(&sealed.id);
        let signed = sign_receipt(receipt, parts.signer.as_ref());
        let written = signed
            .map_err(std::io::Error::other)
            .and_then(|signed| {
                oneiron_organ_protocol::to_vec(&signed).map_err(|error| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
                })
            })
            .and_then(|bytes| {
                let control_dir = sealed.id.control_dir(&self.paths().state_dir);
                write_file_synced(&control_dir.join(RECEIPT_FILE_NAME), &bytes)
            });
        if let Err(error) = written {
            tracing::warn!(key = %sealed.key, %error, "terminal job receipt not kept; the next tick writes it again");
        }
    }

    fn close_expired_held_keys(&self) {
        let now = self.now();
        let mut book = self.lock();
        let Some(journal) = book.journal.as_mut() else {
            return;
        };
        let expired: Vec<(String, oneiron::EntityId)> = journal
            .table()
            .iter()
            .filter(|key| {
                key.state == JobState::Held
                    && key
                        .reserve
                        .as_ref()
                        .is_some_and(|reserve| now.wall_ms > reserve.not_after_ms)
            })
            .map(|key| (key.key.clone(), key.issuer))
            .collect();
        for (key, issuer) in expired {
            if let Err(error) = journal.record(&key, issuer, &now.boot_id, now.wall_ms, withdrawn())
            {
                log_write_error(&key, &error);
            }
        }
    }

    fn keys_without_staging_worker(&self) -> Vec<String> {
        let book = self.lock();
        let Some(journal) = book.journal.as_ref() else {
            return Vec::new();
        };
        journal
            .table()
            .iter()
            .filter(|key| matches!(key.state, JobState::Accepted | JobState::Staging))
            .filter(|key| !book.staging.contains(&key.key))
            .map(|key| key.key.clone())
            .collect()
    }

    /// Steps 1 and 2 for one launched key, under the lock.
    fn settle_launched(&self, key: &str) -> KeyFollowUp {
        let now = self.now();
        let mut guard = self.lock();
        let book: &mut NodeBook = &mut guard;
        let Some(known) = book
            .journal
            .as_ref()
            .and_then(|journal| journal.table().get(key))
            .cloned()
        else {
            return KeyFollowUp::Nothing;
        };
        match known.state {
            JobState::Launching | JobState::Running | JobState::Ending => {
                if let Err(why) = self.read_unit_end(book, &known, &now) {
                    tracing::debug!(key, %why, "job end handling tries again at the next tick");
                }
            }
            JobState::Ended => {}
            _ => return KeyFollowUp::Nothing,
        }
        let Some(known) = book
            .journal
            .as_ref()
            .and_then(|journal| journal.table().get(key))
            .cloned()
        else {
            return KeyFollowUp::Nothing;
        };
        if known.state == JobState::Running {
            return known.reserve.map_or(KeyFollowUp::Nothing, |reserve| {
                KeyFollowUp::ScanCheckpoint {
                    pin: Box::new(reserve.pin),
                }
            });
        }
        if known.state != JobState::Ended {
            return KeyFollowUp::Nothing;
        }
        if known.holds_device() {
            self.release_check(book, &known, &now);
        }
        let Some(known) = book
            .journal
            .as_ref()
            .and_then(|journal| journal.table().get(key))
            .cloned()
        else {
            return KeyFollowUp::Nothing;
        };
        match (&known.release, known.reserve) {
            (DeviceRelease::Confirmed { .. }, Some(reserve))
                if known.outputs == OutputsState::Pending =>
            {
                KeyFollowUp::HashOutputs {
                    pin: Box::new(reserve.pin),
                }
            }
            _ => KeyFollowUp::Nothing,
        }
    }

    /// Step 1: reads the key's end record and its unit, and moves the key.
    ///
    /// # Errors
    ///
    /// The key could not be moved now: its end record or its unit's phase
    /// could not be read, or the record it needs did not land. Recovery keeps
    /// the gate closed on it (design 7.7); the tick asks again.
    pub(super) fn read_unit_end(
        &self,
        book: &mut NodeBook,
        known: &NodeKey,
        now: &super::ReceiptClock,
    ) -> Result<(), String> {
        let Some(journal) = book.journal.as_mut() else {
            return Err("job_service.history_lost".to_owned());
        };
        let control_dir = known.id.control_dir(&self.paths().state_dir);
        match read_end_record(&control_dir, &known.key) {
            Ok(Some(end_record)) => self.apply_end_record(journal, known, &end_record, now),
            Ok(None) => self.read_unit_phase(journal, known, now),
            Err(error) => {
                tracing::warn!(key = %known.key, %error, "job end record unreadable; asking again at the next tick");
                Err(format!("job_end_record {}: {error}", known.key))
            }
        }
    }

    /// Appends `event` for `known`; a write that did not land is logged and
    /// returned.
    fn record_end_step(
        journal: &mut super::JobJournal,
        known: &NodeKey,
        now: &super::ReceiptClock,
        event: JournalEvent,
    ) -> Result<(), String> {
        journal
            .record(&known.key, known.issuer, &now.boot_id, now.wall_ms, event)
            .map(drop)
            .map_err(|error| {
                log_write_error(&known.key, &error);
                format!("job_record {}: {error}", known.key)
            })
    }

    /// An end record ends the key when the unit's control group was empty;
    /// else the kill is unconfirmed.
    fn apply_end_record(
        &self,
        journal: &mut super::JobJournal,
        known: &NodeKey,
        end_record: &EndRecord,
        now: &super::ReceiptClock,
    ) -> Result<(), String> {
        if !end_record.cgroup_empty {
            return self.kill_unconfirmed(journal, known, now);
        }
        let event = JournalEvent::Ended {
            end: end_of(end_record, known.ending_cause),
            end_boot_ns: Some(end_record.end_boot_ns),
        };
        Self::record_end_step(journal, known, now, event)
    }

    /// A process of the unit remained: the key stays `Ending` and its device
    /// is quarantined until a reboot ends it or the owner writes it off.
    fn kill_unconfirmed(
        &self,
        journal: &mut super::JobJournal,
        known: &NodeKey,
        now: &super::ReceiptClock,
    ) -> Result<(), String> {
        if known.state != JobState::Ending {
            let event = JournalEvent::Ending {
                cause: EndingCause::UnitStopping,
            };
            Self::record_end_step(journal, known, now, event)?;
        }
        if !matches!(known.release, DeviceRelease::Unconfirmed { .. }) {
            let why = "kill_unconfirmed";
            let event = JournalEvent::Quarantined {
                why: why.to_owned(),
                other_compute_pids: Vec::new(),
            };
            Self::record_end_step(journal, known, now, event)?;
            self.quarantine_with_incident(known, why);
        }
        Ok(())
    }

    /// Puts the key's device out of every reserve and launch, as the
    /// journal just recorded (design 7.6): the slot table counts it again
    /// only after the key's clean release. Recovery replays it.
    pub(super) fn quarantine_device(&self, known: &NodeKey, why: &str) {
        for lease in known.launch.iter().flat_map(|launch| &launch.devices) {
            self.parts().devices.quarantine(&lease.device_id, why);
        }
    }

    /// Step 1 with no end record: the unit's phase alone. An inactive unit
    /// ends the key as `Lost` only when its control group is empty and its
    /// end record is still missing when read again: the unit may have
    /// written it between the two reads.
    fn read_unit_phase(
        &self,
        journal: &mut super::JobJournal,
        known: &NodeKey,
        now: &super::ReceiptClock,
    ) -> Result<(), String> {
        let status = match self.parts().units.status(&known.id) {
            Ok(status) => status,
            Err(error) => {
                tracing::warn!(key = %known.key, %error, "job unit status unknown; asking again at the next tick");
                return Err(format!("job_unit_status {}: {error}", known.key));
            }
        };
        if status.phase == JobUnitPhase::Inactive {
            if !status.cgroup_empty {
                return self.kill_unconfirmed(journal, known, now);
            }
            let control_dir = known.id.control_dir(&self.paths().state_dir);
            match read_end_record(&control_dir, &known.key) {
                Ok(Some(end_record)) => {
                    return self.apply_end_record(journal, known, &end_record, now);
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(key = %known.key, %error, "job end record unreadable; asking again at the next tick");
                    return Err(format!("job_end_record {}: {error}", known.key));
                }
            }
        }
        let event = match (status.phase, known.state) {
            (JobUnitPhase::Active, JobState::Launching) => Some(JournalEvent::Running),
            (JobUnitPhase::Stopping, JobState::Launching | JobState::Running) => {
                Some(JournalEvent::Ending {
                    cause: EndingCause::UnitStopping,
                })
            }
            (JobUnitPhase::Inactive, state) => {
                let reason = if state == JobState::Launching {
                    "launch_uncertain"
                } else {
                    "end_record_missing"
                };
                Some(JournalEvent::Ended {
                    end: JobEnd::Lost {
                        reason: reason.to_owned(),
                        last_tick_boot_ns: self.last_tick_boot_ns(known),
                        breadcrumbs: self.lost_breadcrumbs(known),
                    },
                    end_boot_ns: None,
                })
            }
            _ => None,
        };
        if let Some(event) = event {
            return Self::record_end_step(journal, known, now, event);
        }
        if known.state == JobState::Ending && status.phase != JobUnitPhase::Stopping {
            // A stop the service manager did not take: ask again.
            self.stop_unit(&known.key);
        } else if matches!(known.state, JobState::Launching | JobState::Running) {
            self.write_tick(known, now);
        }
        Ok(())
    }

    /// While the history is lost: asks the service manager again to stop
    /// every job unit that still runs.
    pub(super) fn stop_every_unit(&self) {
        match self.parts().units.live_units() {
            Ok(units) => {
                for (id, _) in units {
                    if let Err(error) = self.parts().units.stop(&id) {
                        tracing::warn!(unit = %id, %error, "job unit stop not taken; the next tick asks again");
                    }
                }
            }
            Err(error) => {
                tracing::warn!(%error, "job units not listed; the next tick asks again");
            }
        }
    }

    /// The boot-clock time of the key's newest tick, or its launch.
    pub(super) fn last_tick_boot_ns(&self, known: &NodeKey) -> u64 {
        let launched = known
            .launch
            .as_ref()
            .map_or(0, |launch| launch.launch_boot_ns);
        let path = known
            .id
            .control_dir(&self.paths().state_dir)
            .join(TICK_FILE_NAME);
        std::fs::read_to_string(path)
            .ok()
            .and_then(|text| text.trim().parse::<u64>().ok())
            .map_or(launched, |tick| tick.max(launched))
    }

    fn write_tick(&self, known: &NodeKey, now: &super::ReceiptClock) {
        let Some(launch) = known.launch.as_ref() else {
            return;
        };
        if launch.boot_id != now.boot_id {
            return;
        }
        let path = known
            .id
            .control_dir(&self.paths().state_dir)
            .join(TICK_FILE_NAME);
        if let Err(error) = std::fs::write(path, now.boot_ns.to_string()) {
            tracing::warn!(key = %known.key, %error, "job tick file not written");
        }
    }

    /// Step 2: the release check of an ended key that holds its leases. A
    /// key with no device lease is released once its unit is gone.
    pub(super) fn release_check(
        &self,
        book: &mut NodeBook,
        known: &NodeKey,
        now: &super::ReceiptClock,
    ) {
        let Some(journal) = book.journal.as_mut() else {
            return;
        };
        let unconfirmed = matches!(known.release, DeviceRelease::Unconfirmed { .. });
        let quarantine = |why: String, pids: Vec<u32>, journal: &mut super::JobJournal| {
            if unconfirmed {
                return;
            }
            let event = JournalEvent::Quarantined {
                why: why.clone(),
                other_compute_pids: pids,
            };
            match journal.record(&known.key, known.issuer, &now.boot_id, now.wall_ms, event) {
                Ok(_) => self.quarantine_with_incident(known, &why),
                Err(error) => log_write_error(&known.key, &error),
            }
        };
        match self.parts().units.status(&known.id) {
            Ok(status) if status.is_gone() => {}
            Ok(status) if status.phase == JobUnitPhase::Inactive => {
                quarantine("kill_unconfirmed".to_owned(), Vec::new(), journal);
                return;
            }
            Ok(_) => return,
            Err(error) => {
                quarantine(format!("unit_status: {error}"), Vec::new(), journal);
                return;
            }
        }
        let has_device_lease = known
            .launch
            .as_ref()
            .is_some_and(super::journal::KeyLaunch::has_device_lease);
        let processes = if has_device_lease {
            match self.parts().devices.end_check(&known.key) {
                Ok(processes) => processes,
                Err(refusal) => {
                    quarantine(format!("device_probe: {refusal}"), Vec::new(), journal);
                    return;
                }
            }
        } else {
            GpuDeviceProcesses::default()
        };
        // The unit's control group is gone, so a compute entry with a process
        // id is another process's. One with no process id cannot be told
        // from a leftover of the unit's: the device stays out.
        if processes.hidden > 0 {
            let why = format!(
                "device_probe_unattributed: {} compute entries with no process id",
                processes.hidden
            );
            quarantine(why, processes.pids, journal);
            return;
        }
        // No process of the unit is left: its staged code goes before
        // `released`, and a crash in between runs this check again. `out/`
        // and `log/` stay until the `Ack` and the keep time (design 7.6).
        let payload_dir = known.id.payload_dir(&self.paths().work_dir);
        self.parts().stager.unstage(&known.key, &payload_dir);
        let event = JournalEvent::Released {
            other_compute_pids: processes.pids,
        };
        match journal.record(&known.key, known.issuer, &now.boot_id, now.wall_ms, event) {
            Ok(released) => {
                if has_device_lease {
                    let end = drain_end(
                        released,
                        self.parts().admission.job_settings().fast_exit_secs,
                    );
                    if unconfirmed {
                        // The clean probe ends the quarantine the journal set.
                        for lease in known.launch.iter().flat_map(|launch| &launch.devices) {
                            self.parts().devices.clear_quarantine(&lease.device_id);
                        }
                    }
                    self.parts().devices.finish(&known.key, &end);
                }
                book.floors.remove(&known.key);
            }
            Err(error) => log_write_error(&known.key, &error),
        }
    }

    /// Steps 3 and 4: hashes the outputs outside the lock, then records them
    /// and keeps the signed terminal receipt. On the tick, or on a checkpoint
    /// worker after the end's scan; a closed service records nothing.
    pub(super) fn hash_and_seal(&self, key: &str, pin: &WorkloadPin) {
        let payload_dir = super::JobKeyId::for_key(key).payload_dir(&self.paths().work_dir);
        let settings = self.parts().admission.job_settings();
        let outputs = hash_outputs(&payload_dir, pin, &settings);
        let now = self.now();
        let mut book = self.lock();
        if self.service_closed() || book.gate != NodeGate::Open {
            return;
        }
        let Some(journal) = book.journal.as_mut() else {
            return;
        };
        let Some(known) = journal.table().get(key).cloned() else {
            return;
        };
        if known.outputs != OutputsState::Pending {
            return;
        }
        let epoch = journal.epoch();
        let event = JournalEvent::Hashed { outputs };
        let sealed = match journal.record(key, known.issuer, &now.boot_id, now.wall_ms, event) {
            Ok(sealed) => sealed.clone(),
            Err(error) => {
                log_write_error(key, &error);
                return;
            }
        };
        drop(book);
        self.keep_terminal_receipt(&sealed, epoch, &now);
    }
}
