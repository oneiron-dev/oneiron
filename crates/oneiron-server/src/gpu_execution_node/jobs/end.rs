//! The node's tick and the end of a launched key (design pass 33, 7.6 "The
//! engine's end handling"). It is level-triggered: at every tick the engine
//! reads the unit's state and its end record, and never relies on having
//! seen the moment of the exit.
//! 1. An end record whose unit's control group was empty ends the key; the
//!    end of occupancy is the end step's boot-clock time. A record that says
//!    a process remained keeps the key `Ending` and quarantines the device:
//!    nothing settles until a reboot ends it as `Lost` or the owner writes
//!    it off.
//! 2. The release check: the unit is inactive with its control group gone,
//!    and the device probe answers. Then `released`, and the device and the
//!    memory go back. A probe that fails or cannot answer quarantines the
//!    device: it is never read as an empty device. A later clean probe
//!    releases it.
//! 3. The declared outputs are hashed after the release, never before:
//!    regular files opened beneath `out/` without following a link, within
//!    60 s in all.
//! 4. The terminal receipt is signed and kept in the control directory.
//!
//! The tick also closes a `Held` key past its `not_after_ms`, restarts a
//! staging worker that is not running, and writes each running key's tick
//! file, the last boot-clock time a host reset can be dated by.

use std::io::Read as _;
use std::path::Path;
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};

use super::admission::{log_write_error, withdrawn};
use super::job_unit::{
    EndRecord, JobUnitPhase, RECEIPT_FILE_NAME, TICK_FILE_NAME, read_end_record, write_file_synced,
};
use super::journal::{EndingCause, JournalEvent, NodeKey};
use super::node_parts::GpuJobEnd;
use super::receipt::{receipt_of, sign_receipt};
use super::{NodeBook, NodeGate, NodeJobs};
use crate::gpu_execution_node::wire::{
    DeviceRelease, FETCH_MAX_BYTES, JobEnd, JobState, OutputDigest, OutputsState, WorkloadPin,
};

/// The most time the hashing of one key's outputs takes in all.
pub const OUTPUT_HASH_LIMIT_SECS: u64 = 60;

/// The most bytes an output may hold and still travel to the issuer.
pub const RETURNABLE_OUTPUT_MAX_BYTES: u64 = FETCH_MAX_BYTES;

/// An exit this soon after the launch counts against the machine.
const EARLY_EXIT_NS: u64 = 5_000_000_000;

/// What the tick does with one launched key after reading it under the lock.
enum KeyFollowUp {
    Nothing,
    /// Hash the outputs, outside the lock.
    HashOutputs {
        pin: Box<WorkloadPin>,
    },
}

/// The end a key's end record names. The service manager's own limits win;
/// then the cause the engine journaled before it stopped the unit; then the
/// workload's own exit.
#[must_use]
pub fn end_of(record: &EndRecord, cause: Option<EndingCause>) -> JobEnd {
    if !record.workload_started {
        return JobEnd::LaunchRefused {
            reason: record.refusal.clone().unwrap_or_else(|| "unit".to_owned()),
        };
    }
    if record.cutoff_fired || record.service_result == "timeout" {
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
    ]
    .iter()
    .find(|(known, _)| *known == name)
    .map_or(-1, |(_, number)| *number)
}

/// How a key's end counts for the machine's drain guard (design 7.9): a
/// cause that is the machine's counts, a caller's stop neither counts nor
/// resets, a run past 5 s resets.
#[must_use]
pub fn drain_end(key: &NodeKey) -> GpuJobEnd {
    let occupied_ns = key.launch.as_ref().and_then(|launch| {
        key.end_boot_ns
            .map(|end| end.saturating_sub(launch.launch_boot_ns))
    });
    match &key.end {
        Some(JobEnd::Stopped | JobEnd::Revoked | JobEnd::Withdrawn) => GpuJobEnd::Cancelled,
        Some(JobEnd::Lost { reason, .. }) => GpuJobEnd::Failed {
            reason: format!("lost: {reason}"),
        },
        Some(JobEnd::LaunchRefused { reason } | JobEnd::Refused { reason }) => GpuJobEnd::Failed {
            reason: reason.clone(),
        },
        _ if occupied_ns.is_none_or(|ns| ns < EARLY_EXIT_NS) => GpuJobEnd::Failed {
            reason: "ended_within_5_s".to_owned(),
        },
        _ => GpuJobEnd::Succeeded,
    }
}

impl NodeJobs {
    /// One pass of the node's tick. The node's service tick calls it (every
    /// 30 s); tests call it to step the node.
    pub fn tick(&self) {
        if self.gate() == NodeGate::Recovering {
            self.recover();
        }
        if self.gate() != NodeGate::Open {
            return;
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
                KeyFollowUp::HashOutputs { pin } => self.hash_and_seal(&key, &pin),
            }
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
                self.read_unit_end(book, &known, &now);
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
    fn read_unit_end(&self, book: &mut NodeBook, known: &NodeKey, now: &super::ReceiptClock) {
        let Some(journal) = book.journal.as_mut() else {
            return;
        };
        let control_dir = known.id.control_dir(&self.paths().state_dir);
        let record = |event: JournalEvent, journal: &mut super::JobJournal| {
            if let Err(error) =
                journal.record(&known.key, known.issuer, &now.boot_id, now.wall_ms, event)
            {
                log_write_error(&known.key, &error);
            }
        };
        match read_end_record(&control_dir, &known.key) {
            Ok(Some(end_record)) if end_record.cgroup_empty => {
                let end = end_of(&end_record, known.ending_cause);
                let event = JournalEvent::Ended {
                    end,
                    end_boot_ns: Some(end_record.end_boot_ns),
                };
                record(event, journal);
            }
            Ok(Some(_)) => {
                if known.state != JobState::Ending {
                    record(
                        JournalEvent::Ending {
                            cause: EndingCause::UnitStopping,
                        },
                        journal,
                    );
                }
                if !matches!(known.release, DeviceRelease::Unconfirmed { .. }) {
                    let event = JournalEvent::Quarantined {
                        why: "kill_unconfirmed".to_owned(),
                        other_compute_pids: Vec::new(),
                    };
                    record(event, journal);
                }
            }
            Ok(None) => self.read_unit_phase(journal, known, now),
            Err(error) => {
                tracing::warn!(key = %known.key, %error, "job end record unreadable; asking again at the next tick");
            }
        }
    }

    /// Step 1 with no end record: the unit's phase alone.
    fn read_unit_phase(
        &self,
        journal: &mut super::JobJournal,
        known: &NodeKey,
        now: &super::ReceiptClock,
    ) {
        let status = match self.parts().units.status(&known.id) {
            Ok(status) => status,
            Err(error) => {
                tracing::warn!(key = %known.key, %error, "job unit status unknown; asking again at the next tick");
                return;
            }
        };
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
                    },
                    end_boot_ns: None,
                })
            }
            _ => None,
        };
        if let Some(event) = event {
            if let Err(error) =
                journal.record(&known.key, known.issuer, &now.boot_id, now.wall_ms, event)
            {
                log_write_error(&known.key, &error);
            }
        } else if known.state == JobState::Ending && status.phase != JobUnitPhase::Stopping {
            // A stop the service manager did not take: ask again.
            self.stop_unit(&known.key);
        } else if matches!(known.state, JobState::Launching | JobState::Running) {
            self.write_tick(known, now);
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

    /// Step 2: the release check of an ended key that holds its device.
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
                why,
                other_compute_pids: pids,
            };
            if let Err(error) =
                journal.record(&known.key, known.issuer, &now.boot_id, now.wall_ms, event)
            {
                log_write_error(&known.key, &error);
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
        let processes = match self.parts().devices.end_check(&known.key) {
            Ok(processes) => processes,
            Err(refusal) => {
                quarantine(format!("device_probe: {refusal}"), Vec::new(), journal);
                return;
            }
        };
        let event = JournalEvent::Released {
            other_compute_pids: processes.pids,
        };
        match journal.record(&known.key, known.issuer, &now.boot_id, now.wall_ms, event) {
            Ok(released) => {
                let end = drain_end(released);
                self.parts().devices.finish(&known.key, &end);
                book.floors.remove(&known.key);
            }
            Err(error) => log_write_error(&known.key, &error),
        }
    }

    /// Steps 3 and 4: hashes the outputs outside the lock, then records them
    /// and keeps the signed terminal receipt.
    fn hash_and_seal(&self, key: &str, pin: &WorkloadPin) {
        let payload_dir = super::JobKeyId::for_key(key).payload_dir(&self.paths().work_dir);
        let outputs = hash_outputs(
            &payload_dir,
            pin,
            Duration::from_secs(OUTPUT_HASH_LIMIT_SECS),
        );
        let now = self.now();
        let mut book = self.lock();
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
        let parts = self.parts();
        let signed = sign_receipt(
            receipt_of(&sealed, parts.machine, epoch, &now),
            parts.signer.as_ref(),
        );
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
            tracing::warn!(key, %error, "terminal job receipt not kept; the journal still holds the key");
        }
    }
}

/// Hashes the pin's declared outputs beneath `<payload_dir>/out/`: only
/// declared names, only regular files, opened without following a link,
/// within `limit` in all.
#[must_use]
pub fn hash_outputs(payload_dir: &Path, pin: &WorkloadPin, limit: Duration) -> OutputsState {
    use rustix::fs::{FileType, Mode, OFlags};
    let started = Instant::now();
    let directory = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let base = match rustix::fs::open(payload_dir, directory, Mode::empty()) {
        Ok(base) => base,
        Err(rustix::io::Errno::NOENT) => return OutputsState::Hashed(Vec::new()),
        Err(error) => {
            return OutputsState::Failed {
                why: format!("payload_dir: {error}"),
            };
        }
    };
    let out = match rustix::fs::openat(&base, "out", directory, Mode::empty()) {
        Ok(out) => out,
        Err(rustix::io::Errno::NOENT) => return OutputsState::Hashed(Vec::new()),
        Err(error) => {
            return OutputsState::Failed {
                why: format!("out: {error}"),
            };
        }
    };
    let mut digests = Vec::new();
    for decl in &pin.outputs {
        let name = decl.name.as_str();
        if name.is_empty() || name.contains('/') || name == "." || name == ".." {
            return OutputsState::Failed {
                why: format!("{name}: not a plain file name"),
            };
        }
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let descriptor = match rustix::fs::openat(&out, name, flags, Mode::empty()) {
            Ok(descriptor) => descriptor,
            Err(rustix::io::Errno::NOENT) => continue,
            Err(error) => {
                return OutputsState::Failed {
                    why: format!("{name}: {error}"),
                };
            }
        };
        let regular = rustix::fs::fstat(&descriptor)
            .is_ok_and(|stat| FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile);
        if !regular {
            return OutputsState::Failed {
                why: format!("{name}: not a regular file"),
            };
        }
        let mut file = std::fs::File::from(descriptor);
        let mut hasher = Sha256::new();
        let mut bytes = 0u64;
        let mut buffer = vec![0u8; 1 << 16];
        loop {
            if started.elapsed() > limit {
                return OutputsState::Failed {
                    why: "hash_time_limit".to_owned(),
                };
            }
            match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    hasher.update(&buffer[..read]);
                    bytes = bytes.saturating_add(read as u64);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => {
                    return OutputsState::Failed {
                        why: format!("{name}: {error}"),
                    };
                }
            }
        }
        digests.push(OutputDigest {
            name: name.to_owned(),
            sha256: oneiron_hex::encode(&hasher.finalize()),
            bytes,
            returnable: decl.returnable && bytes <= RETURNABLE_OUTPUT_MAX_BYTES,
        });
    }
    OutputsState::Hashed(digests)
}
