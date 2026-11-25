//! Recovery on the node (design pass 33, 7.7). At start, before the gate
//! opens, the engine reads the journal (a torn last record is cut off) and,
//! for every key that is not final, looks at the last record, the unit and
//! the boot:
//!
//! | Last record | Unit and end record | Boot | Action |
//! |---|---|---|---|
//! | `reserved`, `accepted`, `staged` | - | same | Keep the key; a `Held` key past `not_after` is closed as `Withdrawn` before the gate opens |
//! | `reserved`, `accepted`, `staged` | - | another | Close it: `Withdrawn`, or `LaunchRefused { node_restarted }`. Nothing ran |
//! | `launching`, `running`, `ending` | the unit is active | same | Take the device and the memory again as launched |
//! | `launching`, `running`, `ending` | `ended.json` exists | same | The end handling |
//! | `launching` | no unit, no end record | same | `Lost { launch_uncertain }`; never started again; the device waits for a clean probe |
//! | `running`, `ending` | no unit, no end record | same | `Lost { end_record_missing }`; the device waits for a clean probe |
//! | `launching`, `running`, `ending` | - | another | `Lost { host_reset }` with the last tick; the device waits for a clean probe |
//! | (no key that launched) | a job unit is active | - | Drain the node, then stop the unit |
//! | the journal or the epoch is missing or unreadable, and control or payload directories exist | - | - | History lost: stop every job unit; admit nothing until `reset-history` |
//!
//! Then the leases of every launched key are in place (the device, and on
//! the same boot the memory, until its release check passes), each adopted
//! key's end record is read once more, and only then the gate opens. A part
//! that does not answer (the service manager, the slot table, the journal's
//! disk for a record the table requires) keeps the gate closed; the next
//! tick runs the reconciliation again. No launch commit runs before the gate
//! opens. A directory that cannot be listed is never read as empty.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use super::admission::{mib_bytes, withdrawn};
use super::incidents::IncidentKind;
use super::job_unit::{CONTROL_DIR_NAME, JobKeyId};
use super::journal::{JobJournal, JournalEvent, NodeKey};
use super::journal_file::{JournalFile, JournalOpening, JournalWriterLock};
use super::node_parts::{NodeJobParts, NodeJobPaths};
use super::readiness::NodeReadinessShared;
use super::{NodeBook, NodeGate, NodeJobs, NodeJobsShared, ReceiptClock};
use crate::gpu_execution_node::wire::{DeviceRelease, JobEnd, JobState};

impl NodeJobs {
    /// Opens the node's job service on `paths` and runs the start-up
    /// reconciliation. The gate is open on return unless a part did not
    /// answer (the next [`Self::tick`] tries again) or the history is lost.
    ///
    /// # Errors
    ///
    /// The journal's writer lock was not taken: another service on the same
    /// `state_dir` lives ([`std::io::ErrorKind::WouldBlock`]), or the lock
    /// file could not be opened. Nothing was read.
    pub fn open(paths: NodeJobPaths, parts: NodeJobParts) -> std::io::Result<Self> {
        let writer = JournalWriterLock::take(&paths.state_dir)?;
        let opened = ReceiptClock {
            boot_id: parts.clock.boot_id(),
            boot_ns: parts.clock.boot_ns(),
            wall_ms: parts.clock.wall_ms(),
        };
        let (readiness, previous_boot) = NodeReadinessShared::open(&paths.state_dir, &opened);
        let jobs = Self {
            shared: Arc::new(NodeJobsShared {
                paths,
                parts,
                book: Mutex::new(NodeBook {
                    gate: NodeGate::Recovering,
                    journal: None,
                    floors: BTreeMap::new(),
                    staging: BTreeSet::new(),
                    armed_cutoffs: BTreeMap::new(),
                }),
                closed: AtomicBool::new(false),
                readiness,
                _writer: writer,
            }),
        };
        if let Some(previous_boot) = previous_boot {
            jobs.record_incident(IncidentKind::HostReset { previous_boot });
        }
        jobs.recover();
        Ok(jobs)
    }

    /// Runs the start-up reconciliation, once the gate is closed for it.
    pub(super) fn recover(&self) {
        let now = self.now();
        let (restage, unstage) = {
            let mut guard = self.lock();
            let book: &mut NodeBook = &mut guard;
            if book.gate != NodeGate::Recovering {
                return;
            }
            if book.journal.is_none() {
                match self.open_history() {
                    Ok(journal) => book.journal = Some(journal),
                    Err(HistoryOpening::Lost(why)) => {
                        self.lose_history(book, why);
                        return;
                    }
                    Err(HistoryOpening::Unknown(why)) => {
                        tracing::warn!(%why, "job history not established; the next tick tries again");
                        return;
                    }
                }
            }
            if let Err(why) = self.sweep(book, &now) {
                tracing::warn!(%why, "job service still recovering; the next tick tries again");
                return;
            }
            book.gate = NodeGate::Open;
            let restage = book.journal.as_ref().map_or_else(Vec::new, |journal| {
                journal
                    .table()
                    .iter()
                    .filter(|key| matches!(key.state, JobState::Accepted | JobState::Staging))
                    .map(|key| key.key.clone())
                    .collect::<Vec<_>>()
            });
            // A key that ended before its launch keeps no code on the node's
            // disk: a staging the sweep ended, or an end recorded just before
            // a crash took the stager's removal (row R3c). A key that
            // launched has its code removed at its release check.
            let unstage = book.journal.as_ref().map_or_else(Vec::new, |journal| {
                let work_dir = &self.paths().work_dir;
                journal
                    .table()
                    .iter()
                    .filter(|known| known.is_ended() && known.launch.is_none())
                    .map(|known| (known.key.clone(), known.id.payload_dir(work_dir)))
                    .collect::<Vec<_>>()
            });
            (restage, unstage)
        };
        for key in restage {
            self.start_staging(key);
        }
        // The removal runs once the lock is dropped, so a large tree left by
        // a crash holds no admission: an ended key never stages again (its
        // key is answered from the journal), and its payload directory is
        // its own.
        for (key, payload_dir) in unstage {
            self.parts().stager.unstage(&key, &payload_dir);
        }
    }

    /// Reads the journal, or makes the first one. A missing journal beside
    /// control or payload directories is a lost history, not a fresh node.
    fn open_history(&self) -> Result<JobJournal, HistoryOpening> {
        let state_dir = &self.paths().state_dir;
        match JournalFile::open(state_dir) {
            JournalOpening::Absent => {
                if self.payloads_exist().map_err(HistoryOpening::Unknown)? {
                    return Err(HistoryOpening::Lost(
                        "job_journal.absent: control or payload directories exist".to_owned(),
                    ));
                }
                JournalFile::create(state_dir)
                    .map(JobJournal::empty)
                    .map_err(|error| {
                        HistoryOpening::Unknown(format!("job_journal.create: {error}"))
                    })
            }
            JournalOpening::Damaged(damage) => Err(HistoryOpening::Lost(damage.to_string())),
            JournalOpening::Opened {
                file,
                records,
                cut_torn_tail,
            } => {
                if cut_torn_tail {
                    tracing::info!(
                        "job journal: a torn last record was cut off; it was never answered"
                    );
                }
                JobJournal::replay(file, &records).map_err(HistoryOpening::Lost)
            }
        }
    }

    /// Whether a key's control or payload directory exists. Only a missing
    /// directory or a full listing establishes that none does.
    ///
    /// # Errors
    ///
    /// A directory that exists and could not be listed.
    fn payloads_exist(&self) -> Result<bool, String> {
        let control = self.paths().state_dir.join(CONTROL_DIR_NAME);
        let has_key_dir = |dir: &std::path::Path| -> Result<bool, String> {
            let entries = match std::fs::read_dir(dir) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                Err(error) => return Err(format!("{}: {error}", dir.display())),
            };
            for entry in entries {
                let entry = entry.map_err(|error| format!("{}: {error}", dir.display()))?;
                if entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| JobKeyId::parse(name).is_some())
                {
                    return Ok(true);
                }
            }
            Ok(false)
        };
        Ok(has_key_dir(&control)? || has_key_dir(&self.paths().work_dir)?)
    }

    /// History lost: every job unit is stopped, and nothing is admitted
    /// until `reset-history` at the box.
    fn lose_history(&self, book: &mut NodeBook, why: String) {
        tracing::error!(%why, "job history lost; stopping every job unit and admitting nothing");
        self.stop_every_unit();
        self.record_incident(IncidentKind::HistoryLost { why: why.clone() });
        book.journal = None;
        book.gate = NodeGate::HistoryLost { why };
    }

    /// The table of 7.7, then the end handling of every adopted key.
    fn sweep(&self, book: &mut NodeBook, now: &ReceiptClock) -> Result<(), String> {
        let live_units = self
            .parts()
            .units
            .live_units()
            .map_err(|error| error.to_string())?;
        let (keys, launched): (Vec<NodeKey>, BTreeSet<JobKeyId>) = book
            .journal
            .as_ref()
            .map(|journal| {
                let keys = journal
                    .table()
                    .iter()
                    .filter(|key| !key.is_ended() || key.holds_device())
                    .cloned()
                    .collect();
                let launched = journal
                    .table()
                    .iter()
                    .filter(|key| key.launch.is_some())
                    .map(|key| key.id.clone())
                    .collect();
                (keys, launched)
            })
            .unwrap_or_default();
        for known in &keys {
            self.sweep_key(book, known, now)?;
        }
        // A unit of a key that launched is that key's, ended or not: its end
        // handling and release check read it. Any other unit ran outside the
        // journal. The drain is written before the stop, so a stop that
        // fails still leaves the machine taking no new work.
        let foreign = |id: &JobKeyId| !launched.contains(id);
        for (id, _) in live_units.iter().filter(|(id, _)| foreign(id)) {
            tracing::error!(unit = %id, "a job unit runs that no key of the journal launched; draining the node and stopping it");
            self.parts()
                .devices
                .drain(&format!("job unit {id} ran outside the journal"));
            self.parts()
                .units
                .stop(id)
                .map_err(|error| error.to_string())?;
        }
        if live_units.iter().any(|(id, _)| foreign(id)) {
            let still = self
                .parts()
                .units
                .live_units()
                .map_err(|error| error.to_string())?;
            if still.iter().any(|(id, _)| foreign(id)) {
                return Err("job_recovery.foreign_unit_stopping".to_owned());
            }
        }
        for known in &keys {
            let Some(current) = book
                .journal
                .as_ref()
                .and_then(|journal| journal.table().get(&known.key))
                .cloned()
            else {
                continue;
            };
            if matches!(
                current.state,
                JobState::Launching | JobState::Running | JobState::Ending
            ) {
                self.read_unit_end(book, &current, now)?;
            }
        }
        Ok(())
    }

    /// One key of the table.
    ///
    /// # Errors
    ///
    /// A record the table requires did not land, or the key's device could
    /// not be taken again: the gate stays closed, and no old-boot launch
    /// reaches the end handling of this boot.
    fn sweep_key(
        &self,
        book: &mut NodeBook,
        known: &NodeKey,
        now: &ReceiptClock,
    ) -> Result<(), String> {
        let record = |book: &mut NodeBook, event: JournalEvent| -> Result<(), String> {
            let journal = book
                .journal
                .as_mut()
                .ok_or_else(|| "job_service.history_lost".to_owned())?;
            journal
                .record(&known.key, known.issuer, &now.boot_id, now.wall_ms, event)
                .map(drop)
                .map_err(|error| format!("job_recovery.record {}: {error}", known.key))
        };
        let same_boot = known
            .launch
            .as_ref()
            .map_or(known.boot_id == now.boot_id, |launch| {
                launch.boot_id == now.boot_id
            });
        match known.state {
            JobState::Held
                if same_boot
                    && known
                        .reserve
                        .as_ref()
                        .is_none_or(|reserve| now.wall_ms <= reserve.not_after_ms) =>
            {
                Ok(())
            }
            JobState::Accepted | JobState::Staging if same_boot => Ok(()),
            JobState::Held => record(book, withdrawn()),
            JobState::Accepted | JobState::Staging => record(
                book,
                JournalEvent::Ended {
                    end: JobEnd::LaunchRefused {
                        reason: "node_restarted".to_owned(),
                    },
                    end_boot_ns: None,
                },
            ),
            JobState::Launching | JobState::Running | JobState::Ending => {
                self.take_device_again(known)?;
                if same_boot {
                    self.take_memory_again(book, known);
                    return Ok(());
                }
                let end = JobEnd::Lost {
                    reason: "host_reset".to_owned(),
                    last_tick_boot_ns: self.last_tick_boot_ns(known),
                    breadcrumbs: self.lost_breadcrumbs(known),
                };
                record(
                    book,
                    JournalEvent::Ended {
                        end,
                        end_boot_ns: None,
                    },
                )
            }
            JobState::Ended => {
                // Ended, and the release check has not passed: the device
                // stays out until a clean probe, and on the same boot the
                // memory stays taken until then.
                self.take_device_again(known)?;
                if same_boot {
                    self.take_memory_again(book, known);
                }
                Ok(())
            }
        }
    }

    /// The memory floor of a launched key on the boot it launched in, as the
    /// launch commit took it: the placement's host memory, reserved. When the
    /// floor cannot take that now (the job's own bytes are in the machine's
    /// live reading), the request is recorded as allocated instead, so the
    /// floor still never lends it.
    fn take_memory_again(&self, book: &mut NodeBook, known: &NodeKey) {
        let Some(launch) = &known.launch else {
            return;
        };
        if book.floors.contains_key(&known.key) {
            return;
        }
        let bytes = mib_bytes(launch.host_memory_mib);
        let floor = match self.parts().floor.try_lease(bytes) {
            Ok(Some(floor)) => floor,
            Ok(None) | Err(_) => self.parts().floor.track_allocated(bytes),
        };
        book.floors.insert(known.key.clone(), floor);
    }

    /// The key's devices, taken again under its key so no other key can
    /// take them before the gate opens. A key with no device claim takes
    /// none.
    fn take_device_again(&self, known: &NodeKey) -> Result<(), String> {
        let Some(launch) = &known.launch else {
            return Ok(());
        };
        for lease in &launch.devices {
            self.parts()
                .devices
                .reattach(&known.key, &lease.device_id)
                .map_err(|refusal| format!("job_recovery.reattach {}: {refusal}", known.key))?;
        }
        // The slot table keeps quarantines in memory: the journal's comes
        // back with the devices.
        if let DeviceRelease::Unconfirmed { why } = &known.release {
            self.quarantine_device(known, why);
        }
        Ok(())
    }
}

/// Why the journal did not open.
enum HistoryOpening {
    /// The history is lost: admit nothing until `reset-history`.
    Lost(String),
    /// Whether the history exists could not be established now: the next
    /// tick tries again.
    Unknown(String),
}
