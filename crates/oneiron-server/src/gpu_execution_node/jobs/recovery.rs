//! Recovery on the node (design pass 33, 7.7). At start, before the gate
//! opens, the engine reads the journal (a torn last record is cut off) and,
//! for every key that is not final, looks at the last record, the unit and
//! the boot:
//!
//! | Last record | Unit and end record | Boot | Action |
//! |---|---|---|---|
//! | `reserved`, `accepted`, `staged` | - | same | Keep the key; a `Held` key past `not_after` is closed at the tick |
//! | `reserved`, `accepted`, `staged` | - | another | Close it: `Withdrawn`, or `LaunchRefused { node_restarted }`. Nothing ran |
//! | `launching`, `running`, `ending` | the unit is active | same | Take the device and the memory again as launched |
//! | `launching`, `running`, `ending` | `ended.json` exists | same | The end handling |
//! | `launching` | no unit, no end record | same | `Lost { launch_uncertain }`; never started again; the device waits for a clean probe |
//! | `running`, `ending` | no unit, no end record | same | `Lost { end_record_missing }`; the device waits for a clean probe |
//! | `launching`, `running`, `ending` | - | another | `Lost { host_reset }` with the last tick; the device waits for a clean probe |
//! | (no key) | a job unit is active | - | Stop it, and drain the node |
//! | the journal or the epoch is missing or unreadable, and control or payload directories exist | - | - | History lost: stop every job unit; admit nothing until `reset-history` |
//!
//! Then the leases of every launched key are in place, each adopted key's
//! end record is read once more, and only then the gate opens. A part that
//! does not answer (the service manager, the slot table) keeps the gate
//! closed; the next tick runs the reconciliation again. No launch commit
//! runs before the gate opens.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use super::admission::{log_write_error, memory_bytes, withdrawn};
use super::job_unit::{CONTROL_DIR_NAME, JobKeyId};
use super::journal::{JobJournal, JournalEvent, NodeKey};
use super::journal_file::{JournalFile, JournalOpening};
use super::node_parts::{NodeJobParts, NodeJobPaths};
use super::{NodeBook, NodeGate, NodeJobs, NodeJobsShared, ReceiptClock};
use crate::gpu_execution_node::wire::{JobEnd, JobState};

impl NodeJobs {
    /// Opens the node's job service on `paths` and runs the start-up
    /// reconciliation. The gate is open on return unless a part did not
    /// answer (the next [`Self::tick`] tries again) or the history is lost.
    #[must_use]
    pub fn open(paths: NodeJobPaths, parts: NodeJobParts) -> Self {
        let jobs = Self {
            shared: Arc::new(NodeJobsShared {
                paths,
                parts,
                book: Mutex::new(NodeBook {
                    gate: NodeGate::Recovering,
                    journal: None,
                    floors: BTreeMap::new(),
                    staging: BTreeSet::new(),
                }),
            }),
        };
        jobs.recover();
        jobs
    }

    /// Runs the start-up reconciliation, once the gate is closed for it.
    pub(super) fn recover(&self) {
        let now = self.now();
        let restage = {
            let mut guard = self.lock();
            let book: &mut NodeBook = &mut guard;
            if book.gate != NodeGate::Recovering {
                return;
            }
            if book.journal.is_none() {
                match self.open_history() {
                    Ok(journal) => book.journal = Some(journal),
                    Err(why) => {
                        self.lose_history(book, why);
                        return;
                    }
                }
            }
            if let Err(why) = self.sweep(book, &now) {
                tracing::warn!(%why, "job service still recovering; the next tick tries again");
                return;
            }
            book.gate = NodeGate::Open;
            book.journal.as_ref().map_or_else(Vec::new, |journal| {
                journal
                    .table()
                    .iter()
                    .filter(|key| matches!(key.state, JobState::Accepted | JobState::Staging))
                    .map(|key| key.key.clone())
                    .collect::<Vec<_>>()
            })
        };
        for key in restage {
            self.start_staging(key);
        }
    }

    /// Reads the journal, or makes the first one. A missing journal beside
    /// control or payload directories is a lost history, not a fresh node.
    fn open_history(&self) -> Result<JobJournal, String> {
        let state_dir = &self.paths().state_dir;
        match JournalFile::open(state_dir) {
            JournalOpening::Absent => {
                if self.payloads_exist() {
                    return Err(
                        "job_journal.absent: control or payload directories exist".to_owned()
                    );
                }
                JournalFile::create(state_dir)
                    .map(JobJournal::empty)
                    .map_err(|error| format!("job_journal.create: {error}"))
            }
            JournalOpening::Damaged(damage) => Err(damage.to_string()),
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
                JobJournal::replay(file, &records)
            }
        }
    }

    fn payloads_exist(&self) -> bool {
        let control = self.paths().state_dir.join(CONTROL_DIR_NAME);
        let has_key_dir = |dir: &std::path::Path| {
            std::fs::read_dir(dir).is_ok_and(|entries| {
                entries.filter_map(Result::ok).any(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| JobKeyId::parse(name).is_some())
                })
            })
        };
        has_key_dir(&control) || has_key_dir(&self.paths().work_dir)
    }

    /// History lost: every job unit is stopped, and nothing is admitted
    /// until `reset-history` at the box.
    fn lose_history(&self, book: &mut NodeBook, why: String) {
        tracing::error!(%why, "job history lost; stopping every job unit and admitting nothing");
        match self.parts().units.live_units() {
            Ok(units) => {
                for (id, _) in units {
                    if let Err(error) = self.parts().units.stop(&id) {
                        tracing::warn!(unit = %id, %error, "job unit stop not taken");
                    }
                }
            }
            Err(error) => tracing::warn!(%error, "job units not listed after a lost history"),
        }
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
        let keys: Vec<NodeKey> = book
            .journal
            .as_ref()
            .map(|journal| {
                journal
                    .table()
                    .iter()
                    .filter(|key| !key.is_ended() || key.holds_device())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let mut adopted = BTreeSet::new();
        for known in &keys {
            if self.sweep_key(book, known, now)? {
                adopted.insert(known.id.clone());
            }
        }
        for (id, _) in live_units.iter().filter(|(id, _)| !adopted.contains(id)) {
            tracing::error!(unit = %id, "a job unit runs that no key of the journal started; stopping it and draining the node");
            self.parts()
                .units
                .stop(id)
                .map_err(|error| error.to_string())?;
            self.parts()
                .admission
                .drain(&format!("job unit {id} ran outside the journal"));
        }
        if live_units.iter().any(|(id, _)| !adopted.contains(id)) {
            let still = self
                .parts()
                .units
                .live_units()
                .map_err(|error| error.to_string())?;
            if still.iter().any(|(id, _)| !adopted.contains(id)) {
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
                self.read_unit_end(book, &current, now);
            }
        }
        Ok(())
    }

    /// One key of the table. Answers whether the key adopts a unit that may
    /// still run.
    fn sweep_key(
        &self,
        book: &mut NodeBook,
        known: &NodeKey,
        now: &ReceiptClock,
    ) -> Result<bool, String> {
        let record = |book: &mut NodeBook, event: JournalEvent| {
            if let Some(journal) = book.journal.as_mut()
                && let Err(error) =
                    journal.record(&known.key, known.issuer, &now.boot_id, now.wall_ms, event)
            {
                log_write_error(&known.key, &error);
            }
        };
        let same_boot = known
            .launch
            .as_ref()
            .map_or(known.boot_id == now.boot_id, |launch| {
                launch.boot_id == now.boot_id
            });
        match known.state {
            JobState::Held | JobState::Accepted | JobState::Staging if same_boot => Ok(false),
            JobState::Held => {
                record(book, withdrawn());
                Ok(false)
            }
            JobState::Accepted | JobState::Staging => {
                record(
                    book,
                    JournalEvent::Ended {
                        end: JobEnd::LaunchRefused {
                            reason: "node_restarted".to_owned(),
                        },
                        end_boot_ns: None,
                    },
                );
                Ok(false)
            }
            JobState::Launching | JobState::Running | JobState::Ending => {
                self.take_device_again(known)?;
                if same_boot {
                    if let Some(launch) = &known.launch {
                        let bytes = known
                            .reserve
                            .as_ref()
                            .map_or(launch.memory_mib.saturating_mul(1024 * 1024), |reserve| {
                                memory_bytes(&reserve.pin)
                            });
                        let floor = self.parts().floor.track_allocated(bytes);
                        book.floors.insert(known.key.clone(), floor);
                    }
                    return Ok(true);
                }
                let end = JobEnd::Lost {
                    reason: "host_reset".to_owned(),
                    last_tick_boot_ns: self.last_tick_boot_ns(known),
                };
                record(
                    book,
                    JournalEvent::Ended {
                        end,
                        end_boot_ns: None,
                    },
                );
                Ok(false)
            }
            JobState::Ended => {
                // Ended, and the release check has not passed: the device
                // stays out until a clean probe.
                self.take_device_again(known)?;
                Ok(false)
            }
        }
    }

    /// The key's device, taken again under its key so no other key can take
    /// it before the gate opens.
    fn take_device_again(&self, known: &NodeKey) -> Result<(), String> {
        let Some(launch) = &known.launch else {
            return Ok(());
        };
        self.parts()
            .devices
            .reattach(&known.key, &launch.device_id)
            .map_err(|refusal| format!("job_recovery.reattach {}: {refusal}", known.key))
    }
}
