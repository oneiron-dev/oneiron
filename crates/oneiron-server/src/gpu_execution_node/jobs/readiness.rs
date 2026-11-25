//! The node's idle readiness check and the DRAIN slot's default rule (pass
//! 34, `34-compute-general/DESIGN.md` sections 1.2, 2.4 and 7.3; row Q4).
//!
//! A node with no attempt running checks itself every
//! `jobs.readiness.every_secs` (default 900; the first check one period
//! after the service opens). In order, and the first that fails names the
//! result:
//! - `scope`: the launch scope's probe meets the minimum contract;
//! - `devices`: a fresh reading of the devices answers;
//! - `disk`: the payload disk, less what live keys booked, keeps its
//!   reserve, and the state directory its floor;
//! - `mirrors`: each template's mirror is a readable directory;
//! - `clock`: since the last check the wall clock kept step with the boot
//!   clock, within `jobs.submit.skew_secs`;
//! - `units`: no job unit runs that no key launched.
//!
//! The DRAIN slot's default rule, [`DRAIN_RULE_DEFAULT`], acts on the
//! result ([`drain_rule_default`]). A failed check drains the machine
//! through its one drain, so every reserve answers `Drained { why }` and
//! `Node` shows it. A passed check clears the drain, whatever set it, when
//! `machines.drain.clear_by` is `after_readiness_check` (the default, CG-2
//! row 9): the machine recovers without a person. With `person_at_box` the
//! drain waits for `resume` at the box. With `owner` or `grants` it waits
//! for the clear from the owner's panel, `machines.drain.cleared_at`
//! ([`OWNER_CLEAR_RULE`]): each tick clears a drain that began before that
//! clear's time, unless the last check failed. No decider answers the slot
//! before row P1.
//!
//! The result, the streak of failed checks and the clocks of the last check
//! are kept in `readiness.json` beside the journal, so a restart keeps the
//! streak, and `Node` reports them ([`NodeReadiness`]). The issuer escalates
//! on them (16, practice 6); the node raises no question itself.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError, TryLockError};

use oneiron_contracts::register::Register as _;
use serde::{Deserialize, Serialize};

use super::incidents::{IncidentKind, IncidentLog, NodeIncident};
use super::job_unit::{JobKeyId, scope_missing, write_file_synced};
use super::node_parts::NodeJobSettings;
use super::{NodeJobs, ReceiptClock};
use crate::gpu_execution_node::node_settings::DrainClearBy;
use crate::gpu_execution_node::wire::{
    JobState, NodeReadiness, ReadinessCheck, ReadinessResult, ReadinessState,
};

/// The node's readiness record, beside the journal in `state_dir`.
pub const READINESS_FILE_NAME: &str = "readiness.json";

/// The DRAIN slot's default rule (pass 34, 1.2): the drain guard's counts,
/// read from settings, and the readiness check.
pub const DRAIN_RULE_DEFAULT: &str = "drain_guard_counts@1";

/// The rule a clear from the owner's panel names in its incident (pass 34,
/// 2.4): `machines.drain.cleared_at`, newer than the drain.
pub const OWNER_CLEAR_RULE: &str = "owner_clear@1";

/// The DRAIN slot's options after a readiness check (pass 34, 1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrainPick {
    /// Change nothing.
    Serve,
    /// Drain the machine, with why.
    Drain { why: String },
    /// Clear the machine's drain.
    Clear,
}

/// The DRAIN slot's default rule, [`DRAIN_RULE_DEFAULT`], on one readiness
/// check's result: a failed check drains a machine that is not drained
/// (a drain that stands keeps its own why); a passed check clears a drain
/// when `clear_by` leaves the clear to the check; anything else serves on.
#[must_use]
pub fn drain_rule_default(
    drained: Option<&str>,
    found: &ReadinessState,
    clear_by: DrainClearBy,
) -> DrainPick {
    match (found, drained) {
        (ReadinessState::NotReady { check, why }, None) => DrainPick::Drain {
            why: readiness_drain_why(*check, why),
        },
        (ReadinessState::Ready, Some(_)) if clear_by == DrainClearBy::AfterReadinessCheck => {
            DrainPick::Clear
        }
        _ => DrainPick::Serve,
    }
}

/// A drain's why after a failed check, on one line: the drain file keeps
/// only its first.
fn readiness_drain_why(check: ReadinessCheck, why: &str) -> String {
    let why = why.split_whitespace().collect::<Vec<_>>().join(" ");
    format!("readiness {}: {why}", check.name())
}

/// The clocks at one check: the next check measures the wall clock's step
/// against them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ClockMark {
    boot_id: String,
    boot_ns: u64,
    wall_ms: u64,
}

impl ClockMark {
    fn of(now: &ReceiptClock) -> Self {
        Self {
            boot_id: now.boot_id.clone(),
            boot_ns: now.boot_ns,
            wall_ms: now.wall_ms,
        }
    }
}

/// What `readiness.json` holds.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct ReadinessRecord {
    #[serde(default)]
    readiness: NodeReadiness,
    /// The clocks at the last check.
    #[serde(default)]
    mark: Option<ClockMark>,
    /// The boot the node last opened in: another at the next open is a
    /// host reset.
    #[serde(default)]
    boot_id: Option<String>,
    /// The drain the node last saw, so each drain and each clear is one
    /// incident, also across a restart.
    #[serde(default)]
    seen_drain: Option<String>,
}

struct ReadinessBook {
    record: ReadinessRecord,
    /// When this service opened, on the wall clock: the first check is due
    /// one period later.
    opened_at_ms: u64,
}

impl ReadinessBook {
    fn due(&self, now_ms: u64, every_secs: u64) -> bool {
        let since = self
            .record
            .readiness
            .checked_at_ms
            .unwrap_or(self.opened_at_ms);
        now_ms >= since.saturating_add(every_secs.saturating_mul(1_000))
    }
}

/// The readiness record and the incidents, each under a lock of its own,
/// never the admission lock: a device probe may take its full query time.
/// Lock order: `checking`, then `book`, then the admission lock; the
/// incident log is a leaf, taken last and alone.
pub(super) struct NodeReadinessShared {
    path: PathBuf,
    book: Mutex<ReadinessBook>,
    /// Held while one check runs: a second tick skips its check.
    checking: Mutex<()>,
    incidents: Mutex<IncidentLog>,
}

impl std::fmt::Debug for NodeReadinessShared {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NodeReadinessShared")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl NodeReadinessShared {
    /// Reads the node's readiness record and its incidents from
    /// `state_dir`, and notes the boot it opens in. Answers the boot it last
    /// opened in when that was another: a host reset. A record that does not
    /// read starts over as never checked.
    pub(super) fn open(state_dir: &Path, now: &ReceiptClock) -> (Self, Option<String>) {
        let path = state_dir.join(READINESS_FILE_NAME);
        let mut record: ReadinessRecord = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        let previous = record
            .boot_id
            .replace(now.boot_id.clone())
            .filter(|previous| *previous != now.boot_id);
        let shared = Self {
            path,
            book: Mutex::new(ReadinessBook {
                record,
                opened_at_ms: now.wall_ms,
            }),
            checking: Mutex::new(()),
            incidents: Mutex::new(IncidentLog::open(state_dir)),
        };
        shared.persist(&shared.book().record);
        (shared, previous)
    }

    fn book(&self) -> MutexGuard<'_, ReadinessBook> {
        self.book.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn incidents(&self) -> MutexGuard<'_, IncidentLog> {
        self.incidents
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Keeps `record` in `readiness.json`, synced. A write that fails is
    /// logged; the record in memory still counts.
    fn persist(&self, record: &ReadinessRecord) {
        let written = serde_json::to_vec(record)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
            .and_then(|bytes| write_file_synced(&self.path, &bytes));
        if let Err(error) = written {
            tracing::warn!(%error, "execution node readiness record not written");
        }
    }
}

impl NodeJobs {
    /// What the node's last readiness check found, with the streak of
    /// failed checks (`Node`'s `readiness`).
    #[must_use]
    pub fn readiness(&self) -> NodeReadiness {
        self.shared.readiness.book().record.readiness.clone()
    }

    /// The node's kept incidents after `after` (all with `None`), oldest
    /// first, at most `limit`.
    #[must_use]
    pub fn incidents(&self, after: Option<u64>, limit: usize) -> Vec<NodeIncident> {
        self.shared.readiness.incidents().page(after, limit)
    }

    /// Records one incident now.
    pub(super) fn record_incident(&self, kind: IncidentKind) {
        let now = self.now();
        let keep = self.parts().admission.job_settings().incidents_keep;
        self.shared
            .readiness
            .incidents()
            .record(&now.boot_id, now.wall_ms, kind, keep);
    }

    /// The readiness step of the tick: records a drain or a clear that
    /// another path made, then, while no attempt runs and a check is due,
    /// runs the check and the DRAIN rule on its result, then applies a clear
    /// from the owner's panel.
    pub(super) fn readiness_tick(&self) {
        let _checking = match self.shared.readiness.checking.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => return,
        };
        self.observe_drain();
        let settings = self.check_when_due(self.parts().admission.job_settings());
        self.owner_clear(&settings);
    }

    /// The check, while no attempt runs and one is due, and the DRAIN rule
    /// on its result. Answers the settings the rest of the tick reads: read
    /// again after a check ran, since the check can take a while and a box
    /// that took the clear back meanwhile keeps its drain.
    fn check_when_due(&self, settings: NodeJobSettings) -> NodeJobSettings {
        let now = self.now();
        let mark = {
            let book = self.shared.readiness.book();
            if !book.due(now.wall_ms, settings.readiness_every_secs) {
                return settings;
            }
            book.record.mark.clone()
        };
        if self.attempt_runs() {
            return settings;
        }
        let found = match self.check_readiness(mark.as_ref(), &now, &settings) {
            Ok(()) => ReadinessState::Ready,
            Err((check, why)) => ReadinessState::NotReady { check, why },
        };
        let settings = self.parts().admission.job_settings();
        self.settle_check(&found, &now, &settings);
        settings
    }

    /// A clear from the owner's panel (pass 34, 2.4; [`OWNER_CLEAR_RULE`]):
    /// clears a drain that began before `settings.drain_cleared_at_ms`,
    /// unless the last check failed, which keeps the drain until a check
    /// passes. The slot table compares the drain's start and removes it in
    /// one step, so a drain set after the clear stands, whatever its reason.
    /// The node has that time only where the owner's `clear_by`, the box's
    /// file and the row's writer all give the clear to the panel. A time
    /// later than the node's clock waits until the clock reaches it: until
    /// then it would clear each drain as it began, and a mistyped year
    /// would do so for a year.
    fn owner_clear(&self, settings: &NodeJobSettings) {
        let Some(cleared_at_ms) = settings.drain_cleared_at_ms else {
            return;
        };
        if cleared_at_ms > self.now().wall_ms {
            return;
        }
        let failed = matches!(
            self.shared.readiness.book().record.readiness.state,
            ReadinessState::NotReady { .. }
        );
        if failed {
            return;
        }
        match self.parts().devices.clear_drain_begun_before(cleared_at_ms) {
            Ok(false) => {}
            Ok(true) => {
                tracing::info!("the owner cleared the machine's drain from the panel");
                self.note_drain_cleared();
                self.record_incident(IncidentKind::DrainCleared {
                    rule: Some(OWNER_CLEAR_RULE.to_owned()),
                });
            }
            Err(why) => {
                tracing::warn!(
                    %why,
                    "the owner's clear of the drain did not apply; the next tick tries again"
                );
            }
        }
    }

    /// Whether any key is launching, running or ending.
    fn attempt_runs(&self) -> bool {
        self.keys().iter().any(|key| {
            matches!(
                key.state,
                JobState::Launching | JobState::Running | JobState::Ending
            )
        })
    }

    /// The six checks, in order; the first that fails, with why.
    fn check_readiness(
        &self,
        mark: Option<&ClockMark>,
        now: &ReceiptClock,
        settings: &NodeJobSettings,
    ) -> Result<(), (ReadinessCheck, String)> {
        let parts = self.parts();
        let missing = scope_missing(&parts.units.probe(), &[]);
        if !missing.is_empty() {
            return Err((
                ReadinessCheck::Scope,
                format!("the launch scope lacks {}", missing.join(", ")),
            ));
        }
        parts
            .devices
            .probe()
            .map_err(|why| (ReadinessCheck::Devices, why))?;
        parts
            .admission
            .disk_room(self.booked_disk_mib(), 0)
            .map_err(|why| (ReadinessCheck::Disk, why))?;
        for (template, mirror) in parts.admission.template_mirrors() {
            if let Err(error) = std::fs::read_dir(&mirror) {
                return Err((
                    ReadinessCheck::Mirrors,
                    format!(
                        "template {template}: mirror {} unreadable: {error}",
                        mirror.display()
                    ),
                ));
            }
        }
        if let Some(mark) = mark.filter(|mark| mark.boot_id == now.boot_id) {
            let wall_ms = i128::from(now.wall_ms) - i128::from(mark.wall_ms);
            let boot_ms = (i128::from(now.boot_ns) - i128::from(mark.boot_ns)) / 1_000_000;
            let step_ms = (wall_ms - boot_ms).unsigned_abs();
            let limit_ms = u128::from(settings.submit_skew_secs) * 1_000;
            if step_ms > limit_ms {
                return Err((
                    ReadinessCheck::Clock,
                    format!(
                        "the wall clock stepped {step_ms} ms against the boot clock since the last check (at most {limit_ms})"
                    ),
                ));
            }
        }
        let launched: BTreeSet<JobKeyId> = self
            .keys()
            .into_iter()
            .filter(|key| key.launch.is_some())
            .map(|key| key.id)
            .collect();
        match parts.units.live_units() {
            Ok(units) => {
                if let Some((id, _)) = units.iter().find(|(id, _)| !launched.contains(id)) {
                    return Err((
                        ReadinessCheck::Units,
                        format!("job unit {id} runs outside the journal"),
                    ));
                }
            }
            Err(error) => {
                return Err((
                    ReadinessCheck::Units,
                    format!("job units not listed: {error}"),
                ));
            }
        }
        Ok(())
    }

    /// Keeps one check's result with its streak, records the incident a
    /// change makes, and acts on the DRAIN rule's pick.
    fn settle_check(&self, found: &ReadinessState, now: &ReceiptClock, settings: &NodeJobSettings) {
        let incident = {
            let mut book = self.shared.readiness.book();
            let before = book.record.readiness.clone();
            let readiness = &mut book.record.readiness;
            readiness.checked_at_ms = Some(now.wall_ms);
            if matches!(found, ReadinessState::Ready) {
                readiness.failed_in_a_row = 0;
                readiness.failing_since_ms = None;
            } else {
                readiness.failed_in_a_row = readiness.failed_in_a_row.saturating_add(1);
                readiness.failing_since_ms.get_or_insert(now.wall_ms);
            }
            readiness.state = found.clone();
            readiness.results.push(ReadinessResult {
                at_ms: now.wall_ms,
                state: found.clone(),
            });
            let kept = usize::try_from(settings.readiness_results_kept).unwrap_or(usize::MAX);
            let first = readiness.results.len().saturating_sub(kept);
            readiness.results.drain(..first);
            book.record.mark = Some(ClockMark::of(now));
            self.shared.readiness.persist(&book.record);
            check_incident(&before, &book.record.readiness)
        };
        if let Some(kind) = incident {
            self.record_incident(kind);
        }
        let drained = self.parts().admission.controls().drained;
        match drain_rule_default(drained.as_deref(), found, settings.drain_clear_by) {
            DrainPick::Serve => {}
            DrainPick::Drain { why } => {
                tracing::warn!(%why, "readiness check failed; the machine takes no new work until a check passes");
                self.parts().devices.drain(&why);
                self.note_drain();
                self.record_incident(IncidentKind::Drained {
                    why,
                    rule: Some(DRAIN_RULE_DEFAULT.to_owned()),
                });
            }
            DrainPick::Clear => match self.parts().devices.clear_drain() {
                Ok(()) => {
                    tracing::info!("readiness check passed; the machine's drain is cleared");
                    self.note_drain_cleared();
                    self.record_incident(IncidentKind::DrainCleared {
                        rule: Some(DRAIN_RULE_DEFAULT.to_owned()),
                    });
                }
                Err(why) => {
                    tracing::warn!(%why, "readiness check passed and the drain still stands; the next check tries again");
                }
            },
        }
    }

    /// Records a drain or a clear that the node did not make itself: the
    /// count of failed jobs, recovery's drain for a job unit outside the
    /// journal, or `resume` at the box.
    fn observe_drain(&self) {
        let drained = self.parts().admission.controls().drained;
        {
            let mut book = self.shared.readiness.book();
            if book.record.seen_drain == drained {
                return;
            }
            book.record.seen_drain.clone_from(&drained);
            self.shared.readiness.persist(&book.record);
        }
        self.record_incident(match drained {
            Some(why) => IncidentKind::Drained { why, rule: None },
            None => IncidentKind::DrainCleared { rule: None },
        });
    }

    /// Notes the drain as it stands now as seen, after the DRAIN rule
    /// changed it, so [`Self::observe_drain`] does not record it again.
    fn note_drain(&self) {
        let drained = self.parts().admission.controls().drained;
        let mut book = self.shared.readiness.book();
        book.record.seen_drain = drained;
        self.shared.readiness.persist(&book.record);
    }

    /// Notes no drain as seen, after a clear removed the drain: a drain set
    /// again between the removal and this note is then still recorded by
    /// [`Self::observe_drain`].
    fn note_drain_cleared(&self) {
        let mut book = self.shared.readiness.book();
        book.record.seen_drain = None;
        self.shared.readiness.persist(&book.record);
    }
}

/// The incident a check's result makes against the one before: a failure
/// after a pass, or of another check or why; a pass after failures. A
/// repeat of the same failure, and a pass after a pass, make none.
fn check_incident(before: &NodeReadiness, after: &NodeReadiness) -> Option<IncidentKind> {
    match (&before.state, &after.state) {
        (ReadinessState::NotReady { .. }, ReadinessState::Ready) => {
            Some(IncidentKind::ReadinessPassed {
                after_failures: before.failed_in_a_row,
            })
        }
        (previous, ReadinessState::NotReady { check, why }) if previous != &after.state => {
            Some(IncidentKind::ReadinessFailed {
                check: *check,
                why: why.clone(),
                failed_in_a_row: after.failed_in_a_row,
            })
        }
        _ => None,
    }
}
