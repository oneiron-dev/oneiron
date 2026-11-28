//! The node's idle readiness check and the DRAIN slot's default rule (pass
//! 34, `34-compute-general/DESIGN.md` sections 1.2, 2.4 and 7.3; row Q4).
//!
//! A node with no attempt running checks itself at the first tick after the
//! service opens, then once per `jobs.readiness.every_secs` (default 900)
//! and at the next idle tick after its offer changes: enable or disable,
//! pause or unpause, the owner offering or withholding a device, or another
//! booker's withheld list changing (row READINESS-NOT-RUN-AT-OFFER).
//! Checks run in this order, and the first that fails names the result:
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
//! drain waits for `resume` at the box. No decider answers the slot before
//! row P1.
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
use crate::gpu_execution_node::node::NodeSnapshot;
use crate::gpu_execution_node::node_settings::DrainClearBy;
use crate::gpu_execution_node::wire::{
    DeviceRelease, JobState, NodeReadiness, ReadinessCheck, ReadinessResult, ReadinessState,
};

/// The node's readiness record, beside the journal in `state_dir`.
pub const READINESS_FILE_NAME: &str = "readiness.json";

/// The DRAIN slot's default rule (pass 34, 1.2): the drain guard's counts,
/// read from settings, and the readiness check.
pub const DRAIN_RULE_DEFAULT: &str = "drain_guard_counts@1";

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

/// This marks what the node offers to work, as one tick reads it. The drain
/// is not part of the offer because the readiness check can change it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OfferMark {
    /// The node's file enables it and no disable at the box stands.
    enabled: bool,
    /// The node is paused at the box or by the owner's policy.
    paused: bool,
    /// These devices are not offered by the owner's policy, when one was read.
    owner_withheld: BTreeSet<String>,
    /// These devices are withheld by another booker, or the list did not read.
    booker_withheld: Result<BTreeSet<String>, String>,
}

impl OfferMark {
    /// Builds the offer from the tick's controls and policy and the booker's list.
    fn of(snapshot: &NodeSnapshot, booker_withheld: Result<BTreeSet<String>, String>) -> Self {
        Self {
            enabled: snapshot.controls.enabled,
            paused: snapshot.controls.paused.is_some(),
            owner_withheld: snapshot
                .policy
                .iter()
                .flat_map(|policy| &policy.devices)
                .filter(|(_, offer)| !offer.offered)
                .map(|(id, _)| id.clone())
                .collect(),
            booker_withheld,
        }
    }
}

struct ReadinessBook {
    record: ReadinessRecord,
    /// This tracks the last checked offer and does not survive a restart.
    checked_offer: Option<OfferMark>,
    /// An offer change seen since the last check, kept until a check settles.
    offer_changed: bool,
}

impl ReadinessBook {
    fn due(&self, now_ms: u64, every_secs: u64, offer: &OfferMark) -> bool {
        self.offer_changed
            || self.checked_offer.as_ref() != Some(offer)
            || self.record.readiness.checked_at_ms.is_none_or(|since| {
                now_ms >= since.saturating_add(every_secs.saturating_mul(1_000))
            })
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
    /// Reads readiness and incidents from `state_dir` and records this boot.
    /// Returns the previous boot ID if it changed. An unreadable record starts
    /// over as never checked. Even a readable record does not carry the last
    /// checked offer, so the first idle tick is due.
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
                checked_offer: None,
                offer_changed: false,
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
    /// runs the check and the DRAIN rule on its result.
    /// A change seen while an attempt runs is kept and checked at the first
    /// idle tick, even if the offer has gone back by then.
    ///
    /// The check never runs beside a job's end or release check. Each reads
    /// the devices through root's machine-wide query lock, which refuses a
    /// second query (`query_stuck`), and a refused release check
    /// quarantines its key. The release check runs only in
    /// [`NodeJobs::tick`]'s end handling, which ends before this step on the
    /// same thread, and the listener runs one tick at a time and awaits it
    /// (`handler::mesh::shutdown::tick`). A key whose device release is still
    /// owed (its unit is still stopping) defers the check, so the check's
    /// device query never holds the machine's query lock when that release
    /// check runs; the wait ends when the unit is gone and the release
    /// passes, or when the release check quarantines the device (a
    /// quarantined key, release `Unconfirmed`, does not defer it), so it is
    /// bounded by the unit's stop.
    pub(super) fn readiness_tick(&self) {
        let _checking = match self.shared.readiness.checking.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => return,
        };
        let parts = self.parts();
        let snapshot = parts.admission.readiness_snapshot();
        self.observe_drain(&snapshot.controls.drained);
        let settings = parts.admission.job_settings();
        let withheld = parts.devices.booker_withheld();
        let offer = OfferMark::of(&snapshot, withheld.clone());
        let now = self.now();
        let mark = {
            let mut book = self.shared.readiness.book();
            if book.checked_offer.as_ref() != Some(&offer) {
                book.offer_changed = true;
            }
            if !book.due(now.wall_ms, settings.readiness_every_secs, &offer) {
                return;
            }
            book.record.mark.clone()
        };
        if self.attempt_runs() || self.release_owed() {
            return;
        }
        let found = match self.check_readiness(mark.as_ref(), &now, &settings, withheld) {
            Ok(()) => ReadinessState::Ready,
            Err((check, why)) => ReadinessState::NotReady { check, why },
        };
        self.settle_check(&found, &now, &settings, offer);
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

    /// Whether any ended key still owes its device release: its launch holds
    /// a device lease and its unit is still stopping, so the readiness check
    /// waits for it. A quarantined key (`Unconfirmed`) owes none.
    fn release_owed(&self) -> bool {
        self.keys().iter().any(|key| {
            key.state == JobState::Ended
                && key
                    .launch
                    .as_ref()
                    .is_some_and(super::journal::KeyLaunch::has_device_lease)
                && matches!(key.release, DeviceRelease::Held)
        })
    }

    /// The six checks, in order; the first that fails, with why.
    fn check_readiness(
        &self,
        mark: Option<&ClockMark>,
        now: &ReceiptClock,
        settings: &NodeJobSettings,
        withheld: Result<BTreeSet<String>, String>,
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
            .probe_with_withheld(withheld)
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
        // List the units first so each listed unit was journaled before its key
        // is read: launch journals Launching before it starts the unit.
        match parts.units.live_units() {
            Ok(units) => {
                let launched: BTreeSet<JobKeyId> = self
                    .keys()
                    .into_iter()
                    .filter(|key| key.launch.is_some())
                    .map(|key| key.id)
                    .collect();
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
    fn settle_check(
        &self,
        found: &ReadinessState,
        now: &ReceiptClock,
        settings: &NodeJobSettings,
        offer: OfferMark,
    ) {
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
            book.checked_offer = Some(offer);
            book.offer_changed = false;
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
                    self.note_drain();
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
    fn observe_drain(&self, drained: &Option<String>) {
        {
            let mut book = self.shared.readiness.book();
            if &book.record.seen_drain == drained {
                return;
            }
            book.record.seen_drain.clone_from(drained);
            self.shared.readiness.persist(&book.record);
        }
        self.record_incident(match drained {
            Some(why) => IncidentKind::Drained {
                why: why.clone(),
                rule: None,
            },
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
