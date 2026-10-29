//! The managed backup duty (Engine 10-20 backup shipper row (a)): a managed
//! vault's host backs it up hourly when it changed, once before an idle reap,
//! and prunes what its node's supervisor acked, beside the owner's own
//! schedule, which it leaves as it is.
//!
//! Hourly-if-changed runs in the resident scheduling pass, under the backup
//! lock, on a tick where the owner's schedule takes nothing: a backup when
//! the vault's backup watermark differs from what its last accepted backup
//! covered, or does not read, or none was accepted, and no backup of any
//! cause was recorded in the last [`MANAGED_BACKUP_EVERY`]. A backup that
//! landed and was not recorded counts for that hour too (FIX 6731): one whose
//! marker this run's pass did not write, or a failed attempt's guard, by when
//! it went down. So a marker write that keeps failing is retried hourly,
//! never each tick, while a backup that did not land is retried on the next
//! tick. Otherwise the pass prunes alone ([`backup::prune`]), so a backup the
//! supervisor acked past `keep` goes on the next tick; legal holds and the
//! stage-ack pin are checked inside it, and nothing unacked goes to make
//! room. The pass runs only in a resident, admitted vault: it never wakes
//! one, and a tick it misses is skipped.
//!
//! Each pass says what it decided at INFO (FIX 6769): a backup it takes
//! every time, and why, then that it failed and by which closed reason; a
//! decision that takes none (no duty, unchanged, recent, unrecorded recent)
//! once, until the pass decides otherwise, so a resident vault does not
//! repeat it each tick.
//!
//! The backup before an idle reap ([`OwnerHost::back_up_before_idle`]) is the
//! managed reap preparation's: it reuses the last accepted backup when that
//! covers the vault as it stands, and otherwise takes one, the hour
//! notwithstanding, recorded as covered only while its attempt stands.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use oneiron::recovery::checkpoint::BackupWatermark;
use oneiron_vault_contract::IdleBackupFailure;

use super::{OwnerHost, PassStage};
use crate::owner::backup::finalize::{self, Unproduced};
use crate::owner::backup::{self, BackupOutcome, BackupPlan, write_budget};
use crate::owner::stamp::now_unix_ms;

/// How often a managed vault takes a backup when it changed.
pub(crate) const MANAGED_BACKUP_EVERY: Duration = Duration::from_secs(3_600);

/// One backup job in flight on a host, the resident pass or a backup
/// before an idle reap, counted until dropped.
pub(crate) struct BackupJob<'a>(&'a AtomicU64);

impl Drop for BackupJob<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// What a backup before an idle reap asks of the attempt it runs for.
pub(crate) trait PreIdleAttempt {
    /// The attempt's id, as its failed-attempt guard records it.
    fn id(&self) -> &str;
    /// Whether the attempt still stands now that the backup lock is held:
    /// from here on the backup writes.
    fn locked(&self) -> bool;
    /// Whether it still stands to be recorded, before its guard and its
    /// marker go down.
    fn standing(&self) -> bool;
    /// Settles it on `done`: `false` when its deadline passed or it was
    /// dropped first, and the backup is not recorded as covering anything.
    fn settle(&self, done: &PreIdleBackup) -> bool;
}

/// A backup before an idle reap that covers the vault as it stands.
pub(crate) struct PreIdleBackup {
    /// The last accepted backup, not a new one.
    pub(crate) reused: bool,
    /// The artifact's commitment digest, as lowercase hex.
    pub(crate) artifact: String,
    pub(crate) covered: BackupWatermark,
}

impl OwnerHost {
    /// This host with the managed backup duty: a managed vault's.
    pub(crate) fn managed_hourly(mut self) -> Self {
        self.managed_every = Some(MANAGED_BACKUP_EVERY);
        self
    }

    /// A backup job in flight on this host, counted until it drops.
    pub(crate) fn backup_job(&self) -> BackupJob<'_> {
        self.backup_jobs.fetch_add(1, Ordering::SeqCst);
        BackupJob(&self.backup_jobs)
    }

    /// How many backup jobs are in flight on this host.
    pub(crate) fn backup_jobs(&self) -> u64 {
        self.backup_jobs.load(Ordering::SeqCst)
    }

    /// The managed duty's part of the resident pass, the backup lock held
    /// and `plan` the one in force: an hourly backup when it is due, else a
    /// prune alone. Nothing on a host without the duty. A backup recorded
    /// is taken whatever its custody publication or pruning do after.
    pub(super) fn managed_pass(
        &self,
        vault: &oneiron::Vault,
        plan: &BackupPlan,
    ) -> anyhow::Result<Option<BackupOutcome>> {
        let Some(every) = self.managed_every else {
            self.say(Decision::NoDuty);
            return Ok(None);
        };
        self.enter(PassStage::Deciding);
        let unrecorded = self.managed_unrecorded_ms.load(Ordering::SeqCst);
        let decision = hourly(vault, plan, every, (unrecorded != 0).then_some(unrecorded));
        self.say(decision);
        if !decision.due() {
            self.enter(PassStage::Pruning);
            let pruned = backup::prune(vault, plan, None)?;
            if !pruned.is_empty() {
                tracing::info!(
                    pruned = pruned.len(),
                    "backups past keep the node's supervisor acked are pruned"
                );
            }
            return Ok(None);
        }
        self.enter(PassStage::Producing);
        let produced = finalize::produce(vault, plan, None).map_err(|unproduced| {
            let (error, landing) = match unproduced {
                Unproduced::Snapshot(error) => (error, false),
                Unproduced::Landing(error) => (error, true),
            };
            tracing::info!(
                decision = "failed",
                reason = reason(&error, landing).as_str(),
                "managed backup not produced; the next tick decides again"
            );
            error
        })?;
        self.enter(PassStage::Recording);
        if let Err(error) = produced.accept(plan) {
            // It landed, so the next one waits the hour as after a recorded
            // backup (FIX 6731).
            self.managed_unrecorded_ms
                .store(now_unix_ms(), Ordering::SeqCst);
            tracing::warn!(
                reason = "backup_watermark_marker_failed",
                error = %error,
                "the managed backup landed; what it covered was not recorded, so the next check \
                 reads changed and takes one once the hour is up"
            );
        }
        Ok(Some(produced.maintain(vault, plan)))
    }

    /// One backup before an idle reap, for `attempt`: under the backup lock,
    /// after any backup that holds it. The last accepted backup is reused
    /// when it covers the vault as it stands and its file is still that
    /// backup; otherwise one is taken, the hour notwithstanding. A new one
    /// is recorded as covered only while the attempt stands: its guard goes
    /// down first, its marker after, and the guard lifts once the attempt
    /// settled taken. Nothing is pruned and no custody published: the vault
    /// is frozen, and the next resident pass does both. `Ok` once there is
    /// nothing more for the attempt to record; a failure by its closed
    /// reason.
    pub(crate) fn back_up_before_idle(
        &self,
        vault: &oneiron::Vault,
        attempt: &dyn PreIdleAttempt,
    ) -> Result<(), IdleBackupFailure> {
        let _one_at_a_time = self.one_at_a_time();
        if !attempt.locked() {
            return Ok(());
        }
        let (plan, _) = self.effective_plan(vault).map_err(|error| {
            failure(
                &anyhow::Error::new(error).context("backup policy did not read"),
                false,
            )
        })?;
        if let Some(last) = finalize::accepted_marker(&plan)
            && vault
                .backup_watermark()
                .is_ok_and(|now| now == last.covered())
            && last.held(&plan.dir)
        {
            attempt.settle(&PreIdleBackup {
                reused: true,
                artifact: last.commitment_digest().to_owned(),
                covered: last.covered(),
            });
            return Ok(());
        }
        let produced =
            finalize::produce(vault, &plan, None).map_err(|unproduced| match unproduced {
                Unproduced::Snapshot(error) => failure(&error, false),
                Unproduced::Landing(error) => failure(&error, true),
            })?;
        if !attempt.standing() {
            return Ok(());
        }
        finalize::guard_attempt(&plan, attempt.id())
            .map_err(|error| failure(&anyhow::Error::from(error), true))?;
        if !attempt.standing() {
            return Ok(());
        }
        produced
            .mark(&plan)
            .map_err(|error| failure(&anyhow::Error::new(error), true))?;
        let taken = PreIdleBackup {
            reused: false,
            artifact: oneiron_vault_contract::hex(&produced.receipt.evidence.commitment_digest),
            covered: produced.receipt.covered,
        };
        if attempt.settle(&taken) {
            finalize::lift_guard(&plan);
        }
        Ok(())
    }
}

/// What one managed pass decided, as its INFO line names it.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Decision {
    /// The host carries no managed duty.
    NoDuty = 1,
    /// No accepted backup: none was taken, its marker or file is gone, or a
    /// failed attempt's guard stands.
    NoAcceptedBackup,
    /// The vault changed since its last accepted backup, an hour or more ago.
    Changed,
    /// The vault is as its last accepted backup covered.
    Unchanged,
    /// The vault changed, and its last accepted backup is under the hour.
    Recent,
    /// The vault changed or has no accepted backup, and a backup landed
    /// under the hour that was not recorded (FIX 6731).
    UnrecordedRecent,
}

impl Decision {
    fn due(self) -> bool {
        matches!(self, Self::NoAcceptedBackup | Self::Changed)
    }
}

impl OwnerHost {
    /// Says `decision` at INFO: one that takes a backup every time, one that
    /// takes none only when it is not the last one said, so a standing
    /// decision is said once per resident run.
    fn say(&self, decision: Decision) {
        let said = if decision.due() { 0 } else { decision as u8 };
        if self.managed_said.swap(said, Ordering::SeqCst) == said && said != 0 {
            return;
        }
        match decision {
            Decision::NoDuty => tracing::info!(
                decision = "no_duty",
                "managed backup: this host carries no managed duty; the owner's schedule alone \
                 decides"
            ),
            Decision::NoAcceptedBackup => tracing::info!(
                decision = "no_accepted_backup",
                "managed backup due: none accepted yet; taking one"
            ),
            Decision::Changed => tracing::info!(
                decision = "changed",
                "managed backup due: the vault changed since its last accepted backup, an hour or \
                 more ago; taking one"
            ),
            Decision::Unchanged => tracing::info!(
                decision = "unchanged",
                "managed backup not due: the vault is as its last accepted backup covered; \
                 pruning only"
            ),
            Decision::Recent => tracing::info!(
                decision = "recent",
                "managed backup not due: the last accepted backup is under the hour; pruning only"
            ),
            Decision::UnrecordedRecent => tracing::info!(
                decision = "unrecorded_recent",
                "managed backup not due: a backup landed under the hour and was not recorded; \
                 pruning only"
            ),
        }
    }
}

/// What the managed duty decides now: a backup when the vault changed since
/// its last accepted backup, or none was accepted, and none was recorded in
/// the last `every`, nor landed unrecorded (FIX 6731): `unrecorded`, the last
/// this run's pass could not record, or a failed attempt's guard, whichever
/// went down later.
fn hourly(
    vault: &oneiron::Vault,
    plan: &BackupPlan,
    every: Duration,
    unrecorded: Option<u64>,
) -> Decision {
    let every_ms = u64::try_from(every.as_millis()).unwrap_or(u64::MAX);
    let within = |landed_ms: u64| now_unix_ms().saturating_sub(landed_ms) < every_ms;
    // The marker counts only for a backup this install signed, so one another
    // signer signed reads as due; a signer that does not read leaves the read
    // unpinned (FIX 10712).
    let signer = vault.checkpoint_signer().ok();
    let last = finalize::accepted_marker_with_pins(plan, signer.as_ref().map(std::slice::from_ref));
    // FIX 6802: None while a failed-attempt guard stands paces on the
    // guard's mtime below, as a recent guard does; a stuck guard's failed
    // lift refreshes it, so it never yields a backup every tick.
    let guard_ms = finalize::attempt_guard_ms(plan);
    if let Some(last) = &last {
        if vault
            .backup_watermark()
            .is_ok_and(|now| now == last.covered())
        {
            return Decision::Unchanged;
        }
        if within(last.landed_ms()) {
            return Decision::Recent;
        }
    }
    if unrecorded
        .max(guard_ms)
        .is_some_and(within)
    {
        Decision::UnrecordedRecent
    } else if last.is_some() {
        Decision::Changed
    } else {
        Decision::NoAcceptedBackup
    }
}

/// The closed reason `error` fails a backup before an idle reap with, and
/// its log line: [`reason`].
fn failure(error: &anyhow::Error, landing: bool) -> IdleBackupFailure {
    let failure = reason(error, landing);
    tracing::warn!(
        reason = failure.as_str(),
        kind = ?crate::logging::engine_kind(error),
        "the backup before an idle reap failed; the vault reads as changed"
    );
    failure
}

/// The closed reason a backup `error` fails with: the disk's floor or a full
/// disk by type, a keystore or signer that did not read, else the snapshot's
/// failure, or, `landing`, a backup written that did not land or was not
/// recorded.
fn reason(error: &anyhow::Error, landing: bool) -> IdleBackupFailure {
    let secret = || {
        error.chain().any(|cause| {
            matches!(
                cause.downcast_ref::<oneiron::Error>(),
                Some(oneiron::Error::Secret(_))
            )
        })
    };
    match write_budget::Capacity::of_host(error) {
        Some(write_budget::Capacity::Floor) => IdleBackupFailure::DiskFloor,
        Some(write_budget::Capacity::DiskFull) => IdleBackupFailure::DiskFull,
        None if landing => IdleBackupFailure::PublishFailed,
        None if secret() => IdleBackupFailure::SignerUnavailable,
        None => IdleBackupFailure::SnapshotFailed,
    }
}
