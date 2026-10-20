//! A backup's making and its acceptance, apart (Engine 10-20 backup shipper
//! row (a), agreed with L04). [`produce`] writes the artifact and lands it
//! under its name; recording what it covered beside it is a step of its own
//! ([`Produced::mark`]), so a caller decides whether this backup may be
//! recorded at all. One an idle reap's deadline overtook never is: a failed
//! pre-reap backup leaves the vault reading as changed.
//!
//! The failed-attempt guard, `.<label>.backup-attempt`, is that rule's
//! durable half. A pre-idle backup puts it down before its marker and lifts
//! it only once its attempt settled taken. While it stands the label has no
//! accepted backup ([`accepted_marker`]) and the vault reads as changed,
//! across a restart too, even when a late marker landed. The next backup
//! recorded lifts it ([`Produced::accept`]).
//!
//! What follows a recorded backup, custody publication and pruning, is
//! maintenance: its failure never unmakes the backup.

use std::path::PathBuf;

use oneiron::recovery::checkpoint::{BackupMarker, BackupSnapshotReceipt, backup_marker};
use oneiron_vault_contract::backup_handoff::write_private_file;

use super::{
    BackupOutcome, BackupPlan, BackupRecord, FILE_SUFFIX, PARTIAL_SUFFIX, SEQUENCE_WIDTH,
    create_private_dir, list, sync_dir, write_budget,
};
use crate::owner::stamp::{file_stamp, now_unix_ms, rfc3339};

/// The suffix of a label's failed-attempt guard: `.<label>.backup-attempt`.
const ATTEMPT_GUARD_SUFFIX: &str = ".backup-attempt";

fn guard_name(label: &str) -> String {
    format!(".{label}{ATTEMPT_GUARD_SUFFIX}")
}

/// One backup written and landed under its name, not yet recorded as
/// covering anything.
pub(crate) struct Produced {
    pub(crate) file: String,
    pub(crate) path: PathBuf,
    sequence: u64,
    taken_ms: u64,
    pub(crate) receipt: BackupSnapshotReceipt,
}

/// Why [`produce`] made no backup.
pub(crate) enum Unproduced {
    /// Nothing landed: the snapshot or a step before it failed, its partial
    /// file removed.
    Snapshot(anyhow::Error),
    /// The artifact was written and did not land: its rename or the
    /// directory's sync failed.
    Landing(anyhow::Error),
}

impl Unproduced {
    /// The error as [`super::take_as`] answers it.
    pub(crate) fn into_error(self) -> anyhow::Error {
        match self {
            Self::Snapshot(error) | Self::Landing(error) => error,
        }
    }
}

/// Writes one backup of `vault` under a hidden partial name and renames it
/// into place, the next sequence number in `plan`'s directory. The caller
/// serializes backups of one vault, so that number is this one's alone. The
/// artifact claims its room on the floor the plan was lent, and on the disk
/// of the directory it lands in when that is another, and gives it back once
/// written or refused (FIX 5479, FIX 5675). On an owner's request the
/// snapshot rechecks `owner` in its own read transaction.
pub(crate) fn produce(
    vault: &oneiron::Vault,
    plan: &BackupPlan,
    owner: Option<&oneiron::consent::AuthenticatedOwner>,
) -> Result<Produced, Unproduced> {
    create_private_dir(&plan.dir).map_err(Unproduced::Snapshot)?;
    let sequence = list(plan)
        .map_err(Unproduced::Snapshot)?
        .last()
        .map_or(Some(1), |newest| newest.sequence.checked_add(1))
        .ok_or_else(|| {
            Unproduced::Snapshot(anyhow::anyhow!(
                "backup sequence exhausted in {}",
                plan.dir.display()
            ))
        })?;
    let taken_ms = now_unix_ms();
    let stamp = file_stamp(taken_ms);
    let partial = plan
        .dir
        .join(format!(".{}-{stamp}{PARTIAL_SUFFIX}", plan.label));
    let floors = write_budget::landing_floors(plan.floor.as_ref(), &plan.dir);
    let snapshot = vault.ensure_vault_key().and_then(|()| {
        let room = write_budget::WriteClaim::on_each(&floors);
        vault.snapshot_backup_within(
            &partial,
            vault.now_recorded_at(),
            owner,
            plan.registry.as_deref(),
            &room,
        )
    });
    let receipt = match snapshot {
        Ok(receipt) => receipt,
        Err(error) => {
            let _ = std::fs::remove_file(&partial);
            return Err(Unproduced::Snapshot(
                anyhow::Error::new(error).context("backup failed"),
            ));
        }
    };
    let checkpoint_id = &receipt.image_digest;
    let id8 = checkpoint_id.get(..8).unwrap_or(checkpoint_id);
    let file = format!(
        "{}-{sequence:0SEQUENCE_WIDTH$}-{stamp}-{id8}{FILE_SUFFIX}",
        plan.label
    );
    let path = plan.dir.join(&file);
    std::fs::rename(&partial, &path).map_err(|error| Unproduced::Landing(error.into()))?;
    sync_dir(&plan.dir).map_err(Unproduced::Landing)?;
    Ok(Produced {
        file,
        path,
        sequence,
        taken_ms,
        receipt,
    })
}

impl Produced {
    /// Records what this backup covered beside it, the label's marker:
    /// only for a backup that may be recorded.
    pub(crate) fn mark(&self, plan: &BackupPlan) -> oneiron::Result<()> {
        self.receipt
            .persist_marker(&plan.dir, &plan.label, &self.file)
    }

    /// [`Self::mark`], then lifts a failed attempt's guard: the label has an
    /// accepted backup again.
    pub(crate) fn accept(&self, plan: &BackupPlan) -> oneiron::Result<()> {
        self.mark(plan)?;
        lift_guard(plan);
        Ok(())
    }

    /// What follows a recorded managed backup, as after any `take`: its
    /// custody published (FIX 5790) and the backups beyond `keep` pruned.
    /// Maintenance: a prune that fails is logged, and the backup stands.
    pub(crate) fn maintain(self, vault: &oneiron::Vault, plan: &BackupPlan) -> BackupOutcome {
        super::custody::publish_after_take(vault, plan);
        let pruned = super::prune(vault, plan, Some(&self.file)).unwrap_or_else(|error| {
            tracing::warn!(
                reason = "backup_prune_failed",
                error = %format!("{error:#}"),
                "the backup landed and was recorded; pruning beyond keep failed, and the next \
                 pass prunes again"
            );
            Vec::new()
        });
        let bytes = self.receipt.evidence.size;
        self.into_outcome(bytes, pruned)
    }

    /// What `take` answers for this backup: its `bytes`, and the older ones
    /// `pruned` deleted.
    pub(crate) fn into_outcome(self, bytes: u64, pruned: Vec<String>) -> BackupOutcome {
        BackupOutcome {
            backup: BackupRecord {
                file: self.file,
                path: self.path,
                sequence: self.sequence,
                bytes,
                taken: rfc3339(self.taken_ms),
                taken_ms: self.taken_ms,
            },
            checkpoint_id: self.receipt.image_digest,
            pruned,
        }
    }
}

/// Puts `plan`'s failed-attempt guard down for `attempt`, durably: a private
/// file written, synced and renamed into place, its directory synced. From
/// here the label has no accepted backup until one lifts it.
pub(crate) fn guard_attempt(plan: &BackupPlan, attempt: &str) -> std::io::Result<()> {
    write_private_file(&plan.dir, &guard_name(&plan.label), attempt.as_bytes()).map(drop)
}

/// Lifts `plan`'s failed-attempt guard once a backup is recorded. One that
/// is not there is lifted already; one that will not go is logged, and the
/// label reads as changed until the next backup lifts it.
pub(crate) fn lift_guard(plan: &BackupPlan) {
    match std::fs::remove_file(plan.dir.join(guard_name(&plan.label))) {
        Ok(()) => {
            // Unsynced, a crash brings the guard back: changed, never
            // covered.
            let _ = sync_dir(&plan.dir);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => tracing::warn!(
            reason = "backup_attempt_guard_stuck",
            error = %error,
            "a failed backup attempt's guard did not lift; the vault reads as changed until the \
             next backup"
        ),
    }
}

/// The label's last accepted backup, from its marker
/// ([`backup_marker`]): `None`, read as changed, while a failed attempt's
/// guard stands or cannot be told absent, and as the marker read has it.
pub(crate) fn accepted_marker(plan: &BackupPlan) -> Option<BackupMarker> {
    match std::fs::symlink_metadata(plan.dir.join(guard_name(&plan.label))) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            backup_marker(&plan.dir, &plan.label)
        }
        _ => None,
    }
}
