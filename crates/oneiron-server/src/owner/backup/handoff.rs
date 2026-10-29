//! The prune pin (LC backup shipper rows, Engine 10-20). A label whose
//! handoff policy the managed setup installed
//! (`[backup].dir/.backup-handoff/<label>/`,
//! `oneiron_vault_contract::backup_handoff`) keeps every backup retention
//! would prune until the node supervisor's root-stage ack for it is there and
//! names the file held here: its vault, label, name, commitment digest, size
//! and BLAKE3, read from the file itself. Anything short of that is pending
//! and kept: no ack, one that is not a private file of this user, one replaced
//! or naming other bytes, an I/O failure. Nothing pinned is unpinned,
//! evicted, dropped or capped. A label with no handoff directory keeps plain
//! retention.
//!
//! Past `limits.backup_handoff_pending_backups` or
//! `limits.backup_handoff_pending_bytes`, the backups the pin holds raise one
//! typed check, `backup_handoff_backlog`, at most once an hour for the label:
//! the row's question through the vault's limit port and one log line with
//! the kind, count and bytes. Retention still keeps every one, and no backup
//! is refused (rule 5; CALLS BACKUP_PRUNE_PIN_PENDING).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use oneiron::limit_ask::EngineLimit;
use oneiron::recovery::checkpoint::{BackupArtifactEvidence, inspect_backup};
use oneiron_vault_contract::backup_handoff::{
    BackupStageAck, HeldBackup, PrivateFile, backup_handoff_dir, backup_stage_ack_file_name,
    read_private_file,
};

use super::{BackupPlan, BackupRecord};

/// The typed check the backups a pin holds raise past their rows.
pub(crate) const BACKUP_HANDOFF_BACKLOG_CHECK_KIND: &str = "backup_handoff_backlog";

/// How long one label's backlog check stands before it is raised again.
const BACKLOG_CHECK_WINDOW: Duration = Duration::from_secs(3_600);

/// When a plan's label last raised its backlog check, shared by every copy of
/// the plan a host takes.
#[derive(Clone, Debug, Default)]
pub(crate) struct BacklogChecked(Arc<Mutex<Option<Instant>>>);

impl BacklogChecked {
    /// Whether the check may be raised at `now`: none stands in the window.
    fn due(&self, now: Instant) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none_or(|at| now.saturating_duration_since(at) >= BACKLOG_CHECK_WINDOW)
    }

    fn raised(&self, now: Instant) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(now);
    }
}

/// `label`'s handoff directory under `dir` when its backups are pinned: the
/// directory is there, or cannot be told absent. `None` keeps plain
/// retention.
pub(super) fn pinned(dir: &Path, label: &str) -> Option<PathBuf> {
    let handoff = backup_handoff_dir(dir, label)?;
    match std::fs::symlink_metadata(&handoff) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        _ => Some(handoff),
    }
}

/// Which of `excess`, the backups retention would prune, a pinned label lets
/// go: those whose stage ack in `handoff` names the file held here. Each is
/// returned with its ack's path; the rest stay pending.
pub(super) fn released(
    handoff: &Path,
    label: &str,
    excess: Vec<BackupRecord>,
) -> (Vec<(BackupRecord, PathBuf)>, Vec<BackupRecord>) {
    let acks = acks(handoff);
    let mut released = Vec::new();
    let mut pending = Vec::new();
    for record in excess {
        let ack = acks
            .get(&record.file)
            .and_then(|named| acked(handoff, label, &record, named));
        match ack {
            Some(ack) => released.push((record, ack)),
            None => pending.push(record),
        }
    }
    (released, pending)
}

/// Every stage ack in `handoff` that reads as one, by the file it names, with
/// its own file name. One that cannot be read is no ack.
fn acks(handoff: &Path) -> BTreeMap<String, Vec<(String, BackupStageAck)>> {
    let mut acks: BTreeMap<String, Vec<(String, BackupStageAck)>> = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(handoff) else {
        return acks;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("stage-ack-") {
            continue;
        }
        let Ok(PrivateFile::Bytes(bytes)) = read_private_file(&entry.path()) else {
            continue;
        };
        if let Some(ack) = BackupStageAck::parse(&bytes) {
            acks.entry(ack.file.clone()).or_default().push((name, ack));
        }
    }
    acks
}

/// The path of the ack among `named` that names `record` exactly, as its file
/// reads now: filed under the held artifact's commitment digest, with its
/// vault, label, name, size and BLAKE3.
fn acked(
    handoff: &Path,
    label: &str,
    record: &BackupRecord,
    named: &[(String, BackupStageAck)],
) -> Option<PathBuf> {
    let evidence = held_evidence(&record.path)?;
    let key =
        backup_stage_ack_file_name(&oneiron_vault_contract::hex(&evidence.commitment_digest))?;
    let held = HeldBackup {
        engine_vault_id: &evidence.engine_vault_id,
        label,
        file: &record.file,
        commitment_digest: &evidence.commitment_digest,
        size: evidence.size,
        outer_blake3: &evidence.outer_blake3,
    };
    named
        .iter()
        .find(|(name, ack)| *name == key && ack.names(&held))
        .map(|(name, _)| handoff.join(name))
}

/// The evidence of the backup at `path`, read once from the regular file
/// there, never through a symlink. `None` when it cannot be read whole.
fn held_evidence(path: &Path) -> Option<BackupArtifactEvidence> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(
        &mut options,
        libc::O_NOFOLLOW | libc::O_NONBLOCK,
    );
    let file = options.open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() {
        return None;
    }
    let evidence = inspect_backup(std::io::BufReader::new(&file)).ok()?;
    (evidence.size == metadata.len()).then_some(evidence)
}

/// Raises the backlog check when the backups `pending` holds pass either row,
/// once in its window: nothing is refused and every one is kept.
pub(super) fn check_backlog(
    vault: &oneiron::Vault,
    checked: &BacklogChecked,
    pending: &[BackupRecord],
) {
    let now = Instant::now();
    if pending.is_empty() || !checked.due(now) {
        return;
    }
    let count = pending.len() as u64;
    let bytes = pending
        .iter()
        .fold(0u64, |sum, record| sum.saturating_add(record.bytes));
    let over_count = vault.measure_limit(EngineLimit::BackupHandoffPendingBackups, count);
    let over_bytes = vault.measure_limit(EngineLimit::BackupHandoffPendingBytes, bytes);
    if over_count.is_none() && over_bytes.is_none() {
        return;
    }
    checked.raised(now);
    tracing::warn!(
        kind = BACKUP_HANDOFF_BACKLOG_CHECK_KIND,
        count,
        bytes,
        "backups wait for the node's stage ack past their row and are all kept; is everything \
         okay?"
    );
}

/// The backups among `records` a managed handoff pin keeps pending for a
/// stage ack (FIX 6335): retention's excess past `keep`, oldest first, whose
/// ack does not name the file held here. A label with no handoff directory
/// keeps none by pin. The pin still keeps every one, and the backlog check
/// still raises past its rows.
pub(super) fn handoff_pending(plan: &BackupPlan, records: &[BackupRecord]) -> Vec<BackupRecord> {
    let Some(handoff) = pinned(&plan.dir, &plan.label) else {
        return Vec::new();
    };
    let excess = records.len().saturating_sub(plan.keep.max(1));
    let excess: Vec<BackupRecord> = records.iter().take(excess).cloned().collect();
    let (_, pending) = released(&handoff, &plan.label, excess);
    pending
}

/// Removes every stage ack in `plan`'s handoff directory whose artifact is
/// gone (FIX 7607): nothing is at its path anymore. Pinned acks whose
/// artifact exists stay, as does anything unreadable as an ack,
/// which pins nothing. Called from the prune; a sweep that fails is logged and
/// fails nothing else, and the next prune sweeps again.
pub(super) fn sweep_orphan_stage_acks(plan: &BackupPlan) {
    if let Err(error) = sweep_orphans(plan) {
        tracing::warn!(
            reason = "backup_stage_ack_sweep_failed",
            error = %format!("{error:#}"),
            "stage acks whose backup is gone were not swept; the next prune sweeps again"
        );
    }
}

fn sweep_orphans(plan: &BackupPlan) -> anyhow::Result<()> {
    let Some(handoff) = pinned(&plan.dir, &plan.label) else {
        return Ok(());
    };
    let entries = match std::fs::read_dir(&handoff) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let mut swept = false;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("stage-ack-") {
            continue;
        }
        // Only a readable ack names an artifact; anything else stays.
        let Ok(PrivateFile::Bytes(bytes)) = read_private_file(&entry.path()) else {
            continue;
        };
        let Some(ack) = BackupStageAck::parse(&bytes) else {
            continue;
        };
        if ack_orphaned(&plan.dir, &ack.file) {
            remove_ack(&handoff, &name);
            swept = true;
        }
    }
    if swept {
        super::sync_dir(&handoff)?;
    }
    Ok(())
}

/// Whether the artifact `file` is gone from `dir`: nothing is at its path
/// anymore. An artifact still there keeps its ack, listed or not.
fn ack_orphaned(dir: &Path, file: &str) -> bool {
    matches!(
        std::fs::symlink_metadata(dir.join(file)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    )
}

/// Removes the stage ack `name` in `handoff` once its artifact is gone, in the
/// checkpoint fact sweep's remove-and-ignore-NotFound style (FIX 7359): one
/// that is not there is gone already; one that will not go is logged and stays.
fn remove_ack(handoff: &Path, name: &str) {
    match std::fs::remove_file(handoff.join(name)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => tracing::warn!(
            reason = "backup_stage_ack_stuck",
            error = %error,
            "a stage ack whose backup is gone did not go"
        ),
    }
}
