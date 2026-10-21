//! Each backup's checkpoint fact beside it (FIX 7327): the signed fact the
//! snapshot's receipt carries (FIX 7326), as `<artifact>.cpfact` in the
//! backup's directory, so a host that copies the artifact takes its fact with
//! it. A vault VM's guest writes it the same way, and its outbox carries it in
//! the artifact's set.
//!
//! It lands durably before the artifact is renamed into place, so an artifact
//! a listing shows already has the fact it will ever have; it goes after its
//! artifact is pruned, never before. A fact that was not signed, or did not
//! land, is logged and absent: the backup stands without it, and nothing
//! requires one.
//!
//! A fact can still outlive its artifact: a crash between the fact landing
//! and the artifact's rename, an artifact already gone when a prune reaches
//! it, or a fact that would not go. Each prune first sweeps this label's
//! facts whose artifact is gone (FIX 7359, [`sweep`]). A vault VM's outbox
//! then retires the host's copy, as it does any backup file the guest
//! removed.

use std::path::Path;

use oneiron::recovery::checkpoint::BackupSnapshotReceipt;
use oneiron_vault_contract::backup_handoff::write_private_file;

use super::{BackupPlan, FILE_SUFFIX, parse_file_stamp, parse_sequence, sync_dir};

/// The suffix of a backup's checkpoint fact: `<artifact>.cpfact`.
const CHECKPOINT_FACT_SUFFIX: &str = ".cpfact";

fn fact_name(artifact: &str) -> String {
    format!("{artifact}{CHECKPOINT_FACT_SUFFIX}")
}

/// Writes `receipt`'s checkpoint fact as `dir/<artifact>.cpfact`: a private
/// temporary sibling, written and synced, renamed into place, `dir` synced.
/// Whether it landed: not where the receipt has none, and not where the write
/// failed, which is logged and leaves no fact there.
pub(super) fn publish(dir: &Path, artifact: &str, receipt: &BackupSnapshotReceipt) -> bool {
    let Some(signed) = receipt.checkpoint_fact.as_ref() else {
        return false;
    };
    let name = fact_name(artifact);
    match write_private_file(dir, &name, &signed.encode()) {
        Ok(_) => true,
        Err(error) => {
            let _ = std::fs::remove_file(dir.join(&name));
            tracing::warn!(
                reason = "backup_checkpoint_fact_unpublished",
                error = %error,
                "the backup lands with no checkpoint fact beside it"
            );
            false
        }
    }
}

/// Removes the checkpoint fact beside `artifact` in `dir`, once the artifact
/// is gone. One that is not there is gone already; one that will not go is
/// logged and stays, which no listing reads, until a later prune's [`sweep`].
pub(super) fn remove(dir: &Path, artifact: &str) {
    match std::fs::remove_file(dir.join(fact_name(artifact))) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => tracing::warn!(
            reason = "backup_checkpoint_fact_stuck",
            error = %error,
            "a checkpoint fact whose backup is gone did not go"
        ),
    }
}

/// Removes this label's checkpoint facts whose artifact is gone, at the start
/// of each prune (FIX 7359). A fact goes only where nothing at all is at its
/// artifact's exact path: an entry of any kind there keeps it, and so does
/// an error reading that path. The holds are read and each fact goes while
/// the vault's writer is held, as a prune's backups do, so a standing legal
/// hold keeps these too. The caller holds the backup lock, so no fact goes
/// while its artifact is still landing. A sweep that fails is logged and
/// fails nothing else; the next prune sweeps again. A swept fact is not one
/// of the backups a prune names.
pub(super) fn sweep(vault: &oneiron::Vault, plan: &BackupPlan) {
    if let Err(error) = sweep_orphans(vault, plan) {
        tracing::warn!(
            reason = "backup_checkpoint_fact_sweep_failed",
            error = %format!("{error:#}"),
            "checkpoint facts whose backup is gone were not swept; the next prune sweeps again"
        );
    }
}

fn sweep_orphans(vault: &oneiron::Vault, plan: &BackupPlan) -> anyhow::Result<()> {
    let entries = match std::fs::read_dir(&plan.dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let prefix = format!("{}-", plan.label);
    let mut orphans = Vec::new();
    for entry in entries {
        let entry = entry?;
        let file = entry.file_name();
        // This label's `<artifact>.cpfact`, a plain file, not a link: its
        // artifact's name is its own less the one suffix.
        let Some(artifact) = file
            .to_str()
            .and_then(|name| name.strip_suffix(CHECKPOINT_FACT_SUFFIX))
            .filter(|artifact| labels_backup(&prefix, artifact))
        else {
            continue;
        };
        let plain = matches!(entry.file_type(), Ok(kind) if kind.is_file());
        if plain && artifact_gone(&plan.dir, artifact) {
            orphans.push(artifact.to_owned());
        }
    }
    if orphans.is_empty() {
        return Ok(());
    }
    vault.with_backup_hold_exclusion(|holds| -> anyhow::Result<()> {
        if holds.keeps_backups() {
            return Ok(());
        }
        let mut swept = false;
        for artifact in &orphans {
            // Read again under the writer: only the artifact's absence lets
            // its fact go.
            if artifact_gone(&plan.dir, artifact) {
                remove(&plan.dir, artifact);
                swept = true;
            }
        }
        if swept {
            sync_dir(&plan.dir)?;
        }
        Ok(())
    })?
}

/// Whether `artifact` is named as [`super::list`] reads one of the backups
/// `prefix` (`<label>-`) names: `<sequence>-<stamp>-<id8>.oneiron-backup`
/// after it, or `<stamp>-<id8>.oneiron-backup` from before sequences. So a
/// sweep takes no fact whose artifact `list` would not read as this label's,
/// and a longer label's sequenced backups that share its prefix fail it.
fn labels_backup(prefix: &str, artifact: &str) -> bool {
    artifact
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(FILE_SUFFIX))
        .and_then(|rest| rest.rsplit_once('-'))
        .map(|(rest, _)| rest.split_once('-').unwrap_or(("0", rest)))
        .is_some_and(|(sequence, stamp)| {
            parse_sequence(sequence).is_some() && parse_file_stamp(stamp).is_some()
        })
}

/// Whether nothing at all is at `dir/<artifact>`, a link included: the one
/// proof a fact's artifact is gone. An error reading it is logged, and keeps
/// the fact.
fn artifact_gone(dir: &Path, artifact: &str) -> bool {
    match std::fs::symlink_metadata(dir.join(artifact)) {
        Ok(_) => false,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => {
            tracing::warn!(
                reason = "backup_checkpoint_fact_kept",
                error = %error,
                "a checkpoint fact stays: whether its backup is there could not be read"
            );
            false
        }
    }
}
