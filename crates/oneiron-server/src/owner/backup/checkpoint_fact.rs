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

use std::path::Path;

use oneiron::recovery::checkpoint::BackupSnapshotReceipt;
use oneiron_vault_contract::backup_handoff::write_private_file;

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
/// logged and stays, which no listing reads.
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
