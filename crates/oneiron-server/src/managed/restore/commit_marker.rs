//! The attempt-bound commit marker, written inside the destination once
//! every keep is done (the restore's after-keep step): which attempt was
//! kept, for a supervisor that finds the process gone before its last frame.
//!
//! Through the kept vault's own directory only: its writer lease is checked
//! to be this process's and to name the data directory, the directory is
//! opened through its held parent without following a link and checked to
//! be the one the restore landed, and the marker goes in by a private
//! temporary sibling (created new, 0600, written and synced), renamed to
//! [`RESTORE_COMMIT_MARKER_FILE`] without replacing anything there, then the
//! directory synced, and both checks made again. A failure leaves the
//! restore committed and not serving, or uncertain once the marker may have
//! been published; it is never rolled back.

use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;

use oneiron::recovery::checkpoint::{
    RestoreAdmissionError, RestoreAdmissionReason, RestoreCommitFacts, RestoreDestinationState,
    RestorePhase,
};
use oneiron_vault_contract::restore::{RESTORE_COMMIT_MARKER_FILE, RestoreCommitMarker};
use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags};

use crate::managed::isolation::RestoreDestination;

/// Writes `facts`' marker inside the kept vault's directory, the one the
/// restore landed at `landed` (`st_dev`, `st_ino`) under `destination`.
pub(super) fn publish(
    vault: &oneiron::Vault,
    facts: &RestoreCommitFacts,
    destination: &RestoreDestination,
    landed: (u64, u64),
) -> Result<(), RestoreAdmissionError> {
    use RestoreDestinationState::{CommittedNotServing, Uncertain};
    let refuse = |reason, state, error| {
        RestoreAdmissionError::new(reason, RestorePhase::CommitMarker, state, error)
    };
    let io = |state| {
        move |error: std::io::Error| {
            refuse(
                RestoreAdmissionReason::StorageIo,
                state,
                oneiron::Error::Io(error),
            )
        }
    };
    let moved = |state| {
        refuse(
            RestoreAdmissionReason::StartupFailed,
            state,
            oneiron::Error::InvalidConfig(
                "the kept vault's directory is not the one its restore landed".into(),
            ),
        )
    };
    // The kept vault's lease is this process's, over the data directory, and
    // the directory at its name is the one the restore landed and `facts`
    // names.
    let held_here = || -> bool {
        let leased = vault
            .writer_lease()
            .is_some_and(|lease| lease.validate_directory(destination.path()).is_ok());
        let at_name = destination
            .open_landed()
            .and_then(|dir| dir.metadata())
            .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == landed);
        let named = std::fs::metadata(&facts.destination)
            .is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == landed);
        leased && at_name && named
    };
    let marker = serde_json::to_vec(&RestoreCommitMarker {
        restore_id: facts.restore_id.clone(),
        plan_digest: facts.plan_digest,
        attempt_id: facts.attempt_id.clone(),
        generation: facts.generation,
        checkpoint_id: facts.checkpoint_id,
        checkpoint_sequence: facts.checkpoint_sequence,
        checkpoint_crypto_epoch: facts.checkpoint_crypto_epoch,
    })
    .map_err(|error| io(CommittedNotServing)(error.into()))?;
    let held = destination.open_landed().map_err(io(CommittedNotServing))?;
    let opened = held.metadata().map_err(io(CommittedNotServing))?;
    if (opened.dev(), opened.ino()) != landed || !held_here() {
        return Err(moved(CommittedNotServing));
    }
    let temporary = format!("{RESTORE_COMMIT_MARKER_FILE}.{}.tmp", std::process::id());
    let created =
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut file = rustix::fs::openat(&held, temporary.as_str(), created, Mode::RUSR | Mode::WUSR)
        .map(std::fs::File::from)
        .map_err(|error| io(CommittedNotServing)(error.into()))?;
    let unlink = || {
        let _ = rustix::fs::unlinkat(&held, temporary.as_str(), AtFlags::empty());
    };
    if let Err(error) = file.write_all(&marker).and_then(|()| file.sync_all()) {
        unlink();
        return Err(io(CommittedNotServing)(error));
    }
    drop(file);
    match rustix::fs::renameat_with(
        &held,
        temporary.as_str(),
        &held,
        RESTORE_COMMIT_MARKER_FILE,
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {}
        // A marker is there already: another attempt's, never overwritten.
        Err(rustix::io::Errno::EXIST) => {
            unlink();
            return Err(refuse(
                RestoreAdmissionReason::StartupFailed,
                CommittedNotServing,
                oneiron::Error::InvalidConfig(
                    "a restore commit marker is already in the kept vault's directory".into(),
                ),
            ));
        }
        Err(error) => {
            unlink();
            return Err(io(Uncertain)(error.into()));
        }
    }
    rustix::fs::fsync(&held).map_err(|error| io(Uncertain)(error.into()))?;
    if !held_here() {
        return Err(moved(Uncertain));
    }
    Ok(())
}
