//! The cold managed restore start mode (LC FIX 5384/5385; the contract is
//! lanes/l14/t3/restore-contract.md): a managed engine started with
//! `--restore --restore-input-fd R --restore-result-fd W` beside its
//! ordinary flags restores the vault its plan names into `--data-dir`,
//! verifies and keeps it, and goes on to serve it in the same process.
//!
//! - R, the read end of a pipe, carries one [`ManagedRestoreInput`] and EOF
//!   (`plan`). The engine reads it to EOF first, then the 64-byte credential
//!   frame (its DEK is the vault's data key, delivered as on every start),
//!   then the custody anchor credential pipe when one is handed. Any write
//!   order works so long as the supervisor closes R before it waits on W or
//!   the ready byte. Beside the plan the object may carry the source's
//!   host-order legal holds, which the restore installs before it keeps the
//!   vault (`host_holds`).
//! - W, the write end of a pipe, carries the result frames (`framing`): the
//!   supervisor drains it as the engine writes, and closing it is EOF.
//! - Nothing listens before the restore is verified and kept: no HTTP, ctl or
//!   artifact socket. The ready byte and `Ping` come after the ordinary boot,
//!   once the `verified` frame is out; `restore_status` then answers for the
//!   attempt this process restored.
//! - After every keep, the engine writes [`RestoreCommitMarker`] inside the
//!   destination, as [`RESTORE_COMMIT_MARKER_FILE`]: the attempt it kept,
//!   for a supervisor that finds the process gone before its last frame.
//!
//! Build floor: all of it rides contract v3 with no version move. An engine
//! built before it refuses `--restore` as a flag it does not parse, before
//! it touches anything, and answers `restore_status` as an unknown request
//! (`Ok { ok: false }`): neither is ever success. The host-order holds
//! (`host_holds`: the input's field, the receipt's and the source's
//! `host_order_holds` ctl request) carry a build floor of their own, at the
//! engine revision they merged in.

/// Lowercase-hex byte fields.
mod hex;

/// The receipt of a verified restore.
pub mod facts;
/// The result pipe's frames and the `restore_status` answer.
pub mod framing;
/// The host-order legal holds a restore carries from its source (FIX 1485).
pub mod host_holds;
/// The input pipe's plan.
pub mod plan;

use std::path::Path;

use serde::{Deserialize, Serialize};

pub use self::facts::{
    ManagedRestoreIdentity, ManagedRestoreReceipt, RESTORE_RECEIPT_SCHEMA_VERSION,
};
pub use self::framing::{
    ManagedRestoreDestination, ManagedRestorePhase, ManagedRestoreResultFrame,
    RestoreFailureReason, RestoreStatus,
};
pub use self::host_holds::{
    HostHoldsBytes, HostHoldsCursor, HostHoldsOrigin, HostHoldsSource, HostOrderHoldsExport,
    HostOrderHoldsNotProven, ManagedRestoreHostHolds, RestoreHostHoldsStatus,
};
pub use self::plan::{
    EscrowRole, FreshRecipient, ManagedRestoreInput, ManagedRestorePlan,
    RESTORE_INPUT_SCHEMA_VERSION, ReleasedRecipient, RestorePlan,
};

/// The commit marker's file name, inside the restored data directory.
pub const RESTORE_COMMIT_MARKER_FILE: &str = ".oneiron-restore-commit.json";

/// The attempt a cold managed restore kept, written once every keep is done:
/// one JSON object, published by a private temporary sibling, synced,
/// renamed into place without replacing anything, then the directory
/// synced. It says the restore was kept; a destination without it, or with
/// one that names another attempt, is not proof the restore rolled back.
/// It is never a credential to open the destination as ordinary, and never
/// proof the vault served.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreCommitMarker {
    pub restore_id: String,
    #[serde(with = "hex::array")]
    pub plan_digest: [u8; 32],
    pub attempt_id: String,
    pub generation: u64,
    #[serde(with = "hex::array")]
    pub checkpoint_id: [u8; 32],
    pub checkpoint_sequence: u64,
    /// The checkpoint commitment's crypto epoch.
    pub checkpoint_crypto_epoch: u64,
}

impl RestoreCommitMarker {
    /// Whether the marker names `identity`'s attempt.
    #[must_use]
    pub fn names(&self, identity: &ManagedRestoreIdentity) -> bool {
        self.restore_id == identity.restore_id
            && self.plan_digest == identity.plan_digest
            && self.attempt_id == identity.attempt_id
            && self.generation == identity.generation
    }

    /// The marker inside `destination`, read without following a link at its
    /// name: `None` when there is none, a refusal when one is there and is
    /// not one marker.
    pub fn read(destination: &Path) -> anyhow::Result<Option<Self>> {
        let path = destination.join(RESTORE_COMMIT_MARKER_FILE);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) => anyhow::ensure!(
                metadata.is_file(),
                "the restore commit marker is not a file"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        Ok(Some(serde_json::from_slice(&std::fs::read(path)?)?))
    }
}
