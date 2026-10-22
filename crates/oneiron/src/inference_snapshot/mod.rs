//! A vault-owned inference snapshot at rest: its body sealed under its own
//! erasable data key, the key wrapped under the vault's key, the manifest
//! bound as associated data, and the catalog row that names what it was
//! computed from and under.
//!
//! [`seal_snapshot`] seals; [`open_snapshot`] opens. [`WrappedSnapshotKey`]
//! travels apart from [`SealedSnapshot`], so a later erase destroys the key
//! alone and the body never opens again. [`SnapshotRecord`] is the catalog
//! row; an erase reaches every row whose dependency set names the erased
//! id. [`SnapshotRuntime`] is the host's port to the process that holds
//! plaintext state: a vault lock waits for its release before the key goes.
//! The [`retention`] ledger keeps each vault inside its owner's disk budget.

mod catalog;
mod lifecycle;
pub mod retention;
mod seal;

pub use self::catalog::{
    SNAPSHOT_RECORD_SCHEMA, SnapshotClass, SnapshotCompatibility, SnapshotDependencies, SnapshotId,
    SnapshotManifest, SnapshotPins, SnapshotRecord,
};
pub(crate) use self::catalog::{erase_actor_in_txn, erase_in_txn};
pub(crate) use self::lifecycle::SnapshotLifecycle;
pub use self::lifecycle::{
    LOCK_RELEASE_MARGIN, SnapshotAdmission, SnapshotFuture, SnapshotLockReceipt, SnapshotRelease,
    SnapshotRuntime, SnapshotWorkerAbort,
};
pub use self::seal::{SealedSnapshot, WrappedSnapshotKey, open_snapshot, seal_snapshot};
