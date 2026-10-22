//! A vault-owned inference snapshot at rest: its body sealed under its own
//! erasable data key, the key wrapped under the vault's key, the manifest
//! bound as associated data. Opaque bytes only: the store, catalog, quotas
//! and erase wiring land in the next change.
//!
//! [`seal_snapshot`] seals; [`open_snapshot`] opens. [`WrappedSnapshotKey`]
//! travels apart from [`SealedSnapshot`], so a later erase destroys the key
//! alone and the body never opens again.

mod seal;

pub use self::seal::{SealedSnapshot, WrappedSnapshotKey, open_snapshot, seal_snapshot};
