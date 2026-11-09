//! The embedded owner's doors over the snapshot bounds (`vault.settings.snapshot_read` and
//! `.replace`); a server takes the owner's proof from the request instead.

use crate::memory::{Memory, MemoryResult};
use crate::settings::snapshot_read::SnapshotReadSettings;

/// `vault.settings.snapshot_read` on the embedded owner's handle.
///
/// # Errors
///
/// A handle that is not the vault owner's, and storage errors.
pub fn read_snapshot_read_settings(memory: &Memory<'_>) -> MemoryResult<SnapshotReadSettings> {
    Ok(memory
        .vault()
        .snapshot_read_settings_as_owner(&memory.embedded_owner("vault.settings.snapshot_read")?)?)
}

/// `vault.settings.snapshot_read.replace` on the embedded owner's handle.
///
/// # Errors
///
/// A handle that is not the vault owner's, bounds the setter refuses, and
/// storage errors.
pub fn replace_snapshot_read_settings(
    memory: &Memory<'_>,
    input: SnapshotReadSettings,
) -> MemoryResult<SnapshotReadSettings> {
    Ok(memory.vault().replace_snapshot_read_settings_as_owner(
        &memory.embedded_owner("vault.settings.snapshot_read.replace")?,
        input,
    )?)
}
