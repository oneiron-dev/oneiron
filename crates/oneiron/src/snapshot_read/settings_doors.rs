//! The embedded doors over the snapshot bounds (`vault.settings.snapshot_read` and
//! `.replace`); a server takes the owner's proof from the request instead. The replace is the
//! owner's alone. The read also answers a holder of any `engine.controls` class (untangle
//! 6.6f; Engine 10 Nov 14:36, S66F-READ = C).

use crate::memory::{Memory, MemoryResult};
use crate::settings::snapshot_read::SnapshotReadSettings;
use crate::{Vault, WriteActor};

/// The bounds for a holder of any `engine.controls` class, checked at this
/// read (untangle 6.6f; S66F-READ = C: every `engine.controls` read has the
/// learning dials' rule, since a read changes nothing). The vault's owner
/// reads through its own door, under its proof.
///
/// # Errors
///
/// A caller that holds no live grant naming an `engine.controls` class, and
/// storage errors.
pub fn snapshot_read_settings_as_holder(
    vault: &Vault,
    reader: WriteActor,
) -> MemoryResult<SnapshotReadSettings> {
    crate::federation::admit_substrate_read_by(
        vault,
        reader,
        "vault.settings.snapshot_read",
        crate::federation::SubstrateRead::Dials,
    )?;
    Ok(vault.snapshot_read_settings()?)
}

/// `vault.settings.snapshot_read` on a bound handle: the embedded owner
/// reads under its own proof, any other caller as an `engine.controls`
/// holder.
///
/// # Errors
///
/// As [`snapshot_read_settings_as_holder`], and storage errors.
pub fn read_snapshot_read_settings(memory: &Memory<'_>) -> MemoryResult<SnapshotReadSettings> {
    match memory.embedded_owner("vault.settings.snapshot_read") {
        Ok(owner) => Ok(memory.vault().snapshot_read_settings_as_owner(&owner)?),
        Err(_) => snapshot_read_settings_as_holder(
            memory.vault(),
            WriteActor::new(memory.actor(), memory.actor_class()),
        ),
    }
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
