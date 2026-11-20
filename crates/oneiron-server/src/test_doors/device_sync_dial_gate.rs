//! The device sync dial gate (`crate::device_sync::standing`), as the sync
//! host asks it before it opens the connection to its home, so a test reads
//! its answer without a home or a mesh transport.

use oneiron::{EntityId, Vault};

/// This install's MACHINE when it may dial `home`, and whether `home` has a
/// paired mesh address; the gate's own refusal otherwise. `enrolled` says
/// `oneiron device enrol` added this machine, as the host's dial says.
///
/// # Errors
/// The gate's refusal, or a fold or store read error.
pub fn dial_standing(
    vault: &Vault,
    home: EntityId,
    enrolled: bool,
) -> anyhow::Result<(EntityId, bool)> {
    crate::device_sync::standing(vault, home, enrolled)
}
