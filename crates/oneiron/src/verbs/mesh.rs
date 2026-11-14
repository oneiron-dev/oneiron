//! `vault.mesh.path_receipts` (OF-535): the owner reads this vault's mesh
//! path receipts, newest first, through [`crate::Vault::mesh_path_receipts`].
//! Each paired-machine mesh connection leaves one, direct or relayed
//! (CROSS-ARCH-0019); the rows are local to this machine and never synced.
use serde::{Deserialize, Serialize};

#[cfg(feature = "sync")]
use crate::memory::{Memory, MemoryResult};
#[cfg(feature = "sync")]
use crate::sync::mesh_path::{MESH_PATH_RECEIPTS_READ_MAX, MeshPathReceipt};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::mesh::{
    MESH_PATH_RECEIPTS_DEFAULT, MeshDialRequest, MeshMachineBound, MeshMachineRevokeRequest,
    MeshMachineRevoked, MeshPathReceiptsRequest,
};

/// `vault.mesh.path_receipts` on an embedded handle: the vault's own owner
/// reads the receipts; any other actor is refused.
#[cfg(feature = "sync")]
pub fn mesh_path_receipts_as_owner(
    memory: &Memory<'_>,
    input: &MeshPathReceiptsRequest,
) -> MemoryResult<Vec<MeshPathReceipt>> {
    memory.embedded_owner("vault.mesh.path_receipts")?;
    Ok(memory.vault().mesh_path_receipts(input.bound())?)
}

use crate::EntityId;
use crate::authority::MeshMachineAddress;
pub use crate::authority::{MeshAlpnGrant, MeshBindingIdentity, MeshMachineBinding};
