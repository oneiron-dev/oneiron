//! `vault.mesh.path_receipts` (OF-535): the owner reads this vault's mesh
//! path receipts, newest first, through [`crate::Vault::mesh_path_receipts`].
//! Each paired-machine mesh connection leaves one, direct or relayed
//! (CROSS-ARCH-0019); the rows are local to this machine and never synced.
use serde::{Deserialize, Serialize};

use crate::memory::{Memory, MemoryResult};
use crate::sync::mesh_path::{MESH_PATH_RECEIPTS_READ_MAX, MeshPathReceipt};

/// How many receipts one read answers when the caller names no `limit`
/// (canon names no number).
pub const MESH_PATH_RECEIPTS_DEFAULT: usize = 100;

/// `vault.mesh.path_receipts`'s input: how many of the newest receipts.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct MeshPathReceiptsRequest {
    /// The most receipts to answer: [`MESH_PATH_RECEIPTS_DEFAULT`] when
    /// absent, never more than [`MESH_PATH_RECEIPTS_READ_MAX`].
    #[serde(default)]
    pub limit: Option<usize>,
}

impl MeshPathReceiptsRequest {
    /// The bound the read takes.
    #[must_use]
    pub fn bound(&self) -> usize {
        self.limit
            .unwrap_or(MESH_PATH_RECEIPTS_DEFAULT)
            .min(MESH_PATH_RECEIPTS_READ_MAX)
    }
}

/// `vault.mesh.path_receipts` on an embedded handle: the vault's own owner
/// reads the receipts; any other actor is refused.
pub fn mesh_path_receipts_as_owner(
    memory: &Memory<'_>,
    input: &MeshPathReceiptsRequest,
) -> MemoryResult<Vec<MeshPathReceipt>> {
    memory.embedded_owner("vault.mesh.path_receipts")?;
    Ok(memory.vault().mesh_path_receipts(input.bound())?)
}
