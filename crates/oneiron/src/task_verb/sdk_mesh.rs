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

use crate::EntityId;
use crate::authority::MeshMachineAddress;
pub use crate::authority::{MeshAlpnGrant, MeshBindingIdentity, MeshMachineBinding};

/// The MACHINE whose address/key binding just committed, initially without grants.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeshMachineBound {
    pub machine: EntityId,
    pub endpoint_key: [u8; 32],
}

/// The MACHINE whose mesh admission the owner withdraws permanently.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeshMachineRevokeRequest {
    pub machine: EntityId,
}

/// The MACHINE whose mesh admission was revoked.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeshMachineRevoked {
    pub machine: EntityId,
}

/// An actual explicit-address dial, including before the peer pairs this
/// install. It carries no application payload and returns no usable stream.
/// ALPN is its wire bytes (for sync, the UTF-8 bytes of `oneiron/sync/1`).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeshDialRequest {
    pub address: MeshMachineAddress,
    pub alpn: Vec<u8>,
}
