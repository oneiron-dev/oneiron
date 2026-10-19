//! `vault.packs.preview` (FIX 5493): the owner's look at a pack folder
//! before `vault.packs.put`. It names the world a travelling agent would
//! land in when that world's current setting does not cover this machine,
//! stages and writes nothing, and never stops the put that follows.

use serde::{Deserialize, Serialize};

use super::sdk::{PackFileInput, decode_pack_files};
use crate::consent::AuthenticatedOwner;
use crate::memory::{MemoryError, MemoryResult};
use crate::skill_hub::pack_catalog::PackImportPreview;
use crate::{EntityId, Vault};

/// `vault.packs.preview`'s input: the folder `vault.packs.put` would take,
/// and the local world the owner would pick for a travelling agent held for
/// its world.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PackPreviewRequest {
    pub files: Vec<PackFileInput>,
    /// The picked live local world; absent previews the one the agent's
    /// scope names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub world: Option<EntityId>,
}

/// `vault.packs.preview` under the owner's proof.
///
/// # Errors
///
/// A file whose base64 does not decode, a folder the put would refuse as
/// malformed, a picked world that is not a live local world, or an owner
/// proof that no longer holds.
pub fn pack_preview_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: PackPreviewRequest,
) -> MemoryResult<PackImportPreview> {
    let files = decode_pack_files(input.files)
        .map_err(|error| MemoryError::bad_request(error.to_string()))?;
    Ok(vault.preview_pack_import(owner, files, input.world)?)
}
