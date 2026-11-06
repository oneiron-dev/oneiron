//! The member's admitted original replica source over the served facade.

use crate::consent::AuthenticatedOwner;
use crate::federation::Scope;
use crate::memory::MemoryResult;
use crate::{EntityId, Vault};

pub use crate::sync::shared_replica::{
    SharedReplicaManifest, SharedReplicaManifestRequest, SharedReplicaWindow,
    SharedReplicaWindowRequest,
};

pub fn read_shared_replica_manifest_listing(
    vault: &Vault,
    reader: &AuthenticatedOwner,
    scope: &Scope,
    input: SharedReplicaManifestRequest,
) -> MemoryResult<(SharedReplicaManifest, Vec<EntityId>)> {
    Ok(crate::sync::shared_replica::source::manifest_listing(
        vault, reader, scope, input,
    )?)
}

pub fn read_shared_replica_manifest(
    vault: &Vault,
    reader: &AuthenticatedOwner,
    scope: &Scope,
    input: SharedReplicaManifestRequest,
) -> MemoryResult<SharedReplicaManifest> {
    Ok(read_shared_replica_manifest_listing(vault, reader, scope, input)?.0)
}

pub fn read_shared_replica_window_listing(
    vault: &Vault,
    reader: &AuthenticatedOwner,
    scope: &Scope,
    input: SharedReplicaWindowRequest,
) -> MemoryResult<(SharedReplicaWindow, Vec<EntityId>)> {
    Ok(crate::sync::shared_replica::source::window_listing(
        vault, reader, scope, input,
    )?)
}

pub fn read_shared_replica_window(
    vault: &Vault,
    reader: &AuthenticatedOwner,
    scope: &Scope,
    input: SharedReplicaWindowRequest,
) -> MemoryResult<SharedReplicaWindow> {
    Ok(read_shared_replica_window_listing(vault, reader, scope, input)?.0)
}
