//! Owner-bound mesh setup and a real admission-only dial. No handler accepts
//! a signer, impersonates a paired MACHINE, or releases an application stream.
use std::sync::Arc;

use oneiron::memory::MemoryResult;
use oneiron::sync::mesh_path::MeshPathReceipt;
use oneiron::task_verb::sdk::{
    EmptyRequest, MeshAlpnGrant, MeshBindingIdentity, MeshDialRequest, MeshMachineBinding,
    MeshMachineBound, MeshMachineRevokeRequest, MeshMachineRevoked,
};

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// Public install identity and both binding proofs, never secret keys.
pub(crate) async fn vault_mesh_identity(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<MeshBindingIdentity> {
    as_owner_naming(
        server,
        auth,
        "vault.mesh.identity",
        |server, owner| Ok(server.vault().mesh_binding_identity_as_owner(owner)?),
        |_| Vec::new(),
    )
    .await
}

/// The same host issuer pairing uses; the caller's proof reaches the writer.
pub(crate) async fn vault_mesh_bind_machine(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MeshMachineBinding,
) -> Listed<MeshMachineBound> {
    as_owner_naming(
        server,
        auth,
        "vault.mesh.bind_machine",
        move |server, owner| {
            let bound = MeshMachineBound {
                machine: input.machine,
                endpoint_key: input.address.endpoint_key,
            };
            crate::api::pairing::with_issuer(server, |issuer| {
                server
                    .vault()
                    .bind_mesh_machine_as_owner(issuer, owner, input)
            })
            .map_err(|error| super::FacadeApiError::from(error).into_memory_error())?;
            Ok(bound)
        },
        |bound| vec![bound.machine],
    )
    .await
}

/// Both allowing and revoking the exact key/ALPN, through one engine operation.
pub(crate) async fn vault_mesh_set_alpn_grant(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MeshAlpnGrant,
) -> Listed<MeshAlpnGrant> {
    as_owner_naming(
        server,
        auth,
        "vault.mesh.set_alpn_grant",
        move |server, owner| {
            crate::api::pairing::with_issuer(server, |issuer| {
                server
                    .vault()
                    .set_mesh_alpn_grant_as_owner(issuer, owner, input.clone())
            })
            .map_err(|error| super::FacadeApiError::from(error).into_memory_error())?;
            Ok(input)
        },
        |grant| vec![grant.machine],
    )
    .await
}

pub(crate) async fn vault_mesh_revoke_machine(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MeshMachineRevokeRequest,
) -> Listed<MeshMachineRevoked> {
    as_owner_naming(
        server,
        auth,
        "vault.mesh.revoke_machine",
        move |server, owner| {
            crate::api::pairing::with_issuer(server, |issuer| {
                server
                    .vault()
                    .revoke_mesh_machine_as_owner(issuer, owner, input.machine)
            })
            .map_err(|error| super::FacadeApiError::from(error).into_memory_error())?;
            Ok(MeshMachineRevoked {
                machine: input.machine,
            })
        },
        |revoked| vec![revoked.machine],
    )
    .await
}

/// An unpaired caller still uses its install's real transport key. Only the
/// peer's ordinary live gate decides admission. This door returns its path
/// receipt and closes without ever opening an application stream.
pub(crate) async fn vault_mesh_dial(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MeshDialRequest,
) -> Listed<MeshPathReceipt> {
    (dial(server, auth, input).await, Vec::new())
}

fn unavailable() -> oneiron::memory::MemoryError {
    oneiron::memory::MemoryError::new(
        oneiron::memory::MEMORY_CODE_INVALID_STATE,
        "mesh is not enabled on this server",
        &["Enable the mesh feature and explicitly configure ONEIRON_MESH_BIND."],
    )
}

#[cfg(feature = "mesh")]
async fn dial(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MeshDialRequest,
) -> MemoryResult<MeshPathReceipt> {
    let transport =
        super::legal_hold_doors::as_owner(server, auth, "vault.mesh.dial", |server, owner| {
            server.vault().recheck_owner(owner)?;
            server.mesh_transport.get().cloned().ok_or_else(unavailable)
        })
        .await?;
    transport
        .dial_address(&input.address, &input.alpn)
        .await
        .map_err(|error| {
            oneiron::memory::MemoryError::new(
                oneiron::memory::MEMORY_CODE_BAD_REQUEST,
                format!("mesh dial: {error}"),
                &["Check the endpoint key, direct addresses, ALPN and configured private relays."],
            )
        })
}

#[cfg(not(feature = "mesh"))]
async fn dial(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: MeshDialRequest,
) -> MemoryResult<MeshPathReceipt> {
    super::host_doors::support::owner_proof(auth, server, "vault.mesh.dial")?;
    Err(unavailable())
}
