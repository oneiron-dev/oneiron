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

/// The refusal a mesh write gets on an install that holds no host issuer for
/// the vault. A binding and a grant are this host's own signed rows, so
/// without one it signs neither. `with_issuer` alone would answer an
/// unexplained 401 (REVIEW-10531 P1).
fn require_host_issuer(server: &SyncServer) -> Result<(), oneiron::memory::MemoryError> {
    if server.host_issuer().is_some() {
        return Ok(());
    }
    Err(oneiron::memory::MemoryError::new(
        oneiron::memory::MEMORY_CODE_INVALID_STATE,
        "this install holds no host issuer for the vault, so it signs no mesh binding or grant \
         here",
        &[
            "Bind and grant on an install that already holds the vault's live host issuer, such as the home. A replica that joined its home holds none, and a restart gives it none (FIX-LIST 10770): only a restore of the vault's protected custody carries the issuer seed.",
        ],
    ))
}

/// Whether `error` is [`oneiron::Vault::PAIR_SELF_UNANSWERED`]: this
/// install's own MACHINE has no answered profile yet.
fn unanswered_home(error: &oneiron::Error) -> bool {
    matches!(
        error,
        oneiron::Error::Record(oneiron::error::RecordError::AuthorityRefused(reason))
            if *reason == oneiron::Vault::PAIR_SELF_UNANSWERED
    )
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
            require_host_issuer(server)?;
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

/// This install's own MACHINE paired as a machine of its vault, for the owner
/// to bind on each other replica (`vault.mesh.bind_machine` there). The home
/// never redeems a link of its own, so nothing else pairs it, and no node
/// could prove a home that issues jobs (PLAN-HOME-ISSUER-MESH-PROOF, R6 1.5).
/// The pairing's ceiling is every protocol this engine serves
/// (MESH-PAIRING-CEILING = A). The answer carries this home's mesh address
/// while its listener runs. It binds and grants nothing here.
pub(crate) async fn vault_mesh_pair_self(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<MeshMachineBinding> {
    as_owner_naming(
        server,
        auth,
        "vault.mesh.pair_self",
        |server, owner| {
            require_host_issuer(server)?;
            // An unanswered home's refusal is taken here, before the pairing
            // door's mapping answers it as an unnamed 401 (REVIEW-10531
            // round 2 P1).
            let paired = crate::api::pairing::with_issuer(server, |issuer| {
                match server.vault().pair_own_mesh_machine_as_owner(
                    issuer,
                    owner,
                    crate::device_sync::enrolment::home_bind::enrolment_ceiling(),
                ) {
                    Err(error) if unanswered_home(&error) => Ok(None),
                    paired => paired.map(Some),
                }
            })
            .map_err(|error| super::FacadeApiError::from(error).into_memory_error())?;
            let mut binding = paired.ok_or_else(|| {
                oneiron::memory::MemoryError::new(
                    oneiron::memory::MEMORY_CODE_INVALID_STATE,
                    oneiron::Vault::PAIR_SELF_UNANSWERED,
                    &[
                        "As the owner, answer this install's MACHINE \"yours\" (POST /v1/owner/machines/answer), then call vault.mesh.pair_self again.",
                    ],
                )
            })?;
            if let Some(address) =
                crate::device_sync::enrolment::home_bind::home_mesh_address(server)
                    .filter(|address| address.endpoint_key == binding.address.endpoint_key)
            {
                binding.address = address;
            }
            Ok(binding)
        },
        |binding| vec![binding.machine],
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
            require_host_issuer(server)?;
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
    let (transport, owner) =
        super::legal_hold_doors::as_owner(server, auth, "vault.mesh.dial", |server, owner| {
            server.vault().recheck_owner(owner)?;
            let transport = server
                .mesh_transport
                .get()
                .cloned()
                .ok_or_else(unavailable)?;
            Ok((transport, owner.clone()))
        })
        .await?;
    // Every direct address is dialed (FIX 8091, L13 09:35): the owner's
    // count is measured as the engine's own doors measure theirs, and only
    // asks; it never waits or refuses.
    server
        .vault()
        .measure_authority_items(input.address.direct_addrs.len());
    // The owner's complete MACHINE lookup names the receipt's machine where
    // the bounded one stops (FIX 8622).
    let lookup = oneiron_mesh_transport::iroh_transport::owner_machine_lookup(
        Arc::clone(server.vault()),
        owner,
    );
    transport
        .dial_address_attributed(&input.address, &input.alpn, Some(lookup))
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
