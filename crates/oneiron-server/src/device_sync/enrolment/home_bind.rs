//! The home's half of a device's mesh enrolment (FIX 3374). When a machine
//! link's redemption enrols a machine, the home binds that machine's mesh
//! endpoint and grants it the sync ALPN, through the engine operations the
//! owner's mesh doors call (`vault.mesh.bind_machine`,
//! `vault.mesh.set_alpn_grant`), and answers its own mesh address for the
//! device to dial.
//!
//! The binding stands on a pairing slip the home mints for the MACHINE
//! itself: the enrolment slip cannot serve, as its holder is the link's actor
//! and its key the connection key, where the binding needs the MACHINE as
//! holder and the machine key its enrolment request proved. The slip carries
//! the sync ALPN alone. The device's own two proofs bind its endpoint key.

use oneiron::authority::{MachineEnrolmentRequest, MeshBindingIdentity, MeshMachineAddress};

use crate::server::SyncServer;

/// How long the pairing an enrolled machine's mesh binding stands on runs:
/// the longest a mesh ALPN grant runs, so the sync grant it carries is never
/// cut short by it.
#[cfg(feature = "mesh")]
const ENROLLED_PAIRING_SECS: u64 = 365 * 24 * 60 * 60;

/// Binds the mesh endpoint `identity` names for the machine `request`
/// enrolled, and grants it the sync ALPN; a machine already granted keeps its
/// grant. Returns this home's own mesh address when its listener runs. A
/// binding that fails is logged, and the enrolment stands without it.
#[cfg(feature = "mesh")]
pub(crate) fn bind_enrolled_machine(
    server: &SyncServer,
    request: &MachineEnrolmentRequest,
    identity: &MeshBindingIdentity,
) -> Option<MeshMachineAddress> {
    let bound = match server.host_issuer() {
        Some(issuer) => bind(server.vault(), issuer, request, identity),
        None => Err(anyhow::anyhow!("this host holds no slip issuer")),
    };
    if let Err(error) = bound {
        tracing::warn!(
            machine = %request.machine.to_hex(),
            error = %format!("{error:#}"),
            "pairing: the enrolled machine's mesh endpoint was not bound"
        );
    }
    let transport = server.mesh_transport.get()?;
    let addr = transport.addr();
    Some(MeshMachineAddress {
        endpoint_key: transport.id(),
        direct_addrs: addr.ip_addrs().copied().collect(),
        relay_url: addr.relay_urls().next().map(ToString::to_string),
    })
}

/// A build without the `mesh` feature runs no listener: it binds nothing.
#[cfg(not(feature = "mesh"))]
pub(crate) fn bind_enrolled_machine(
    _server: &SyncServer,
    _request: &MachineEnrolmentRequest,
    _identity: &MeshBindingIdentity,
) -> Option<MeshMachineAddress> {
    None
}

/// [`bind_enrolled_machine`]'s engine writes: the grant again on a binding
/// that stands, else a fresh pairing, its binding and the grant. A pairing
/// whose binding is refused is revoked, as it serves nothing.
#[cfg(feature = "mesh")]
fn bind(
    vault: &oneiron::Vault,
    issuer: &oneiron::authority::HostSlipIssuer,
    request: &MachineEnrolmentRequest,
    identity: &MeshBindingIdentity,
) -> anyhow::Result<()> {
    use std::collections::BTreeSet;

    use oneiron::federation::{Scope, ScopeAxis};
    use oneiron_mesh_transport::SYNC_ALPN;
    use rand_core::RngCore;

    anyhow::ensure!(
        identity.machine == request.machine && identity.device_key == request.machine_key,
        "the mesh identity is not the enrolled machine's"
    );
    let (machine, endpoint_key) = (request.machine, identity.endpoint_key);
    if vault.mesh_grant_permits(machine, endpoint_key, SYNC_ALPN)? {
        return Ok(());
    }
    let regranted = vault
        .mesh_machine(machine)?
        .is_some_and(|row| row.endpoint_key == endpoint_key)
        && vault
            .set_mesh_alpn_grant(issuer, machine, endpoint_key, SYNC_ALPN, true)
            .is_ok();
    if regranted {
        return Ok(());
    }
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from([mesh_alpn_verb(SYNC_ALPN)]));
    let mut slip_id = [0; 32];
    rand_core::OsRng.fill_bytes(&mut slip_id);
    let now = vault.capability_slip_now()?;
    let pairing = vault.mint_capability_slip(
        issuer,
        oneiron::authority::SlipClaims {
            slip_id,
            vault_id: request.vault_id,
            parent_id: None,
            holder_ref: machine.to_hex(),
            binding_key: request.machine_key,
            scope,
            issued_at: now,
            expires_at: now.saturating_add(ENROLLED_PAIRING_SECS),
            ttl_secs: ENROLLED_PAIRING_SECS,
            single_use: false,
            records: Default::default(),
            channels: Default::default(),
            actor_class: None,
            org_ref: None,
            grant_ref: None,
            invitation_ref: None,
            delegation: None,
            comm: None,
        },
    )?;
    let address = MeshMachineAddress {
        endpoint_key,
        direct_addrs: Vec::new(),
        relay_url: None,
    };
    if let Err(error) = vault.bind_mesh_machine(
        issuer,
        machine,
        address,
        request.machine_key,
        pairing.claims.slip_id,
        [
            identity.device_proof.as_slice(),
            identity.transport_proof.as_slice(),
        ],
    ) {
        let _ = vault.revoke_capability_slip(issuer, pairing.claims.slip_id);
        return Err(error.into());
    }
    vault.set_mesh_alpn_grant(issuer, machine, endpoint_key, SYNC_ALPN, true)?;
    Ok(())
}

/// The verb a mesh ALPN grant carries, as the engine spells it
/// (`authority::mesh_machine`): `mesh:alpn:` and the ALPN in lower-case hex.
#[cfg(feature = "mesh")]
fn mesh_alpn_verb(alpn: &[u8]) -> String {
    let hex: String = alpn.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("mesh:alpn:{hex}")
}
