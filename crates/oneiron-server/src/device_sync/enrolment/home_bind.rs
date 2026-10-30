//! The home's half of a device's mesh enrolment (FIX 3374, L02 04:5x). When
//! a machine link's redemption enrols a machine that sent its mesh identity,
//! the engine binds that endpoint and grants it the sync ALPN in the
//! redemption's own transaction (`Vault::redeem_pairing_link_with_mesh`).
//! This leaf names the ALPN, reads the home's own mesh address for the
//! device to dial, and words the receipt the redeem answer carries: the
//! binding it made, or the reason it made none. The pairing stands either
//! way.

use oneiron::authority::{MeshBindRefusal, MeshBindingIdentity, MeshEnrolment, MeshMachineAddress};
use serde::Serialize;

use crate::server::SyncServer;

/// The ALPN an enrolled machine is granted: sync.
#[cfg(feature = "mesh")]
pub(crate) fn enrolment_alpn() -> Option<&'static [u8]> {
    Some(oneiron_mesh_transport::SYNC_ALPN)
}

/// A build without the `mesh` feature runs no listener and binds nothing.
#[cfg(not(feature = "mesh"))]
pub(crate) fn enrolment_alpn() -> Option<&'static [u8]> {
    None
}

/// This home's own mesh address while its listener runs.
#[cfg(feature = "mesh")]
pub(crate) fn home_mesh_address(server: &SyncServer) -> Option<MeshMachineAddress> {
    let transport = server.mesh_transport.get()?;
    let addr = transport.addr();
    Some(MeshMachineAddress {
        endpoint_key: transport.id(),
        direct_addrs: addr.ip_addrs().copied().collect(),
        relay_url: addr.relay_urls().next().map(ToString::to_string),
    })
}

/// A build without the `mesh` feature has no listener and no address.
#[cfg(not(feature = "mesh"))]
pub(crate) fn home_mesh_address(_server: &SyncServer) -> Option<MeshMachineAddress> {
    None
}

/// The mesh identity a redeem body carries, read apart from the rest of it,
/// with the ALPN it is granted.
pub(crate) fn read_mesh_identity(
    raw: &serde_json::Value,
) -> Result<(MeshBindingIdentity, &'static [u8]), MeshRefusedReason> {
    let identity = serde_json::from_value(raw.clone()).map_err(|_| MeshRefusedReason::Malformed)?;
    let alpn = enrolment_alpn().ok_or(MeshRefusedReason::Unavailable)?;
    Ok((identity, alpn))
}

/// Why the home bound no mesh endpoint for the machine it enrolled.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MeshRefusedReason {
    /// The `mesh` field does not read as a mesh identity.
    Malformed,
    /// The identity names another MACHINE or key than the enrolled one.
    NotTheEnrolledMachine,
    /// A binding proof does not verify.
    BadProof,
    /// The binding or its grant was refused where it would land.
    BindRefused,
    /// This home runs no mesh.
    Unavailable,
}

impl From<MeshBindRefusal> for MeshRefusedReason {
    fn from(refusal: MeshBindRefusal) -> Self {
        match refusal {
            MeshBindRefusal::NotTheEnrolledMachine => Self::NotTheEnrolledMachine,
            MeshBindRefusal::BadProof => Self::BadProof,
            MeshBindRefusal::BindRefused => Self::BindRefused,
        }
    }
}

/// The mesh binding as the redeem answer names it.
#[derive(Debug, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub(crate) enum MeshBindReceipt {
    /// The endpoint is bound and holds the ALPN: on a fresh pairing slip,
    /// named here, or on the binding an earlier pairing made.
    Bound {
        machine: String,
        endpoint_key: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pairing_slip_id: Option<String>,
        alpn: String,
    },
    Refused {
        reason: MeshRefusedReason,
    },
}

impl MeshBindReceipt {
    /// The receipt of what the engine did for `alpn`.
    pub(crate) fn of(outcome: &MeshEnrolment, alpn: &[u8]) -> Self {
        match outcome {
            MeshEnrolment::Bound {
                machine,
                endpoint_key,
                pairing_slip_id,
            } => Self::granted(*machine, endpoint_key, Some(pairing_slip_id), alpn),
            MeshEnrolment::Regranted {
                machine,
                endpoint_key,
            }
            | MeshEnrolment::AlreadyGranted {
                machine,
                endpoint_key,
            } => Self::granted(*machine, endpoint_key, None, alpn),
            MeshEnrolment::Refused(refusal) => Self::Refused {
                reason: (*refusal).into(),
            },
        }
    }

    fn granted(
        machine: oneiron::EntityId,
        endpoint_key: &[u8; 32],
        pairing_slip_id: Option<&[u8; 32]>,
        alpn: &[u8],
    ) -> Self {
        Self::Bound {
            machine: machine.to_hex(),
            endpoint_key: hex(endpoint_key),
            pairing_slip_id: pairing_slip_id.map(|slip| hex(slip.as_slice())),
            alpn: String::from_utf8_lossy(alpn).into_owned(),
        }
    }

    /// The receipt of a redemption whose mesh identity `read` gave, and of
    /// what the engine did with it: a redemption that carried it to the
    /// engine always names an outcome.
    pub(crate) fn read(
        read: Result<(MeshBindingIdentity, &'static [u8]), MeshRefusedReason>,
        outcome: Option<&MeshEnrolment>,
    ) -> Self {
        match (read, outcome) {
            (Ok((_, alpn)), Some(outcome)) => Self::of(outcome, alpn),
            (Ok(_), None) => Self::Refused {
                reason: MeshRefusedReason::BindRefused,
            },
            (Err(reason), _) => Self::Refused { reason },
        }
    }

    /// Whether the endpoint is bound and holds the ALPN.
    pub(crate) fn bound(&self) -> bool {
        matches!(self, Self::Bound { .. })
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
