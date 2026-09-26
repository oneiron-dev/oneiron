//! Vault-scoped mesh transport. The roster supplies addresses; a separate authority door
//! must authorize each key and ALPN. No transport or relay is itself a trust root.

use std::{future::Future, pin::Pin, sync::Arc};

pub use oneiron::authority::{MeshMachineAddress, MeshMachineAddressEnvelope};
use oneiron::{ErrorKind, Vault, entity_id::EntityId};

#[cfg(feature = "iroh")]
pub mod iroh_transport;
pub mod transport_key;

/// Protocol-neutral identifier of a MACHINE entity in this vault.
pub type MachineId = EntityId;
/// A boxed operation, so callers can select transports at runtime.
pub type MeshFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, MeshError>> + Send + 'a>>;

#[derive(Debug)]
pub enum MeshError {
    Refused,
    Unavailable,
    InvalidRoster,
    Io(String),
}

impl std::fmt::Display for MeshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for MeshError {}

/// Read-only, live source of vault MACHINE rows. Missing/deleted rows fail closed.
pub trait MachineRoster: Send + Sync + std::fmt::Debug {
    fn by_machine(&self, machine: MachineId) -> Result<Option<MeshMachineAddress>, MeshError>;
    fn by_endpoint(
        &self,
        endpoint_key: [u8; 32],
    ) -> Result<Option<(MachineId, MeshMachineAddress)>, MeshError>;
}

/// Fetches only MACHINE entities from the supplied vault, never DNS or a relay directory.
/// The MACHINE row has an address envelope but confers no grant: the verifier below is required.
#[derive(Clone)]
pub struct VaultMachineRoster(pub Arc<Vault>);
impl std::fmt::Debug for VaultMachineRoster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultMachineRoster")
    }
}

fn roster_error(error: oneiron::Error) -> MeshError {
    if error.kind() == ErrorKind::InvalidAuthorityLogBody {
        MeshError::InvalidRoster
    } else {
        MeshError::Io(error.to_string())
    }
}
impl MachineRoster for VaultMachineRoster {
    fn by_machine(&self, machine: MachineId) -> Result<Option<MeshMachineAddress>, MeshError> {
        self.0.mesh_machine(machine).map_err(roster_error)
    }
    fn by_endpoint(
        &self,
        endpoint_key: [u8; 32],
    ) -> Result<Option<(MachineId, MeshMachineAddress)>, MeshError> {
        self.0
            .mesh_machine_by_endpoint(endpoint_key)
            .map_err(roster_error)
    }
}

/// Production grant verifier. It never interprets a MACHINE address as authority.
#[derive(Clone)]
pub struct VaultMachineGrants(pub Arc<Vault>);
impl std::fmt::Debug for VaultMachineGrants {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultMachineGrants")
    }
}
impl MachineGrants for VaultMachineGrants {
    fn permits(&self, machine: MachineId, key: [u8; 32], alpn: &[u8]) -> Result<bool, MeshError> {
        self.0
            .mesh_grant_permits(machine, key, alpn)
            .map_err(|e| MeshError::Io(e.to_string()))
    }
}

/// Mandatory, trusted authority evaluation for the live MACHINE/key/ALPN tuple.
/// Implementations must check the current grant and revocation state, not a cached roster flag.
pub trait MachineGrants: Send + Sync + std::fmt::Debug {
    fn permits(&self, machine: MachineId, key: [u8; 32], alpn: &[u8]) -> Result<bool, MeshError>;
}

/// Performs a fresh roster lookup and mandatory grant check at every admission.
#[derive(Debug, Clone)]
pub struct AcceptPolicy {
    pub roster: Arc<dyn MachineRoster>,
    pub grants: Arc<dyn MachineGrants>,
}
impl AcceptPolicy {
    pub fn inbound(&self, key: [u8; 32], alpn: &[u8]) -> Result<MachineId, MeshError> {
        let (machine, _) = self.roster.by_endpoint(key)?.ok_or(MeshError::Refused)?;
        if !self.grants.permits(machine, key, alpn)? {
            return Err(MeshError::Refused);
        }
        Ok(machine)
    }
    pub fn outbound(
        &self,
        machine: MachineId,
        alpn: &[u8],
    ) -> Result<MeshMachineAddress, MeshError> {
        let row = self.roster.by_machine(machine)?.ok_or(MeshError::Refused)?;
        if !self.grants.permits(machine, row.endpoint_key, alpn)? {
            return Err(MeshError::Refused);
        }
        Ok(row)
    }
}

/// One bidirectional bounded message stream (send finishes the write half).
pub trait MeshStream: Send {
    fn send<'a>(&'a mut self, bytes: &'a [u8]) -> MeshFuture<'a, ()>;
    fn recv(&mut self) -> MeshFuture<'_, Vec<u8>>;
}
/// An authenticated peer connection. Opening multiple streams does not bypass admission.
pub trait MeshConnection: Send + Sync {
    fn machine(&self) -> MachineId;
    fn alpn(&self) -> &[u8];
    fn open_stream(&self) -> MeshFuture<'_, Box<dyn MeshStream>>;
    fn accept_stream(&self) -> MeshFuture<'_, Box<dyn MeshStream>>;
    fn close(&self);
}
/// Engine-side dial/accept seam. ALPN is selected by the caller, not by the relay.
pub trait MeshTransport: Send + Sync {
    fn dial(&self, machine: MachineId, alpn: &[u8]) -> MeshFuture<'_, Box<dyn MeshConnection>>;
    fn accept(&self) -> MeshFuture<'_, Box<dyn MeshConnection>>;
}
