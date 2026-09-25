//! Vault-scoped mesh transport. The roster supplies addresses; a separate authority door
//! must authorize each key and ALPN. No transport or relay is itself a trust root.

use std::{future::Future, net::SocketAddr, pin::Pin, sync::Arc};

use oneiron::{Vault, entity_id::EntityId, registry::ENTITY_TYPE_MACHINE};
use serde::{Deserialize, Serialize};

#[cfg(feature = "iroh")]
pub mod iroh_transport;

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

/// Network hints stored on a MACHINE. These bytes are never authorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineAddress {
    pub endpoint_key: [u8; 32],
    pub direct_addrs: Vec<SocketAddr>,
    /// Optional home relay, usable only if it is in this endpoint's private relay map.
    pub relay_url: Option<String>,
}

/// Explicitly tagged address-only MACHINE envelope. Other existing MACHINE
/// actors (calendar, connectors, etc.) are not transport roster members.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineAddressEnvelope {
    pub domain: String,
    pub version: u8,
    pub address: MachineAddress,
}
impl MachineAddressEnvelope {
    pub const DOMAIN: &'static str = "oneiron/mesh-machine/v1";
    pub fn new(address: MachineAddress) -> Self {
        Self {
            domain: Self::DOMAIN.into(),
            version: 1,
            address,
        }
    }
}

/// Read-only, live source of vault MACHINE rows. Missing/deleted rows fail closed.
pub trait MachineRoster: Send + Sync + std::fmt::Debug {
    fn by_machine(&self, machine: MachineId) -> Result<Option<MachineAddress>, MeshError>;
    fn by_endpoint(
        &self,
        endpoint_key: [u8; 32],
    ) -> Result<Option<(MachineId, MachineAddress)>, MeshError>;
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

impl VaultMachineRoster {
    fn read(&self, id: MachineId) -> Result<Option<MachineAddress>, MeshError> {
        // `get_raw` reads type and body from ONE vault snapshot. Separate
        // `get_entity_type` and `get` transactions could straddle a rewrite.
        // The engine's current EntityMetadataHeader is 25 bytes; the typed
        // single-snapshot read door belongs with the MACHINE grant cut.
        const RAW_BODY_OFFSET: usize = 25;
        let Some(raw) = self
            .0
            .get_raw(&id)
            .map_err(|e| MeshError::Io(e.to_string()))?
        else {
            return Ok(None);
        };
        if raw.first() != Some(&ENTITY_TYPE_MACHINE) {
            return Ok(None);
        }
        let body = raw.get(RAW_BODY_OFFSET..).ok_or(MeshError::InvalidRoster)?;
        // `get_raw` includes stored metadata; `get` additionally excludes an
        // erased/stale body. A concurrent rewrite must not change the body we
        // just type-checked. Grants are separately rechecked at admission.
        if self
            .0
            .get(&id)
            .map_err(|e| MeshError::Io(e.to_string()))?
            .as_deref()
            != Some(body)
        {
            return Ok(None);
        }
        let Ok(envelope) = rmp_serde::from_slice::<MachineAddressEnvelope>(body) else {
            return Ok(None); // not one of this vault's versioned transport rows
        };
        if envelope.domain != MachineAddressEnvelope::DOMAIN || envelope.version != 1 {
            return Ok(None);
        }
        if envelope.address.direct_addrs.len() > 32 {
            return Err(MeshError::InvalidRoster);
        }
        Ok(Some(envelope.address))
    }
}
impl MachineRoster for VaultMachineRoster {
    fn by_machine(&self, machine: MachineId) -> Result<Option<MachineAddress>, MeshError> {
        self.read(machine)
    }
    fn by_endpoint(
        &self,
        endpoint_key: [u8; 32],
    ) -> Result<Option<(MachineId, MachineAddress)>, MeshError> {
        // Bound hostile handshake work even when a vault has many non-transport MACHINE actors.
        const MAX_MACHINE_ROWS: usize = 1024;
        let ids = self
            .0
            .entities_by_type_page(ENTITY_TYPE_MACHINE, None, MAX_MACHINE_ROWS + 1)
            .map_err(|e| MeshError::Io(e.to_string()))?;
        if ids.len() > MAX_MACHINE_ROWS {
            return Err(MeshError::InvalidRoster);
        }
        let mut found = None;
        for id in ids {
            if let Some(row) = self.read(id)?
                && row.endpoint_key == endpoint_key
            {
                if found.is_some() {
                    return Err(MeshError::InvalidRoster);
                }
                found = Some((id, row));
            }
        }
        Ok(found)
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
    pub fn outbound(&self, machine: MachineId, alpn: &[u8]) -> Result<MachineAddress, MeshError> {
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
