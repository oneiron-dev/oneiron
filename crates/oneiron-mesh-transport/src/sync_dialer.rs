//! The sync client's carrier to its home machine over the mesh (OF-535). Set
//! a [`MeshSyncDialer`] as `SyncClientConfig::mesh_dialer` and the steady
//! socket and every residence socket ride the paired home's connection; the
//! upgrade, its slip and machine proofs are the bytes they are on TCP. Each
//! dial asks its resolver which home it targets, so a dialer that follows
//! the elected home dials it from the next attempt on (FIX 3131).

use std::sync::Arc;

use oneiron::sync::{SyncDial, SyncDialer, SyncStream};

use crate::{MachineId, MeshError, MeshTransport, SYNC_ALPN};

/// The home MACHINE one dial targets, asked once per attempt.
pub type HomeResolver = Arc<dyn Fn() -> MachineId + Send + Sync>;

/// Dials the home MACHINE by its roster key on [`SYNC_ALPN`] and opens the one
/// stream a sync socket rides. The transport's policy admits the home: build
/// it with [`crate::PairedMachineGrants`].
pub struct MeshSyncDialer {
    transport: Arc<dyn MeshTransport>,
    home: HomeResolver,
}

impl std::fmt::Debug for MeshSyncDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The home is resolved per dial, so none is shown here.
        f.debug_struct("MeshSyncDialer").finish_non_exhaustive()
    }
}

impl MeshSyncDialer {
    /// Dials `home` on every attempt.
    pub fn new(transport: Arc<dyn MeshTransport>, home: MachineId) -> Self {
        Self::resolving(transport, Arc::new(move || home))
    }

    /// Dials the home `home` resolves at each attempt (FIX 3131): the steady
    /// socket, each residence socket and each request on the carrier capture
    /// their own.
    pub fn resolving(transport: Arc<dyn MeshTransport>, home: HomeResolver) -> Self {
        Self { transport, home }
    }

    /// Binds this install's own endpoint on `bind_addr` for sync and dials
    /// `home` through it: the transport key derives from this install's
    /// machine key, and only the paired machine `home` names is admitted.
    /// Each dial leaves a path receipt in the vault. Refused before the
    /// install has a machine id.
    #[cfg(feature = "iroh")]
    pub async fn bind_for_install(
        vault: Arc<oneiron::Vault>,
        home: MachineId,
        bind_addr: std::net::SocketAddr,
        relays: &[String],
    ) -> Result<Self, MeshError> {
        let (_, key) = crate::transport_key::TransportKey::for_install(&vault)?
            .ok_or(MeshError::Unavailable)?;
        let policy = crate::AcceptPolicy {
            roster: Arc::new(crate::VaultMachineRoster(Arc::clone(&vault))),
            grants: Arc::new(crate::PairedMachineGrants(Arc::clone(&vault))),
        };
        let transport = crate::iroh_transport::IrohTransport::bind_paired(
            key,
            policy,
            vec![SYNC_ALPN.to_vec()],
            bind_addr,
            crate::iroh_transport::private_relay_map(relays)?,
            Arc::new(crate::VaultPathReceipts(vault)),
        )
        .await?;
        Ok(Self::new(Arc::new(transport), home))
    }
}

fn io_error(error: MeshError) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

impl SyncDialer for MeshSyncDialer {
    fn dial(&self) -> SyncDial<'_> {
        Box::pin(async move {
            let home = (self.home)();
            let connection = self
                .transport
                .dial(home, SYNC_ALPN)
                .await
                .map_err(io_error)?;
            let stream = connection.open_duplex().await.map_err(io_error)?;
            Ok(Box::new(stream) as Box<dyn SyncStream>)
        })
    }
}
