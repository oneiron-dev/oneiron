//! Paired client endpoints that expose no inbound application service.

use std::{net::SocketAddr, sync::Arc};

use iroh::RelayMap;

use super::{IrohTransport, PathRecorder};
use crate::{AcceptPolicy, MeshError, PathReceipts, transport_key::TransportKey};

impl IrohTransport {
    /// A paired client endpoint with no inbound application service. Outgoing
    /// dials keep `alpns` and the same live pairing policy and path receipts.
    pub async fn bind_outbound_paired(
        key: TransportKey,
        policy: AcceptPolicy,
        alpns: Vec<Vec<u8>>,
        bind_addr: SocketAddr,
        private_relays: Option<RelayMap>,
        receipts: Arc<dyn PathReceipts>,
    ) -> Result<Self, MeshError> {
        Self::bind_with(
            key.into_iroh_secret(),
            policy,
            alpns,
            bind_addr,
            private_relays,
            Some(PathRecorder::new(receipts)),
            true,
        )
        .await
    }
}
