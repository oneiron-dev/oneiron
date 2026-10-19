//! The shared authenticated handshake used by a paired dial and by the
//! owner's explicit-address admission attempt. The latter returns no stream
//! or connection: it cannot turn an address into application authority.
use super::*;

/// A transport-only acknowledgement, sent after the live inbound gate.
/// It occupies a unidirectional stream, never an application's duplex stream.
pub(super) const ADMISSION: &[u8] = b"oneiron/mesh-admitted/1";

impl IrohTransport {
    /// One authenticated handshake, followed by the remote gate's admission
    /// acknowledgement. TLS completion alone does not mean the peer admitted us.
    async fn connect_endpoint(
        &self,
        address: EndpointAddr,
        alpn: &[u8],
    ) -> Result<Connection, MeshError> {
        if alpn.is_empty() || alpn.len() > 255 {
            return Err(MeshError::Refused);
        }
        let connection = self
            .endpoint
            .connect(address, alpn)
            .await
            .map_err(|error| MeshError::Io(error.to_string()))?;
        let mut accepted = connection
            .accept_uni()
            .await
            .map_err(|_| MeshError::Refused)?;
        let acknowledgement = accepted
            .read_to_end(ADMISSION.len())
            .await
            .map_err(|_| MeshError::Refused)?;
        if acknowledgement != ADMISSION {
            connection.close(0u32.into(), b"admission refused");
            return Err(MeshError::Refused);
        }
        Ok(connection)
    }

    /// Dial an explicit private address with this endpoint's real identity.
    /// This works before the peer pairs us, so its ordinary inbound gate can
    /// refuse the attempt. No application stream is opened, no local grant is
    /// minted, and no connection escapes, even if the peer admits the handshake.
    /// A relay must already be in this transport's configured private map.
    pub async fn dial_address(
        &self,
        address: &crate::MeshMachineAddress,
        alpn: &[u8],
    ) -> Result<MeshPathReceipt, MeshError> {
        if address.direct_addrs.len() > 32 || alpn.is_empty() || alpn.len() > 255 {
            return Err(MeshError::InvalidRoster);
        }
        let key =
            EndpointId::from_bytes(&address.endpoint_key).map_err(|_| MeshError::InvalidRoster)?;
        let mut target = EndpointAddr::from_parts(
            key,
            address
                .direct_addrs
                .iter()
                .copied()
                .map(iroh::TransportAddr::Ip),
        );
        if let Some(raw) = &address.relay_url {
            let relay: iroh::RelayUrl = raw.parse().map_err(|_| MeshError::InvalidRoster)?;
            if !self.allowed_relays.contains(&relay) {
                return Err(MeshError::Refused);
            }
            target = target.with_relay_url(relay);
        }
        let mut receipt = match self.connect_endpoint(target, alpn).await {
            Ok(connection) => {
                let mut receipt = MeshPathReceipt::new(
                    MeshPathDirection::Outbound,
                    MeshPathOutcome::Admitted,
                    alpn,
                );
                note_open_paths(&mut receipt, &connection);
                connection.close(0u32.into(), b"dial complete");
                receipt.closed_at_ms = Some(unix_millis());
                receipt
            }
            Err(error) => {
                let outcome = match &error {
                    MeshError::Refused => MeshPathOutcome::Refused,
                    _ => MeshPathOutcome::Failed,
                };
                attempt(
                    MeshPathDirection::Outbound,
                    outcome,
                    alpn,
                    Some(address.endpoint_key),
                    &error,
                )
            }
        };
        receipt.endpoint_key = Some(key_hex(address.endpoint_key));
        receipt.machine = self
            .policy
            .roster
            .by_endpoint(address.endpoint_key)?
            .map(|(machine, _)| machine.to_hex());
        let recorder = self.receipts.as_ref().ok_or(MeshError::Unavailable)?;
        receipt.id = write_receipt(&recorder.sink, &receipt)
            .await
            .ok_or_else(|| MeshError::Io("mesh path receipt could not be retained".into()))?;
        Ok(receipt)
    }
}

impl MeshTransport for IrohTransport {
    fn dial(&self, machine: MachineId, alpn: &[u8]) -> MeshFuture<'_, Box<dyn MeshConnection>> {
        let alpn = alpn.to_vec();
        Box::pin(async move {
            if !self.alpns.contains(&alpn) {
                return Err(MeshError::Refused);
            }
            let row = match self.policy.outbound(machine, &alpn) {
                Ok(row) => row,
                Err(error) => {
                    let receipt = attempt(
                        MeshPathDirection::Outbound,
                        MeshPathOutcome::Refused,
                        &alpn,
                        None,
                        &error,
                    );
                    self.dial_refused(machine, receipt, None);
                    return Err(error);
                }
            };
            let key =
                EndpointId::from_bytes(&row.endpoint_key).map_err(|_| MeshError::InvalidRoster)?;
            // Key only: addresses must be resolved by our private roster lookup.
            let connection = match self.connect_endpoint(EndpointAddr::new(key), &alpn).await {
                Ok(connection) => connection,
                Err(error) => {
                    let outcome = match &error {
                        MeshError::Refused => MeshPathOutcome::Refused,
                        _ => MeshPathOutcome::Failed,
                    };
                    let receipt = attempt(
                        MeshPathDirection::Outbound,
                        outcome,
                        &alpn,
                        Some(row.endpoint_key),
                        &error,
                    );
                    self.dial_refused(machine, receipt, None);
                    return Err(error);
                }
            };
            if connection.remote_id() != key {
                let receipt = attempt(
                    MeshPathDirection::Outbound,
                    MeshPathOutcome::Refused,
                    &alpn,
                    Some(*connection.remote_id().as_bytes()),
                    &MeshError::Refused,
                );
                self.dial_refused(machine, receipt, Some(&connection));
                return Err(MeshError::Refused);
            }
            let admitted = IrohConnection {
                machine,
                alpn,
                inner: connection,
                policy: self.policy.clone(),
                incoming: false,
            };
            if let Err(error) = admitted.check() {
                let receipt = attempt(
                    MeshPathDirection::Outbound,
                    MeshPathOutcome::Refused,
                    &admitted.alpn,
                    Some(row.endpoint_key),
                    &error,
                );
                self.dial_refused(machine, receipt, Some(&admitted.inner));
                return Err(error);
            }
            if let Some(receipts) = &self.receipts {
                let receipt = admission(
                    MeshPathDirection::Outbound,
                    &admitted.alpn,
                    machine,
                    row.endpoint_key,
                );
                receipts.admitted(receipt, &admitted.inner);
            }
            Ok(Box::new(admitted) as Box<dyn MeshConnection>)
        })
    }
    fn accept(&self) -> MeshFuture<'_, Box<dyn MeshConnection>> {
        Box::pin(async move {
            let (machine, alpn, inner) = self
                .accepted
                .lock()
                .await
                .recv()
                .await
                .ok_or(MeshError::Unavailable)?;
            let admitted = IrohConnection {
                machine,
                alpn,
                inner,
                policy: self.policy.clone(),
                incoming: true,
            };
            // A queued connection does not outlive a grant revoke.
            admitted.check()?;
            Ok(Box::new(admitted) as Box<dyn MeshConnection>)
        })
    }
}
