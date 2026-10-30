//! The shared authenticated handshake used by a paired dial and by the
//! owner's explicit-address admission attempt. The latter returns no stream
//! or connection: it cannot turn an address into application authority.
use std::collections::VecDeque;

use super::*;

/// A transport-only acknowledgement, sent after the live inbound gate.
/// It occupies a unidirectional stream, never an application's duplex stream.
pub(super) const ADMISSION: &[u8] = b"oneiron/mesh-admitted/1";

/// The owner's complete MACHINE lookup by endpoint key (FIX 8622): every
/// MACHINE row, however many, read under the owner's proof, where the
/// lookup any key may make stops at its bound. One lookup serves a dial's
/// receipt and the receipts earlier lookups left unattributed (FIX 11153).
pub type OwnerMachineLookup =
    Box<dyn Fn([u8; 32]) -> Result<Option<MachineId>, MeshError> + Send>;

/// The receipts a failed lookup left with an unknown MACHINE, each with the
/// endpoint key it names, oldest first, for the owner's next lookup to
/// attribute (FIX 11153).
pub(super) type Unattributed = StdMutex<VecDeque<([u8; 32], MeshPathReceipt)>>;

/// How many unattributed receipts wait for the owner's next lookup; past
/// it the oldest keeps its unknown MACHINE.
const UNATTRIBUTED_KEPT: usize = 64;

impl PathRecorder {
    fn keep_unattributed(&self, receipts: impl IntoIterator<Item = ([u8; 32], MeshPathReceipt)>) {
        let mut kept = self.unattributed.lock().unwrap_or_else(PoisonError::into_inner);
        kept.extend(receipts);
        while kept.len() > UNATTRIBUTED_KEPT {
            kept.pop_front();
        }
    }

    fn take_unattributed(&self) -> VecDeque<([u8; 32], MeshPathReceipt)> {
        std::mem::take(&mut *self.unattributed.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

/// [`OwnerMachineLookup`] through `vault`'s owner door, under `owner`'s proof
/// (`Vault::mesh_machine_by_endpoint_as_owner`).
pub fn owner_machine_lookup(
    vault: Arc<oneiron::Vault>,
    owner: oneiron::consent::AuthenticatedOwner,
) -> OwnerMachineLookup {
    Box::new(move |key| {
        vault
            .mesh_machine_by_endpoint_as_owner(&owner, key)
            .map(|found| found.map(|(machine, _)| machine))
            .map_err(crate::roster_error)
    })
}

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
        self.dial_address_attributed(address, alpn, None).await
    }

    /// [`Self::dial_address`] for the owner's diagnostic (FIX 8622). The
    /// completed dial's receipt is written first, naming the MACHINE the
    /// bounded lookup any key may make finds, or none when that lookup stops
    /// at its bound. `owner_lookup` then reads every MACHINE and the same
    /// receipt is written again with the one it names. Without it, or when it
    /// fails, the receipt keeps its unknown MACHINE and the lookup's error is
    /// returned; the receipt waits, and the owner's next lookup attributes it
    /// with that dial's own (FIX 11153).
    pub async fn dial_address_attributed(
        &self,
        address: &crate::MeshMachineAddress,
        alpn: &[u8],
        owner_lookup: Option<OwnerMachineLookup>,
    ) -> Result<MeshPathReceipt, MeshError> {
        // Every direct address the owner names is dialed (Phase2 A, FIX 7922);
        // the ALPN's own 1..255-byte bound stays.
        if alpn.is_empty() || alpn.len() > 255 {
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
        let bounded = self.policy.roster.by_endpoint(address.endpoint_key);
        receipt.machine = bounded
            .as_ref()
            .ok()
            .and_then(Option::as_ref)
            .map(|(machine, _)| machine.to_hex());
        let recorder = self.receipts.as_ref().ok_or(MeshError::Unavailable)?;
        let retained = || MeshError::Io("mesh path receipt could not be retained".into());
        receipt.id = write_receipt(&recorder.sink, &receipt)
            .await
            .ok_or_else(retained)?;
        let mut due: Vec<_> = bounded
            .is_err()
            .then(|| (address.endpoint_key, receipt.clone(), true))
            .into_iter()
            .collect();
        let Some(lookup) = owner_lookup else {
            recorder.keep_unattributed(due.into_iter().map(|(key, kept, _)| (key, kept)));
            return bounded.map(|_| receipt);
        };
        due.extend(
            recorder
                .take_unattributed()
                .into_iter()
                .map(|(key, kept)| (key, kept, false)),
        );
        let looked = tokio::task::spawn_blocking(move || {
            due.into_iter()
                .map(|(key, kept, current)| (lookup(key), key, kept, current))
                .collect::<Vec<_>>()
        })
        .await
        .map_err(|error| MeshError::Io(error.to_string()))?;
        let mut outcome = Ok(());
        let mut still = Vec::new();
        for (found, key, mut kept, current) in looked {
            let error = match found {
                Ok(None) => continue,
                Ok(Some(machine)) => {
                    kept.machine = Some(machine.to_hex());
                    if write_receipt(&recorder.sink, &kept).await.is_some() {
                        if current {
                            receipt = kept;
                        }
                        continue;
                    }
                    retained()
                }
                Err(error) => error,
            };
            if current {
                outcome = Err(error);
            }
            still.push((key, kept));
        }
        recorder.keep_unattributed(still);
        outcome.map(|()| receipt)
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
            let (machine, alpn, inner) = self.admissions.next().await?;
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
