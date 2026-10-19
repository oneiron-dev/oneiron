//! Durable inbound federation drain, entered on startup, receive and timer ticks.

use super::base::SyncClient;
use super::federated::map_federated_admission_err;
use crate::sync::WindowKey;
use crate::sync::federation_burst::{DeferredWork, FederationPeer, WorkKind};
use crate::sync::selector::{FederationAdmissionRole, admit_peer_window_update_as};
use crate::sync::transport::TransportError;

impl SyncClient {
    /// Binds the authenticated transport's peer/grant and resumes durable work.
    /// The caller must authenticate the principal before making this context.
    /// No credential, selector member field, or CRDT peer id is inferred here.
    pub fn bind_federation_peer(&mut self, peer: FederationPeer) -> Result<(), TransportError> {
        peer.revalidate(&self.vault)
            .map_err(map_federated_admission_err)?;
        self.config.federation_peer = Some(peer);
        self.replay_deferred_federation_update()?;
        Ok(())
    }

    /// Automatically retries one retained inbound update without another rate
    /// debit. The connection loop calls this on its housekeeping tick; custom
    /// transports may call the same door. Startup and incoming frames also drain.
    /// Returns true only after the update is durable and its queue row is gone.
    pub fn replay_deferred_federation_update(&mut self) -> Result<bool, TransportError> {
        let Some(peer) = self.config.federation_peer.clone() else {
            return Ok(false);
        };
        let Some(work) =
            DeferredWork::next_update(&self.vault, &peer).map_err(map_federated_admission_err)?
        else {
            return Ok(false);
        };
        self.replay_federation_work(&peer, work)
    }

    /// Retries exactly one retained batch, without a second rate debit.
    /// A still-isolated batch stays pending until recovery or owner release.
    pub fn replay_federation_burst(
        &mut self,
        batch_ref: &str,
    ) -> Result<crate::sync::federation_burst::FederationBurstReceipt, TransportError> {
        let peer = self
            .config
            .federation_peer
            .clone()
            .ok_or(TransportError::InvalidPayload("federation peer unbound"))?;
        let id = crate::deletion::parse_hex::<32>(batch_ref)
            .ok_or(TransportError::InvalidPayload("invalid batch_ref"))?;
        let receipt = self
            .vault
            .federation_burst_disposition(&peer, batch_ref)
            .map_err(map_federated_admission_err)?;
        if receipt.state == crate::sync::federation_burst::FederationBurstWorkState::Pending {
            if let Some(work) = DeferredWork::update_by_id(&self.vault, &peer, &id)
                .map_err(map_federated_admission_err)?
            {
                self.replay_federation_work(&peer, work)?;
            }
        }
        self.vault
            .federation_burst_disposition(&peer, batch_ref)
            .map_err(map_federated_admission_err)
    }

    fn replay_federation_work(
        &mut self,
        peer: &FederationPeer,
        work: DeferredWork,
    ) -> Result<bool, TransportError> {
        let role = match work.kind {
            WorkKind::MemberUpdate => FederationAdmissionRole::Member,
            WorkKind::GuestUpdate => FederationAdmissionRole::Guest,
            WorkKind::Selector => {
                return Err(TransportError::InvalidPayload(
                    "selector is not an inbound update",
                ));
            }
        };
        let key = WindowKey::try_new(&work.window).ok_or(TransportError::InvalidWindowKey)?;
        // The peer's standing is read again too (FIX 360). No standing
        // refuses the update and leaves its row held, as a lapsed grant does.
        let standing = peer
            .membership(&self.vault)
            .map_err(map_federated_admission_err)?;
        // The grant and the local claim gate are read again at the actual
        // admission door. Stored raw bytes are not trusted replay authority.
        // Admission authors deterministic local op ids from these exact bytes,
        // and the pact the grant delivers through is read again too (FIX 3497).
        let delivery = self.pact_delivery(peer.grant())?;
        let admitted = match admit_peer_window_update_as(
            &self.vault,
            &key,
            &work.payload,
            role,
            (peer.principal(), standing),
            delivery.as_ref(),
        ) {
            Ok(admitted) => admitted,
            Err(error) => {
                // Refused as the peer's own bytes, as a live update would
                // be (an agent definition turned off since it was held):
                // the row settles, so the work behind it drains.
                let error = map_federated_admission_err(error);
                if matches!(error, TransportError::InvalidPayload(_)) {
                    work.reject(&self.vault, peer)
                        .map_err(map_federated_admission_err)?;
                }
                return Err(error);
            }
        };
        let vault = std::sync::Arc::clone(&self.vault);
        crate::sync::federation_burst::with_import_guard(
            &vault,
            peer,
            &work.id,
            &work.authority_digest,
            || self.import_peer_update(&admitted, peer.grant(), delivery),
        )?;
        work.complete(&self.vault, peer)
            .map_err(map_federated_admission_err)?;
        Ok(true)
    }
    /// Replays only an already retained, authenticated batch. The owner's
    /// proof and the original grant remain guards on every write it makes.
    pub fn replay_federation_burst_as_owner(
        manager: &std::sync::Arc<crate::sync::WindowManager>,
        owner: &crate::consent::AuthenticatedOwner,
        input: crate::sync::federation_burst::FederationBurstReplayRequest,
    ) -> crate::Result<crate::sync::federation_burst::FederationBurstReceipt> {
        let peer = input
            .peer
            .authorize(manager.vault())?
            .with_owner(manager.vault(), owner)?;
        let (mut client, _events) = Self::new(std::sync::Arc::clone(manager), Default::default())?;
        client.config.federation_peer = Some(peer);
        client
            .replay_federation_burst(&input.batch_ref)
            .map_err(burst_transport_error)
    }
}

fn burst_transport_error(error: TransportError) -> crate::Error {
    match error {
        TransportError::AdmissionDenied(denial) => crate::error::GateError::GateWriteRejected {
            outcome: denial.outcome().as_str(),
            reason_codes: denial
                .reason_codes()
                .iter()
                .map(|reason| reason.as_str())
                .collect(),
        }
        .into(),
        other => crate::Error::InvalidConfig(other.to_string()),
    }
}
