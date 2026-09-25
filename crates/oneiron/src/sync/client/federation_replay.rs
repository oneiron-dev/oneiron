//! Durable inbound federation drain, entered on startup, receive and timer ticks.

use super::base::SyncClient;
use super::federated::map_federated_admission_err;
use crate::sync::WindowKey;
use crate::sync::federation_burst::{DeferredWork, FederationPeer, WorkKind};
use crate::sync::selector::{FederationAdmissionRole, admit_federated_window_update};
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
        // The grant and the local claim gate are read again at the actual
        // admission door. Stored raw bytes are not trusted replay authority.
        // Admission authors deterministic local op ids from these exact bytes.
        let admitted = admit_federated_window_update(&self.vault, &key, &work.payload, role)
            .map_err(map_federated_admission_err)?;
        let window = self.ensure_window(&work.window)?;
        self.import_accepted_window_update(&work.window, &window, &admitted)?;
        work.complete(&self.vault, &peer)
            .map_err(map_federated_admission_err)?;
        Ok(true)
    }
}
