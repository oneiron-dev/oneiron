//! In-memory home CLAIM copy holders for the actual raw update import.

use std::sync::Arc;

use super::base::SyncClient;
use super::own_device::OwnDeviceImport;
use crate::EntityId;
pub(super) use crate::embed::home_vectors::copy_scope::with_home_claim_copies;
use crate::embed::home_vectors::retained_copy::PreparedHomeClaimCopy;
use crate::sync::transport::TransportError;
use crate::sync::types::WindowKey;
use crate::sync::window::LoadedWindow;

pub(in crate::sync::client) type HomeClaimCopies = Vec<Arc<PreparedHomeClaimCopy>>;

/// Keeps the original sender and actual native leases through deferral and heal.
/// Dropping this unacknowledged update releases its holders; it is not a receipt.
#[derive(Clone)]
pub(crate) struct StagedWorldUpdate {
    pub(crate) key: WindowKey,
    pub(crate) bytes: Vec<u8>,
    pub(crate) from: crate::authority::PeerMachine,
    pub(crate) copies: Vec<Arc<PreparedHomeClaimCopy>>,
    /// Original wire bytes, before native repo-copy translation; data only.
    pub(crate) copy_delivery: Option<[u8; 32]>,
}

impl SyncClient {
    pub(super) fn retain_late_window_home_claim_copies(
        &mut self,
        key: &WindowKey,
        envelope: crate::sync::transport::ReceivedWindowPadEnvelope,
    ) {
        if self.config.federation_peer.is_some() {
            return;
        }
        let copies = self.vault.prepare_relayed_home_claim_copy_bytes(
            self.home_peer,
            &crate::embed::home_vectors::HomeClaimDelivery {
                window: key.as_str(),
                payload: &envelope.payload,
            },
            &envelope.home_claim_copies,
        );
        if copies.is_empty() {
            return;
        }
        let digest = *blake3::hash(&envelope.payload).as_bytes();
        let mut attached = false;
        for deferred in &mut self.deferred_sealed_updates {
            if deferred.key == *key
                && deferred.from == self.home_peer
                && deferred.envelope.payload == envelope.payload
            {
                deferred.copies.extend(copies.iter().cloned());
                attached = true;
            }
        }
        for staged in &mut self.staged_world_updates {
            if staged.key == *key
                && staged.from == self.home_peer
                && staged.copy_delivery == Some(digest)
            {
                staged.copies.extend(copies.iter().cloned());
                attached = true;
            }
        }
        if !attached {
            crate::embed::home_vectors::copy_scope::retain_pending_copies(
                &self.vault,
                key,
                &copies,
            );
        }
    }

    pub(in crate::sync::client) fn import_accepted_window_update_with_evidence(
        &mut self,
        window_key: &str,
        window: &LoadedWindow,
        payload: &[u8],
        evidence: &std::collections::HashMap<EntityId, (WindowKey, Vec<u8>)>,
        own_device: Option<&OwnDeviceImport>,
    ) -> std::result::Result<(), TransportError> {
        self.import_accepted_window_update_with_copies(
            window_key,
            window,
            payload,
            evidence,
            own_device,
            &[],
        )
    }

    pub(in crate::sync::client) fn import_accepted_window_update_with_copies(
        &mut self,
        window_key: &str,
        window: &LoadedWindow,
        payload: &[u8],
        evidence: &std::collections::HashMap<EntityId, (WindowKey, Vec<u8>)>,
        own_device: Option<&OwnDeviceImport>,
        copies: &[Arc<PreparedHomeClaimCopy>],
    ) -> std::result::Result<(), TransportError> {
        let vault = Arc::clone(&self.vault);
        with_home_claim_copies(&vault, &window.key, copies, || {
            self.land_accepted_window_update_with_evidence(
                window_key, window, payload, evidence, own_device,
            )
        })
    }
}
