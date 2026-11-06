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
