//! In-memory home CLAIM copy holders for the actual raw update import.

use std::sync::Arc;

use super::base::SyncClient;
use super::own_device::OwnDeviceImport;
use crate::embed::home_vectors::copy_scope::with_copies;
use crate::embed::home_vectors::retained::PreparedHomeClaimResponse;
use crate::sync::transport::TransportError;
use crate::sync::types::WindowKey;
use crate::sync::window::LoadedWindow;
use crate::{EntityId, Vault};

/// Keeps the original sender and actual native leases through deferral and heal.
/// Dropping this unacknowledged update releases its holders; it is not a receipt.
#[derive(Clone)]
pub(crate) struct StagedWorldUpdate {
    pub(crate) key: WindowKey,
    pub(crate) bytes: Vec<u8>,
    pub(crate) from: crate::authority::PeerMachine,
    pub(crate) copies: Vec<Arc<PreparedHomeClaimResponse>>,
}

pub(super) fn with_home_claim_copies<T>(
    vault: &Vault,
    key: &WindowKey,
    copies: &[Arc<PreparedHomeClaimResponse>],
    land: impl FnOnce() -> T,
) -> T {
    let (landed, attempts) = with_copies(vault, key, copies, land);
    for attempt in attempts {
        tracing::debug!(
            entity = %attempt.entity_id.to_hex(),
            error = ?attempt.result.as_ref().err().map(|error| error.kind()),
            writer_result = ?attempt.writer_result,
            "derived home CLAIM copy attempt; not a durable receipt"
        );
    }
    landed
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
        copies: &[Arc<PreparedHomeClaimResponse>],
    ) -> std::result::Result<(), TransportError> {
        let vault = Arc::clone(&self.vault);
        with_home_claim_copies(&vault, &window.key, copies, || {
            self.land_accepted_window_update_with_evidence(
                window_key, window, payload, evidence, own_device,
            )
        })
    }
}
