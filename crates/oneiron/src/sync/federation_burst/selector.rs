//! Decode and authorize before deferral; retry only with current authentication.

use super::{
    DeferredWork, FederationBurstDecision, FederationPeer, WorkKind, admit_work, record_outcome,
};
use crate::error::SyncProtocolValidation;
use crate::sync::{SyncSelector, WindowKey, decode_selector_vv_request};
use crate::{EntityId, Error, FederationGrantScope, Result, Vault};
use loro::VersionVector;

/// An authorized selector fetch, possibly durably deferred.
pub struct PreparedSelectorFetch {
    /// Only this selector may be exported.
    pub selector: SyncSelector,
    /// A defer response must carry its request id and the original request.
    pub decision: FederationBurstDecision,
    peer: FederationPeer,
    work: Option<DeferredWork>,
}

impl PreparedSelectorFetch {
    /// Completes an allowed fetch after the direct response has been queued.
    /// Failed sends retain their durable request for reconnect/retry.
    pub fn complete(self, vault: &Vault) -> Result<()> {
        if !matches!(self.decision, FederationBurstDecision::Allow(_)) {
            return Err(Error::sync_protocol(
                SyncProtocolValidation::FederationReplayMismatch,
            ));
        }
        match self.work {
            Some(work) => work.complete(vault, &self.peer),
            None => record_outcome(vault, &self.peer, false),
        }
    }
}

fn peer_for_request(
    vault: &Vault,
    principal: EntityId,
    scope: FederationGrantScope,
    payload: &[u8],
) -> Result<FederationPeer> {
    if payload.len() > crate::sync::transport::MAX_DECODED_PAYLOAD_BYTES {
        return Err(Error::sync_protocol(SyncProtocolValidation::Selector {
            reason: crate::error::SyncSelectorValidation::TooLarge,
        }));
    }
    let request = decode_selector_vv_request(payload)?;
    let vv = VersionVector::decode(&request.remote_vv)
        .map_err(|_| Error::sync_protocol(SyncProtocolValidation::SelectorVersionVector))?;
    if !vv.is_empty() {
        return Err(Error::sync_protocol(
            SyncProtocolValidation::SelectorVersionVector,
        ));
    }
    FederationPeer::authorize(vault, principal, scope, &request.selector)
}

/// Validates the full request and current grant before recording observations.
/// A repeated durable request automatically enters its replay door.
pub fn prepare_selector_fetch(
    vault: &Vault,
    principal: EntityId,
    scope: FederationGrantScope,
    key: &WindowKey,
    payload: &[u8],
) -> Result<PreparedSelectorFetch> {
    let peer = peer_for_request(vault, principal, scope, payload)?;
    let (decision, work) = admit_work(vault, &peer, key, WorkKind::Selector, payload, 1)?;
    Ok(PreparedSelectorFetch {
        selector: peer.selector.clone(),
        peer,
        decision,
        work,
    })
}

/// Replays a durable request, binding request id, principal, grant, window and
/// exact request bytes. Grant revocation/expiry and narrowed scope apply NOW.
pub fn replay_selector_fetch(
    vault: &Vault,
    principal: EntityId,
    scope: FederationGrantScope,
    key: &WindowKey,
    id: &[u8; 32],
    payload: &[u8],
) -> Result<PreparedSelectorFetch> {
    let peer = peer_for_request(vault, principal, scope, payload)?;
    let expected = DeferredWork::new(&peer, key, WorkKind::Selector, payload)?;
    if expected.id != *id {
        return Err(Error::sync_protocol(
            SyncProtocolValidation::FederationReplayMismatch,
        ));
    }
    let txn = vault.store.env.read_txn()?;
    let work = match expected.load_in_txn(vault, &txn)? {
        Some(work) => work,
        None if expected.completed_selector_in_txn(vault, &txn)? => expected,
        None => {
            return Err(Error::sync_protocol(
                SyncProtocolValidation::FederationReplayMismatch,
            ));
        }
    };
    Ok(PreparedSelectorFetch {
        selector: peer.selector.clone(),
        peer,
        decision: FederationBurstDecision::Allow(work.inputs),
        work: Some(work),
    })
}
