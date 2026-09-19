//! Peer-relative federation admission with durable, automatically replayable work.
//!
//! These rows are local `sync_queue` metadata, never CRDT rematerialization
//! markers. A defer retains the actual request/update, its grant and principal.
//! Transport payload, fabricated-window, and malformed-record bounds still apply.

mod observations;
mod queue;
pub use queue::FederationBurstReviewBundle;
mod selector;

pub use selector::{PreparedSelectorFetch, prepare_selector_fetch, replay_selector_fetch};

use crate::error::{SyncProtocolValidation, SyncSelectorValidation};
use crate::llm::NormalizedBurstInputs;
use crate::sync::{SyncSelector, WindowKey, authorize_sync_selector};
use crate::{EntityId, Error, FederationGrantScope, Result, Vault};

pub(in crate::sync) use queue::{DeferredWork, WorkKind};

/// Authenticated identity plus the grant that authorizes this federation lane.
///
/// The embedding transport supplies the principal ONLY after authentication.
/// A shared secret, socket number, Loro peer id, and a request's claimed member
/// are not authentication. The server uses its verified in-band `auth.bind`.
/// The client host must bind the authenticated remote principal explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationPeer {
    principal: EntityId,
    scope: FederationGrantScope,
    selector: SyncSelector,
}

impl FederationPeer {
    /// Binds a transport-authenticated principal to a currently active grant.
    pub fn authorize(
        vault: &Vault,
        principal: EntityId,
        scope: FederationGrantScope,
        selector: &SyncSelector,
    ) -> Result<Self> {
        if principal != selector.member_ref {
            return Err(Error::sync_protocol(SyncProtocolValidation::Selector {
                reason: SyncSelectorValidation::MemberNotGranted,
            }));
        }
        authorize_sync_selector(vault, scope, selector)?;
        Ok(Self {
            principal,
            scope,
            selector: selector.clone(),
        })
    }

    pub(in crate::sync) fn revalidate(&self, vault: &Vault) -> Result<()> {
        authorize_sync_selector(vault, self.scope, &self.selector)
    }

    fn digest(&self) -> [u8; 32] {
        let mut hash = blake3::Hasher::new();
        hash.update(b"oneiron/federation-peer/v1");
        hash.update(self.principal.to_hex().as_bytes());
        hash.update(self.selector.grant_id.to_hex().as_bytes());
        let FederationGrantScope::Vault { vault_id } = self.scope;
        hash.update(&vault_id.to_be_bytes());
        *hash.finalize().as_bytes()
    }
}

/// Federation policy has no rate Block or human Pause outcome.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FederationBurstDecision {
    /// Continue through the ordinary authorization/admission door.
    Allow(NormalizedBurstInputs),
    /// Payload and authority context are durable; retry without a human gate.
    Defer {
        request_id: [u8; 32],
        inputs: NormalizedBurstInputs,
    },
}

pub(in crate::sync) fn admit_work(
    vault: &Vault,
    peer: &FederationPeer,
    key: &WindowKey,
    kind: WorkKind,
    payload: &[u8],
    writes: u64,
) -> Result<(FederationBurstDecision, Option<DeferredWork>)> {
    admit_work_at(
        vault,
        peer,
        key,
        kind,
        payload,
        (writes, crate::unix_seconds_now()),
    )
}

fn admit_work_at(
    vault: &Vault,
    peer: &FederationPeer,
    key: &WindowKey,
    kind: WorkKind,
    payload: &[u8],
    sample: (u64, u64),
) -> Result<(FederationBurstDecision, Option<DeferredWork>)> {
    let (writes, now) = sample;
    peer.revalidate(vault)?;
    let work = DeferredWork::new(peer, key, kind, payload)?;
    vault.with_write_txn(|txn| {
        // Duplicate/reconnected requests replay the exact durable item. They
        // neither add a debit nor go through the burst policy a second time.
        if let Some(saved) = work.load_in_txn(vault, txn)? {
            return Ok((FederationBurstDecision::Allow(saved.inputs), Some(saved)));
        }
        let inputs = observations::observe_in_txn(vault, txn, peer, writes, now)?;
        // One is equality with this peer's baseline at this vault size, NOT
        // an absolute write/window count. Structural failures lower confidence.
        if f64::from(inputs.rate_ratio) * (1.0 + f64::from(inputs.streak)) > 1.0 {
            let work = work.with_inputs(inputs);
            work.put_in_txn(vault, txn)?;
            Ok((
                FederationBurstDecision::Defer {
                    request_id: work.id,
                    inputs,
                },
                Some(work),
            ))
        } else {
            Ok((FederationBurstDecision::Allow(inputs), None))
        }
    })
}

pub(in crate::sync) fn record_outcome(
    vault: &Vault,
    peer: &FederationPeer,
    structural_failure: bool,
) -> Result<()> {
    observations::record_outcome(vault, peer, structural_failure)
}

fn corrupt() -> Error {
    Error::CorruptedIndex("federation deferred work")
}

#[cfg(test)]
pub(in crate::sync) mod tests;
