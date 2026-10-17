//! Peer-relative federation admission with durable, automatically replayable work.
//!
//! These rows are local `sync_queue` metadata, never CRDT rematerialization
//! markers. A defer retains the actual request/update, its grant and principal.
//! Transport payload, fabricated-window, and malformed-record bounds still apply.

mod observations;
mod peer_health;
mod queue;
mod review_bundle;
pub use review_bundle::{FederationBurstReviewBundle, FederationIsolatedUpdate};
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

    /// The transport-authenticated principal this peer speaks as.
    pub(in crate::sync) const fn principal(&self) -> EntityId {
        self.principal
    }

    /// The grant this peer speaks under.
    pub(in crate::sync) const fn grant(&self) -> EntityId {
        self.selector.grant_id
    }

    /// This peer's standing in the shared vault, read over its own grant
    /// (FIX 360): the selector is revalidated, then the authority lane
    /// classifies that grant's member and scope. No standing refuses; it is
    /// never a member.
    pub(in crate::sync) fn membership(
        &self,
        vault: &Vault,
    ) -> Result<crate::federation::MembershipStanding> {
        self.revalidate(vault)?;
        let txn = vault.store.env.read_txn()?;
        vault
            .authenticated_grant_membership_in_txn(
                &txn,
                self.scope,
                self.principal,
                self.selector.grant_id,
            )?
            .ok_or_else(|| {
                Error::sync_protocol(SyncProtocolValidation::Selector {
                    reason: SyncSelectorValidation::MemberNotGranted,
                })
            })
    }

    fn digest(&self) -> [u8; 32] {
        let mut hash = blake3::Hasher::new();
        hash.update(b"oneiron/federation-peer/v1");
        hash.update(self.principal.to_hex().as_bytes());
        hash.update(self.selector.grant_id.to_hex().as_bytes());
        match self.scope {
            FederationGrantScope::Vault { vault_id } => {
                hash.update(b"vault");
                hash.update(&vault_id.to_be_bytes());
            }
            FederationGrantScope::Ask { ask_ref } => {
                hash.update(b"ask");
                hash.update(ask_ref.as_bytes());
            }
        }
        *hash.finalize().as_bytes()
    }
}

/// Federation policy has no rate Block or human Pause outcome.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FederationBurstDecision {
    /// Continue through the ordinary authorization/admission door.
    Allow(NormalizedBurstInputs),
    /// Rows stay outside the live graph in one peer review bundle. Recovery
    /// replays them automatically through current admission, not human approval.
    IsolateAndPropose {
        request_id: [u8; 32],
        bundle_id: [u8; 32],
        inputs: NormalizedBurstInputs,
    },
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
    admitted_update: Option<&[u8]>,
) -> Result<(FederationBurstDecision, Option<DeferredWork>)> {
    admit_work_at(
        vault,
        peer,
        key,
        kind,
        payload,
        (writes, vault.now_recorded_at()),
        admitted_update,
    )
}

fn admit_work_at(
    vault: &Vault,
    peer: &FederationPeer,
    key: &WindowKey,
    kind: WorkKind,
    payload: &[u8],
    sample: (u64, u64),
    admitted_update: Option<&[u8]>,
) -> Result<(FederationBurstDecision, Option<DeferredWork>)> {
    let (writes, now) = sample;
    peer.revalidate(vault)?;
    let work = DeferredWork::new(peer, key, kind, payload)?;
    vault.with_write_txn_grouped(|txn| {
        // Duplicate/reconnected requests replay the exact durable item. They
        // neither add a debit nor go through the burst policy a second time.
        if let Some(saved) = work.load_in_txn(vault, txn)? {
            let decision = if saved.isolated_update.is_some()
                && !observations::replay_ready_in_txn(vault, txn, peer, now)?
            {
                FederationBurstDecision::IsolateAndPropose {
                    request_id: saved.id,
                    bundle_id: peer.digest(),
                    inputs: saved.inputs,
                }
            } else {
                FederationBurstDecision::Allow(saved.inputs)
            };
            return Ok((decision, Some(saved)));
        }
        let health = observations::observe_in_txn(vault, txn, peer, writes, now)?;
        if !health.unusual_rate() {
            return Ok((FederationBurstDecision::Allow(health.inputs), None));
        }
        let mut work = work.with_inputs(health.inputs);
        let decision = if health.isolate() && admitted_update.is_some() {
            work.isolated_update = admitted_update.map(<[u8]>::to_vec);
            work.streak_ratio = health.streak_ratio;
            FederationBurstDecision::IsolateAndPropose {
                request_id: work.id,
                bundle_id: peer.digest(),
                inputs: health.inputs,
            }
        } else {
            FederationBurstDecision::Defer {
                request_id: work.id,
                inputs: health.inputs,
            }
        };
        work.put_in_txn(vault, txn)?;
        Ok((decision, Some(work)))
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
