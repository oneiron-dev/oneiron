//! Peer-relative federation admission with durable, automatically replayable work.
//!
//! These rows are local `sync_queue` metadata, never CRDT rematerialization
//! markers. A defer retains the actual request/update, its grant and principal.
//! Transport payload, fabricated-window, and malformed-record bounds still apply.

mod documents;
pub(crate) mod erase;
mod import_guard;
mod ledger;
mod observations;
mod policy;
pub(crate) mod schedule;
pub(crate) use erase::{erase_retained_copies_in_txn, retained_copies_in, scrub_retained_copies};
pub(crate) use import_guard::check_active_in_txn;
pub(in crate::sync) use import_guard::with_import_guard;
mod review_doors;
mod types;
pub use types::*;
mod peer_health;
mod queue;
mod review_bundle;
pub use review_bundle::{FederationBurstReviewBundle, FederationIsolatedUpdate};
pub use schedule::{
    FACET_STAMP_WAIT_SECS, FEDERATION_BURST_WAIT_SECS, MAINTENANCE_INGEST_WAIT_SECS,
    RetainedWorkQueue,
};
mod selector;

pub use selector::{PreparedSelectorFetch, prepare_selector_fetch, replay_selector_fetch};

use crate::error::{SyncProtocolValidation, SyncSelectorValidation};
use crate::llm::NormalizedBurstInputs;
use crate::sync::{SyncSelector, WindowKey, authorize_sync_selector};
use crate::{EntityId, Error, FederationGrantScope, Result, Vault};

pub(crate) use queue::expire_retained_work;
pub(in crate::sync) use queue::{DeferredWork, WorkKind};

/// An admitted update as review evidence: each part it lands as, with the
/// window that part imports into, in import order (FIX 3662).
pub(in crate::sync) type AdmittedParts<'a> = &'a [(&'a str, &'a [u8])];

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
    owner: Option<crate::consent::AuthenticatedOwner>,
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
            owner: None,
        })
    }

    pub(in crate::sync) fn with_owner(
        mut self,
        vault: &Vault,
        owner: &crate::consent::AuthenticatedOwner,
    ) -> Result<Self> {
        self.owner = Some(owner.clone());
        self.revalidate(vault)?;
        Ok(self)
    }

    pub(in crate::sync) fn revalidate(&self, vault: &Vault) -> Result<()> {
        let txn = vault.store.env.read_txn()?;
        self.revalidate_in_txn(vault, &txn)
    }

    pub(in crate::sync) fn revalidate_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<()> {
        if let Some(owner) = &self.owner {
            owner.revalidate_in_txn(vault, txn)?;
        }
        crate::sync::selector::authorize_sync_selector_in_txn(
            vault,
            txn,
            self.scope,
            &self.selector,
        )
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

    pub(in crate::sync) fn authority_digest_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<[u8; 32]> {
        self.revalidate_in_txn(vault, txn)?;
        let raw = crate::federation::live_federation_grant_in(vault, txn, &self.grant())?;
        let fold = vault.authority_view_readonly_in_txn(txn)?;
        let mut hash = blake3::Hasher::new();
        hash.update(&raw);
        for (id, pact) in fold
            .federation_pacts
            .iter()
            .filter(|(_, pact)| pact.grant_ref == self.grant())
        {
            hash.update(id);
            hash.update(&pact.pact_epoch.to_be_bytes());
            let scope = rmp_serde::to_vec_named(&(&pact.effective_scope, &pact.pact_scope))
                .map_err(|_| corrupt())?;
            hash.update(&scope);
        }
        Ok(*hash.finalize().as_bytes())
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
            FederationGrantScope::Connect { peer_vault_id } => {
                hash.update(b"connect");
                hash.update(&peer_vault_id);
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

/// Observes the request `payload` in `key` from `peer`, and decides whether
/// it runs now, defers, or is isolated for review. Isolation keeps
/// `admitted_update`, every part, as the review's evidence; the work, its
/// debit and its replay stay the original request's. `carried` names the
/// rows whose bytes the work carries, which an erase of any scrubs.
pub(in crate::sync) fn admit_work(
    vault: &Vault,
    peer: &FederationPeer,
    key: &WindowKey,
    kind: WorkKind,
    payload: &[u8],
    (writes, carried): (u64, &[EntityId]),
    admitted_update: Option<AdmittedParts<'_>>,
) -> Result<(FederationBurstDecision, Option<DeferredWork>)> {
    admit_work_at(
        vault,
        peer,
        key,
        kind,
        payload,
        (writes, vault.now_recorded_at(), carried),
        admitted_update,
    )
}

fn admit_work_at(
    vault: &Vault,
    peer: &FederationPeer,
    key: &WindowKey,
    kind: WorkKind,
    payload: &[u8],
    sample: (u64, u64, &[EntityId]),
    admitted_update: Option<AdmittedParts<'_>>,
) -> Result<(FederationBurstDecision, Option<DeferredWork>)> {
    let (writes, now, carried) = sample;
    peer.revalidate(vault)?;
    let mut work = DeferredWork::new(peer, key, kind, payload)?;
    work.carried = carried.to_vec();
    vault.with_write_txn_grouped(|txn| {
        work.authority_digest = peer.authority_digest_in_txn(vault, txn)?;
        // Duplicate/reconnected requests replay the exact durable item. They
        // neither add a debit nor go through the burst policy a second time.
        // One held under an older grant or pact scope, or past its wait, ends
        // alone with its typed receipt, and this delivery is admitted afresh
        // under the current authority (FIX 7997, 7999).
        let saved = match work.load_in_txn(vault, txn)? {
            Some(saved) => match saved.ended_in_txn(vault, txn, peer, now)? {
                Some(state) => {
                    saved.retire_in_txn(&vault.store, txn, state)?;
                    None
                }
                None => Some(saved),
            },
            None => None,
        };
        if let Some(saved) = saved {
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
        if let Some(receipt) = ledger::load(vault, txn, peer, &work.id)?
            && receipt.state.is_settled()
        {
            let inputs = NormalizedBurstInputs {
                rate_ratio: receipt.baseline.rate_ratio,
                streak: receipt.baseline.streak,
            };
            return Ok((
                FederationBurstDecision::Allow(inputs),
                Some(work.with_inputs(inputs)),
            ));
        }
        let health = observations::observe_in_txn(vault, txn, peer, writes, now)?;
        let mut work = work.with_inputs(health.inputs);
        work.arrive_in_txn(vault, txn, now)?;
        let decision = match health.outcome() {
            FederationBurstOutcome::Allow => FederationBurstDecision::Allow(health.inputs),
            FederationBurstOutcome::IsolateAndPropose if admitted_update.is_some() => {
                work.isolated_update = admitted_update.map(|parts| {
                    parts
                        .iter()
                        .map(|(window, bytes)| ((*window).to_owned(), bytes.to_vec()))
                        .collect()
                });
                work.streak_ratio = health.streak_ratio;
                FederationBurstDecision::IsolateAndPropose {
                    request_id: work.id,
                    bundle_id: peer.digest(),
                    inputs: health.inputs,
                }
            }
            // A read has no rows to isolate: retain its exact request instead.
            FederationBurstOutcome::Defer | FederationBurstOutcome::IsolateAndPropose => {
                FederationBurstDecision::Defer {
                    request_id: work.id,
                    inputs: health.inputs,
                }
            }
        };
        work.put_in_txn(vault, txn)?;
        ledger::record(vault, txn, peer, &work, decision, health.baseline)?;
        review_doors::retain_in_txn(vault, txn, &work)?;
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
