//! Retained coalesced review evidence and owner release/reject acts.
use super::{
    DeferredWork, FederationBurstReceipt, FederationBurstReviewBundle,
    FederationBurstReviewReceipt, FederationIsolatedUpdate, FederationPeer, corrupt, ledger,
};
use crate::consent::AuthenticatedOwner;
use crate::store::Store;
use crate::{Result, Vault};

fn key(peer: &[u8; 32]) -> Vec<u8> {
    let mut key = b"m:federation-review:v1:".to_vec();
    key.extend_from_slice(peer);
    key
}

pub(super) fn retained_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<FederationBurstReviewBundle>> {
    vault
        .store
        .sync_queue
        .prefix_iter(txn, b"m:federation-review:v1:")?
        .map(|row| {
            let (_, bytes) = row?;
            rmp_serde::from_slice(&bytes).map_err(|_| corrupt())
        })
        .collect()
}

pub(super) fn retain_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    work: &DeferredWork,
) -> Result<()> {
    let Some(parts) = &work.isolated_update else {
        return Ok(());
    };
    let key = key(&work.peer);
    let mut bundle: FederationBurstReviewBundle = match vault.store.sync_queue.get(txn, &key)? {
        Some(bytes) => rmp_serde::from_slice(&bytes).map_err(|_| corrupt())?,
        None => FederationBurstReviewBundle {
            bundle_ref: format!(
                "federation-review:{}",
                blake3::Hash::from(work.peer).to_hex()
            ),
            request_refs: Vec::new(),
            updates: Vec::new(),
            quarantined: true,
            replay_automatic: true,
        },
    };
    let request_ref = blake3::Hash::from(work.id).to_hex().to_string();
    if !bundle.request_refs.contains(&request_ref) {
        bundle.request_refs.push(request_ref.clone());
        bundle.updates.extend(
            parts
                .iter()
                .map(|(window, bytes)| FederationIsolatedUpdate {
                    request_ref: request_ref.clone(),
                    window: window.clone(),
                    admitted_update: bytes.clone(),
                    rate_ratio: work.inputs.rate_ratio,
                    streak_ratio: work.streak_ratio,
                }),
        );
        let bytes = rmp_serde::to_vec_named(&bundle).map_err(|_| corrupt())?;
        vault.store.sync_queue.put(txn, &key, &bytes)?;
    }
    Ok(())
}

/// Drops the review copies of request `id` once its batch is settled, ended
/// or erased: the bundle keeps the request's reference, not its bytes (FIX
/// 7998).
pub(super) fn scrub_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    peer: &[u8; 32],
    id: &[u8; 32],
) -> Result<()> {
    let key = key(peer);
    let mut bundle: FederationBurstReviewBundle = match store.sync_queue.get(txn, &key)? {
        Some(bytes) => rmp_serde::from_slice(&bytes).map_err(|_| corrupt())?,
        None => return Ok(()),
    };
    let request_ref = blake3::Hash::from(*id).to_hex().to_string();
    let held = bundle.updates.len();
    bundle
        .updates
        .retain(|update| update.request_ref != request_ref);
    if bundle.updates.len() != held {
        let bytes = rmp_serde::to_vec_named(&bundle).map_err(|_| corrupt())?;
        store.sync_queue.put(txn, &key, &bytes)?;
    }
    Ok(())
}

impl Vault {
    /// The owner's retained evidence, using the same review projection as sync.
    pub fn federation_burst_reviews_as_owner(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<Vec<FederationBurstReviewBundle>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        self.federation_burst_review_bundles_in_txn(&txn)
    }

    /// Release removes only the burst hold. Replay still enters the current
    /// grant, member/guest admission and provenance-preserving import doors.
    pub fn release_federation_burst_review(
        &self,
        owner: &AuthenticatedOwner,
        bundle_ref: &str,
    ) -> Result<FederationBurstReviewReceipt> {
        self.settle_federation_burst_review(owner, bundle_ref, false)
    }

    pub fn reject_federation_burst_review(
        &self,
        owner: &AuthenticatedOwner,
        bundle_ref: &str,
    ) -> Result<FederationBurstReviewReceipt> {
        self.settle_federation_burst_review(owner, bundle_ref, true)
    }

    fn settle_federation_burst_review(
        &self,
        owner: &AuthenticatedOwner,
        bundle_ref: &str,
        reject: bool,
    ) -> Result<FederationBurstReviewReceipt> {
        let digest = bundle_ref
            .strip_prefix("federation-review:")
            .and_then(crate::deletion::parse_hex::<32>)
            .ok_or_else(|| crate::Error::InvalidConfig("invalid bundle_ref".into()))?;
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            if self.store.sync_queue.get(txn, &key(&digest))?.is_none() {
                return Err(crate::Error::EntityNotFound);
            }
            let mut prefix = b"m:federation-deferred:v1:".to_vec();
            prefix.extend_from_slice(&digest);
            let work = self
                .store
                .sync_queue
                .prefix_iter(txn, &prefix)?
                .map(|row| {
                    let (key, bytes) = row?;
                    let work = DeferredWork::decode(&bytes)?;
                    if work.key().as_slice() != key.as_ref() {
                        return Err(corrupt());
                    }
                    Ok(work)
                })
                .collect::<Result<Vec<_>>>()?;
            let mut batches = Vec::<FederationBurstReceipt>::new();
            for mut work in work {
                // A released bundle may still have pending replay work; reject
                // retires those original isolated batches as well.
                let selector = crate::sync::decode_sync_selector(&work.selector)?;
                let raw = if reject {
                    self.get_raw_in(txn, &selector.grant_id)?
                        .ok_or(crate::Error::EntityNotFound)?
                } else {
                    crate::federation::live_federation_grant_in(self, txn, &selector.grant_id)?
                };
                let grant = crate::federation::decode_federation_grant_body(
                    &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
                )?;
                let peer = FederationPeer {
                    principal: selector.member_ref,
                    scope: grant.scope,
                    selector,
                    owner: None,
                };
                if peer.digest() != digest {
                    return Err(corrupt());
                }
                let Some(receipt) = ledger::load(self, txn, &peer, &work.id)? else {
                    continue;
                };
                if !matches!(
                    receipt.disposition,
                    super::FederationBurstDisposition::IsolateAndPropose { .. }
                ) {
                    continue;
                }
                if reject {
                    work.remove_in_txn(&self.store, txn)?;
                    ledger::settle(
                        self,
                        txn,
                        &peer,
                        &work,
                        super::FederationBurstWorkState::Rejected,
                    )?;
                } else if let Some(state) =
                    work.ended_in_txn(self, txn, &peer, self.now_recorded_at())?
                {
                    // A batch held under an older grant or pact scope, or
                    // past its wait, ends alone; the rest are released
                    // (FIX 7999).
                    work.retire_in_txn(&self.store, txn, state)?;
                } else {
                    work.isolated_update = None;
                    work.put_in_txn(self, txn)?;
                }
                if let Some(receipt) = ledger::load(self, txn, &peer, &work.id)? {
                    batches.push(receipt)
                }
            }
            Ok(FederationBurstReviewReceipt {
                bundle_ref: bundle_ref.to_owned(),
                batches,
            })
        })
    }
}
