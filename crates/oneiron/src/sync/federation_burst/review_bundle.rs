//! One advisory proposal per peer, with an actual isolated ledger subgraph.
//! The payloads live only in the local queue, not in entities or observed docs.

use std::collections::{BTreeMap, BTreeSet};

use super::{corrupt, queue::DeferredWork};
use crate::{Result, Vault};
use serde::{Deserialize, Serialize};

/// One part of a locally admitted window update held outside the live graph:
/// the window that part imports into (`window`) and its admitted bytes. An
/// update a guest's admission lands across several windows is one of these
/// per part, each with the same request ref, rate and streak (FIX 3662). It
/// is review evidence, not replay authority: replay re-admits the original
/// peer bytes under the window the request named.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FederationIsolatedUpdate {
    pub request_ref: String,
    pub window: String,
    pub admitted_update: Vec<u8>,
    pub rate_ratio: f32,
    pub streak_ratio: f32,
}

/// One coalesced proposal, rather than an approval prompt for every row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FederationBurstReviewBundle {
    pub bundle_ref: String,
    /// Each isolated request once, in the order its parts first appear.
    pub request_refs: Vec<String>,
    pub updates: Vec<FederationIsolatedUpdate>,
    pub quarantined: bool,
    pub replay_automatic: bool,
}

impl Vault {
    /// Only isolated writes appear here. Ordinary deferred reads/writes are
    /// resumable work, not review proposals. Recovery drains either without
    /// waiting for human approval, and one peer never holds another's queue.
    pub fn federation_burst_review_bundles(&self) -> Result<Vec<FederationBurstReviewBundle>> {
        let txn = self.store.env.read_txn()?;
        self.federation_burst_review_bundles_in_txn(&txn)
    }

    pub(super) fn federation_burst_review_bundles_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Vec<FederationBurstReviewBundle>> {
        let mut bundles = BTreeMap::<[u8; 32], Vec<FederationIsolatedUpdate>>::new();
        for row in self
            .store
            .sync_queue
            .prefix_iter(&txn, b"m:federation-deferred:v1:")?
        {
            let (key, value) = row?;
            let work = DeferredWork::decode(&value)?;
            if key.as_ref() != work.key() {
                return Err(corrupt());
            }
            let Some(parts) = work.isolated_update else {
                continue;
            };
            let request_ref = blake3::Hash::from(work.id).to_hex().to_string();
            let updates = bundles.entry(work.peer).or_default();
            for (window, admitted_update) in parts {
                updates.push(FederationIsolatedUpdate {
                    request_ref: request_ref.clone(),
                    window,
                    admitted_update,
                    rate_ratio: work.inputs.rate_ratio,
                    streak_ratio: work.streak_ratio,
                });
            }
        }
        let mut retained = super::review_doors::retained_in_txn(self, &txn)?;
        let pending = bundles
            .into_iter()
            .map(|(peer, updates)| FederationBurstReviewBundle {
                bundle_ref: format!("federation-review:{}", blake3::Hash::from(peer).to_hex()),
                request_refs: request_refs(&updates),
                updates,
                quarantined: true,
                replay_automatic: true,
            })
            .collect::<Vec<_>>();
        for bundle in &mut retained {
            bundle.quarantined = pending
                .iter()
                .any(|row| row.bundle_ref == bundle.bundle_ref);
        }
        for bundle in pending {
            if !retained
                .iter()
                .any(|row| row.bundle_ref == bundle.bundle_ref)
            {
                retained.push(bundle);
            }
        }
        Ok(retained)
    }
}

/// Each request `updates` holds a part of, once, in the order its parts first
/// appear.
fn request_refs(updates: &[FederationIsolatedUpdate]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    updates
        .iter()
        .filter(|update| seen.insert(update.request_ref.as_str()))
        .map(|update| update.request_ref.clone())
        .collect()
}
