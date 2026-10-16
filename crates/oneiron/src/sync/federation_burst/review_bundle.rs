//! One advisory proposal per peer, with an actual isolated ledger subgraph.
//! The payloads live only in the local queue, not in entities or observed docs.

use std::collections::BTreeMap;

use super::{corrupt, queue::DeferredWork};
use crate::{Result, Vault};
use serde::{Deserialize, Serialize};

/// A locally admitted window update held outside the live graph. It is review
/// evidence, not replay authority: replay re-admits the original peer bytes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FederationIsolatedUpdate {
    pub request_ref: String,
    pub window: String,
    pub admitted_update: Vec<u8>,
    pub rate_ratio: f32,
    pub streak_ratio: f32,
}

/// One coalesced proposal, rather than an approval prompt for every row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FederationBurstReviewBundle {
    pub bundle_ref: String,
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
            let Some(admitted_update) = work.isolated_update else {
                continue;
            };
            bundles
                .entry(work.peer)
                .or_default()
                .push(FederationIsolatedUpdate {
                    request_ref: blake3::Hash::from(work.id).to_hex().to_string(),
                    window: work.window,
                    admitted_update,
                    rate_ratio: work.inputs.rate_ratio,
                    streak_ratio: work.streak_ratio,
                });
        }
        Ok(bundles
            .into_iter()
            .map(|(peer, updates)| FederationBurstReviewBundle {
                bundle_ref: format!("federation-review:{}", blake3::Hash::from(peer).to_hex()),
                request_refs: updates
                    .iter()
                    .map(|update| update.request_ref.clone())
                    .collect(),
                updates,
                quarantined: true,
                replay_automatic: true,
            })
            .collect())
    }
}
