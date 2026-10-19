//! Owner policy changes and the peer's own observed baseline.
use super::{
    FederationBurstBaseline, FederationBurstBaselineState, FederationBurstPolicy, FederationPeer,
    corrupt, observations,
};
use crate::consent::AuthenticatedOwner;
use crate::{Result, Vault};

fn key(peer: &FederationPeer) -> Vec<u8> {
    let mut key = b"m:federation-policy:v1:".to_vec();
    key.extend_from_slice(&peer.digest());
    key
}

pub(super) fn load_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    peer: &FederationPeer,
) -> Result<FederationBurstPolicy> {
    vault.store.sync_queue.get(txn, &key(peer))?.map_or_else(
        || Ok(FederationBurstPolicy::default()),
        |bytes| rmp_serde::from_slice(&bytes).map_err(|_| corrupt()),
    )
}

impl Vault {
    pub fn federation_burst_policy(
        &self,
        owner: &AuthenticatedOwner,
        peer: &FederationPeer,
    ) -> Result<FederationBurstPolicy> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        peer.revalidate_in_txn(self, &txn)?;
        load_in_txn(self, &txn, peer)
    }

    pub fn set_federation_burst_policy(
        &self,
        owner: &AuthenticatedOwner,
        peer: &FederationPeer,
        policy: FederationBurstPolicy,
    ) -> Result<FederationBurstPolicy> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            peer.revalidate_in_txn(self, txn)?;
            policy.validate()?;
            let bytes = rmp_serde::to_vec_named(&policy).map_err(|_| corrupt())?;
            self.store.sync_queue.put(txn, &key(peer), &bytes)?;
            Ok(policy.clone())
        })
    }

    pub fn federation_burst_baseline(
        &self,
        owner: &AuthenticatedOwner,
        peer: &FederationPeer,
    ) -> Result<FederationBurstBaselineState> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        peer.revalidate_in_txn(self, &txn)?;
        observations::baseline_in_txn(self, &txn, peer, self.now_recorded_at())
    }
}

pub(super) fn resolved_baseline(
    policy: &FederationBurstPolicy,
    learned_rate: f64,
    learned_streak: f64,
) -> FederationBurstBaseline {
    policy
        .baseline
        .clone()
        .unwrap_or_else(|| FederationBurstBaseline {
            name: "observed".into(),
            writes_per_sec: if learned_rate > 0.0 {
                learned_rate
            } else {
                1.0
            },
            structural_streak: if learned_streak > 0.0 {
                learned_streak
            } else {
                1.0
            },
        })
}
