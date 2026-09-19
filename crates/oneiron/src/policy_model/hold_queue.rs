//! Device-local moderation queue. Hashes only: no content, sync, or federation.
use super::{
    PolicyClassifyDecision, PolicyClassifyRequest, PolicyClassifyVerdict, PolicyVerdictCategory,
};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, RelayError};
use crate::{Result, Vault};
use serde::{Deserialize, Serialize};
const PREFIX: &str = "policy-hold:v1:";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldPolicyItem {
    pub queue_ref: String,
    pub row_ref: String,
    pub human: String,
    pub content_hash: [u8; 32],
    pub policy_frontier: [u8; 32],
    pub held_at: u64,
    pub receipt_ref: String,
    pub resolution: Option<PolicyHoldResolution>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyHoldResolution {
    Cleared,
    Declined,
}
fn queue_ref(request: &PolicyClassifyRequest, verdict: &PolicyClassifyVerdict) -> Option<String> {
    let PolicyVerdictCategory::OwnerPolicy { row_ref } = &verdict.category else {
        return None;
    };
    let mut h = blake3::Hasher::new();
    h.update(b"oneiron.policy-hold.v1");
    for field in [
        request.caller_ref.as_deref().unwrap_or_default().as_bytes(),
        row_ref.as_bytes(),
        &verdict.binding.content_hash,
        &verdict.binding.read_frontier_hash,
    ] {
        h.update(&(field.len() as u64).to_be_bytes());
        h.update(field);
    }
    Some(format!("{PREFIX}{}", h.finalize().to_hex()))
}
impl Vault {
    pub(super) fn queue_policy_hold_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        request: &PolicyClassifyRequest,
        verdict: &PolicyClassifyVerdict,
        receipt_ref: String,
    ) -> Result<String> {
        let queue_ref =
            queue_ref(request, verdict).ok_or(Error::Relay(RelayError::PolicyVerdictNotInForce))?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, txn)?;
        if policy.read_frontier_hash()? != verdict.binding.read_frontier_hash {
            return Err(Error::Relay(RelayError::PolicyVerdictNotInForce));
        }
        let PolicyVerdictCategory::OwnerPolicy { row_ref } = &verdict.category else {
            unreachable!("validated above")
        };
        let human = policy
            .active_owner_policy_rows(request.world_ref.as_deref())
            .into_iter()
            .find(|row| row.row_ref == *row_ref)
            .and_then(|row| row.human.clone())
            .ok_or(Error::Relay(RelayError::PolicyVerdictNotInForce))?;
        let item = HeldPolicyItem {
            queue_ref: queue_ref.clone(),
            row_ref: row_ref.clone(),
            human,
            content_hash: verdict.binding.content_hash,
            policy_frontier: verdict.binding.read_frontier_hash,
            held_at: crate::unix_seconds_now(),
            receipt_ref,
            resolution: None,
        };
        // A re-classification is a new decision. Resetting to pending does not release content.
        let bytes =
            serde_json::to_vec(&item).map_err(|_| Error::CorruptedIndex("policy hold encoding"))?;
        self.store
            .vault_meta
            .put(txn, queue_ref.as_bytes(), &bytes)?;
        Ok(queue_ref)
    }
    pub(super) fn policy_hold_for_verdict(
        &self,
        request: &PolicyClassifyRequest,
        verdict: &PolicyClassifyVerdict,
    ) -> Result<Option<HeldPolicyItem>> {
        if verdict.decision != PolicyClassifyDecision::Hold {
            return Ok(None);
        }
        let Some(key) = queue_ref(request, verdict) else {
            return Ok(None);
        };
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, key.as_bytes())?
            .map(|bytes| {
                serde_json::from_slice(&bytes).map_err(|_| Error::CorruptedIndex("policy hold"))
            })
            .transpose()
    }
    pub fn policy_holds(&self, limit: usize) -> Result<Vec<HeldPolicyItem>> {
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .prefix_iter(&txn, PREFIX.as_bytes())?
            .take(limit)
            .map(|row| {
                let (_, bytes) = row?;
                serde_json::from_slice(&bytes).map_err(|_| Error::CorruptedIndex("policy hold"))
            })
            .collect()
    }
    /// Record a later human ruling. This never sends content or turns a stale verdict into a permit.
    pub fn resolve_policy_hold(
        &self,
        owner: &AuthenticatedOwner,
        reference: &str,
        resolution: PolicyHoldResolution,
    ) -> Result<()> {
        if !reference.starts_with(PREFIX) {
            return Err(Error::InvalidConfig("not a policy hold reference".into()));
        }
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let bytes = self
            .store
            .vault_meta
            .get(&txn, reference.as_bytes())?
            .ok_or(Error::CorruptedIndex("missing policy hold"))?;
        let mut item: HeldPolicyItem =
            serde_json::from_slice(&bytes).map_err(|_| Error::CorruptedIndex("policy hold"))?;
        if item.human != owner.actor().to_hex() || item.resolution.is_some() {
            return Err(Error::Relay(RelayError::PolicyVerdictNotInForce));
        }
        item.resolution = Some(resolution);
        self.store.vault_meta.put(
            &mut txn,
            reference.as_bytes(),
            &serde_json::to_vec(&item)
                .map_err(|_| Error::CorruptedIndex("policy hold encoding"))?,
        )?;
        txn.commit()?;
        Ok(())
    }
}
