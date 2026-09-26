//! Device-local moderation queue. Hashes only: no content, sync, or federation.
use super::{
    PolicyClassifyDecision, PolicyClassifyRequest, PolicyClassifyVerdict, PolicyVerdictCategory,
};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, RelayError};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{Result, Vault};
use serde::{Deserialize, Serialize};
const PREFIX: &str = "policy-hold:v1:";

/// The device-local moderation queue, keyed by the hex digest after `PREFIX`
/// (the `queue_ref`/`reference` strings this module hands callers keep the
/// full prefixed spelling; this table's key is only the suffix after it).
const HOLD_QUEUE: SideTable<String, HeldPolicyItem, LegacyJson> =
    SideTable::new(&side_table::POLICY_HOLD_QUEUE);

/// The table key for a `queue_ref`/`reference` string, which always carries `PREFIX`.
fn hold_key(reference: &str) -> String {
    reference
        .strip_prefix(PREFIX)
        .unwrap_or(reference)
        .to_owned()
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldPolicyItem {
    pub queue_ref: String,
    pub row_ref: String,
    /// Authenticated principal reference assigned by the policy, not a display label.
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
        // Reclassifying the same caller/content/frontier cannot erase a human ruling.
        if HOLD_QUEUE.contains(&self.store, txn, &hold_key(&queue_ref))? {
            return Ok(queue_ref);
        }
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
        let bytes =
            serde_json::to_vec(&item).map_err(|_| Error::CorruptedIndex("policy hold encoding"))?;
        crate::store::check_queue_capacity(
            &self.store.vault_meta,
            txn,
            PREFIX.as_bytes(),
            queue_ref.as_bytes(),
            bytes.len(),
            self.config.map_size / 16,
        )?;
        HOLD_QUEUE.put(&self.store, txn, &hold_key(&queue_ref), &item)?;
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
        HOLD_QUEUE.get(&self.store, &txn, &hold_key(&key))
    }
    pub fn policy_holds(&self, limit: usize) -> Result<Vec<HeldPolicyItem>> {
        let txn = self.store.env.read_txn()?;
        Ok(HOLD_QUEUE
            .scan(&self.store, &txn)?
            .into_iter()
            .take(limit)
            .map(|(_, item)| item)
            .collect())
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
        let mut item = HOLD_QUEUE
            .get(&self.store, &txn, &hold_key(reference))?
            .ok_or(Error::CorruptedIndex("missing policy hold"))?;
        if item.human != owner.principal_ref() || item.resolution.is_some() {
            return Err(Error::Relay(RelayError::PolicyVerdictNotInForce));
        }
        if crate::gate::resolve_policy_manifest(&self.store, &txn)?.read_frontier_hash()?
            != item.policy_frontier
        {
            return Err(Error::Relay(RelayError::PolicyVerdictNotInForce));
        }
        item.resolution = Some(resolution);
        HOLD_QUEUE.put(&self.store, &mut txn, &hold_key(reference), &item)?;
        self.store.append_gate_decision_in_txn(
            &mut txn,
            &crate::store::GateDecisionRecord {
                version: 0,
                decision_id: crate::store::GateDecisionId::now(),
                created_at: crate::unix_seconds_now(),
                outcome: match resolution {
                    PolicyHoldResolution::Cleared => "allow",
                    PolicyHoldResolution::Declined => "block",
                }
                .to_owned(),
                reason_codes: vec![
                    match resolution {
                        PolicyHoldResolution::Cleared => "gate.policy_model.hold_cleared",
                        PolicyHoldResolution::Declined => "gate.policy_model.hold_declined",
                    }
                    .to_owned(),
                ],
                receipt_reasons: Vec::new(),
                system_notices: Vec::new(),
                actor_class: "human".to_owned(),
                actor_ref: Some(owner.actor().to_hex()),
                content_kind: "policy_hold".to_owned(),
                policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
                claim_id: None,
                grant_ref: Some(reference.to_owned()),
                diff_handle: item.content_hash.to_vec(),
                read_frontier_hash: item.policy_frontier,
                redacted_at: None,
            },
        )?;
        txn.commit()?;
        Ok(())
    }
    /// Remove old resolved or policy-stale local holds. Gate ledger receipts remain.
    /// Current unresolved holds are never silently discarded.
    pub fn prune_policy_holds(
        &self,
        owner: &AuthenticatedOwner,
        held_before: u64,
        limit: usize,
    ) -> Result<usize> {
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let frontier =
                crate::gate::resolve_policy_manifest(&self.store, txn)?.read_frontier_hash()?;
            let mut keys = Vec::new();
            for row in HOLD_QUEUE.iter_from(&self.store, txn, &[])? {
                if keys.len() >= limit {
                    break;
                }
                let (key, item) = row?;
                if item.human == owner.principal_ref()
                    && item.held_at < held_before
                    && (item.resolution.is_some() || item.policy_frontier != frontier)
                {
                    keys.push(key);
                }
            }
            for key in &keys {
                HOLD_QUEUE.delete(&self.store, txn, key)?;
            }
            Ok(keys.len())
        })
    }
}
