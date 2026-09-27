//! Passive OF-327 per-try audit observations; never resend authority.
use super::kernel::{ReceiptKind, ReceiptRecord};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::error::{Error, Result};
use crate::outbound::{FrozenDispatchIdentity, OutboundDispatchOutcome, OutboundDispatchResult};
use crate::store::Store;
use serde::{Deserialize, Serialize};

const PREFIX: &[u8] = b"dispatch_observation:v1/";

#[derive(Debug, Clone, Copy)]
pub(crate) struct DispatchObservationKey {
    pub(crate) attempt_id: AttemptId,
    pub(crate) attempt_count: u32,
}
impl DispatchObservationKey {
    fn bytes(self) -> Vec<u8> {
        [
            PREFIX,
            self.attempt_id.as_bytes(),
            self.attempt_count.to_be_bytes().as_slice(),
        ]
        .concat()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DispatchObservation {
    version: u8,
    attempt_ref: String,
    attempt_count: u32,
    identity: Option<FrozenDispatchIdentity>,
    outcome: String,
    gate_decision_id: Option<String>,
    gate_outcome: String,
    gate_reason_codes: Vec<String>,
    receipt: ReceiptRecord,
}
impl DispatchObservation {
    pub(crate) fn identity(&self) -> Option<&FrozenDispatchIdentity> {
        self.identity.as_ref()
    }
    pub(crate) fn receipt_id(&self) -> &str {
        &self.receipt.receipt_id
    }
    pub(crate) fn occurred_at(&self) -> u64 {
        self.receipt.occurred_at
    }
    /// Historical return data only. The outbound pipeline validates its ledger
    /// Done binding before it is permitted to consume this row.
    pub(crate) fn result(&self) -> Result<OutboundDispatchResult> {
        let outcome = match self.outcome.as_str() {
            "delivered_to_channel" => OutboundDispatchOutcome::DeliveredToChannel,
            "held" => OutboundDispatchOutcome::Held,
            "degraded" => OutboundDispatchOutcome::Degraded,
            "suppressed" => OutboundDispatchOutcome::Suppressed,
            "let_go" => OutboundDispatchOutcome::LetGo,
            "failed" => OutboundDispatchOutcome::Failed,
            _ => return Err(Error::CorruptedIndex("dispatch observation outcome")),
        };
        Ok(OutboundDispatchResult {
            outcome,
            gate_decision_id: self.gate_decision_id.clone(),
            gate_outcome: self.gate_outcome.clone(),
            gate_reason_codes: self.gate_reason_codes.clone(),
            receipt: self.receipt.clone(),
            // Runtime meter echoes belong to the originating call, not audit replay.
            effector_budget: None,
            budget_ladder_events: Vec::new(),
        })
    }
}
fn decode(key: &[u8], bytes: &[u8]) -> Result<DispatchObservation> {
    let row: DispatchObservation = serde_json::from_slice(bytes)
        .map_err(|_| Error::CorruptedIndex("dispatch observation schema"))?;
    if !key.starts_with(PREFIX)
        || key.len() != PREFIX.len() + 20
        || row.version != 1
        || row.attempt_ref
            != crate::entity_id::bytes_to_hex_lower(&key[PREFIX.len()..PREFIX.len() + 16])
        || row.attempt_count.to_be_bytes() != key[PREFIX.len() + 16..]
        || row.receipt.receipt_kind != ReceiptKind::Outbound
        || row.receipt.outcome != row.outcome
        || (row.outcome == "delivered_to_channel" && row.identity.is_none())
    {
        return Err(Error::CorruptedIndex("dispatch observation binding"));
    }
    Ok(row)
}
pub(crate) fn read_dispatch_observation(
    vault: &Vault,
    key: DispatchObservationKey,
) -> Result<Option<DispatchObservation>> {
    let txn = vault.store.env.read_txn()?;
    vault
        .store
        .vault_meta
        .get(&txn, &key.bytes())?
        .map(|raw| decode(&key.bytes(), &raw))
        .transpose()
}
pub(crate) fn append_dispatch_observation_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    key: DispatchObservationKey,
    identity: Option<FrozenDispatchIdentity>,
    result: &OutboundDispatchResult,
) -> Result<()> {
    let bytes_key = key.bytes();
    if store.vault_meta.get(txn, &bytes_key)?.is_some() {
        return Err(Error::ConcurrentWrite(
            "dispatch observation already stored",
        ));
    }
    let row = DispatchObservation {
        version: 1,
        attempt_ref: crate::entity_id::bytes_to_hex_lower(key.attempt_id.as_bytes()),
        attempt_count: key.attempt_count,
        identity,
        outcome: result.outcome.as_str().into(),
        gate_decision_id: result.gate_decision_id.clone(),
        gate_outcome: result.gate_outcome.clone(),
        gate_reason_codes: result.gate_reason_codes.clone(),
        receipt: result.receipt.clone(),
    };
    let bytes = serde_json::to_vec(&row)
        .map_err(|_| Error::InvariantViolation("dispatch observation encoding"))?;
    store.vault_meta.put(txn, &bytes_key, &bytes)?;
    Ok(())
}
/// Exhaustive audit projector, like the existing durable-send source.
pub(super) fn dispatch_observations(vault: &Vault) -> Result<Vec<ReceiptRecord>> {
    let txn = vault.store.env.read_txn()?;
    vault
        .store
        .vault_meta
        .prefix_iter(&txn, PREFIX)?
        .map(|entry| {
            let (key, bytes) = entry?;
            Ok(decode(&key, &bytes)?.receipt)
        })
        .collect()
}
