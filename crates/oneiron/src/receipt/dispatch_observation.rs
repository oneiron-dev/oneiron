//! Passive OF-327 per-try audit observations; never resend authority.
use super::kernel::{ReceiptKind, ReceiptRecord};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::error::{Error, Result};
use crate::outbound::{FrozenDispatchIdentity, OutboundDispatchOutcome, OutboundDispatchResult};
use crate::side_table::{self, CodecError, Raw, RawValue, SideKey, SideTable};
use crate::store::Store;
use serde::{Deserialize, Serialize};

const OBSERVATIONS: SideTable<DispatchObservationKey, DispatchObservation, Raw> =
    SideTable::new(&side_table::DISPATCH_OBSERVATION);

#[derive(Debug, Clone, Copy)]
pub(crate) struct DispatchObservationKey {
    pub(crate) attempt_id: AttemptId,
    pub(crate) attempt_count: u32,
}
impl SideKey for DispatchObservationKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.attempt_id.as_bytes());
        out.extend_from_slice(&self.attempt_count.to_be_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (id, count) = bytes.split_at_checked(16)?;
        Some(Self {
            attempt_id: AttemptId::from_bytes(id).ok()?,
            attempt_count: u32::from_be_bytes(count.try_into().ok()?),
        })
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
            "ambiguous" => OutboundDispatchOutcome::Ambiguous,
            _ => return Err(Error::CorruptedIndex("dispatch observation outcome")),
        };
        Ok(OutboundDispatchResult {
            outcome,
            gate_decision_id: self.gate_decision_id.clone(),
            gate_outcome: self.gate_outcome.clone(),
            gate_reason_codes: self.gate_reason_codes.clone(),
            receipt: self.receipt.clone(),
            // The observation is not resend authority; terminal consumers
            // resolve the exact ledger row instead of trusting this echo.
            resolution: None,
            // Runtime meter echoes belong to the originating call, not audit replay.
            effector_budget: None,
            budget_ladder_events: Vec::new(),
        })
    }
}
impl RawValue for DispatchObservation {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        serde_json::to_vec(self)
            .map_err(|_| Error::InvariantViolation("dispatch observation encoding").into())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        serde_json::from_slice(bytes)
            .map_err(|_| Error::CorruptedIndex("dispatch observation schema").into())
    }
}

fn validate(key: DispatchObservationKey, row: DispatchObservation) -> Result<DispatchObservation> {
    if row.version != 1
        || row.attempt_ref != crate::entity_id::bytes_to_hex_lower(key.attempt_id.as_bytes())
        || row.attempt_count != key.attempt_count
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
    OBSERVATIONS
        .get(&vault.store, &txn, &key)?
        .map(|row| validate(key, row))
        .transpose()
}
pub(crate) fn append_dispatch_observation_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    key: DispatchObservationKey,
    identity: Option<FrozenDispatchIdentity>,
    result: &OutboundDispatchResult,
) -> Result<()> {
    if OBSERVATIONS.contains(store, txn, &key)? {
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
    OBSERVATIONS.put(store, txn, &key, &row)?;
    Ok(())
}
/// Exhaustive audit projector, like the existing durable-send source.
pub(super) fn dispatch_observations(vault: &Vault) -> Result<Vec<ReceiptRecord>> {
    let txn = vault.store.env.read_txn()?;
    OBSERVATIONS
        .iter_from(&vault.store, &txn, &[])?
        .map(|entry| {
            let (key, row) = entry?;
            Ok(validate(key, row)?.receipt)
        })
        .collect()
}
