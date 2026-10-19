//! The owner's nonce/frontier-bound critical-claim confirmation ceremony.
//! The authority log is the receipt; no second confirmation ledger is kept.
use serde::{Deserialize, Serialize};

use crate::authority::{
    CRITICAL_WRITE_CONFIRM_SCHEMA_VERSION, CriticalWriteConfirmAction,
    CriticalWriteConfirmDisposition, CriticalWriteConfirmMethod, CriticalWriteConfirmState,
    HostSlipIssuer,
};
use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::gate::{
    CriticalWriteConfirmBinding, CriticalWriteConfirmResolution, critical_confirm_has_no_deadline,
    critical_write_confirm_binding, pending_row_holds_critical_confirm,
};
use crate::store::{GateDecisionId, PendingGateConsentRecord};

use super::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CriticalWriteConfirmPendingRequest {
    /// The candidate's gate decision ref (gate:<32-hex>).
    pub pending_operation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CriticalWriteConfirmRequest {
    pub pending_operation: String,
    /// The 32-hex nonce the pending read returned.
    pub nonce: String,
    /// The 64-hex policy frontier the pending read returned.
    pub read_frontier_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CriticalWriteConfirmReceiptRequest {
    /// The 64-hex confirmation id the pending read or settlement returned.
    pub confirm_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CriticalWriteConfirmPending {
    pub pending_operation: String,
    pub claim_ref: String,
    pub confirm_id: String,
    pub nonce: String,
    pub read_frontier_hash: String,
    pub effect_digest: String,
    pub expires_at: u64,
    /// Replicated and reopened owner-answer obligations have no deadline.
    pub has_deadline: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CriticalWriteConfirmAnswer {
    Clear,
    Decline,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CriticalWriteConfirmReceipt {
    /// The signed, fold-verified authority entry (authority:<64-hex>).
    pub receipt_ref: String,
    pub confirm_id: String,
    pub pending_operation: String,
    pub claim_ref: String,
    pub nonce: String,
    pub read_frontier_hash: String,
    pub effect_digest: String,
    pub expires_at: u64,
    pub disposition: CriticalWriteConfirmAnswer,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CriticalWriteConfirmSettlement {
    pub receipt: CriticalWriteConfirmReceipt,
    pub resolution: CriticalWriteConfirmResolution,
}

impl CriticalWriteConfirmPending {
    fn from_binding(
        binding: &CriticalWriteConfirmBinding,
        pending: &PendingGateConsentRecord,
    ) -> Self {
        Self {
            pending_operation: format!("gate:{}", binding.gate_decision_id.to_hex()),
            claim_ref: binding.claim_id.to_hex(),
            confirm_id: bytes_to_hex_lower(&binding.confirm_id),
            nonce: bytes_to_hex_lower(&binding.nonce),
            read_frontier_hash: bytes_to_hex_lower(&binding.read_frontier_hash),
            effect_digest: bytes_to_hex_lower(&binding.effect_digest),
            expires_at: binding.expires_at,
            has_deadline: !critical_confirm_has_no_deadline(pending),
        }
    }
}

impl CriticalWriteConfirmReceipt {
    fn from_state(state: &CriticalWriteConfirmState) -> Self {
        let action = &state.action;
        Self {
            receipt_ref: format!(
                "authority:{}",
                bytes_to_hex_lower(&state.authority_entry_hash)
            ),
            confirm_id: bytes_to_hex_lower(&action.confirm_id),
            pending_operation: format!("gate:{}", bytes_to_hex_lower(&action.gate_decision_id)),
            claim_ref: action.claim_id.to_hex(),
            nonce: bytes_to_hex_lower(&action.nonce),
            read_frontier_hash: bytes_to_hex_lower(&action.read_frontier_hash),
            effect_digest: bytes_to_hex_lower(&action.effect_digest),
            expires_at: action.expires_at,
            disposition: match action.disposition {
                CriticalWriteConfirmDisposition::Clear => CriticalWriteConfirmAnswer::Clear,
                CriticalWriteConfirmDisposition::Decline => CriticalWriteConfirmAnswer::Decline,
            },
        }
    }
}

impl Memory<'_> {
    /// Reads exactly one candidate's attachment, including a timed-out one.
    /// None means its gate decision has no current critical confirmation.
    pub fn critical_write_confirm_pending_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &CriticalWriteConfirmPendingRequest,
    ) -> MemoryResult<Option<CriticalWriteConfirmPending>> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        self.critical_confirm_owner_in_txn(owner, &txn)?;
        let Some((binding, pending)) =
            self.critical_confirm_pending_in_txn(&txn, &lane, &input.pending_operation)?
        else {
            return Ok(None);
        };
        self.produced_from([binding.claim_id]);
        Ok(Some(CriticalWriteConfirmPending::from_binding(
            &binding, &pending,
        )))
    }

    pub fn critical_write_confirm_clear_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        input: &CriticalWriteConfirmRequest,
    ) -> MemoryResult<CriticalWriteConfirmSettlement> {
        self.critical_write_confirm_answer_as_owner(
            owner,
            issuer,
            input,
            CriticalWriteConfirmDisposition::Clear,
        )
    }

    pub fn critical_write_confirm_decline_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        input: &CriticalWriteConfirmRequest,
    ) -> MemoryResult<CriticalWriteConfirmSettlement> {
        self.critical_write_confirm_answer_as_owner(
            owner,
            issuer,
            input,
            CriticalWriteConfirmDisposition::Decline,
        )
    }

    fn critical_write_confirm_answer_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        issuer: &HostSlipIssuer,
        input: &CriticalWriteConfirmRequest,
        disposition: CriticalWriteConfirmDisposition,
    ) -> MemoryResult<CriticalWriteConfirmSettlement> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let settlement = self
            .vault
            .try_with_write_txn_grouped(|txn| -> MemoryResult<_> {
                let person = self.critical_confirm_owner_in_txn(owner, txn)?;
                let (binding, pending) = self
                    .critical_confirm_pending_in_txn(txn, &lane, &input.pending_operation)?
                    .ok_or_else(no_pending)?;
                let nonce = parse_hex::<16>(&input.nonce, "nonce")?;
                let frontier = parse_hex::<32>(&input.read_frontier_hash, "read_frontier_hash")?;
                let now = self.vault.store.clock.now_recorded_at();
                if nonce != binding.nonce || frontier != binding.read_frontier_hash {
                    return Err(stale_confirmation());
                }
                if disposition == CriticalWriteConfirmDisposition::Clear
                    && binding.expires_at <= now
                    && !critical_confirm_has_no_deadline(&pending)
                {
                    return Err(stale_confirmation());
                }
                let action = CriticalWriteConfirmAction {
                    schema_version: CRITICAL_WRITE_CONFIRM_SCHEMA_VERSION,
                    confirm_id: binding.confirm_id,
                    gate_decision_id: binding.gate_decision_id.as_bytes(),
                    claim_id: binding.claim_id,
                    effect_digest: binding.effect_digest,
                    read_frontier_hash: binding.read_frontier_hash,
                    nonce: binding.nonce,
                    expires_at: binding.expires_at,
                    disposition,
                    // This door reauthenticates the owner's own credential; it
                    // accepts no caller claim of passphrase reentry.
                    method: CriticalWriteConfirmMethod::TokenReauth,
                };
                let state = self.vault.append_critical_write_confirm_as_owner_in_txn(
                    txn, owner, issuer, action, now,
                )?;
                let resolution = self.vault.settle_critical_write_confirm_in_txn(
                    txn,
                    binding.confirm_id,
                    now,
                    Some(person),
                )??;
                if (disposition == CriticalWriteConfirmDisposition::Clear
                    && resolution != CriticalWriteConfirmResolution::Cleared)
                    || self
                        .vault
                        .store
                        .pending_gate_consent_in_txn(txn, &binding.claim_id)?
                        .is_some_and(|row| row.decision_id == binding.gate_decision_id)
                {
                    return Err(stale_confirmation());
                }
                Ok(CriticalWriteConfirmSettlement {
                    receipt: CriticalWriteConfirmReceipt::from_state(&state),
                    resolution,
                })
            })?;
        if let Ok(id) = EntityId::from_hex(&settlement.receipt.claim_ref) {
            self.produced_from([id]);
        }
        Ok(settlement)
    }

    /// Reads the existing signed receipt from the authority fold, never
    /// mutating or settling a pending claim as a side effect.
    pub fn critical_write_confirm_receipt_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &CriticalWriteConfirmReceiptRequest,
    ) -> MemoryResult<CriticalWriteConfirmReceipt> {
        let confirm_id = parse_hex::<32>(&input.confirm_id, "confirm_id")?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        self.critical_confirm_owner_in_txn(owner, &txn)?;
        let fold = self.vault.authority_fold_readonly_in_txn(&txn)?;
        let state = fold
            .critical_write_confirms
            .get(&confirm_id)
            .filter(|_| {
                !fold
                    .conflicted_critical_write_confirms
                    .contains(&confirm_id)
            })
            .ok_or_else(|| MemoryError::not_found("no folded critical confirmation has that id"))?;
        require_readable(&lane, &txn, state.action.claim_id)?;
        self.produced_from([state.action.claim_id]);
        Ok(CriticalWriteConfirmReceipt::from_state(state))
    }

    fn critical_confirm_owner_in_txn(
        &self,
        owner: &AuthenticatedOwner,
        txn: &heed::RoTxn<'_>,
    ) -> MemoryResult<EntityId> {
        let person = owner.owner_authored_write_in_txn(self.vault, txn)?.actor();
        if person != self.actor || self.actor_class != EdgeActorClass::Human {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "a critical confirmation is answered on its owner's own handle",
                &["Present the owner's own verified, unattenuated credential."],
            ));
        }
        Ok(person)
    }

    fn critical_confirm_pending_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        lane: &ScopedRead<'_>,
        pending_operation: &str,
    ) -> MemoryResult<Option<(CriticalWriteConfirmBinding, PendingGateConsentRecord)>> {
        let reference = pending_operation.strip_prefix("gate:").ok_or_else(|| {
            MemoryError::bad_request("pending_operation is the candidate's gate:<32-hex> ref")
        })?;
        let decision = GateDecisionId::from_bytes(parse_hex::<16>(reference, "pending_operation")?);
        let record = self
            .vault
            .store
            .gate_decision_in_txn(txn, decision)?
            .ok_or_else(|| MemoryError::not_found("no gate decision has that ref"))?;
        let id = record
            .claim_id
            .map(EntityId::from_bytes)
            .transpose()?
            .ok_or_else(|| MemoryError::bad_request("the gate decision names no claim"))?;
        require_readable(lane, txn, id)?;
        let Some(pending) = self.vault.store.pending_gate_consent_in_txn(txn, &id)? else {
            return Ok(None);
        };
        if pending.decision_id != decision || !pending_row_holds_critical_confirm(&pending) {
            return Ok(None);
        }
        Ok(Some((critical_write_confirm_binding(&pending)?, pending)))
    }
}

fn require_readable(
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> MemoryResult<()> {
    if lane.entities_readable_in_txn(txn, &[id])?.first() == Some(&true) {
        return Ok(());
    }
    Err(MemoryError::not_found(
        "no claim this caller may read has that ref",
    ))
}

fn parse_hex<const N: usize>(value: &str, field: &str) -> MemoryResult<[u8; N]> {
    let refused = || MemoryError::bad_request(format!("{field} must be {} hex characters", N * 2));
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(refused());
    }
    let mut bytes = [0; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| refused())?;
    }
    Ok(bytes)
}

fn no_pending() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        "the critical confirmation is no longer pending",
        &["Read the candidate's current pending confirmation before answering."],
    )
}

fn stale_confirmation() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        "the critical confirmation expired or its nonce or policy frontier changed",
        &["Read the current pending confirmation and answer its exact binding."],
    )
}
