//! The Gate receipt for one refused agent-power act (SPAWN-KNOB): a spawn by an
//! instance whose `spawn` is off, a child asked a power above its parent's, or a
//! definition authored by an instance whose `save_agent` is off.

use super::input::GateContentKind;
use super::policy_basis_in_txn;
use crate::agent_def::AgentPowerTarget;
use crate::code_run::SelfEffect;
use crate::error::Result;
use crate::store::gate_reason::GateReceiptOutcome;
use crate::store::{GateDecisionId, GateReceipt, ReceiptActor};
use crate::{Vault, WriteActor};

/// Appends the deny receipt in the caller's writer, which commits it with no
/// other effect of the refused act. `request` is the act's canonical request,
/// hashed as the receipt's diff handle; `target` is the grant that decided.
pub(crate) fn record_agent_power_refusal_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: WriteActor,
    target: AgentPowerTarget,
    effect: SelfEffect,
    request: &[u8],
    reason: &'static str,
) -> Result<GateDecisionId> {
    let mut receipt = GateReceipt::new(
        GateReceiptOutcome::Deny,
        GateContentKind::AgentPower.as_str(),
        reason,
        ReceiptActor::Row(actor),
        blake3::hash(request).as_bytes().to_vec(),
        policy_basis_in_txn(&vault.store, txn)?,
    );
    receipt.grant_ref = Some(target.grant_ref());
    receipt.details = vec![format!("effect {}", effect.as_str())];
    Ok(vault
        .store
        .record_gate_receipt_in_txn(txn, receipt)?
        .decision_id)
}
