//! The Gate receipt for one refused agent-power act (SPAWN-KNOB): a spawn by an
//! instance whose `spawn` is off, a child asked a power above its parent's, or a
//! definition authored by an instance whose `save_agent` is off.

use super::constants::POLICY_SCHEMA_VERSION;
use super::input::GateContentKind;
use super::resolve_policy_manifest;
use crate::agent_def::AgentPowerTarget;
use crate::code_run::SelfEffect;
use crate::error::Result;
use crate::store::{GateDecisionId, GateDecisionRecord, GateSystemNoticeRecord};
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
    let policy = resolve_policy_manifest(&vault.store, txn)?;
    let content_kind = GateContentKind::AgentPower.as_str();
    let mut record = GateDecisionRecord {
        version: crate::store::GATE_DECISION_LEDGER_VERSION,
        decision_id: GateDecisionId::from_bytes(vault.store.clock.ulid()?),
        created_at: crate::ports::recorded_at_in_txn(&vault.store, txn)?,
        outcome: "deny".to_owned(),
        reason_codes: vec![reason.to_owned()],
        receipt_reasons: Vec::new(),
        system_notices: GateSystemNoticeRecord::receipt_details(
            content_kind,
            vec![format!("effect {}", effect.as_str())],
        ),
        actor_class: actor.actor_class().gate_actor_class().to_owned(),
        actor_ref: Some(actor.entity_ref().to_hex()),
        content_kind: content_kind.to_owned(),
        policy_manifest_version: POLICY_SCHEMA_VERSION.to_owned(),
        claim_id: None,
        grant_ref: Some(target.grant_ref()),
        diff_handle: blake3::hash(request).as_bytes().to_vec(),
        read_frontier_hash: policy.read_frontier_hash()?,
        context: Default::default(),
        redacted_at: None,
    };
    vault
        .store
        .append_fresh_gate_decision_in_txn(txn, &mut record)?;
    Ok(record.decision_id)
}
