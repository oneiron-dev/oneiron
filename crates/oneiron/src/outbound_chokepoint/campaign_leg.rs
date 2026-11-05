//! The native campaign driver's live context at the outbound writer.

use super::replay::effect_result;
use super::types::{OutboundEffectResult, PreparedEffect};
use crate::Vault;
use crate::campaign::enrollment::{
    CampaignLegCall, CampaignLegHold, admit_frozen_campaign_leg_in_txn,
};
use crate::outbound_intent_ledger::{
    IntentDispatchResult, IntentId, IntentLedgerError, IntentLedgerRecord, OutboundCallClass,
};

pub(super) fn hold_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    call: CampaignLegCall<'_>,
    local_node_id: Option<u64>,
) -> Result<Option<CampaignLegHold>, IntentLedgerError> {
    let Some(node) = local_node_id else {
        return Ok(None);
    };
    Ok(admit_frozen_campaign_leg_in_txn(vault, txn, call, node)?.hold())
}

pub(super) fn prepared_hold_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    prepared: &PreparedEffect,
    local_node_id: Option<u64>,
) -> Result<Option<OutboundEffectResult>, IntentLedgerError> {
    let call = CampaignLegCall {
        attempt_id: prepared.attempt_id,
        call_seq: prepared.call_seq,
        channel: &prepared.server,
        verb: &prepared.tool,
        payload: &prepared.payload,
    };
    let Some(hold) = hold_in_txn(vault, txn, call, local_node_id)? else {
        return Ok(None);
    };
    Ok(Some(OutboundEffectResult {
        dispatch: IntentDispatchResult {
            class: OutboundCallClass::Effectful,
            intent_id: Some(prepared.intent_id()?),
            state: None,
            send_outcome: None,
            replayed: false,
            escalation: None,
        },
        resolution: None,
        gate_decision_id: None,
        gate_outcome: None,
        gate_reason_codes: Vec::new(),
        gate_receipt_reasons: Vec::new(),
        budget_charge: None,
        dedupe_suppressed: false,
        suppression_receipt: None,
        ceiling_count: None,
        approval_digest: None,
        ask_consent: None,
        approval_actor: None,
        paced_until: None,
        campaign_leg: Some(hold),
    }))
}

pub(super) fn held_result(
    record: &IntentLedgerRecord,
    hold: CampaignLegHold,
    replayed: bool,
) -> OutboundEffectResult {
    let mut result = effect_result(record, None, replayed, None);
    result.campaign_leg = Some(hold);
    result
}
