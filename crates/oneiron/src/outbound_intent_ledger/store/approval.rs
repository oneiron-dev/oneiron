//! The typed owner approval a ledger row may carry (moved out of
//! `validate_record`; FIX 6362, an L12-B seam the Engine approved 10-20). A
//! native-mail cold send's proof binds its canonical mail digest, exactly as
//! before. An e-sign send for signature or reminder's proof binds the digest
//! the gate's approve-once lookup composed for that send, recomposed from its
//! frozen actor, act, channel and brief. Any other row carries none.

use super::super::types::{IntentLedgerError, IntentLedgerRecord, IntentLedgerResult};

/// Refuses a row whose admitted approval does not bind the row itself: its
/// own intent, no endpoint or capability binding, and the digest its frozen
/// payload recomposes for its server and tool.
pub(super) fn validate_admitted_approval(record: &IntentLedgerRecord) -> IntentLedgerResult<()> {
    let Some(approval) = record.admitted_approval else {
        return Ok(());
    };
    let digest = match (record.server.as_str(), record.tool.as_str()) {
        ("email", "send") => {
            crate::channel_identity_provider::native_mail::approval_digest_from_frozen_payload(
                record.payload(),
            )
        }
        ("esign", tool @ ("send_for_signature" | "remind")) => {
            crate::outbound::esign_approval_digest_from_frozen_payload(record.payload(), tool)
        }
        _ => None,
    };
    if approval.intent_id() != record.id
        || record.resolved_endpoint.is_some()
        || record.capability_provenance.is_some()
        || digest != Some(approval.effect_digest())
    {
        return Err(IntentLedgerError::InvalidRecord(
            "admitted mail approval binding mismatch",
        ));
    }
    Ok(())
}
