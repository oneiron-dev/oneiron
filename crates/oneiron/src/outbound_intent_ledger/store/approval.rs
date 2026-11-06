//! The typed owner approval a ledger row may carry (moved out of
//! `validate_record`; FIX 6362, an L12-B seam the Engine approved 10-20). A
//! native-mail cold send's proof binds its canonical mail digest, exactly as
//! before; a reply sent as the mailbox's own account binds the ordinary
//! frozen target's digest. An e-sign send for signature or reminder's proof binds the digest
//! the gate's approve-once lookup composed for that send, recomposed from its
//! frozen actor, act, channel and brief. A failure-signal batch's proof binds
//! the digest its lookup composed for that batch, recomposed the same way
//! from its frozen endpoint, content ref and send ref (FIX 6679). Any other
//! row carries none.

use super::super::types::{IntentLedgerError, IntentLedgerRecord, IntentLedgerResult};

/// Refuses a row whose admitted approval does not bind the row itself: its
/// own intent, no endpoint or capability binding, and the digest its frozen
/// `payload` (the row's readable request) recomposes for its server and tool.
pub(super) fn validate_admitted_approval(
    record: &IntentLedgerRecord,
    payload: &[u8],
) -> IntentLedgerResult<()> {
    let Some(approval) = record.admitted_approval else {
        return Ok(());
    };
    let digest = match (record.server.as_str(), record.tool.as_str()) {
        // A reply sent as the mailbox's own account (SMTP, Graph) names no
        // sender identity: its press binds the ordinary frozen target, so the
        // digest is recomposed that way when the payload is no native mail
        // send (fix list rows 17872, 17643).
        ("email", "send") => {
            crate::channel_identity_provider::native_mail::approval_digest_from_frozen_payload(
                payload,
            )
            .or_else(|| {
                crate::outbound::connector_slate_effect_from_frozen_payload(
                    payload, "email", "send",
                )
                .as_ref()
                .and_then(crate::gate::external_effect_approval_digest)
            })
        }
        ("esign", tool @ ("send_for_signature" | "remind")) => {
            crate::outbound::esign_approval_digest_from_frozen_payload(payload, tool)
        }
        ("failure_signals", "send") => {
            crate::outbound::failure_signals_approval_digest_from_frozen_payload(payload)
        }
        _ => None,
    };
    if approval.intent_id() != record.id
        || record.resolved_endpoint.is_some()
        || record.capability_provenance.is_some()
        || digest != Some(approval.effect_digest())
    {
        return Err(IntentLedgerError::InvalidRecord(
            "admitted approval binding mismatch",
        ));
    }
    Ok(())
}
