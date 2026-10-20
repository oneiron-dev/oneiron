//! The owner's one-send press a send's admission records on its ledger row
//! (FIX 6362; an L12-B seam the Engine approved 10-20). A native-mail cold
//! send records it as before. An e-sign send for signature or reminder now
//! records the press the gate spent admitting it too, so the signing links
//! its deliveries carry mint under that recorded owner act, and its live
//! retry reuses the spent press rather than asking again.

use super::{ApprovalContext, ExternalEffectGovernance};
use crate::gate::ExternalEffectGateInput;
use crate::outbound_intent_ledger::{AdmittedApproval, IntentId};

impl ExternalEffectGovernance {
    /// The actual one-send tap selected under the admission writer lock.
    /// Its proof is persisted only if this Gate decision and Pending insertion
    /// commit together; a preflight lookup never authors admission authority.
    /// Only a native-mail cold send or an e-sign send for signature or
    /// reminder carries one.
    pub(crate) fn admitted_send_approval(&self, intent_id: IntentId) -> Option<AdmittedApproval> {
        if self.approval_context != ApprovalContext::FirstAdmission {
            return None;
        }
        let effect = self.input.external_effect.as_ref()?;
        if !effect.mail_approve_once && !esign_press_send(&effect.channel, &effect.verb) {
            return None;
        }
        self.approve_once
            .as_ref()
            .map(|tap| AdmittedApproval::from_gate(intent_id, tap.digest()))
    }
}

/// Whether `context` retries an e-sign send on the owner's press its first
/// admission recorded for this exact effect: the retry reuses that spent
/// press, with no second spend. A native-mail proof never matches here; it
/// keeps its own cold-send digest.
pub(super) fn esign_retry_authorized(
    effect: &ExternalEffectGateInput,
    context: ApprovalContext,
) -> bool {
    let ApprovalContext::Retry(proof) = context else {
        return false;
    };
    esign_press_send(&effect.channel, &effect.verb)
        && super::external_effect_approval_digest(effect)
            .is_some_and(|digest| digest == proof.effect_digest())
}

/// An e-sign act whose deliveries carry a signing link: a send for signature
/// or a reminder. A void carries none.
fn esign_press_send(channel: &str, verb: &str) -> bool {
    channel == "esign" && matches!(verb, "send_for_signature" | "remind")
}
