//! The owner's one-send press a send's admission records on its ledger row
//! (FIX 6362; an L12-B seam the Engine approved 10-20). A native-mail cold
//! send records it as before. An e-sign send for signature or reminder now
//! records the press the gate spent admitting it too, so the signing links
//! its deliveries carry mint under that recorded owner act, and its live
//! retry reuses the spent press rather than asking again. A failure-signal
//! batch the owner released records it the same way, so a definite retry of
//! that batch under its own ref reuses it (FIX 6679).
//!
//! FIX 6424 part 2a (Engine 10-20 21:0x ruling 8): a Linear mutation's and a
//! campaign leg's spent press is kept by its own family, typed by its target
//! ([`super::ApprovalTarget::keeps_spent_press`]), beside its ledger row or
//! its mirror operation, never in this row field, whose native-mail, e-sign
//! and failure-signal validation stays as it is. Its retry reuses it under
//! the same retry context.

use super::{ApprovalContext, ExternalEffectGovernance};
use crate::failure_signals::{FAILURE_SIGNALS_CHANNEL, FAILURE_SIGNALS_SEND_VERB};
use crate::gate::{ExternalEffectGateInput, GateOutcome};
use crate::outbound_intent_ledger::{AdmittedApproval, IntentId, PinnedApproval};

impl ExternalEffectGovernance {
    /// The actual one-send tap selected under the admission writer lock.
    /// Its proof is persisted only if this Gate decision and Pending insertion
    /// commit together; a preflight lookup never authors admission authority.
    /// Only a native-mail cold send, an e-sign send for signature or
    /// reminder, or a failure-signal batch carries one.
    pub(crate) fn admitted_send_approval(&self, intent_id: IntentId) -> Option<AdmittedApproval> {
        if self.approval_context != ApprovalContext::FirstAdmission {
            return None;
        }
        let effect = self.input.external_effect.as_ref()?;
        if !effect.mail_approve_once && !press_send(&effect.channel, &effect.verb) {
            return None;
        }
        self.approve_once
            .as_ref()
            .map(|tap| AdmittedApproval::from_gate(intent_id, tap.digest()))
    }

    /// FIX 6424 part 2a: the actual one-send tap a pinned family's first
    /// admission selected under the writer lock (a Linear dispatch, a
    /// campaign leg), filed under its target's family, kept with the
    /// Pending row it admits. `None` for every other effect, a mail path
    /// and a retry.
    pub(crate) fn pinned_send_approval(&self, intent_id: IntentId) -> Option<PinnedApproval> {
        if self.approval_context != ApprovalContext::FirstAdmission
            || self
                .input
                .external_effect
                .as_ref()
                .is_none_or(|effect| effect.mail_approve_once)
        {
            return None;
        }
        let family = self
            .input
            .provenance
            .approval_target
            .as_ref()?
            .pinned_family()?;
        self.approve_once.as_ref().map(|tap| {
            PinnedApproval::new(family, AdmittedApproval::from_gate(intent_id, tap.digest()))
        })
    }

    /// FIX 6424 part 2a: the press recording this governance spends, the
    /// test [`super::record_external_effect_policy`] applies, read before
    /// it is recorded, so its family can keep it for the same send's retry.
    pub(crate) fn spent_press_digest(&self) -> Option<crate::consent::EffectDigest> {
        let mail_approve_once = self
            .input
            .external_effect
            .as_ref()
            .is_some_and(|effect| effect.mail_approve_once);
        if self.decision.outcome() != GateOutcome::Allow
            || (self.approval_context == ApprovalContext::Observe && mail_approve_once)
        {
            return None;
        }
        self.approve_once.as_ref().map(|tap| tap.digest())
    }

    /// FIX 6424 part 2a (Engine 10-20 21:0x ruling 2): an Allow the
    /// mutation's other actor did not match admits nothing, so recording it
    /// spends no press: that press still releases this operation once the
    /// other actor is answered.
    pub(crate) fn release_unadmitted_press(&mut self) {
        self.approve_once = None;
    }
}

/// Whether `context` retries an e-sign send or a failure-signal batch on the
/// owner's press its first admission recorded for this exact effect: the
/// retry reuses that spent press, with no second spend. A native-mail proof
/// never matches here; it keeps its own cold-send digest.
pub(super) fn press_retry_authorized(
    effect: &ExternalEffectGateInput,
    context: ApprovalContext,
) -> bool {
    let ApprovalContext::Retry(proof) = context else {
        return false;
    };
    // FIX 6424 part 2a: or a Linear mutation's or a campaign leg's kept
    // press, by its pinned target, never by its channel.
    (press_send(&effect.channel, &effect.verb)
        || effect
            .provenance
            .approval_target
            .as_ref()
            .is_some_and(super::ApprovalTarget::keeps_spent_press))
        && super::external_effect_approval_digest(effect)
            .is_some_and(|digest| digest == proof.effect_digest())
}

/// A send whose admitted press its ledger row records (CALLS `FIX 6679 held
/// batch retry proof`): an e-sign act whose deliveries carry a signing link
/// (a send for signature or a reminder; a void carries none), or a
/// failure-signal batch.
fn press_send(channel: &str, verb: &str) -> bool {
    (channel == "esign" && matches!(verb, "send_for_signature" | "remind"))
        || (channel == FAILURE_SIGNALS_CHANNEL && verb == FAILURE_SIGNALS_SEND_VERB)
}
