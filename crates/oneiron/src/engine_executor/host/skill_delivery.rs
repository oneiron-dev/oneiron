//! A skill body a call's answer delivered to the step's own program (FIX
//! 3608): what the call's native producer witnessed (`crate::skill`), held
//! from the call's answer until the runtime hands its guest the reply
//! ([`JsCodeModeHost::guest_reply_delivered`]), and kept for the step's
//! replay context only then. A body is held only for a call the step's own
//! program made, never a callable's, only while the answer the dispatcher
//! gave is the one the producer made (its JSON still hashes as witnessed,
//! so no hook redacted it in the verb's door), and only while no verb
//! hook's view replaced it. A stored card in the answer's place, made before
//! the reply ([`RecordingJsHost::store_answer`]) or as the runtime fits the
//! reply to one message ([`JsCodeModeHost::store_reply`]), drops it; so
//! does a call whose answer failed, and the next call. A denial, a
//! redaction, a card and a transformed answer deliver nothing.

use super::*;
use crate::skill::answer_digest;

impl RecordingJsHost<'_, '_> {
    /// Holds the skill bodies the producer of the call at bridge position
    /// `seq` witnessed, as `outcome`, the call's answer as the dispatcher
    /// gave it, delivers them to the step's own program: none for a call a
    /// callable made, for an answer that is not the one the producer made,
    /// nor for one whose answer a verb hook's view replaced (`hooked`). What
    /// the producer witnessed is taken either way.
    pub(super) fn hold_delivery(
        &mut self,
        seq: u64,
        hooked: bool,
        outcome: Option<&SelfDispatchOutcome>,
    ) {
        let witnessed = self.gated_write.take_skill_bodies();
        self.held_delivery.clear();
        let Some(witnessed) = witnessed else {
            return;
        };
        let made = outcome.and_then(outcome_digest) == Some(witnessed.answer);
        if self.callable_depth > 0 || hooked || !made {
            return;
        }
        let held = witnessed
            .bodies
            .into_iter()
            .map(|body| CapturedSkillDelivery { seq, body });
        self.held_delivery.extend(held);
    }

    /// Keeps each skill body held for the call whose reply the runtime just
    /// handed the guest, in the step's replay context.
    pub(super) fn deliver_held(&mut self) {
        let held = std::mem::take(&mut self.held_delivery);
        self.context_capture.deliveries.extend(held);
    }
}

/// The BLAKE3 of `outcome`'s answer as JSON, as its producer's witness binds
/// it: a verb's output, or the leader's answer text. `None` for any other
/// outcome, which no producer witnesses.
fn outcome_digest(outcome: &SelfDispatchOutcome) -> Option<[u8; 32]> {
    match outcome {
        SelfDispatchOutcome::AgentVerb(answer) => serde_json::to_vec(&answer.output)
            .ok()
            .map(|json| answer_digest(&json)),
        SelfDispatchOutcome::Leader(json) => Some(answer_digest(json.as_bytes())),
        _ => None,
    }
}
