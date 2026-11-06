//! A skill body a call's answer delivered to the step's own program (FIX
//! 3608): what the call's native producer witnessed (`crate::skill`), held
//! from the call's answer until the runtime hands its guest the reply
//! ([`JsCodeModeHost::guest_reply_delivered`]), and kept for the step's
//! replay context only then. A body is held only for a call the step's own
//! program made, never a callable's, and only while no verb hook's view
//! replaced its answer. A stored card in the answer's place, made before the
//! reply ([`RecordingJsHost::store_answer`]) or as the runtime fits the reply
//! to one message ([`JsCodeModeHost::store_reply`]), drops it; so does a
//! call whose answer failed, and the next call. A denial, a redaction, a card
//! and a transformed answer deliver nothing.

use super::*;

impl RecordingJsHost<'_, '_> {
    /// Holds the skill bodies the producer of the call at bridge position
    /// `seq` witnessed, as its answer delivers them to the step's own
    /// program: none for a call a callable made, nor for one whose answer a
    /// verb hook's view replaced (`hooked`). What the producer witnessed is
    /// taken either way.
    pub(super) fn hold_delivery(&mut self, seq: u64, hooked: bool) {
        let bodies = self.gated_write.take_skill_bodies();
        self.held_delivery.clear();
        if self.callable_depth > 0 || hooked {
            return;
        }
        let held = bodies
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
