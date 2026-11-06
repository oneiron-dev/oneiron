//! One rung's own work: its route id, the call as it binds it, and its
//! note as the rung that answered a captured call.
use super::*;

impl LadderRung {
    /// The full `model@place` route id of this rung (FIX 11768 seam for
    /// L05): its model and the place [`offer_place`] names for its
    /// binding's locality and its route's origin, minted through
    /// [`offer_id`] — the one producer, the same resolution the ladder's
    /// doors judge.
    #[must_use]
    pub(in crate::models) fn offer_id(&self) -> String {
        let place = offer_place(
            self.offer.binding.locality,
            self.offer.binding.route.origin(),
        );
        offer_id(&self.model, &place)
    }

    /// The call as this rung sends it: its model at its route, its
    /// instruction first.
    pub(super) fn bind(&self, mut request: LlmRequest) -> LlmRequest {
        request.model = self.model.clone();
        request.envelope.locality = self.offer.binding.locality;
        if let Some(prompt) = &self.prompt {
            request.messages.insert(
                0,
                LlmMessage {
                    role: LlmMessageRole::System,
                    content: vec![ContentPart::Text {
                        text: prompt.clone(),
                    }],
                },
            );
            oneiron::code_run::shift_cache_boundaries(&mut request);
            // The instruction is part of the call this rung sends, so the
            // manifest stamps it as its own first segment; unstamped, the
            // manifest describes a call one message shorter and this
            // rung's turns get no session (FIX 10366). The restamp keeps
            // the admitted turn's digest (REVIEW-4386 P1): pending, commit
            // and restore-authority lookups still name it.
            if let Some(manifest) = &request.host_segments {
                let mut shifted = Vec::with_capacity(manifest.segments().len() + 1);
                shifted.push(Segment::whole(SegmentKind::System, SegmentClock::Epoch, 0));
                shifted.extend(manifest.segments().iter().map(|segment| Segment {
                    message: segment.message + 1,
                    ..segment.clone()
                }));
                request.host_segments =
                    Some(Arc::new(manifest.restamped(shifted, &request.messages)));
            }
        }
        request
    }

    /// Names this rung as the one that answered `request` (before its
    /// binding), for the step replay capsule a capture on this thread waits
    /// to finalize (FIX 3028): its model, where it ran and the prompt it put
    /// first, so the capsule holds what was really sent.
    pub(super) fn note_answered(&self, request: &LlmRequest) {
        oneiron::code_run::note_answering_rung(
            request,
            &self.model,
            self.offer.binding.locality,
            self.prompt.as_deref(),
        );
        super::shadow_capture::note_answered(self, request);
    }
}
