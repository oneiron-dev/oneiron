//! Whether a media rung takes a call (FIX 8612, FIX 8614, FIX 8627): its row
//! serves the call's operation and inputs, and its offer's wire carries the
//! call's whole reference set, in order. A rung that does not is passed,
//! unsent, before its permit starts, and the call goes on down its ladder;
//! a call no rung takes ends as a call no rung serves always has. No
//! reference is cut to fit an offer, and a row's `max_references` is only a
//! hint.
use oneiron::llm::media::MediaRequest;

use super::MediaRung;

impl MediaRung {
    /// Whether this rung takes `request`, bound as the rung would send it.
    pub(in crate::models) fn takes(&self, request: &MediaRequest) -> bool {
        self.row.admit_media(request).is_ok()
            && self
                .backend
                .reference_compatibility(request)
                .takes(request.references.len())
    }
}
