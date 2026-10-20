//! A media job's owners and its erased answer (KS-2B2, FIX 5683 part B2).
//!
//! A job's row is stamped at its submit with who owns its content: the
//! actor that asked, when its caller names one; the subject its request is
//! about, a banked voice's owner; and the rows it was made from, none today.
//! Its payer is never one of them. A stamp the caller cannot name stays
//! absent, and the job is kept and runs all the same. The end keeps them:
//! each later write is of the row read back.
//!
//! The engine masks the row and scrubs it on an erase of an owner
//! (`oneiron::store`); here a poll of an erased job answers its erased end,
//! typed as `FatalLlmError::ResponseErased` (FIX 6296), with the reason
//! logged as a kind only.

use oneiron::EntityId;
use oneiron::llm::media::{MediaJobState, MediaRequest, MediaVoice};
use oneiron::store::ResponseStamps;

/// The stamps a job submitted for `request` keeps, its actor `actor`.
pub(in crate::models::media) fn submit_stamps(
    actor: Option<EntityId>,
    request: &MediaRequest,
) -> ResponseStamps {
    let subject = match &request.voice {
        Some(MediaVoice::Reference { owner, .. }) => EntityId::from_hex(owner).ok(),
        _ => None,
    };
    ResponseStamps {
        actor,
        subject,
        sources: Vec::new(),
    }
}

/// What a poll of the erased job `ticket` answers: it ended, and nothing of
/// it is left to give. Never taken up, resumed or resubmitted.
pub(in crate::models::media) fn erased_poll(ticket: &str) -> MediaJobState {
    tracing::info!(
        reason = "media_job_erased",
        ticket,
        "a media job's content was erased"
    );
    oneiron::store::media_job_erased_state()
}
