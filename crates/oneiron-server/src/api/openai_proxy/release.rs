//! FIX 8191: the completed answer, judged right before it is released. The
//! rows recall put in the prompt (its producers, as it listed them) were
//! checked for where the prompt went before the model read them; the answer
//! carries their words to the caller, and the owner's world settings may
//! have changed while the model answered. So the answer is judged again,
//! by those same rows, for the caller's destination as the settings stand
//! now, with the rule recall's own check applies: never wider.

use axum::{http::StatusCode, response::Response};
use oneiron::EntityId;
use oneiron::settings::ReleaseHold;

use crate::api::McpCallContext;
use crate::server::SyncServer;

/// Refuses the completed `answers` when a world now keeps one of the
/// `producers` recall put in their prompt from the caller's destination,
/// with recall's own content-free reason (FIX 4939); a check that cannot be
/// read is an integrity hold. Answers whose prompt carried no recalled row
/// are released as before.
pub(super) fn completed_answers(
    server: &SyncServer,
    actor: &McpCallContext,
    producers: &[EntityId],
    answers: &[String],
) -> Result<(), Response> {
    if producers.is_empty() {
        return Ok(());
    }
    let payload = answers.join("\n");
    let hold = crate::device_local::retained_hold(
        &server.vault,
        &actor.destination(),
        producers,
        payload.as_bytes(),
    )
    .unwrap_or(Some(ReleaseHold::Placement));
    match hold {
        None => Ok(()),
        Some(hold) => Err(super::wire::error(
            StatusCode::FORBIDDEN,
            "permission_error",
            "memory_withheld",
            format!(
                "the answer carries recalled memory that stays on this device: {}",
                hold.reason()
            ),
        )),
    }
}
