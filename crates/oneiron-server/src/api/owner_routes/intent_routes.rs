//! `/v1/owner/intents`: the owner states an intent in his own words (FIX
//! 8949). His words land as an Approved, UserStated `profile.intent` about
//! him, the intent the digest's urgent breakthrough weighs a wait against,
//! citing the MESSAGE they came from when he names one. The engine checks
//! his proof again in the write. A Dreamer extraction never lands here: a
//! stated intent the Dreamer noticed is his to confirm at
//! `/v1/owner/decisions`.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::response::Json;
use axum::routing::post;
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::entity_id;
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/intents", post(state_intent))
}

/// The owner's intent: his exact words, and the MESSAGE (32 hex) they came
/// from, when there is one.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateIntent {
    text: String,
    #[serde(default)]
    message: Option<String>,
}

/// The intent's claim, as 32 hex.
#[derive(Serialize)]
struct IntentStated {
    claim: String,
}

/// `POST /v1/owner/intents`: one intent, in the owner's words.
async fn state_intent(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<StateIntent>,
) -> OwnerReply<IntentStated> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let stated = blocking(move || {
        let message = request
            .message
            .as_deref()
            .map(|hex| entity_id("message", hex))
            .transpose()?;
        let claim = server
            .vault()
            .record_owner_intent(&owner, &request.text, message)?;
        Ok(IntentStated {
            claim: claim.to_hex(),
        })
    })
    .await?;
    Ok(Json(stated))
}
