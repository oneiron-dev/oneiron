//! `/v1/owner/authority/handoff-alarms`: the saved fork alarms a held root
//! handoff left (OF-166 = A). Each alarm names a retired key that signed a
//! refused row; it stays saved until the vault's owner acknowledges it, and a
//! refused row the owner has not seen raises it again. Each route runs its
//! `vault.authority.handoff_alarms` row's verb hooks once around the engine
//! door, on the row's own input type (OF-580).

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::task_verb::sdk::{EmptyRequest, HandoffAlarmRequest};
use serde_json::Value;

use super::{OwnerReply, blocking, hooked_owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, hooked_row};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/authority/handoff-alarms", get(list))
        .route("/authority/handoff-alarms/acknowledge", post(acknowledge))
}

/// `GET /v1/owner/authority/handoff-alarms`: every saved alarm in the
/// shape and order `vault.authority.handoff_alarms` answers (OF-158): unix
/// seconds, oldest raised first, then by signer.
async fn list(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<Value> {
    let (_, actor) = hooked_owner(&auth, &server)?;
    let alarms = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.authority.handoff_alarms",
            EmptyRequest {},
            |_| Ok(vault.authority_handoff_alarms()?),
        )
    })
    .await?;
    Ok(Json(alarms))
}

/// `POST /v1/owner/authority/handoff-alarms/acknowledge`: the owner has seen
/// one alarm, named by its retired key (`signer`, `suite:hex`, as the list
/// names it). It stays saved with its refused row marked seen; acknowledging
/// it again changes nothing.
async fn acknowledge(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<HandoffAlarmRequest>, JsonRejection>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let alarm = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.authority.handoff_alarms.acknowledge",
            request,
            |request: HandoffAlarmRequest| match vault
                .acknowledge_authority_handoff_alarm(&owner, &request.signer)
            {
                Ok(alarm) => Ok(alarm),
                Err(error) if error.kind() == oneiron::ErrorKind::EntityNotFound => {
                    Err(OwnerError::NotFound("handoff_alarm", request.signer))
                }
                Err(error) => Err(error.into()),
            },
        )
    })
    .await?;
    Ok(Json(alarm))
}
