//! `/v1/owner/authority/handoff-alarms`: the saved fork alarms a held root
//! handoff left (OF-166 = A). Each alarm names a retired key that signed a
//! refused row; it stays saved until the vault's owner acknowledges it, and a
//! refused row the owner has not seen raises it again.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::authority::AuthorityHandoffAlarm;
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::owner::stamp::rfc3339_secs;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/authority/handoff-alarms", get(list))
        .route("/authority/handoff-alarms/acknowledge", post(acknowledge))
}

#[derive(Debug, Serialize)]
struct HandoffAlarm {
    /// The retired key, `suite:hex`.
    signer: String,
    /// The refused row's hash, hex.
    refused: String,
    /// The held handoffs the key signed, hex.
    handoffs: Vec<String>,
    raised: String,
    /// Who acknowledged it and when; none while it is open.
    acknowledged: Option<HandoffAlarmAck>,
    /// Refused rows the owner has acknowledged.
    seen: Vec<String>,
}

#[derive(Debug, Serialize)]
struct HandoffAlarmAck {
    by: String,
    at: String,
}

impl From<AuthorityHandoffAlarm> for HandoffAlarm {
    fn from(alarm: AuthorityHandoffAlarm) -> Self {
        Self {
            signer: alarm.signer,
            refused: alarm.refused,
            handoffs: alarm.handoffs,
            raised: rfc3339_secs(alarm.raised_at),
            acknowledged: alarm.acknowledged.map(|ack| HandoffAlarmAck {
                by: ack.by,
                at: rfc3339_secs(ack.at),
            }),
            seen: alarm.seen.into_iter().collect(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcknowledgeAlarm {
    /// The alarm's retired key, `suite:hex`, as the list names it.
    signer: String,
}

/// `GET /v1/owner/authority/handoff-alarms`: every saved alarm, open ones
/// first.
async fn list(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<HandoffAlarm>> {
    owner(&auth, &server)?;
    let alarms = blocking(move || -> OwnerResult<Vec<HandoffAlarm>> {
        let mut alarms = server.vault().authority_handoff_alarms()?;
        alarms.sort_by_key(|alarm| alarm.acknowledged.is_some());
        Ok(alarms.into_iter().map(HandoffAlarm::from).collect())
    })
    .await?;
    Ok(Json(alarms))
}

/// `POST /v1/owner/authority/handoff-alarms/acknowledge`: the owner has seen
/// one alarm. It stays saved with its refused row marked seen; acknowledging
/// it again changes nothing.
async fn acknowledge(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<AcknowledgeAlarm>, JsonRejection>,
) -> OwnerReply<HandoffAlarm> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let alarm = blocking(move || -> OwnerResult<HandoffAlarm> {
        match server
            .vault()
            .acknowledge_authority_handoff_alarm(&owner, &request.signer)
        {
            Ok(alarm) => Ok(alarm.into()),
            Err(error) if error.kind() == oneiron::ErrorKind::EntityNotFound => {
                Err(OwnerError::NotFound("handoff_alarm", request.signer))
            }
            Err(error) => Err(error.into()),
        }
    })
    .await?;
    Ok(Json(alarm))
}
