//! `/v1/owner/connectors/subscriptions`: the owner's door that lets an agent
//! answer a built-in channel (OF-519). Subscribing an agent to Slack or LINE
//! makes each message that channel's pack routes to the agent wake it, and
//! the served responder answers on the message's own thread. The list shows
//! an agent's standing subscriptions; a revoke stops further wakes.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::connector_key::ChannelMessageSubscription;
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/connectors/subscriptions", get(list).post(subscribe))
        .route("/connectors/subscriptions/revoke", post(revoke))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    /// The agent whose subscriptions to show, as 32 hex.
    agent: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubscribeRequest {
    /// The agent that answers, as 32 hex.
    agent: String,
    /// `slack` or `line`.
    channel: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeRequest {
    /// The subscription to stop, as 32 hex.
    subscription: String,
}

#[derive(Debug, Serialize)]
struct SubscriptionRow {
    subscription: String,
    connector_key: String,
    connector: String,
    event_kind: Option<String>,
    predicate: Option<String>,
    active: bool,
}

#[derive(Debug, Serialize)]
struct Subscriptions {
    agent: String,
    subscriptions: Vec<SubscriptionRow>,
}

#[derive(Debug, Serialize)]
struct Revoked {
    subscription: String,
}

fn invalid(error: oneiron::Error) -> OwnerError {
    match error {
        oneiron::Error::InvalidConfig(reason) => OwnerError::Invalid(reason),
        error => error.into(),
    }
}

/// `GET /v1/owner/connectors/subscriptions?agent=`: the agent's connector
/// event subscriptions, standing and revoked.
async fn list(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> OwnerReply<Subscriptions> {
    let _owner = owner(&auth, &server)?;
    let query = query_params(query)?;
    let reply = blocking(move || -> OwnerResult<Subscriptions> {
        let agent = entity_id("agent", &query.agent)?;
        let subscriptions = server
            .vault()
            .connector_event_subscriptions(agent)?
            .into_iter()
            .map(|(id, row)| SubscriptionRow {
                subscription: id.to_hex(),
                connector_key: row.connector_key.to_hex(),
                connector: row.filter.connector,
                event_kind: row.filter.event_kind,
                predicate: row.filter.predicate,
                active: row.active,
            })
            .collect();
        Ok(Subscriptions {
            agent: agent.to_hex(),
            subscriptions,
        })
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/connectors/subscriptions`: subscribes the agent to the
/// messages the channel's built-in pack routes to it.
async fn subscribe(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<SubscribeRequest>, JsonRejection>,
) -> OwnerReply<ChannelMessageSubscription> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let reply = blocking(move || -> OwnerResult<ChannelMessageSubscription> {
        let agent = entity_id("agent", &request.agent)?;
        server
            .vault()
            .subscribe_agent_to_channel_messages(&owner, agent, &request.channel)
            .map_err(invalid)
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/connectors/subscriptions/revoke`: the subscription wakes
/// nothing more; its key stays.
async fn revoke(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<RevokeRequest>, JsonRejection>,
) -> OwnerReply<Revoked> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let reply = blocking(move || -> OwnerResult<Revoked> {
        let id = entity_id("subscription", &request.subscription)?;
        server
            .vault()
            .revoke_connector_event_subscription(&owner, id)
            .map_err(invalid)?;
        Ok(Revoked {
            subscription: id.to_hex(),
        })
    })
    .await?;
    Ok(Json(reply))
}
