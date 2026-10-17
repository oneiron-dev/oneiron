//! `/v1/owner/connectors/consent`: the owner's one act that lets an actor
//! call a catalog connector's tools (ONE-1794). Each accepted tool row
//! becomes one scoped-MCP standing grant and one per-grant connector key in
//! one transaction. The endpoint the owner consents to is the one this host
//! installed under `[connectors.<name>]`, shown by the read and checked
//! again at the write, so a config edit between them consents to nothing.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::get;
use oneiron::connector_key::{
    ConnectorConsentTarget, ConnectorConsentView, ConnectorToolConsent, ConnectorToolConsentRow,
    ConnectorToolGrant,
};
use oneiron::outbound_consent::DataClass;
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::config::connectors::normalize_name;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/connectors/consent", get(read).post(consent))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsentQuery {
    connector: String,
    /// The actor whose grants to show, as 32 hex; the owner when absent.
    #[serde(default)]
    actor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsentRequest {
    connector: String,
    /// The actor the grants cover, as 32 hex.
    #[serde(default)]
    actor: Option<String>,
    /// A held call's ref, as 32 hex: the grants cover the actor it runs as.
    #[serde(default)]
    call_ref: Option<String>,
    /// The endpoint the owner was shown.
    endpoint: String,
    rows: Vec<ConsentRow>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsentRow {
    tool: String,
    /// The payload ceiling; a row starts at public (ARCH-0072).
    #[serde(default = "public")]
    ceiling: DataClass,
    /// The owner also lets the tool's header parameters reach the wire.
    #[serde(default)]
    headers: bool,
}

fn public() -> DataClass {
    DataClass::Public
}

#[derive(Debug, Serialize)]
struct ConsentRead {
    #[serde(flatten)]
    view: ConnectorConsentView,
    /// The endpoint this host installed for the connector; none: no
    /// transport, so no consent can be written.
    endpoint: Option<String>,
}

#[derive(Debug, Serialize)]
struct Consented {
    connector: String,
    endpoint: String,
    grants: Vec<ConnectorToolGrant>,
}

/// The endpoint this host installed under the connector's name.
fn installed_endpoint(server: &SyncServer, connector: &str) -> Option<String> {
    let name = normalize_name(connector);
    server
        .config
        .connectors
        .iter()
        .find(|(section, _)| normalize_name(section) == name)
        .map(|(_, installed)| installed.endpoint.clone())
}

/// `GET /v1/owner/connectors/consent?connector=&actor=`: the connector's
/// tool rows, the actor's live grant per row, and the installed endpoint.
async fn read(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<ConsentQuery>, QueryRejection>,
) -> OwnerReply<ConsentRead> {
    let owner = owner(&auth, &server)?;
    let query = query_params(query)?;
    let reply = blocking(move || -> OwnerResult<ConsentRead> {
        let actor = query
            .actor
            .as_deref()
            .map(|actor| entity_id("actor", actor))
            .transpose()?;
        let view = server
            .vault()
            .connector_consent_view(&owner, &query.connector, actor)?
            .ok_or_else(|| OwnerError::Invalid("no catalog connector by that name".to_owned()))?;
        Ok(ConsentRead {
            view,
            endpoint: installed_endpoint(&server, &query.connector),
        })
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/connectors/consent`: grants the named tool rows to one
/// actor (a held call's, a named one, else the owner's) at the installed
/// endpoint. A row consented again replaces the actor's earlier grant.
async fn consent(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ConsentRequest>, JsonRejection>,
) -> OwnerReply<Consented> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let reply = blocking(move || -> OwnerResult<Consented> {
        let installed = installed_endpoint(&server, &request.connector).ok_or_else(|| {
            OwnerError::Invalid("this host installed no transport for the connector".to_owned())
        })?;
        if installed != request.endpoint {
            return Err(OwnerError::Invalid(
                "the endpoint is not the one this host installed".to_owned(),
            ));
        }
        let target = match (request.call_ref.as_deref(), request.actor.as_deref()) {
            (Some(_), Some(_)) => {
                return Err(OwnerError::Invalid(
                    "name a held call or an actor, not both".to_owned(),
                ));
            }
            (Some(call_ref), None) => {
                ConnectorConsentTarget::HeldCall(entity_id("call_ref", call_ref)?)
            }
            (None, Some(actor)) => ConnectorConsentTarget::Actor(entity_id("actor", actor)?),
            (None, None) => ConnectorConsentTarget::Owner,
        };
        let grants = server
            .vault()
            .consent_connector_tools(
                &owner,
                &ConnectorToolConsent {
                    connector: request.connector.clone(),
                    target,
                    endpoint: installed.clone(),
                    rows: request
                        .rows
                        .into_iter()
                        .map(|row| ConnectorToolConsentRow {
                            tool: row.tool,
                            data_class_ceiling: row.ceiling,
                            headers: row.headers,
                        })
                        .collect(),
                },
            )
            .map_err(|error| match error {
                oneiron::Error::InvalidConfig(reason) => OwnerError::Invalid(reason),
                error => error.into(),
            })?;
        Ok(Consented {
            connector: request.connector,
            endpoint: installed,
            grants,
        })
    })
    .await?;
    Ok(Json(reply))
}
