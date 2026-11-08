//! `POST /oauth/register`: dynamic client registration (RFC 7591) for public clients, which
//! prove each code with PKCE and hold no secret. DCR sits beside the client ID metadata
//! document (ARCH-0028:90): a client that has one needs no registration. Open to anyone, so
//! its flood cap is asked before the body is read ([`super::OAuthFloodCaps`]).

use std::sync::Arc;

use axum::extract::{FromRequest, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use oneiron::authority::{OAuthClientRegistration, OAuthRegistrationRefusal};
use serde::Deserialize;

use super::{OAuthFloodCaps, OAuthIdentity, not_found, now, oauth_error};
use crate::auth::ClientAddress;
use crate::server::SyncServer;

/// The registration fields this vault reads (RFC 7591 §2); every other is ignored.
#[derive(Deserialize)]
pub(super) struct RegistrationRequest {
    #[serde(default)]
    redirect_uris: Vec<String>,
    #[serde(default)]
    client_name: Option<String>,
    #[serde(default)]
    token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    grant_types: Option<Vec<String>>,
    #[serde(default)]
    response_types: Option<Vec<String>>,
}

/// Registers one public client: 201 with its fresh `client_id` and the metadata it holds, or
/// RFC 7591 §3.2.2's error; past the flood cap, the cap's 429 before the body is read.
pub(super) async fn register(
    State(server): State<Arc<SyncServer>>,
    Extension(caps): Extension<Arc<OAuthFloodCaps>>,
    ClientAddress(source): ClientAddress,
    request: Request,
) -> Response {
    if OAuthIdentity::of(&server).is_none() {
        return not_found();
    }
    if let Some(shed) = caps.shed_registration(source) {
        return shed;
    }
    let Ok(Json(request)) = Json::<RegistrationRequest>::from_request(request, &server).await
    else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_client_metadata");
    };
    let registration = OAuthClientRegistration {
        redirect_uris: request.redirect_uris,
        client_name: request.client_name,
        token_endpoint_auth_method: request.token_endpoint_auth_method,
        grant_types: request.grant_types,
        response_types: request.response_types,
    };
    match server.vault().register_oauth_client(&registration, now()) {
        Ok(Ok(client)) => {
            let mut body = serde_json::json!({
                "client_id": client.client_id,
                "client_id_issued_at": client.registered_at,
                "redirect_uris": client.redirect_uris,
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            });
            if let (Some(name), Some(fields)) = (client.client_name, body.as_object_mut()) {
                fields.insert("client_name".to_owned(), name.into());
            }
            (StatusCode::CREATED, Json(body)).into_response()
        }
        Ok(Err(refusal)) => {
            let status = match refusal {
                OAuthRegistrationRefusal::RegistryFull => StatusCode::SERVICE_UNAVAILABLE,
                OAuthRegistrationRefusal::InvalidRedirectUri
                | OAuthRegistrationRefusal::InvalidClientMetadata => StatusCode::BAD_REQUEST,
            };
            oauth_error(status, refusal.error_code())
        }
        Err(error) => {
            tracing::warn!(%error, "OAuth client registration failed");
            oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
        }
    }
}
