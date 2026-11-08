//! The two public discovery documents a stock client reads before it signs in: the protected
//! resource's (RFC 9728), naming this vault's authorization server, and the authorization
//! server's (RFC 8414), naming its endpoints and what it supports.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use oneiron::authority::oauth_scopes_supported;

use super::{AUTHORIZE_PATH, OAuthIdentity, REGISTER_PATH, REVOKE_PATH, TOKEN_PATH, not_found};
use crate::server::SyncServer;

/// How long a client may cache a metadata document (CALLS, FIX 4902: an engine call), as the
/// client metadata documents are cached.
const METADATA_CACHE_CONTROL: &str = "public, max-age=300";

/// `GET /.well-known/oauth-protected-resource` and `.../mcp`: the `/mcp` resource, its one
/// authorization server, the bearer header as its only method, and its scopes.
pub(super) async fn protected_resource(State(server): State<Arc<SyncServer>>) -> Response {
    let Some(identity) = OAuthIdentity::of(&server) else {
        return not_found();
    };
    (
        [(header::CACHE_CONTROL, METADATA_CACHE_CONTROL)],
        Json(serde_json::json!({
            "resource": identity.resource(),
            "authorization_servers": [identity.issuer()],
            "bearer_methods_supported": ["header"],
            "scopes_supported": oauth_scopes_supported(),
        })),
    )
        .into_response()
}

/// `GET /.well-known/oauth-authorization-server`: the issuer, its endpoints, and the one shape
/// of sign-in it serves: authorization code with PKCE S256 for public clients, refresh by
/// rotation, registered or metadata-document clients, and the `iss` authorization response
/// parameter (RFC 9207).
pub(super) async fn authorization_server(State(server): State<Arc<SyncServer>>) -> Response {
    let Some(identity) = OAuthIdentity::of(&server) else {
        return not_found();
    };
    (
        [(header::CACHE_CONTROL, METADATA_CACHE_CONTROL)],
        Json(serde_json::json!({
            "issuer": identity.issuer(),
            "authorization_endpoint": identity.endpoint(AUTHORIZE_PATH),
            "token_endpoint": identity.endpoint(TOKEN_PATH),
            "registration_endpoint": identity.endpoint(REGISTER_PATH),
            "revocation_endpoint": identity.endpoint(REVOKE_PATH),
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "revocation_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": oauth_scopes_supported(),
            "client_id_metadata_document_supported": true,
            "authorization_response_iss_parameter_supported": true,
        })),
    )
        .into_response()
}
