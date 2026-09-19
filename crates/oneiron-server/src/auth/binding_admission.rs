//! Consume holder proofs at the network door, once per request or upgrade.
use super::{BindingProof, CoreAuth, bearer_token, constant_time_eq};
use crate::server::SyncServer;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

pub(crate) async fn admit_http_binding(
    State(server): State<Arc<SyncServer>>,
    request: Request,
    next: Next,
) -> Response {
    // Public endpoints retain their no-credential behavior. Their protected
    // siblings still reject absent or malformed credentials in the handler.
    let mcp_credential = matches!(request.uri().path(), "/mcp" | "/mcp/tool-first")
        .then(|| request.headers().get("x-oneiron-mcp-credential")
            .and_then(|value| value.to_str().ok()).map(str::trim)
            .filter(|value| !value.is_empty()))
        .flatten();
    // MCP's credential header has the same precedence at admission and use.
    // It cannot sidestep nonce consumption with an unrelated Bearer header.
    if let Some(token) = mcp_credential.or_else(|| bearer_token(request.headers()).ok().flatten()) {
        let retained_secret = server
            .config
            .auth_secret
            .as_deref()
            .is_some_and(|secret| constant_time_eq(token, secret));
        if !retained_secret && token.starts_with("v2.slip.") {
            let accepted = BindingProof::from_headers(request.headers()).and_then(|proof| {
                CoreAuth::bind_transport_once(
                    token,
                    &proof,
                    &server.config,
                    server.vault().as_ref(),
                )
            });
            if let Err(error) = accepted {
                // Preserve the route's error contract: `/v1` callers receive
                // the typed envelope even when the transport door refuses
                // before the handler runs; other planes keep the flat shape.
                if request.uri().path().starts_with("/v1/") {
                    return crate::error::EnvelopedApiError::from(error).into_response();
                }
                return error.into_response();
            }
        }
    }
    next.run(request).await
}
