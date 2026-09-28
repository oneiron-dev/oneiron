//! Consume holder proofs at the network door, once per request or upgrade.
use super::{BindingProof, CoreAuth, bearer_token};
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
        .then(|| {
            request
                .headers()
                .get("x-oneiron-mcp-credential")
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .flatten();
    // MCP's credential header has the same precedence at admission and use.
    // It cannot sidestep nonce consumption with an unrelated Bearer header.
    if let Some(token) = mcp_credential.or_else(|| bearer_token(request.headers()).ok().flatten())
        && token.starts_with("v2.slip.")
    {
        let accepted = BindingProof::from_headers(request.headers()).and_then(|proof| {
            CoreAuth::bind_transport_once(token, &proof, server.vault().as_ref())
        });
        if let Err(error) = accepted {
            // Keep the /v1 envelope when the transport door refuses first.
            if request.uri().path().starts_with("/v1/") {
                return crate::error::EnvelopedApiError::from(error).into_response();
            }
            return error.into_response();
        }
    }
    next.run(request).await
}
