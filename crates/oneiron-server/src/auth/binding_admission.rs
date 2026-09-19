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
    if let Ok(Some(token)) = bearer_token(request.headers()) {
        let retained_secret = server.config.auth_secret.as_deref()
            .is_some_and(|secret| constant_time_eq(token, secret));
        if !retained_secret && token.starts_with("v2.slip.") {
            let accepted = BindingProof::from_headers(request.headers()).and_then(|proof| {
                CoreAuth::bind_transport_once(token, &proof, &server.config, server.vault().as_ref())
            });
            if let Err(error) = accepted { return error.into_response(); }
        }
    }
    next.run(request).await
}
