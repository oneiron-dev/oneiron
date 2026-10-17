//! Consume holder proofs at the network door, once per request or upgrade,
//! and stop serving a shared vault its Owners deleted (OF-163).
use super::{BindingProof, CoreAuth, bearer_token};
use crate::server::SyncServer;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use oneiron::authority::PeerMachine;
use std::sync::Arc;

/// What a deleted shared vault still answers: its holders read the deletion
/// marker, their own outcome notices and receipts; the operator keeps its
/// disaster-recovery door; the host's health probe stays up.
fn served_after_deletion(path: &str) -> bool {
    matches!(
        path,
        "/v1/core/facade/vault.shared.deletion"
            | "/v1/core/facade/vault.shared.outcomes"
            | "/v1/core/facade/vault.shared.receipt"
            | "/api/health"
    ) || path.starts_with("/v1/operator/")
}

/// The refusal of every other request once the engine's
/// `shared-vault:deleted:v1` marker is present: the vault is gone for its
/// API, MCP, artifact and sync doors, with no proof nonce spent. A marker
/// read that fails refuses too.
fn deleted_vault_refusal(server: &SyncServer, path: &str) -> Option<Response> {
    let (message, suggestion) = match server.vault().shared_vault_deletion() {
        Ok(None) => return None,
        Ok(Some(deletion)) => (
            "this shared vault was deleted",
            format!(
                "Its Owners deleted it (act {}); its backups are kept until {} for disaster \
                 recovery, then let go.",
                deletion.act_id, deletion.backup_retain_until
            ),
        ),
        Err(_) => (
            "this vault's deletion state could not be read",
            "The host serves nothing until it can read it.".to_owned(),
        ),
    };
    let error = crate::error::ApiError::new(
        message,
        crate::error::ApiErrorDetails::NotFound {
            resource: "vault".to_owned(),
            id: None,
        },
        [suggestion],
    );
    Some(if path.starts_with("/v1/") {
        crate::error::EnvelopedApiError::from(error).into_response()
    } else {
        error.into_response()
    })
}

pub(crate) async fn admit_http_binding(
    State(server): State<Arc<SyncServer>>,
    request: Request,
    next: Next,
) -> Response {
    if !served_after_deletion(request.uri().path())
        && let Some(refusal) = deleted_vault_refusal(&server, request.uri().path())
    {
        return refusal;
    }
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
    let mut machine = PeerMachine::Unknown;
    if let Some(token) = mcp_credential.or_else(|| bearer_token(request.headers()).ok().flatten())
        && token.starts_with("v2.slip.")
    {
        let accepted = BindingProof::from_headers(request.headers()).and_then(|proof| {
            CoreAuth::bind_transport_once(token, &proof, server.vault().as_ref()).map(|_| proof)
        });
        match accepted {
            Ok(proof) => {
                machine = super::machine_proof::peer_machine(
                    request.headers(),
                    token,
                    &proof,
                    server.vault(),
                );
            }
            Err(error) => {
                // Keep the /v1 envelope when the transport door refuses first.
                if request.uri().path().starts_with("/v1/") {
                    return crate::error::EnvelopedApiError::from(error).into_response();
                }
                return error.into_response();
            }
        }
    }
    // Every admitted request carries the machine it proved, or Unknown.
    let mut request = request;
    request.extensions_mut().insert(machine);
    next.run(request).await
}
