//! Consume holder proofs at the network door, once per request or upgrade,
//! and stop serving a shared vault its Owners deleted (OF-163). A request off
//! a mesh stream may not prove, over HTTP, a machine other than the one its
//! handshake proved.
use super::managed_request::{AdmittedCaller, caller_binding_refused, caller_binding_replayed};
use super::{BindingProof, CoreAuth, bearer_token};
use crate::error::ApiError;
use crate::server::SyncServer;
use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use oneiron::authority::PeerMachine;
use std::sync::Arc;

/// What a deleted shared vault still answers: its holders read the deletion
/// marker, their own outcome notices and receipts, and a device removed
/// earlier reads its leave notices on its revoked slip; the operator keeps
/// its disaster-recovery door; the host's health probe stays up.
fn served_after_deletion(path: &str) -> bool {
    matches!(
        path,
        "/v1/core/facade/vault.shared.deletion"
            | "/v1/core/facade/vault.shared.outcomes"
            | "/v1/core/facade/vault.shared.receipt"
            | "/v1/shared/left-notices"
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

/// The refusal a managed vault gives a forwarded caller's slip this door
/// refused (WILL-PLAN L14 row 01), named, since nothing is served in its
/// place: a holder proof already spent, apart from a slip or proof that does
/// not verify. A proof the vault's clock refuses keeps its own name.
fn managed_refusal(
    error: ApiError,
    token: &str,
    headers: &HeaderMap,
    vault: &oneiron::Vault,
) -> ApiError {
    if error == ApiError::proof_clock_ahead() {
        return error;
    }
    let verifies = BindingProof::from_headers(headers)
        .is_ok_and(|proof| CoreAuth::from_slip_token(token, &proof, vault).is_ok());
    if verifies {
        caller_binding_replayed()
    } else {
        caller_binding_refused()
    }
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
    let mut request = request;
    // A request the owner's reserve admitted (FIX 8274) carries that
    // admission here, used once: no second nonce is spent.
    let early = request.extensions_mut().remove::<AdmittedBinding>();
    let AdmittedBinding { machine, admitted } = match early {
        Some(binding) => binding,
        None => match admit_binding(&server, request.uri().path(), request.headers()) {
            Ok(binding) => binding,
            Err(error) => {
                // Keep the /v1 envelope when the transport door refuses first.
                if request.uri().path().starts_with("/v1/") {
                    return crate::error::EnvelopedApiError::from(error).into_response();
                }
                return error.into_response();
            }
        },
    };
    // A mesh stream's handshake proved its MACHINE: an HTTP proof of another
    // machine refuses (FIX 997). A request with no proof stays Unknown, as on
    // any transport.
    if let Some(mesh) = request
        .extensions()
        .get::<crate::handler::mesh::MeshProvedMachine>()
        .copied()
        && matches!(machine, PeerMachine::Proven { machine: proved, .. } if proved != mesh.0)
    {
        let error = crate::error::ApiError::unauthorized();
        if request.uri().path().starts_with("/v1/") {
            return crate::error::EnvelopedApiError::from(error).into_response();
        }
        return error.into_response();
    }
    // Every admitted request carries the machine it proved, or Unknown.
    request.extensions_mut().insert(machine);
    if let Some(admitted) = admitted {
        request.extensions_mut().insert(admitted);
    }
    next.run(request).await
}

/// One request's admission at this door: the machine it proved, or
/// Unknown, and on a managed vault the caller it admitted. Only
/// [`admit_binding`] makes one, and only [`admit_owner_proof`] puts one on
/// its own request, for [`admit_http_binding`] to take once (FIX 8274).
#[derive(Clone)]
struct AdmittedBinding {
    machine: PeerMachine,
    admitted: Option<AdmittedCaller>,
}

/// The owner's authority clock repair route (FIX 10106). A damaged clock
/// floor refuses every holder proof this door judges, so it spends none for
/// this one path: the repair judges the owner's slip and proof, and spends
/// the nonce, in its own writer against the floor it proves.
pub(crate) const AUTHORITY_CLOCK_REPAIR_PATH: &str = "/v1/owner/authority/clock/repair";

/// This door's decision on a request to `path` with `headers`, with no
/// reply made yet: its slip's holder proof spent once, or the refusal it
/// gets. A request with no slip is admitted on no proof, and so is the
/// authority clock repair's ([`AUTHORITY_CLOCK_REPAIR_PATH`]).
fn admit_binding(
    server: &SyncServer,
    path: &str,
    headers: &HeaderMap,
) -> Result<AdmittedBinding, ApiError> {
    if path == AUTHORITY_CLOCK_REPAIR_PATH {
        return Ok(AdmittedBinding {
            machine: PeerMachine::Unknown,
            admitted: None,
        });
    }
    // Public endpoints retain their no-credential behavior. Their protected
    // siblings still reject absent or malformed credentials in the handler.
    // The OpenAI proxy takes the MCP connector credential as `/mcp` does, so
    // its holder proof is spent here once too (FIX 5124).
    let mcp_credential = matches!(path, "/mcp" | "/mcp/tool-first" | "/v1/chat/completions")
        .then(|| {
            headers
                .get("x-oneiron-mcp-credential")
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .flatten();
    // MCP's credential header has the same precedence at admission and use.
    // It cannot sidestep nonce consumption with an unrelated Bearer header.
    let mut machine = PeerMachine::Unknown;
    let mut admitted = None;
    if let Some(token) = mcp_credential.or_else(|| bearer_token(headers).ok().flatten())
        && token.starts_with("v2.slip.")
    {
        // The operator's own credential (FIX 1814) at a self-hosted vault's
        // operator door: its proof spent here once, as any slip's. It names
        // no caller, so nothing rides on to a door but the machine it shows.
        if let Some(spent) =
            super::operator_credential::bind_operator_once(server, path, token, headers)
        {
            let proof = spent?;
            machine = super::machine_proof::peer_machine(headers, token, &proof, server.vault());
            return Ok(AdmittedBinding { machine, admitted });
        }
        let accepted = BindingProof::from_headers(headers).and_then(|proof| {
            CoreAuth::bind_transport_once(token, &proof, server.vault().as_ref())
                .map(|auth| (auth, proof))
        });
        match accepted {
            Ok((auth, proof)) => {
                machine =
                    super::machine_proof::peer_machine(headers, token, &proof, server.vault());
                // A managed vault keeps the caller admitted here, with the
                // token and holder proof it accepted and the machine proof
                // it carries over them, for its renewal door (FIX 4559) and
                // the readers that reuse them (FIX 6160). A missing or
                // malformed machine proof refuses nothing here.
                if server.managed_issuer.is_some() {
                    let device = super::machine_proof::machine_proof_over(headers, token, &proof);
                    admitted = Some(AdmittedCaller::new(auth, token, &proof, device.ok()));
                }
            }
            Err(error) => {
                return Err(if server.managed_issuer.is_some() {
                    managed_refusal(error, token, headers, server.vault())
                } else {
                    error
                });
            }
        }
    }
    Ok(AdmittedBinding { machine, admitted })
}

/// The owner's own proof on a request his reserve connection may serve
/// (FIX 8274), judged before this door runs. The caller
/// [`CoreAuth::for_request`] names must be the owner by
/// [`crate::api::owner`] before anything is spent; only then is its holder
/// proof spent, once, by this door's own [`admit_binding`], and the request
/// carries that admission on to [`admit_http_binding`] in place of a second
/// nonce. `false` spends and answers nothing: the request then meets this
/// door as every request does. An account key never names the owner, so it
/// is not shown to its verifier here.
pub(crate) async fn admit_owner_proof(server: &SyncServer, parts: &mut Parts) -> bool {
    let account_key = server.account_keys.is_some()
        && bearer_token(&parts.headers)
            .ok()
            .flatten()
            .is_some_and(|token| !token.starts_with(super::CORE_TOKEN_V2_PREFIX));
    if account_key {
        return false;
    }
    let owner = CoreAuth::for_request(parts, server)
        .await
        .is_ok_and(|auth| crate::api::owner(&auth, server).is_ok());
    let path = parts.uri.path();
    if !owner || (!served_after_deletion(path) && deleted_vault_refusal(server, path).is_some()) {
        return false;
    }
    let Ok(binding) = admit_binding(server, path, &parts.headers) else {
        return false;
    };
    parts.extensions.insert(binding);
    true
}
