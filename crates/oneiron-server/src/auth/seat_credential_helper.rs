//! `POST /v1/seat/credential-helper` (FIX 10624 step 2; ARCH-0069 T1, the
//! credential-helper shim): the value a vendor tool inside an official CLI
//! seat asks for at the moment it uses it, answered to the asking helper
//! alone, never into the CLI's environment.
//!
//! The helper (`oneiron credential-helper`) presents its run's seat-child
//! slip in `x-oneiron-seat-slip` and the usual holder proof in
//! `x-oneiron-binding`, from this device. The engine admits only a
//! seat-child slip whose claim still holds and spends the nonce. The door
//! then finds the run's helper registration under that claim and the
//! destination the request names, refuses a git context other than the
//! destination's own and a secret the slip's records do not name, and mints
//! the grant through the same vault grant door `self.secrets.materialize`
//! uses: a T1 grant on the `helper:<name>` host destination, held by the
//! slip's per-claim holder for the run's attempt, its receipt taken at
//! materialization. The run's registration records the grant and its taint
//! before the value leaves, and the claim is checked again; the value goes
//! back once, `no-store`. The run's teardown revokes the grant.
//!
//! Every refusal reads as unauthorized and names nothing.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use oneiron::AttemptId;
use oneiron::authority::CapabilitySlip;
use oneiron::claim::CallerLocality;
use oneiron::edge::EdgeActorClass;
use oneiron::secret_lease::{SecretGrantCaller, SecretGrantTarget, SecretTaintRef};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{BindingProof, caller_locality, parse_signature};
use crate::error::{ApiError, EnvelopedApiError};
use crate::runtime::{HELPER_DESTINATION_PREFIX, HelperReplyDelivery};
use crate::server::SyncServer;

/// The route the credential helper calls.
pub(crate) const SEAT_CREDENTIAL_HELPER_PATH: &str = "/v1/seat/credential-helper";

/// The header that carries the seat-child slip, never as a bearer token: no
/// other door admits it.
pub(crate) const SEAT_SLIP_HEADER: &str = "x-oneiron-seat-slip";

/// The most a helper's ask may weigh: a name and a git context.
const ASK_LIMIT: usize = 4096;

pub(crate) fn seat_credential_helper_routes() -> Router<Arc<SyncServer>> {
    Router::new().route(SEAT_CREDENTIAL_HELPER_PATH, post(credential_helper))
}

/// What the helper asks for: the destination the seat host named to it, and
/// the git context git handed it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperAsk {
    destination: String,
    protocol: String,
    host: String,
    #[serde(default)]
    path: Option<String>,
}

/// What the helper prints for git: the destination's username and the
/// value. Never logged or kept.
#[derive(Serialize)]
struct HelperAnswer {
    username: String,
    password: String,
}

async fn credential_helper(
    State(server): State<Arc<SyncServer>>,
    request: Request,
) -> Result<Response, EnvelopedApiError> {
    let (parts, body) = request.into_parts();
    if caller_locality(&parts.headers, &parts.extensions) != CallerLocality::OnDevice {
        return Err(ApiError::unauthorized().into());
    }
    let slip = parts
        .headers
        .get(SEAT_SLIP_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|token| CapabilitySlip::from_token(token.trim()).ok())
        .ok_or_else(ApiError::unauthorized)?;
    let proof = BindingProof::from_headers(&parts.headers)?;
    let signature = parse_signature(&proof.signature)?;
    let bytes = axum::body::to_bytes(body, ASK_LIMIT)
        .await
        .map_err(|_| ApiError::unauthorized())?;
    let ask: HelperAsk = serde_json::from_slice(&bytes).map_err(|_| ApiError::unauthorized())?;
    let answer =
        tokio::task::spawn_blocking(move || answer(&server, &slip, &proof, &signature, &ask))
            .await
            .map_err(|_| ApiError::unauthorized())?
            .ok_or_else(ApiError::unauthorized)?;
    let mut response = axum::Json(answer).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

/// The answer for `ask`, or `None` for any refusal. Blocking.
fn answer(
    server: &SyncServer,
    slip: &CapabilitySlip,
    proof: &BindingProof,
    signature: &[u8],
    ask: &HelperAsk,
) -> Option<HelperAnswer> {
    let vault = server.vault();
    let credential = vault
        .admit_seat_child_slip_request(slip, proof.timestamp, signature, proof.nonce.as_bytes())
        .ok()?;
    let attempt = AttemptId::from_bytes(&credential.attempt()).ok()?;
    let run = server.seat_helpers.of(
        attempt,
        credential.lease_owner(),
        credential.attempt_count(),
    )?;
    let destination = format!("{HELPER_DESTINATION_PREFIX}{}", ask.destination);
    let bound = run.destination(&ask.destination)?;
    if !bound.answers(&ask.protocol, &ask.host, ask.path.as_deref())
        || !credential.records().contains(&bound.secret)
    {
        return None;
    }
    let holder = oneiron::EntityId::from_hex(credential.holder_ref()).ok()?;
    let caller =
        SecretGrantCaller::of(&vault.memory(holder, EdgeActorClass::Agent), Some(attempt)).ok()?;
    let mut delivery = HelperReplyDelivery::new(attempt, destination.clone(), bound.effector);
    let minted = vault
        .mint_secret_grant_for_name(
            &caller,
            &bound.secret,
            SecretGrantTarget::HostDestination { name: destination },
            None,
            Some(credential.expires_at()),
            &mut delivery,
        )
        .map_err(|error| tracing::warn!(%error, "a seat helper's grant was refused"))
        .ok()?;
    let grant = minted.grant.grant_id;
    let taint = SecretTaintRef {
        secret_ref: bound.secret.clone(),
        generation: minted.grant.generation,
    };
    // The run's teardown revokes what its registration recorded; a
    // registration closed meanwhile, or a claim lost, hands nothing out.
    // A refusal takes back only this grant: the grants and taints recorded
    // before it stay for the run's teardown and exhaust. A grant the
    // registration's close already took is revoked by that teardown.
    let recorded = run.record(grant, taint);
    if !recorded || !vault.seat_child_holds(&credential).unwrap_or(false) {
        if recorded && !run.withdraw(&grant) {
            return None;
        }
        if let Err(error) = vault.teardown_secret_grant(&caller, &grant, &mut delivery) {
            tracing::warn!(%error, "a refused seat helper's grant could not be torn down");
        }
        return None;
    }
    let value: Zeroizing<Vec<u8>> = delivery.take()?;
    let password = String::from_utf8(value.to_vec()).ok()?;
    Some(HelperAnswer {
        username: bound.username,
        password,
    })
}
