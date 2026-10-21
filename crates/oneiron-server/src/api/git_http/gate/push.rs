//! The push half of the smart-HTTP gate (FIX 6867, G1-PUSH): the pusher's
//! sidecar, built from the credential this transport authenticated, the
//! preflight of every receive-pack advertisement and RPC before it queues or
//! reads a body byte, and the typed refusal naming the missing capability.
//!
//! The gate's credential rules are unchanged (Write, an unrestricted record
//! scope and a registered principal for every receive-pack). Past them, who
//! may push is the engine's one decision
//! ([`oneiron::origin::smart_http::admit_receive_pack`]): the vault's owner,
//! a live `git_push` Grant on this repo, or an SDK checkout whose run's Grant
//! covers it. Nothing here reads the caller's class to decide; the sidecar
//! only carries what the credential proved.

use std::sync::Arc;

use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use oneiron::federation::{GitPushCaller, GitPushCredential};
use oneiron::origin::smart_http;
use oneiron::{EdgeActorClass, EntityId};

use super::text_response;
use crate::auth::{CoreAuth, revoked_token_jti_key};
use crate::server::SyncServer;

/// The public code a refused push answers with.
const GIT_PUSH_CAPABILITY_REQUIRED: &str = "git_push_capability_required";

/// The pusher `auth` names, for the push decision: its registered principal,
/// the actor class its slip binds (when it binds one), and its credential's
/// revocable identity with a digest naming it. `None` for a caller with no
/// registered principal, which pushes as no one.
pub(in crate::api::git_http) fn push_caller(auth: &CoreAuth) -> Option<GitPushCaller> {
    let principal = EntityId::from_hex(auth.principal_ref()?).ok()?;
    let class = match auth.actor_class() {
        Some("human") => Some(EdgeActorClass::Human),
        Some("agent") => Some(EdgeActorClass::Agent),
        Some("system") => Some(EdgeActorClass::System),
        _ => None,
    };
    // A 64-hex jti is a capability slip's id, judged live in the vault's
    // fold; any other is a token whose revocation is a registry row.
    let (slip, revoked_marker) = match auth.jti() {
        Some(jti) if jti.len() == 64 => (slip_id(jti), None),
        Some(jti) => (None, Some(revoked_token_jti_key(jti))),
        None => (None, None),
    };
    let mut binding = blake3::Hasher::new();
    binding.update(b"oneiron:git-push:credential:v1\0");
    binding.update(auth.idempotency_principal().as_bytes());
    Some(GitPushCaller::authenticated(
        principal,
        class,
        GitPushCredential::new(slip, revoked_marker, Some(*binding.finalize().as_bytes())),
    ))
}

/// A capability slip id in canonical lower hex.
fn slip_id(text: &str) -> Option<[u8; 32]> {
    let mut id = [0_u8; 32];
    for (slot, pair) in id.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let pair = std::str::from_utf8(pair).ok()?;
        if pair.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return None;
        }
        *slot = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(id)
}

/// The push decision for `request`, before it queues or reads a body byte.
/// `Some` answer stops the request: the typed refusal. Any other failure
/// (a repository that does not resolve, a store fault) is left to the
/// exchange to answer, which makes the same decision again.
pub(in crate::api::git_http) async fn preflight(
    server: &Arc<SyncServer>,
    repo: &str,
    request: &smart_http::ServeRequest,
    caller: Option<&GitPushCaller>,
) -> Option<Response> {
    let vault = Arc::clone(server.vault());
    let (repo, request, caller) = (repo.to_owned(), request.clone(), caller.cloned());
    let decided = tokio::task::spawn_blocking(move || {
        smart_http::admit_receive_pack(&vault, &repo, &request, caller.as_ref())
    })
    .await;
    match decided {
        Ok(Err(oneiron::Error::Code(oneiron::error::CodeError::GitPushCapabilityRequired {
            repo,
            reason,
        }))) => Some(capability_refused(&repo, &reason)),
        _ => None,
    }
}

/// The typed refusal of a push that holds no `git_push` capability: `403`,
/// the public code and the missing capability in headers, and a body naming
/// the repo and which check refused it.
pub(in crate::api::git_http) fn capability_refused(repo: &str, reason: &str) -> Response {
    let mut response = text_response(
        StatusCode::FORBIDDEN,
        &format!(
            "{GIT_PUSH_CAPABILITY_REQUIRED}: pushing to `{repo}` needs the git_push capability: {reason}"
        ),
    );
    let headers = response.headers_mut();
    headers.insert(
        "x-oneiron-error-code",
        HeaderValue::from_static(GIT_PUSH_CAPABILITY_REQUIRED),
    );
    headers.insert(
        "x-oneiron-missing-capability",
        HeaderValue::from_static(oneiron::federation::GIT_PUSH_VERB),
    );
    response
}
