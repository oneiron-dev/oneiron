//! The owner's editor capability (FIX 5618). The editor shell, `GET
//! /sign/editor`, admits an owner-grade caller exactly as before; it then
//! mints a random editor-computation token bound to that caller and embeds
//! it in its no-store page. The page keeps the token in memory and sends it
//! only in the `x-oneiron-esign-editor` header of its `/sign/layout` and
//! `/sign/geometry` POSTs, where [`EditorIngress`] admits it from the request
//! head, before a byte of the body is read. The server keeps only the
//! token's digest, its purpose, the caller it was minted for and its expiry,
//! in this router's own registry: a restart forgets every token, and the
//! owner reloads the shell for a new one. The token buys computation over
//! the caller's own bytes; it reads no vault document, acts for no recipient
//! and reaches no other door.
//!
//! A POST with no editor header is the capability-free computation it was,
//! under its route's body limit and [`EditorBudget`]'s two slots and
//! 60-per-minute window. A present header the registry does not admit is
//! refused before the body; it never falls back to that anonymous door.
use super::editor_budget::{EditorBudget, EditorWaitError};
use super::*;
use axum::extract::FromRequestParts;
use base64::Engine as _;
use rand_core::{OsRng, RngCore as _};
use sha2::Digest as _;
use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};
use tokio::sync::OwnedSemaphorePermit;

/// The header an admitted editor POST carries its token in. The token is
/// never a URL, cookie or browser-storage carrier.
pub(super) const EDITOR_HEADER: &str = "x-oneiron-esign-editor";

/// How long a minted editor token admits new POSTs (CALLS.md, FIX 5618
/// editor capability). A POST admitted before then runs to its end.
const EDITOR_TOKEN_LIFETIME: Duration = Duration::from_secs(3_600);

/// What a token was minted for: the editor's computation POSTs alone.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Purpose {
    EditorComputation,
}

/// One live token, keyed by its digest.
struct Grant {
    purpose: Purpose,
    /// The caller the shell admitted, rechecked on each POST.
    caller: crate::auth::CoreAuth,
    expires: Instant,
}

/// The editor router's own state, shared through an `Extension`: the live
/// tokens and the editor's two computation slots.
pub(super) struct EditorDesk {
    grants: Mutex<HashMap<[u8; 32], Grant>>,
    pub(super) budget: Arc<EditorBudget>,
}

impl EditorDesk {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            grants: Mutex::new(HashMap::new()),
            budget: EditorBudget::new(),
        })
    }

    /// Mints a token for `caller`, whom the shell admitted, and keeps only
    /// its digest. Expired tokens are reaped here; no count bounds the live
    /// ones.
    pub(super) fn mint(&self, caller: crate::auth::CoreAuth) -> String {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret);
        let now = Instant::now();
        let mut grants = self.grants.lock().unwrap_or_else(PoisonError::into_inner);
        grants.retain(|_, grant| grant.expires > now);
        grants.insert(
            digest(token.as_bytes()),
            Grant {
                purpose: Purpose::EditorComputation,
                caller,
                expires: now + EDITOR_TOKEN_LIFETIME,
            },
        );
        token
    }

    /// The caller a presented token was minted for, when it is a live
    /// editor-computation token. Expired tokens are reaped here.
    fn admit(&self, presented: &[u8]) -> Option<crate::auth::CoreAuth> {
        let now = Instant::now();
        let mut grants = self.grants.lock().unwrap_or_else(PoisonError::into_inner);
        grants.retain(|_, grant| grant.expires > now);
        grants
            .get(&digest(presented))
            .filter(|grant| grant.purpose == Purpose::EditorComputation)
            .map(|grant| grant.caller.clone())
    }
}

fn digest(token: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(token).into()
}

/// How an editor computation POST arrived.
pub(super) enum EditorIngress {
    /// No editor header: the capability-free door, under its route's body
    /// limit and [`EditorBudget`]'s window, both as they were.
    Anonymous,
    /// A token the shell minted, admitted from the request head, holding
    /// one of the editor's two slots it waited for. The permit moves into
    /// the worker that spools and computes, and lives until that worker
    /// exits.
    Admitted(EditorSlot),
}

/// An admitted editor POST's slot, and the owner it computes for.
pub(super) struct EditorSlot {
    pub(super) permit: OwnedSemaphorePermit,
    /// The vault owner or co-owner the token was minted for, when the
    /// caller's credential names one: a limits row the computation crosses
    /// asks naming them (FIX 5702). A record, not authority.
    pub(super) owner: Option<oneiron::EntityId>,
}

impl FromRequestParts<Arc<SyncServer>> for EditorIngress {
    type Rejection = Response;

    /// Runs on the request's head alone, before any body poll. The token's
    /// digest, purpose and expiry are checked first, then its caller's
    /// credential is re-consulted the way a live sync socket's is
    /// ([`crate::auth::CoreAuth::credential_is_live`]). An admitted request
    /// waits its turn for a slot, at most `limits.queue_wait_timeout_ms`
    /// (then 503 `editor_waited_out`); no queue length or count refuses it.
    /// After the wait the token is admitted again, so one that expired or
    /// was reaped while queued admits nothing, and its caller is
    /// re-consulted. Once it holds a slot the upload runs to its end.
    async fn from_request_parts(
        parts: &mut Parts,
        server: &Arc<SyncServer>,
    ) -> Result<Self, Self::Rejection> {
        let Some(presented) = parts.headers.get(EDITOR_HEADER) else {
            return Ok(Self::Anonymous);
        };
        let desk = parts
            .extensions
            .get::<Arc<EditorDesk>>()
            .cloned()
            .ok_or_else(unavailable)?;
        let caller = desk
            .admit(presented.as_bytes())
            .ok_or_else(|| editor_refused("editor_token_unadmitted"))?;
        if !caller.credential_is_live(server.vault()) {
            return Err(editor_refused("editor_caller_not_live"));
        }
        crate::http_listener::authenticated();
        let permit = match desk.budget.queue(server.config.limits.queue_wait()).await {
            Ok(permit) => permit,
            Err(EditorWaitError::TimedOut) => return Err(editor_waited_out()),
            Err(EditorWaitError::Closed) => return Err(unavailable()),
        };
        let caller = desk
            .admit(presented.as_bytes())
            .ok_or_else(|| editor_refused("editor_token_unadmitted"))?;
        if !caller.credential_is_live(server.vault()) {
            return Err(editor_refused("editor_caller_not_live"));
        }
        Ok(Self::Admitted(EditorSlot {
            permit,
            owner: caller.principal_entity(),
        }))
    }
}

/// An admitted editor POST that waited `limits.queue_wait_timeout_ms` for
/// one of the two slots. The body is unread and nothing was started.
fn editor_waited_out() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::RETRY_AFTER, "1")],
        Json(serde_json::json!({"error":{"code":"editor_waited_out"}})),
    )
        .into_response()
}

/// A present editor header that does not admit its request: an unknown or
/// expired token, or one whose caller's credential no longer stands. The
/// body is unread; the owner reloads the editor shell for a new token.
fn editor_refused(code: &'static str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"error":{"code":code}})),
    )
        .into_response()
}
