//! ONE-1441 WIRE-P1: the bounded HTTP projection of the engine memory surface.
//!
//! One route per §HEAD-CONTRACT verb at `/v1/core/facade/<verb>`, the verb's
//! full dotted name, and nothing else. Every handler does the same four things: require the
//! scope, resolve the actor from the CREDENTIAL, bind
//! [`oneiron::Vault::memory`] to it, and serialize what the engine returned.
//! There is no transport-only domain model here — the request and response
//! types ARE the engine DTOs — so this projection and the in-process N-API
//! binding cannot drift into two dialects of the same verb.
//!
//! The route projection is generated from `scripts/sdk/agent-verbs.json`.
//! Claim lifecycle, scoped reads, export, notes, artifacts, tasks and rooms
//! all use the same inventory and engine DTOs as the native clients. Every
//! route runs its row through the generated dispatch (`dispatch.rs`), the one
//! the held socket's `rpc.req` runs too (OF-489), so a verb meets the same
//! admission on both. Live subscriptions remain owned by the held socket
//! rather than this router.
//!
//! ERRORS are the facade's own, not the server's closed
//! [`crate::error::ErrorCode`] enum.
//! The engine's `code` string travels verbatim inside the same
//! `{error:{code,message,requestId,suggestions}}` envelope shape the rest of
//! `/v1/core` uses, so a future engine code reaches a client losslessly
//! instead of collapsing into `INTERNAL_SERVER_ERROR`. `crate::error` is not
//! edited to admit these codes; that is the whole point of the local type.

pub(super) mod action_routes;
mod agent_verbs;
mod call_context;
mod connector_call_doors;
mod core_write_doors;
mod decision_ask_doors;
pub(super) mod decision_role_asks;
mod dispatch;
mod embedding_space_doors;
mod graph_ask_doors;
mod guest_doors;
pub(super) mod host_doors;
mod legal_hold_doors;
mod policy_doors;
mod reaction_doors;
pub(super) mod role_picks;
mod secret_lift_doors;
mod setting_doors;
mod share_doors;
mod shared_act_doors;
mod shared_member_doors;
#[cfg(test)]
pub(super) mod tests;
mod vault_shape_doors;
mod wave_doors;
mod weave_doors;
mod widen_proposal_doors;

pub(crate) use call_context::{FacadeCall, FacadeCallOutput};
use call_context::{VerbContext, context_required, facade_invocation_id};
pub(crate) use connector_call_doors::connector_call_as;
pub(crate) use dispatch::call_verb;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, FromRequestParts, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::post;
use oneiron::receipt::{CallOutcome, CallReceiptInput, CallTransport};
use serde::Serialize;

use super::call_receipt;
use crate::auth::{CoreAuth, CoreScope};
use crate::error::ApiError;
use crate::server::SyncServer;
use oneiron::claim::{CallerLocality, ScopedReadActorKey};
use oneiron::federation::record_scope::BirthPosition;
use oneiron::federation::{ScopeAxis, ScopeId};
use oneiron::memory::RewriteAdmit;
use oneiron::memory::caps::MAX_REMOTE_REQUEST_BYTES;
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_BUDGET_SPENT, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL,
    MEMORY_CODE_INVALID_STATE, MEMORY_CODE_LEASE_REQUIRED, MEMORY_CODE_MODEL_UNAVAILABLE,
    MEMORY_CODE_NOT_FOUND, MEMORY_CODE_OFF_RECORD_SESSION_DOOR, MEMORY_CODE_OWNER_BINDING_REQUIRED,
    MEMORY_CODE_PENDING_ASK, MEMORY_CODE_VAULT_LOCKED_SINGLE_WRITER, MemoryError,
};
use oneiron::runtime_hooks::verb::{
    InvocationClaim, InvocationEntry, InvocationOutcome, VerbAskCredential, VerbAskDoor,
    VerbAskDrainPermit, VerbAskRefusal,
};
use oneiron::runtime_hooks::{InvocationId, VerbCall, VerbHookPre, VerbHookStop, hook_class};
use oneiron::task_verb::verb_hook_boundary;
use oneiron::{EdgeActorClass, EntityId};

use super::credential_memory;
use super::write_facet::{SESSION_HEADER, landing_facet};

/// Request-body ceiling for the facade nest: 64 MiB.
///
/// Sized for the largest legal blob append (32 MiB raw) once base64 and JSON
/// framing are paid for. Applied as a layer on THIS router, so the limit is a
/// property of the facade projection and no other route's body handling moves.
const FACADE_MAX_BODY_BYTES: usize = MAX_REMOTE_REQUEST_BYTES;

/// The facade route table.
///
/// Exactly one row per verb, all `POST`: the read verbs carry structured
/// request bodies (`vault.recall` has five inputs), and `/v1/core`'s own read
/// routes — `/query`, `/context-pack`, `/hydrate` — already post their
/// requests for the same reason. One method per verb also keeps the route
/// census a flat list a contract test can compare against the catalog.
pub(crate) fn facade_routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .merge(agent_verbs::routes())
        .fallback(facade_unknown_verb)
        .layer(DefaultBodyLimit::max(FACADE_MAX_BODY_BYTES))
}

/// [`facade_routes`] with every reply's call receipt (OF-538): one layer
/// around the generated routes and the unknown-verb fallback alike. Inside
/// it, a request that names its invocation claims it for the whole route.
pub(crate) fn recorded_facade_routes(server: Arc<SyncServer>) -> Router<Arc<SyncServer>> {
    facade_routes()
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&server),
            facade_invocation_claim,
        ))
        .layer(axum::middleware::from_fn_with_state(
            server,
            facade_call_receipt,
        ))
}

/// Claims the invocation a request names, once, around its whole route
/// (OF-580): a second request naming it for the same call waits for this
/// one's reply and gets it, and one naming it for another call is refused at
/// once. An action's verb-table row reaches its route here with its step's
/// id, and is claimed once, here. A request no credential authenticates, or
/// whose header is no id, is left to its route's own refusal.
async fn facade_invocation_claim(
    State(server): State<Arc<SyncServer>>,
    request: Request,
    next: Next,
) -> Response {
    let Ok(Some(invocation)) = facade_invocation_id(request.headers()) else {
        return next.run(request).await;
    };
    let (mut parts, body) = request.into_parts();
    let Ok(auth) = CoreAuth::from_request_parts(&mut parts, &server).await else {
        return next.run(Request::from_parts(parts, body)).await;
    };
    let bytes = axum::body::to_bytes(body, FACADE_MAX_BODY_BYTES)
        .await
        .unwrap_or_default();
    let digest = match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(value) => oneiron::receipt::call_json_digest(&value),
        Err(_) => oneiron::receipt::call_bytes_digest(&bytes),
    };
    let header = |name: &str| {
        parts
            .headers
            .get(name)
            .map_or(&[][..], HeaderValue::as_bytes)
    };
    let call = invocation_body(
        Some(&auth),
        auth.locality(),
        &[
            b"facade".as_slice(),
            parts.uri.path().as_bytes(),
            header(ROOM_TURN_HEADER),
            header(SESSION_HEADER),
            digest.as_bytes(),
        ],
    );
    match claim_door_invocation(&server, invocation, call).await {
        DoorClaim::Run(claim) => {
            let response = next
                .run(Request::from_parts(parts, Body::from(bytes)))
                .await;
            finish_door_claim(claim, response).await
        }
        DoorClaim::Answered(outcome) => door_replay(outcome),
        DoorClaim::InFlight => FacadeApiError::new(
            StatusCode::CONFLICT,
            INVOCATION_IN_FLIGHT,
            "another request is still running this invocation",
            ["Retry with the same invocation once the first call returns."],
        )
        .into_response(),
        DoorClaim::Conflict => FacadeApiError::new(
            StatusCode::CONFLICT,
            INVOCATION_CONFLICT,
            "this invocation id names a different call",
            ["Name a fresh invocation for a different call."],
        )
        .into_response(),
    }
}

/// How long a request naming an invocation another request is running
/// waits for that call's reply before it is told to retry.
const INVOCATION_WAIT: Duration = Duration::from_secs(30);
/// The refusal a request naming a running invocation gets once its wait
/// runs out, or when the first call left no reply to send again.
pub(crate) const INVOCATION_IN_FLIGHT: &str = "invocation_in_flight";
/// The refusal a request naming a running invocation for a different call
/// gets at once.
pub(crate) const INVOCATION_CONFLICT: &str = "invocation_conflict";

/// What a door does with an invocation its client named (OF-580).
pub(crate) enum DoorClaim {
    /// This request runs the call: hand its reply to [`finish_door_claim`].
    Run(InvocationClaim),
    /// The first call's reply, sent as this request's.
    Answered(InvocationOutcome),
    /// The first call is still running past the wait, or left no reply.
    InFlight,
    /// The id names a different call.
    Conflict,
}

/// Claims `invocation` for the request whose call `body` names, waiting up
/// to [`INVOCATION_WAIT`] for another request's run of the same call. Each
/// door that takes a client's id claims it once, at its outermost point.
pub(crate) async fn claim_door_invocation(
    server: &SyncServer,
    invocation: InvocationId,
    body: [u8; 32],
) -> DoorClaim {
    match server.vault.claim_invocation(invocation, body) {
        InvocationEntry::Claimed(claim) => DoorClaim::Run(claim),
        InvocationEntry::Conflict => DoorClaim::Conflict,
        InvocationEntry::Busy(wait) => {
            match tokio::task::spawn_blocking(move || wait.outcome(INVOCATION_WAIT)).await {
                Ok(Some(outcome)) => DoorClaim::Answered(outcome),
                _ => DoorClaim::InFlight,
            }
        }
    }
}

/// The call a claimed invocation names: the caller (its actor, class and
/// credential), where it sits, and the door's own parts, each
/// length-prefixed.
pub(crate) fn invocation_body(
    auth: Option<&CoreAuth>,
    locality: CallerLocality,
    parts: &[&[u8]],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron door invocation body v1");
    let mut part = |bytes: &[u8]| {
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    };
    if let Some(auth) = auth {
        let (actor_ref, actor_class) = call_receipt::call_actor(auth);
        part(actor_ref.as_bytes());
        part(actor_class.as_bytes());
        part(
            call_receipt::credential_ref(auth)
                .unwrap_or_default()
                .as_bytes(),
        );
    }
    part(match locality {
        CallerLocality::OnDevice => b"on-device".as_slice(),
        CallerLocality::OffDevice => b"off-device".as_slice(),
    });
    for &bytes in parts {
        part(bytes);
    }
    *hasher.finalize().as_bytes()
}

/// Sends `response` as the claimed call's reply, saving it for each request
/// waiting on the same call. A body that is not JSON is sent as it is and
/// saved for none of them.
pub(crate) async fn finish_door_claim(claim: InvocationClaim, response: Response) -> Response {
    let (head, body) = response.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if let Ok(body) = serde_json::from_slice(&bytes) {
        claim.finish(InvocationOutcome {
            status: head.status.as_u16(),
            body,
        });
    }
    Response::from_parts(head, Body::from(bytes))
}

/// The first call's reply, sent again to a request that waited on it.
pub(crate) fn door_replay(outcome: InvocationOutcome) -> Response {
    let status = StatusCode::from_u16(outcome.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(outcome.body)).into_response()
}

/// Records one facade call once its handler has answered, in its own write
/// transaction, and states the receipt on the reply: the
/// `x-oneiron-receipt-ref` header on every reply, and `receiptRef` inside a
/// refusal's error body. A success body keeps its shape (some are JSON
/// arrays). A call inside an anonymous off-record session records nothing
/// and says so (`none; no-record`).
///
/// The call is attributed to the authenticated credential. A request no
/// credential authenticates is answered as before, by the handler's own
/// refusal, and records nothing: there is nobody to scope it to.
async fn facade_call_receipt(
    State(server): State<Arc<SyncServer>>,
    request: Request,
    next: Next,
) -> Response {
    let (mut parts, body) = request.into_parts();
    let Ok(auth) = CoreAuth::from_request_parts(&mut parts, &server).await else {
        return next.run(Request::from_parts(parts, body)).await;
    };
    // OF-063: the no-record exception serves only a caller verified in the
    // session, judged on arrival and again before the receipt is written.
    let principal = call_receipt::request_principal(&auth);
    let session_headers = parts.headers.clone();
    let anonymous = call_receipt::in_anonymous_session(&server, &session_headers, principal);
    let verb = parts.uri.path().trim_start_matches('/').to_owned();
    // The handler reads these same bytes. A body past the facade's limit
    // reaches it empty and is refused there as malformed, as it was before.
    let bytes = axum::body::to_bytes(body, FACADE_MAX_BODY_BYTES)
        .await
        .unwrap_or_default();
    let request_digest = match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(value) => oneiron::receipt::call_json_digest(&value),
        Err(_) => oneiron::receipt::call_bytes_digest(&bytes),
    };
    let mut response = next
        .run(Request::from_parts(parts, Body::from(bytes)))
        .await;
    let mut refusal = response.extensions_mut().remove::<FacadeApiError>();
    let status = response.status();
    let mut result_digest = None;
    if refusal.is_none() && status.is_success() {
        let (head, body) = response.into_parts();
        response = match axum::body::to_bytes(body, usize::MAX).await {
            Ok(bytes) => {
                result_digest = Some(oneiron::receipt::call_bytes_digest(&bytes));
                Response::from_parts(head, Body::from(bytes))
            }
            Err(_) => {
                let failed = FacadeApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    MEMORY_CODE_INTERNAL,
                    "result encoding failed",
                    ["Report this SDK response mismatch."],
                );
                let reply = failed.reply();
                refusal = Some(failed);
                reply
            }
        };
    }
    if let Some(refusal) = &refusal {
        result_digest = Some(oneiron::receipt::call_refusal_digest(
            &refusal.body.error.code,
            &refusal.body.error.message,
        ));
    }
    if let Some(refusal) = &refusal {
        result_digest = Some(oneiron::receipt::call_refusal_digest(
            &refusal.body.error.code,
            &refusal.body.error.message,
        ));
    }
    let outcome = match &refusal {
        Some(refusal) => CallOutcome::Refused {
            code: refusal.body.error.code.clone(),
        },
        None if status.is_success() => CallOutcome::Ok,
        // A reply no facade refusal built (an axum rejection): its status.
        None => CallOutcome::Refused {
            code: format!("HTTP_{}", status.as_u16()),
        },
    };
    let anonymous =
        anonymous || call_receipt::in_anonymous_session(&server, &session_headers, principal);
    let (actor_ref, actor_class) = call_receipt::call_actor(&auth);
    let stamp = call_receipt::record(
        &server,
        anonymous,
        CallReceiptInput {
            transport: CallTransport::HttpFacade,
            verb,
            actor_ref,
            actor_class,
            credential_ref: call_receipt::credential_ref(&auth),
            outcome,
            request_digest,
            result_digest,
            served: Vec::new(),
        },
    );
    if let Some(mut refusal) = refusal {
        refusal.body.error.receipt_ref = stamp.receipt_ref().map(str::to_owned);
        response = refusal.reply();
    }
    stamp.stamp_header(&mut response);
    response
}

/// A facade path that names no verb. One naming a canonical verb under the
/// wrong root is refused with that verb as its correction, before the actor,
/// the body or any effect is touched; there is no redirect and no alias.
async fn facade_unknown_verb(uri: axum::http::Uri) -> FacadeApiError {
    unknown_verb(uri.path().trim_start_matches('/'))
}

/// Every generated facade route ([`agent_verbs`]): the request's credential
/// and headers are the call's context, its JSON body the verb's input, and
/// the row runs in the facade's dispatch ([`call_verb`]), which the held
/// socket runs too. A body that is not JSON is refused where the row reads
/// it, as its handler refused it before.
async fn facade_route(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    payload: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<Json<serde_json::Value>, FacadeApiError> {
    let call = FacadeCall::http(&auth, &headers);
    let verb = uri.path().trim_start_matches('/');
    let output = call_verb(&server, &call, verb, facade_json(payload)).await?;
    Ok(Json(output.value))
}

/// `verb`, which names no facade verb, refused before the actor, the input
/// or any effect is touched: with its correction when it is a canonical verb
/// under the wrong root, else as not found.
fn unknown_verb(verb: &str) -> FacadeApiError {
    let served = oneiron::task_verb::sdk::AgentVerb::ALL
        .iter()
        .filter(|verb| verb.is_facade())
        .map(|verb| verb.as_str());
    match oneiron::task_verb::sdk::wrong_root_in(verb, served) {
        Some(refusal) => refusal.into(),
        None => FacadeApiError::new(
            StatusCode::NOT_FOUND,
            MEMORY_CODE_NOT_FOUND,
            format!("`{verb}` is not an SDK verb"),
            ["Use a verb from the SDK catalog."],
        ),
    }
}

/// Resolves the write identity every facade verb runs as, from the CREDENTIAL
/// and from nowhere else.
///
/// BOTH claims are required, and their absence is a `FORBIDDEN` the handler
/// raises rather than a `401` the extractor raises. The split is the contract:
/// a malformed claim value never reaches here (the MAC-verified parse already
/// 401'd it), so everything this function can see is a well-formed credential
/// that simply is not actor-bound — an owner-grade secret, or a scoped slip
/// minted without `--actor-class`. Those callers keep every non-facade route
/// they have today; they only cannot write as somebody.
///
/// Nothing here is authority. The engine re-checks, per write, that the named
/// principal exists and that its stored entity type admits the asserted class.
fn facade_actor(auth: &CoreAuth) -> Result<(EntityId, EdgeActorClass), FacadeApiError> {
    let principal_ref = auth.principal_ref().ok_or_else(|| {
        FacadeApiError::forbidden(
            "facade routes bind writes to an authenticated principal",
            [
                "Present a slip paired from a link created with --principal-ref <32-hex person id>.",
                "An owner-grade credential names no principal and cannot write here.",
            ],
        )
    })?;
    let actor = EntityId::from_hex(principal_ref).map_err(|_| {
        // Unreachable through the extractor, which canonicalizes the claim
        // through `EntityId::from_hex` before it ever builds a `CoreAuth`.
        // Kept as a typed refusal anyway: this function must not be the place
        // that assumes an upstream check ran.
        FacadeApiError::forbidden(
            "principal_ref is not a 32-hex entity id",
            ["Re-mint the slip with a 32-character lowercase hex principal ref."],
        )
    })?;
    let actor_class = match auth.actor_class() {
        Some("human") => EdgeActorClass::Human,
        Some("agent") => EdgeActorClass::Agent,
        Some("system") => EdgeActorClass::System,
        // `None` is the well-formed-but-unbound credential above. `Some(_)`
        // outside the enum cannot occur — `parse_actor_class` 401s it — and is
        // folded in here so the match stays total and fails CLOSED either way.
        None | Some(_) => {
            return Err(FacadeApiError::forbidden(
                "facade routes bind writes to a declared actor class",
                [
                    "Present a slip paired from a link created with --actor-class <human|agent|system>.",
                    "Reconnect with a differently scoped slip to act as another actor.",
                ],
            ));
        }
    };
    Ok((actor, actor_class))
}

/// Names the room whose turn a request runs in (ARCH-0067 §8). It names only
/// the room: the engine reads the roster and its Scope from the vault.
pub(crate) const ROOM_TURN_HEADER: &str = "x-oneiron-room-turn";

/// Names the logical verb a request runs (ARCH-0080 §3), as 32 hex digits:
/// its verb hooks fire once for it, and a retry of a pending call names the
/// same one to find its ask.
pub(crate) const INVOCATION_HEADER: &str = "x-oneiron-invocation";

/// `memory` bound to the invocation the call names, if it names one, and
/// to the off-record session it names (OF-063: inside an anonymous one a
/// reference refusal writes no receipt, as its call writes none, OF-538).
/// The facade, in the room turn the call names, is the door a credential
/// caller's call came in by: a verb hook's ask saves it, so settlement runs
/// the call again here (ARCH-0080 §3 Ask).
fn facade_invocation<'v>(
    memory: oneiron::Memory<'v>,
    call: &FacadeCall<'_>,
) -> Result<oneiron::Memory<'v>, FacadeApiError> {
    let memory = match call.session_ref() {
        Some(session_ref) => memory.in_off_record_session(session_ref),
        None => memory,
    };
    let memory = memory.with_credential_door(VerbAskDoor::Facade {
        room: call.room_turn()?,
    });
    Ok(match call.invocation()? {
        Some(invocation) => memory.with_invocation(invocation),
        None => memory,
    })
}

/// The pre chain of row `verb` for `actor` over `args`, off the async
/// runtime (ARCH-0080 §3): a hook may write, open an ask and run its
/// sandbox. Every server door that runs a row itself, not through `invoke`,
/// crosses it here. Its hooks read as `actor`; a door that holds its
/// caller's key calls [`row_hooks_pre_with`].
pub(crate) async fn row_hooks_pre(
    server: &Arc<SyncServer>,
    actor: EntityId,
    class: EdgeActorClass,
    invocation: Option<InvocationId>,
    verb: &str,
    args: serde_json::Value,
) -> Result<VerbHookPre, MemoryError> {
    let resume = RowHookResume::default();
    row_hooks_pre_with(
        server, None, None, actor, class, invocation, verb, args, resume,
    )
    .await
}

/// What a row's pre chain carries for settlement (ARCH-0080 §3 Ask): the
/// credential a caller's call can run again on through its door, and the
/// drain's permit when settlement runs it again. The default carries
/// neither.
#[derive(Default)]
pub(crate) struct RowHookResume {
    pub(crate) credential: Option<VerbAskCredential>,
    pub(crate) drain: Option<VerbAskDrainPermit>,
}

/// [`row_hooks_pre`] for a door that holds its caller's read key and its own
/// admission of rewritten args. The hooks read under `reader`, capped by
/// their grant, and as `actor` when it is `None`. A rewrite must pass the
/// row's input check, then `check`, as if the caller sent it. An ask saves
/// `resume`'s credential, and its drain permit marks the chain's thread as
/// the drain's run of the call.
#[expect(
    clippy::too_many_arguments,
    reason = "row_hooks_pre's inputs plus the caller's key, rewrite admission and resume"
)]
pub(crate) async fn row_hooks_pre_with(
    server: &Arc<SyncServer>,
    reader: Option<ScopedReadActorKey>,
    check: Option<RewriteAdmit>,
    actor: EntityId,
    class: EdgeActorClass,
    invocation: Option<InvocationId>,
    verb: &str,
    args: serde_json::Value,
    resume: RowHookResume,
) -> Result<VerbHookPre, MemoryError> {
    let server = Arc::clone(server);
    let verb = verb.to_owned();
    tokio::task::spawn_blocking(move || {
        let _drain = resume.drain.as_ref().map(VerbAskDrainPermit::enter);
        let call = VerbCall {
            verb: verb.clone(),
            invocation: invocation.unwrap_or_else(InvocationId::mint),
            actor,
            class: hook_class(class),
            scope: None,
            board_epoch: None,
            domain: verb_hook_boundary::row_domain(&verb),
            reader,
        };
        let admit = |args: &serde_json::Value| {
            oneiron::task_verb::sdk::validate_input(&verb, args)
                .map_err(|error| error.to_string())?;
            check
                .as_ref()
                .map_or(Ok(()), |check| check(verb.as_str(), args))
        };
        server
            .vault
            .pre_verb_hooks_for_credential(call, args, &admit, resume.credential)?
            .map_err(|stop| MemoryError::from(oneiron::Error::from(stop)))
    })
    .await
    .map_err(|_| hooks_did_not_finish())?
}

/// The post chain over that row's result, off the async runtime: the
/// caller's view of it.
pub(crate) async fn row_hooks_post(
    server: &Arc<SyncServer>,
    pre: VerbHookPre,
    result: serde_json::Value,
) -> Result<serde_json::Value, MemoryError> {
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || verb_hook_boundary::row_post(&server.vault, pre, result))
        .await
        .map_err(|_| hooks_did_not_finish())?
}

fn hooks_did_not_finish() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INTERNAL,
        "the verb's hooks did not finish on this server",
        &["Retry; if the failure persists, report it with this request's id."],
    )
}

/// The pre chain of a row this route runs itself (ARCH-0080 §3): the args to
/// run it with. Its caller is the credential's actor; a credential bound to
/// none calls as the host, the vault's owner in person when it is
/// owner-grade. The row's door checks its own authority first, so a hook
/// never fires on a call the door refuses.
async fn facade_hooks_pre(
    server: &Arc<SyncServer>,
    call: &FacadeCall<'_>,
    verb: &str,
    value: serde_json::Value,
) -> Result<VerbHookPre, FacadeApiError> {
    let auth = call.auth();
    if verb == "vault.export" {
        export_admits(server, auth)?;
    } else {
        host_doors::door_admits(server, auth, verb)?;
    }
    let bound = facade_actor(auth).ok();
    let (actor, class) = match bound {
        Some(actor) => actor,
        None => (
            verb_hook_boundary::host_actor().map_err(MemoryError::from)?,
            if auth.is_owner_grade() {
                EdgeActorClass::Human
            } else {
                EdgeActorClass::System
            },
        ),
    };
    let invocation = call.invocation()?;
    // A credential caller's own call can run again through this door once
    // its hook's ask settles, on the drain's permit when it does. A context
    // the row refuses saves none.
    let credential = match bound {
        Some(_) if VerbCall::may_run(&server.vault, verb) => facade_invocation(
            credential_memory(&server.vault, Some(auth), actor, class).at(auth.locality()),
            call,
        )
        .ok()
        .and_then(|memory| memory.verb_ask_credential()),
        _ => None,
    };
    let resume = RowHookResume {
        credential,
        drain: call.drain().cloned(),
    };
    // What only a hook reads, built only when one may run: the caller's read
    // key, its credential's where its connection sits (an owner-grade
    // credential that calls as the host reads as the host, its owner), and
    // the re-admission of a rewritten ref.
    let (reader, check) = if VerbCall::may_run(&server.vault, verb) {
        let reader = match bound {
            Some(_) => Some(
                credential_memory(&server.vault, Some(auth), actor, class)
                    .at(auth.locality())
                    .read_key()?,
            ),
            None if auth.is_owner_grade() => None,
            None => Some(
                super::scoped_read_for_core_auth(&server.vault, auth)?
                    .actor_key()
                    .clone(),
            ),
        };
        (reader, Some(facade_rewrite_admit(server, auth, &value)))
    } else {
        (None, None)
    };
    Ok(row_hooks_pre_with(
        server, reader, check, actor, class, invocation, verb, value, resume,
    )
    .await?)
}

/// What the facade admits before a host-door row's pre chain, for a door
/// that runs the chain itself: the row door's own authority check, and
/// whole-vault export's owner admission. A hook never fires on a call the
/// row's door refuses.
pub(crate) fn row_door_admits(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> Result<(), MemoryError> {
    if verb == "vault.export" {
        export_admits(server, auth).map_err(FacadeApiError::into_memory_error)
    } else {
        host_doors::door_admits(server, auth, verb)
    }
}

/// Whole-vault export's owner admission, as the export runs it in its own
/// snapshot: the host's root, or the owner's own live slip. The route has
/// already refused a credential short of owner-grade or with no verified
/// slip.
fn export_admits(server: &SyncServer, auth: &CoreAuth) -> Result<(), FacadeApiError> {
    let Some(proof) = auth.verified_slip() else {
        return Ok(());
    };
    if proof.claims().holder_ref == "host" {
        server.vault.admit_host_owner_export(proof)?;
    } else {
        let (actor, class) = facade_actor(auth)?;
        server
            .vault
            .memory(actor, class)
            .at(auth.locality())
            .admit_export(Some(proof))?;
    }
    Ok(())
}

/// The post chain over that row's result: the caller's view of it.
async fn facade_hooks_post(
    server: &Arc<SyncServer>,
    pre: VerbHookPre,
    output: serde_json::Value,
) -> Result<serde_json::Value, FacadeApiError> {
    Ok(row_hooks_post(server, pre, output).await?)
}

/// The proof a write carries when the vault's owner makes it in person, on the
/// owner's own undelegated full slip: owner-authored writes carry their own
/// confirmation. `None` for any other credential, which writes as itself. The
/// owner's own credential that no longer holds (revoked, or its PERSON
/// deleted, merged or split) is refused, never downgraded to an ordinary
/// write.
pub(super) fn owner_authorship(
    auth: &CoreAuth,
    server: &SyncServer,
) -> Result<Option<oneiron::consent::AuthenticatedOwner>, ApiError> {
    let Some((principal, actor)) = auth
        .principal_ref()
        .and_then(|principal| Some((principal, oneiron::EntityId::from_hex(principal).ok()?)))
    else {
        return Ok(None);
    };
    let Some(slip) = auth.verified_slip().filter(|slip| {
        let claims = slip.claims();
        slip.is_full_vault_owner_grade()
            && claims.parent_id.is_none()
            && claims.holder_ref == actor.to_hex()
            && claims.actor_class.as_deref() == Some("human")
    }) else {
        return Ok(None);
    };
    if server.managed_issuer.is_some() || !auth.is_owner_grade() {
        return Ok(None);
    }
    let refused = || ApiError::forbidden_scope("owner");
    let Some(owner) = server
        .vault()
        .authenticate_recorded_owner(actor, principal, oneiron::store::GateDecisionId::now())
        .map_err(|_| refused())?
    else {
        return Ok(None);
    };
    if !server
        .vault()
        .is_live_vault_owner(&owner)
        .map_err(|_| refused())?
    {
        return Ok(None);
    }
    server
        .vault()
        .bind_owner_credential(owner, slip.clone())
        .map(Some)
        .map_err(|_| refused())
}

/// Runs one SDK verb as the caller's credential reads, inside the named room
/// turn when the call names one. Its reads list the rows they pick in
/// `producers`.
fn facade_invoke(
    server: &SyncServer,
    call: &FacadeCall<'_>,
    actor: EntityId,
    class: EdgeActorClass,
    verb: &str,
    value: serde_json::Value,
    producers: &oneiron::memory::ProducerRows,
) -> Result<serde_json::Value, FacadeApiError> {
    let auth = call.auth();
    let memory = facade_invocation(
        credential_memory(&server.vault, Some(auth), actor, class)
            .at(auth.locality())
            .listing_producers(producers),
        call,
    )?;
    let memory = facade_rewrites_admitted(server, auth, verb, &value, memory);
    // Settlement's run of the call enters its boundary here as the drain's.
    let _drain = call.drain().map(VerbAskDrainPermit::enter);
    Ok(match call.room_turn()? {
        Some(room) => memory.for_room_turn(room)?.invoke(verb, value)?,
        None => {
            // The owner's own request on the owner's own full credential:
            // owner-authored writes carry their own confirmation. Any other
            // caller writes as itself; the owner's credential that no longer
            // holds is refused.
            let memory = match owner_authorship(auth, server)? {
                Some(owner) => memory.with_owner_authorship(&owner),
                None => memory,
            };
            oneiron::task_verb::sdk::invoke(&memory, verb, value)?
        }
    })
}

/// Where the records this credential births land (owner ruling FACET-READ;
/// placement stays derived, ARCH-0028). A credential never narrowed to facets
/// keeps the derived birth, under the same strict door as before. A narrowed
/// one lands in its landing facet, which it must carry; any other narrowing
/// still fails closed.
fn facade_landing(
    server: &SyncServer,
    call: &FacadeCall<'_>,
) -> Result<BirthPosition, FacadeApiError> {
    let auth = call.auth();
    let Some(proof) = auth.verified_slip() else {
        return Ok(BirthPosition::default());
    };
    if matches!(proof.scope().facets, ScopeAxis::All) {
        auth.require_unrestricted_record_scope()?;
        return Ok(BirthPosition::default());
    }
    let session = call.session()?;
    let write_facet = server
        .vault
        .paired_write_facet(&proof.claims().slip_id)
        .map_err(MemoryError::from)?;
    let landing = landing_facet(&server.vault, session, &proof.scope().facets, write_facet)
        .map_err(|_| {
            FacadeApiError::forbidden(
                "the session this request names does not place this credential's writes",
                ["Name a session whose facet this credential reads, or none."],
            )
        })?;
    auth.require_record_scope_carried(
        ScopeAxis::All,
        landing.map_or(ScopeAxis::All, |facet| {
            ScopeAxis::Some(std::collections::BTreeSet::from([ScopeId(facet)]))
        }),
    )?;
    Ok(BirthPosition {
        world: None,
        facet: landing,
    })
}

/// [`facade_invoke`] for a verb that births records at `position`.
#[expect(
    clippy::too_many_arguments,
    reason = "the generated dispatch passes facade_invoke's inputs plus the birth position"
)]
fn facade_invoke_born(
    server: &SyncServer,
    call: &FacadeCall<'_>,
    actor: EntityId,
    class: EdgeActorClass,
    verb: &str,
    value: serde_json::Value,
    position: BirthPosition,
    producers: &oneiron::memory::ProducerRows,
) -> Result<serde_json::Value, FacadeApiError> {
    let auth = call.auth();
    let memory = facade_invocation(
        credential_memory(&server.vault, Some(auth), actor, class)
            .at(auth.locality())
            .with_birth_position(position)
            .listing_producers(producers),
        call,
    )?;
    let memory = facade_rewrites_admitted(server, auth, verb, &value, memory);
    let _drain = call.drain().map(VerbAskDrainPermit::enter);
    Ok(match call.room_turn()? {
        Some(room) => memory.for_room_turn(room)?.invoke(verb, value)?,
        None => oneiron::task_verb::sdk::invoke(&memory, verb, value)?,
    })
}

/// A verb that reads around the read lane is not served inside a room turn.
fn facade_outside_room_turn(call: &FacadeCall<'_>, verb: &str) -> Result<(), FacadeApiError> {
    facade_room_turn_serves(call, verb, false)
}

/// Refuses, before any lookup the verb would make, a verb the named room
/// turn does not serve, so the refusal says nothing about the verb's target.
fn facade_room_turn_serves(
    call: &FacadeCall<'_>,
    verb: &str,
    served: bool,
) -> Result<(), FacadeApiError> {
    if !served && call.room_turn()?.is_some() {
        return Err(FacadeApiError::new(
            StatusCode::BAD_REQUEST,
            MEMORY_CODE_BAD_REQUEST,
            format!("{verb} is not served inside a room turn"),
            ["Call it without the room turn header."],
        ));
    }
    Ok(())
}

/// Decodes a facade request body, reporting a malformed one in the FACADE
/// error vocabulary rather than the server's closed one.
fn facade_json<T>(payload: Result<Json<T>, JsonRejection>) -> Result<T, FacadeApiError> {
    payload.map(|Json(payload)| payload).map_err(|_| {
        FacadeApiError::new(
            StatusCode::BAD_REQUEST,
            MEMORY_CODE_BAD_REQUEST,
            "invalid JSON request body",
            ["Send a JSON body matching this verb's documented input."],
        )
    })
}

/// Decodes a request `validate_input` already admitted into the verb's typed
/// input, for a route that works on the typed result before encoding it.
fn facade_input<T: serde::de::DeserializeOwned>(
    value: serde_json::Value,
) -> Result<T, FacadeApiError> {
    serde_json::from_value(value).map_err(|_| {
        FacadeApiError::new(
            StatusCode::BAD_REQUEST,
            MEMORY_CODE_BAD_REQUEST,
            "invalid typed SDK arguments",
            ["Send a JSON body matching this verb's documented input."],
        )
    })
}

/// Encodes a typed verb result in the facade's vocabulary.
fn facade_output<T: Serialize>(output: T) -> Result<serde_json::Value, FacadeApiError> {
    serde_json::to_value(output).map_err(|_| {
        FacadeApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            MEMORY_CODE_INTERNAL,
            "result encoding failed",
            ["Report this SDK response mismatch."],
        )
    })
}

/// Refuses a caller-named entity this credential cannot read, with the
/// NOT_FOUND a missing one gets, so the route never confirms that the id
/// exists. A ref that is not an entity id is left for the engine to refuse.
fn facade_admit_readable_ref(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    value: &serde_json::Value,
    field: &str,
) -> Result<(), FacadeApiError> {
    let Some(id) = value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .and_then(|id| EntityId::from_hex(id).ok())
    else {
        return Ok(());
    };
    if auth
        .can_read_entity(vault, &id)
        .map_err(MemoryError::from)?
    {
        Ok(())
    } else {
        Err(MemoryError::from(oneiron::Error::EntityNotFound).into())
    }
}

/// Re-admits each top-level `*_ref` field a hook's rewrite changed, as the
/// route admitted the caller's own refs ([`facade_admit_readable_ref`]): a
/// rewrite may not point the verb at an entity this credential cannot read.
/// The reason refuses the rewrite.
fn facade_admit_rewritten(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    original: &serde_json::Value,
    rewritten: &serde_json::Value,
) -> Result<(), String> {
    let Some(fields) = rewritten.as_object() else {
        return Ok(());
    };
    for (field, value) in fields {
        if field.ends_with("_ref") && original.get(field) != Some(value) {
            facade_admit_readable_ref(vault, auth, rewritten, field)
                .map_err(|refusal| refusal.body.error.message)?;
        }
    }
    Ok(())
}

/// [`facade_admit_rewritten`] against the caller's `original` args, as a
/// row's rewrite admission.
fn facade_rewrite_admit(
    server: &SyncServer,
    auth: &CoreAuth,
    original: &serde_json::Value,
) -> RewriteAdmit {
    let (vault, auth, original) = (Arc::clone(&server.vault), auth.clone(), original.clone());
    Arc::new(move |_: &str, rewritten: &serde_json::Value| {
        facade_admit_rewritten(&vault, &auth, &original, rewritten)
    })
}

/// `memory` bound to re-admit a hook's rewritten refs, when a hook may run on
/// `verb`.
fn facade_rewrites_admitted<'v>(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
    original: &serde_json::Value,
    memory: oneiron::Memory<'v>,
) -> oneiron::Memory<'v> {
    if VerbCall::may_run(&server.vault, verb) {
        memory.with_rewrite_admit(facade_rewrite_admit(server, auth, original))
    } else {
        memory
    }
}

/// Drops every TASKS row this credential cannot read from a described
/// section, as MCP's board does, then encodes the description. A row id that
/// is not an entity id cannot be proven readable, so only a credential without
/// a slip, which reads every entity, keeps it. A card passes unchanged: its
/// task ref was admitted before the engine call.
fn facade_readable_task_rows(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    mut description: oneiron::task_verb::TaskDescription,
) -> Result<serde_json::Value, FacadeApiError> {
    if let oneiron::task_verb::TaskDescription::Section(section) = &mut description {
        let mut rows = Vec::with_capacity(section.rows.len());
        for row in std::mem::take(&mut section.rows) {
            let readable = match EntityId::from_hex(&row.id) {
                Ok(id) => auth
                    .can_read_entity(vault, &id)
                    .map_err(MemoryError::from)?,
                Err(_) => auth.verified_slip().is_none(),
            };
            if readable {
                rows.push(row);
            }
        }
        section.rows = rows;
    }
    serde_json::to_value(description).map_err(|_| {
        FacadeApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            MEMORY_CODE_INTERNAL,
            "SDK result encoding failed",
            ["Report this SDK response mismatch."],
        )
    })
}

/// A facade failure on its way to the wire.
///
/// Carries the RAW engine code string, never [`crate::error::ErrorCode`]. An
/// engine code this server has never heard of still reaches the client spelled
/// the way the engine spelled it; only the HTTP status is this file's opinion.
#[derive(Clone, Debug)]
pub(crate) struct FacadeApiError {
    status: StatusCode,
    body: FacadeErrorEnvelope,
}

/// `{error: {...}}`, the same transport envelope shape `/v1/core` uses,
/// with the read receipt beside the error when a read verb refused.
#[derive(Clone, Debug, Serialize)]
struct FacadeErrorEnvelope {
    error: FacadeErrorBody,
    /// Boxed so the refusal stays small on every `Result` that carries it.
    #[serde(skip_serializing_if = "Option::is_none")]
    narrowing: Option<Box<oneiron::claim::ScopedReadReceipt>>,
}

/// The facade error payload: `{code, message, requestId, suggestions}`.
///
/// `code` is a `String` and that is the load-bearing difference from
/// [`crate::error::ApiErrorEnvelopeBody`]. `details` is absent because the
/// engine vocabulary has no per-code detail variants to project.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FacadeErrorBody {
    code: String,
    message: String,
    request_id: String,
    suggestions: Vec<String>,
    /// The lasting receipt of the call this refusal answered (OF-538),
    /// `call:<32hex>`, resolvable through `vault.receipts.get`. Set by the
    /// facade's receipt layer once the call is recorded; absent for a call
    /// that has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_ref: Option<String>,
    /// A `WRONG_ROOT` refusal's `{attempted, replacement, schemaRef}`.
    #[serde(flatten)]
    wrong_root: Option<Box<oneiron::memory::MemoryWrongRoot>>,
    /// A verb hook's stop (ARCH-0080 §3): skipped with its reason, pending
    /// on an ask with the invocation and the ask, or hidden.
    #[serde(skip_serializing_if = "Option::is_none")]
    hook: Option<Box<VerbHookStop>>,
}

/// The OpenAPI mirror of a facade refusal's body ([`FacadeErrorEnvelope`]):
/// the engine's `MemoryError` as the wire carries it, `code` spelled as the
/// engine spells it. A route that answers with [`FacadeApiError`] names it as
/// that refusal's body.
#[derive(utoipa::ToSchema)]
#[expect(
    dead_code,
    reason = "OpenAPI schema mirror; a refusal serializes FacadeErrorEnvelope"
)]
pub(crate) struct MemoryErrorEnvelopeSchema {
    error: MemoryErrorBodySchema,
    narrowing: Option<crate::api::read_receipt::ReadReceiptSchema>,
}

/// The OpenAPI mirror of [`FacadeErrorBody`].
#[derive(utoipa::ToSchema)]
#[expect(
    dead_code,
    reason = "OpenAPI schema mirror; a refusal serializes FacadeErrorBody"
)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MemoryErrorBodySchema {
    code: String,
    message: String,
    request_id: String,
    suggestions: Vec<String>,
    receipt_ref: Option<String>,
}

impl FacadeApiError {
    fn new(
        status: StatusCode,
        code: &str,
        message: impl Into<String>,
        suggestions: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            status,
            body: FacadeErrorEnvelope {
                error: FacadeErrorBody {
                    code: code.to_owned(),
                    message: message.into(),
                    request_id: facade_request_id(),
                    suggestions: suggestions.into_iter().map(Into::into).collect(),
                    receipt_ref: None,
                    wrong_root: None,
                    hook: None,
                },
                narrowing: None,
            },
        }
    }

    fn forbidden(
        message: impl Into<String>,
        suggestions: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            MEMORY_CODE_FORBIDDEN,
            message,
            suggestions,
        )
    }
}

/// The engine's refusal, forwarded whole.
///
/// The status is derived from the code; the code, message, and suggestions are
/// the engine's own bytes. An unrecognized code keeps its string and takes a
/// `500`: unknown means this server cannot claim to know the failure is the
/// caller's fault.
impl From<MemoryError> for FacadeApiError {
    fn from(error: MemoryError) -> Self {
        let status = match error.code.as_str() {
            // A wrong root is the caller's spelling, refused before any
            // effect with the name to call instead.
            MEMORY_CODE_BAD_REQUEST | oneiron::memory::MEMORY_CODE_WRONG_ROOT => {
                StatusCode::BAD_REQUEST
            }
            MEMORY_CODE_NOT_FOUND => StatusCode::NOT_FOUND,
            // `LEASE_REQUIRED` is a refusal to serve without a credential the
            // caller does not hold, which is what 403 means. The engine code
            // carries the specific meaning; the status only has to be an
            // honest 4xx so no client reads the body as success.
            // `OWNER_BINDING_REQUIRED` is a 403 for the same reason
            // `FORBIDDEN` is: the authority log refuses this actor the verb.
            // It carries its own code so a client can tell the authority door
            // from the gate door, but the status is the same honest 403.
            MEMORY_CODE_FORBIDDEN
            | MEMORY_CODE_LEASE_REQUIRED
            | MEMORY_CODE_OWNER_BINDING_REQUIRED => StatusCode::FORBIDDEN,
            // Both are "the store is not in a state that admits this", which
            // is the conflict family the rest of this plane already maps to
            // 409. `VAULT_LOCKED_SINGLE_WRITER` cannot arise server-side — it
            // is the EMBEDDED constructor's refusal — and is mapped anyway so
            // the vocabulary has no hole.
            MEMORY_CODE_INVALID_STATE
            | MEMORY_CODE_OFF_RECORD_SESSION_DOOR
            | MEMORY_CODE_VAULT_LOCKED_SINGLE_WRITER => StatusCode::CONFLICT,
            // OF-123: the person the effect names is not settled yet; the
            // same request succeeds once `self.identity.settle` settles it.
            oneiron::memory::MEMORY_CODE_IDENTITY_UNSETTLED => StatusCode::CONFLICT,
            // A paid call its line cannot cover, as a chat turn's is.
            MEMORY_CODE_BUDGET_SPENT => StatusCode::PAYMENT_REQUIRED,
            // A verb hook asked first: accepted, not run, and the body names
            // the ask a retry with the same invocation waits on.
            MEMORY_CODE_PENDING_ASK => StatusCode::ACCEPTED,
            // The model the request needs did not answer: not the caller's
            // fault, and not this server's to stand in for.
            MEMORY_CODE_MODEL_UNAVAILABLE => StatusCode::SERVICE_UNAVAILABLE,
            // OF-063: the write named a record its writer cannot resolve. The
            // request was well formed and refused, so it is the caller's
            // to correct, and a missing record and an unreadable one are this
            // same status.
            oneiron::memory::MEMORY_CODE_INVENTED_REFERENCE => StatusCode::UNPROCESSABLE_ENTITY,
            // A credential call settlement refused before it ran (ARCH-0080
            // §3 Ask): the caller's credential no longer admits it, or this
            // host could not run it again. Either way a new invocation.
            code if VerbAskRefusal::from_code(code)
                .is_some_and(VerbAskRefusal::names_credential) =>
            {
                StatusCode::FORBIDDEN
            }
            code if VerbAskRefusal::from_code(code).is_some() => StatusCode::CONFLICT,
            MEMORY_CODE_INTERNAL => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(code = %error.code, error = %error.message, "facade verb failed");
        }
        Self {
            status,
            body: FacadeErrorEnvelope {
                error: FacadeErrorBody {
                    code: error.code,
                    message: error.message,
                    request_id: facade_request_id(),
                    suggestions: error.suggestions,
                    receipt_ref: None,
                    wrong_root: error.wrong_root,
                    hook: error.hook,
                },
                narrowing: error.read_receipt,
            },
        }
    }
}

/// Scope refusals keep coming from the shared `CoreAuth::require`, so the one
/// scope check in this crate stays one implementation. Only the SERIALIZATION
/// changes here: the closed enum's stable string becomes this envelope's raw
/// `code`, which is the same text a client would have read either way.
impl From<ApiError> for FacadeApiError {
    fn from(error: ApiError) -> Self {
        Self::new(
            error.status(),
            error.code().as_str(),
            error.message().to_owned(),
            error.suggestions().to_vec(),
        )
    }
}

impl FacadeApiError {
    /// The refusal's wire reply: its status and `{error, narrowing?}` body.
    fn reply(&self) -> Response {
        (self.status, Json(&self.body)).into_response()
    }

    /// The refusal as the engine's typed error, for a door outside the
    /// facade (MCP's row door admission, the held socket's `rpc.err`): its
    /// open code, message and suggestions, its read receipt, wrong-root
    /// correction and hook stop. Only the HTTP status stays behind.
    pub(crate) fn into_memory_error(self) -> MemoryError {
        let FacadeErrorEnvelope { error, narrowing } = self.body;
        let mut refusal = MemoryError::new(&error.code, error.message, &[]);
        refusal.suggestions = error.suggestions;
        refusal.read_receipt = narrowing;
        refusal.wrong_root = error.wrong_root;
        refusal.hook = error.hook;
        refusal
    }
}

/// The reply, with the refusal itself riding along in the response's
/// extensions, so the facade's receipt layer reads its code and states the
/// call's receipt in its body (OF-538).
impl IntoResponse for FacadeApiError {
    fn into_response(self) -> Response {
        let mut response = self.reply();
        response.extensions_mut().insert(self);
        response
    }
}

/// Diagnostic correlation id for one facade error.
///
/// Its own counter with its own prefix rather than a reach into
/// `crate::error`'s private one: two sequences that cannot be confused for
/// each other are better than one sequence shared through a widened seam that
/// this ticket is not allowed to widen.
fn facade_request_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("facade-req-{id:016x}")
}
