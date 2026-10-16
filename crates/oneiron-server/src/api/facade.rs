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
//! all use the same inventory and engine DTOs as the native clients. Live
//! subscriptions remain owned by the held socket rather than this router.
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
pub(super) mod role_picks;
pub(super) mod host_doors;
mod legal_hold_doors;
mod shared_act_doors;
#[cfg(test)]
pub(super) mod tests;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::body::Body;
use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, FromRequestParts, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::post;
use oneiron::receipt::{CallOutcome, CallReceiptInput, CallTransport};
use serde::Serialize;

use super::call_receipt;
use crate::auth::{CoreAuth, CoreScope};
use crate::error::ApiError;
use crate::server::SyncServer;
use oneiron::federation::record_scope::BirthPosition;
use oneiron::federation::{ScopeAxis, ScopeId};
use oneiron::memory::caps::MAX_REMOTE_REQUEST_BYTES;
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_BUDGET_SPENT, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL,
    MEMORY_CODE_INVALID_STATE, MEMORY_CODE_LEASE_REQUIRED, MEMORY_CODE_MODEL_UNAVAILABLE,
    MEMORY_CODE_NOT_FOUND, MEMORY_CODE_OFF_RECORD_SESSION_DOOR, MEMORY_CODE_OWNER_BINDING_REQUIRED,
    MEMORY_CODE_VAULT_LOCKED_SINGLE_WRITER, MemoryError,
};
use oneiron::{EdgeActorClass, EntityId};

use super::credential_memory;
use super::write_facet::{landing_facet, request_session};

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
/// around the generated routes and the unknown-verb fallback alike.
pub(crate) fn recorded_facade_routes(server: Arc<SyncServer>) -> Router<Arc<SyncServer>> {
    facade_routes().layer(axum::middleware::from_fn_with_state(
        server,
        facade_call_receipt,
    ))
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
    let anonymous = call_receipt::in_anonymous_session(&server, &parts.headers);
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
    let verb = uri.path().trim_start_matches('/');
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

fn facade_room_turn(headers: &HeaderMap) -> Result<Option<EntityId>, FacadeApiError> {
    let Some(value) = headers.get(ROOM_TURN_HEADER) else {
        return Ok(None);
    };
    value
        .to_str()
        .ok()
        .and_then(|room| EntityId::from_hex(room).ok())
        .map(Some)
        .ok_or_else(|| {
            FacadeApiError::new(
                StatusCode::BAD_REQUEST,
                MEMORY_CODE_BAD_REQUEST,
                "invalid room turn header",
                ["Name the room as its 32-hex id."],
            )
        })
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
/// turn when the request names one.
fn facade_invoke(
    server: &SyncServer,
    headers: &HeaderMap,
    auth: &CoreAuth,
    actor: EntityId,
    class: EdgeActorClass,
    verb: &str,
    value: serde_json::Value,
) -> Result<serde_json::Value, FacadeApiError> {
    let memory = credential_memory(&server.vault, Some(auth), actor, class).at(auth.locality());
    Ok(match facade_room_turn(headers)? {
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
    headers: &HeaderMap,
    auth: &CoreAuth,
) -> Result<BirthPosition, FacadeApiError> {
    let Some(proof) = auth.verified_slip() else {
        return Ok(BirthPosition::default());
    };
    if matches!(proof.scope().facets, ScopeAxis::All) {
        auth.require_unrestricted_record_scope()?;
        return Ok(BirthPosition::default());
    }
    let session = request_session(headers).map_err(|()| {
        FacadeApiError::new(
            StatusCode::BAD_REQUEST,
            MEMORY_CODE_BAD_REQUEST,
            "invalid session header",
            ["Name the session as its 32-hex id."],
        )
    })?;
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
    reason = "the generated route passes facade_invoke's inputs plus the birth position"
)]
fn facade_invoke_born(
    server: &SyncServer,
    headers: &HeaderMap,
    auth: &CoreAuth,
    actor: EntityId,
    class: EdgeActorClass,
    verb: &str,
    value: serde_json::Value,
    position: BirthPosition,
) -> Result<serde_json::Value, FacadeApiError> {
    let memory = credential_memory(&server.vault, Some(auth), actor, class)
        .at(auth.locality())
        .with_birth_position(position);
    Ok(match facade_room_turn(headers)? {
        Some(room) => memory.for_room_turn(room)?.invoke(verb, value)?,
        None => oneiron::task_verb::sdk::invoke(&memory, verb, value)?,
    })
}

/// A verb that reads around the read lane is not served inside a room turn.
fn facade_outside_room_turn(headers: &HeaderMap, verb: &str) -> Result<(), FacadeApiError> {
    facade_room_turn_serves(headers, verb, false)
}

/// Refuses, before any lookup the verb would make, a verb the named room
/// turn does not serve, so the refusal says nothing about the verb's target.
fn facade_room_turn_serves(
    headers: &HeaderMap,
    verb: &str,
    served: bool,
) -> Result<(), FacadeApiError> {
    if !served && facade_room_turn(headers)?.is_some() {
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
pub(super) struct FacadeApiError {
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
            // A paid call its line cannot cover, as a chat turn's is.
            MEMORY_CODE_BUDGET_SPENT => StatusCode::PAYMENT_REQUIRED,
            // The model the request needs did not answer: not the caller's
            // fault, and not this server's to stand in for.
            MEMORY_CODE_MODEL_UNAVAILABLE => StatusCode::SERVICE_UNAVAILABLE,
            // OF-063: the write named a record its writer cannot resolve. The
            // request was well formed and refused, so it is the caller's
            // to correct, and a missing record and an unreadable one are this
            // same status.
            oneiron::memory::MEMORY_CODE_INVENTED_REFERENCE => StatusCode::UNPROCESSABLE_ENTITY,
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
