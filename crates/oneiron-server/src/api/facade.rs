//! ONE-1441 WIRE-P1: the bounded HTTP projection of the engine memory surface.
//!
//! One route per §HEAD-CONTRACT verb at `/v1/core/facade/<snake_case_verb>`,
//! and nothing else. Every handler does the same four things: require the
//! scope, resolve the actor from the CREDENTIAL, bind
//! [`oneiron::Vault::memory`] to it, and serialize what the engine returned.
//! There is no transport-only domain model here — the request and response
//! types ARE the engine DTOs — so this projection and the in-process N-API
//! binding cannot drift into two dialects of the same verb.
//!
//! L1 ships the canonical quickstart, which is four calls: `witness` →
//! `claim_upsert` → `recall` → `receipts`. The rest of the §HEAD-CONTRACT
//! catalog is deliberately ABSENT rather than stubbed, except the five
//! exact keyed-memory routes below and eight generated tasks/rooms routes.
//! A `501` stub is still a
//! registered row: it enters the route census, a client's catalog test counts
//! it as shipped, and the only thing it proves is that somebody meant to write
//! the verb. An absent route says the same thing without the false positive.
//!
//! ERRORS are the facade's own, not the server's closed
//! [`crate::error::ErrorCode`] enum.
//! The engine's `code` string travels verbatim inside the same
//! `{error:{code,message,requestId,suggestions}}` envelope shape the rest of
//! `/v1/core` uses, so a future engine code reaches a client losslessly
//! instead of collapsing into `INTERNAL_SERVER_ERROR`. `crate::error` is not
//! edited to admit these codes; that is the whole point of the local type.

mod agent_verbs;
#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::post;
use serde::Serialize;

use crate::auth::{CoreAuth, CoreScope};
use crate::error::ApiError;
use crate::server::SyncServer;
use oneiron::memory::caps::MAX_REMOTE_REQUEST_BYTES;
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL,
    MEMORY_CODE_INVALID_STATE, MEMORY_CODE_LEASE_REQUIRED, MEMORY_CODE_NOT_FOUND,
    MEMORY_CODE_OFF_RECORD_SESSION_DOOR, MEMORY_CODE_OWNER_BINDING_REQUIRED,
    MEMORY_CODE_VAULT_LOCKED_SINGLE_WRITER, MemoryError,
};
use oneiron::{EdgeActorClass, EntityId};

/// Request-body ceiling for the facade nest: 64 MiB.
///
/// Sized for the largest legal blob append (32 MiB raw) once base64 and JSON
/// framing are paid for. Applied as a layer on THIS router, so the limit is a
/// property of the facade projection and no other route's body handling moves.
const FACADE_MAX_BODY_BYTES: usize = MAX_REMOTE_REQUEST_BYTES;

/// The facade route table.
///
/// Exactly one row per verb, all `POST`: the read verbs carry structured
/// request bodies (`recall` has five inputs), and `/v1/core`'s own read
/// routes — `/query`, `/context-pack`, `/hydrate` — already post their
/// requests for the same reason. One method per verb also keeps the route
/// census a flat list a contract test can compare against the catalog.
pub(crate) fn facade_routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .merge(agent_verbs::routes())
        .layer(DefaultBodyLimit::max(FACADE_MAX_BODY_BYTES))
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
                "Present a slip minted with --principal-ref <32-hex person id>.",
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
                    "Present a slip minted with --actor-class <human|agent|system>.",
                    "Reconnect with a differently scoped slip to act as another actor.",
                ],
            ));
        }
    };
    Ok((actor, actor_class))
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

/// Drops every TASKS row this credential cannot read, as MCP's board does,
/// then encodes the section. A row id that is not an entity id cannot be
/// proven readable, so only a credential without a slip, which reads every
/// entity, keeps it.
fn facade_readable_task_rows(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    mut section: oneiron::context_board::TasksSection,
) -> Result<serde_json::Value, FacadeApiError> {
    let mut rows = Vec::with_capacity(section.rows.len());
    for row in section.rows {
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
    serde_json::to_value(section).map_err(|_| {
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
#[derive(Debug)]
struct FacadeApiError {
    status: StatusCode,
    body: FacadeErrorEnvelope,
}

/// `{error: {...}}`, the same transport envelope shape `/v1/core` uses.
#[derive(Debug, Serialize)]
struct FacadeErrorEnvelope {
    error: FacadeErrorBody,
}

/// The facade error payload: `{code, message, requestId, suggestions}`.
///
/// `code` is a `String` and that is the load-bearing difference from
/// [`crate::error::ApiErrorEnvelopeBody`]. `details` is absent because the
/// engine vocabulary has no per-code detail variants to project.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FacadeErrorBody {
    code: String,
    message: String,
    request_id: String,
    suggestions: Vec<String>,
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
                },
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
            MEMORY_CODE_BAD_REQUEST => StatusCode::BAD_REQUEST,
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
                },
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

impl IntoResponse for FacadeApiError {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
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
