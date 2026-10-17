//! POST /v1/core/context-board/scratchpad: the caller's one session pad
//! (OF-548). A line appends to the session's live `scratchpad` NOTE, opening
//! it (and sealing the actor's prior pad) on the session's first line; a seal
//! ends the run. The board serves the live pad as its SCRATCHPAD rows.
//! POST /v1/core/context-board/scratchpad/recall searches the whole pad and
//! answers its matching lines in full, the ones the board folds included.
//! A write answers the SDK's [`ScratchpadWriteReply`] through the same SDK
//! calls the `self.focus.scratchpad.append` and `.seal` rows make.

use super::validate_session_id;
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;
use crate::error::ApiErrorDetails;
use crate::error::ApiErrorEnvelope;
use crate::error::EnvelopedApiError;
use crate::server::SyncServer;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use oneiron::context_board::SCRATCHPAD_LINE_MAX_BYTES;
use oneiron::task_verb::sdk::{
    ScratchpadAppendRequest, ScratchpadRecallMark, ScratchpadSealRequest, ScratchpadWriteReply,
};
use serde::Deserialize;
use serde::Serialize;
use std::sync::Arc;
use utoipa::ToSchema;

/// An optional line mark: after the seal `keep` lines extract and `scratch`
/// lines never do.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ContextBoardScratchpadMark {
    Keep,
    Scratch,
}

impl ContextBoardScratchpadMark {
    fn sdk(self) -> ScratchpadRecallMark {
        match self {
            Self::Keep => ScratchpadRecallMark::Keep,
            Self::Scratch => ScratchpadRecallMark::Scratch,
        }
    }

    fn served(mark: oneiron::context_board::ScratchpadMark) -> Self {
        match mark {
            oneiron::context_board::ScratchpadMark::Keep => Self::Keep,
            oneiron::context_board::ScratchpadMark::Scratch => Self::Scratch,
        }
    }
}

/// One scratchpad write: a line, or the seal that ends the session's run.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
#[schema(example = json!({
    "session_id": "session-123",
    "text": "the hallway door sticks after rain",
    "mark": "keep"
}))]
pub(crate) struct ContextBoardScratchpadRequest {
    /// The run's session id; one live pad per session.
    session_id: String,
    /// The line to append. Required unless `seal` is set.
    #[serde(default)]
    text: Option<String>,
    /// Optional line mark.
    #[serde(default)]
    mark: Option<ContextBoardScratchpadMark>,
    /// Keep the line in full on the board however old it gets.
    #[serde(default)]
    pin: bool,
    /// Seal the session's pad instead of writing a line.
    #[serde(default)]
    seal: bool,
}

/// What the write did to the session's pad: the OpenAPI mirror of
/// [`ScratchpadWriteReply`], which the route answers.
#[derive(ToSchema)]
#[allow(dead_code, reason = "OpenAPI mirror of the SDK reply")]
pub(crate) struct ContextBoardScratchpadResponse {
    /// Hex id of the pad NOTE written or sealed; absent when a seal found no pad.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    pad: Option<String>,
    /// Whether the pad is now sealed.
    sealed: bool,
    /// Hex id of the actor's prior pad, sealed because this line opened a new one.
    #[serde(skip_serializing_if = "Option::is_none")]
    sealed_prior: Option<String>,
}

/// Append one line to the caller's session pad, or seal it.
#[utoipa::path(
    post,
    path = "/v1/core/context-board/scratchpad",
    request_body(content = ContextBoardScratchpadRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Line appended or pad sealed.", body = ContextBoardScratchpadResponse, content_type = "application/json"),
        (status = 400, description = "Malformed scratchpad request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:write, or names no entity principal and actor class.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 409, description = "The session's pad is sealed.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 413, description = "The line exceeds the scratchpad line limit.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Scratchpad write failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn context_board_scratchpad(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ContextBoardScratchpadRequest>, JsonRejection>,
) -> Result<Json<ScratchpadWriteReply>, EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    auth.require_unrestricted_record_scope()?;
    let req = super::super::json_payload(payload)?;
    validate_session_id(&req.session_id, "session_id")?;
    let memory = scratchpad_memory(&server, &auth)?;
    if req.seal {
        if req.text.is_some() || req.mark.is_some() || req.pin {
            return Err(ApiError::bad_request("a seal carries no line", Some("seal")).into());
        }
        let reply = oneiron::task_verb::sdk::scratchpad_seal_reply(
            &memory,
            &ScratchpadSealRequest {
                session_id: req.session_id,
            },
        )
        .map_err(scratchpad_error)?;
        return Ok(Json(reply));
    }
    let text = req
        .text
        .ok_or_else(|| ApiError::bad_request("text is required", Some("text")))?;
    if text.len() > SCRATCHPAD_LINE_MAX_BYTES {
        return Err(
            ApiError::payload_too_large("text", SCRATCHPAD_LINE_MAX_BYTES, text.len()).into(),
        );
    }
    let reply = oneiron::task_verb::sdk::scratchpad_append_reply(
        &memory,
        &ScratchpadAppendRequest {
            session_id: req.session_id,
            text,
            mark: req.mark.map(ContextBoardScratchpadMark::sdk),
            pin: req.pin,
        },
    )
    .map_err(scratchpad_error)?;
    Ok(Json(reply))
}

/// One recall over the caller's session pad.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
#[schema(example = json!({
    "session_id": "session-123",
    "query": "hallway door"
}))]
pub(crate) struct ContextBoardScratchpadRecallRequest {
    /// The run's session id whose pad is searched, live or sealed.
    session_id: String,
    /// The words every answered line holds, case-folded.
    query: String,
}

/// One pad line a recall matched, in full.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardScratchpadRecallLine {
    /// The line's place in the pad, from 0 for the oldest.
    index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    mark: Option<ContextBoardScratchpadMark>,
    pin: bool,
    text: String,
}

/// What the recall found in the session's pad.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ContextBoardScratchpadRecallResponse {
    /// Hex id of the pad searched; absent when the session has no pad.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    pad: Option<String>,
    /// Whether the pad is sealed.
    sealed: bool,
    /// How many lines matched; `lines` holds the newest 16 of them.
    matched: usize,
    /// The newest matching lines in full, newest first.
    lines: Vec<ContextBoardScratchpadRecallLine>,
}

/// Search the caller's whole session pad for the lines holding every query
/// word, folded lines included.
#[utoipa::path(
    post,
    path = "/v1/core/context-board/scratchpad/recall",
    request_body(content = ContextBoardScratchpadRecallRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "The pad's matching lines, newest first.", body = ContextBoardScratchpadRecallResponse, content_type = "application/json"),
        (status = 400, description = "Malformed recall request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read, or names no entity principal and actor class.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 413, description = "The query exceeds the scratchpad line limit.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Scratchpad recall failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn context_board_scratchpad_recall(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ContextBoardScratchpadRecallRequest>, JsonRejection>,
) -> Result<Json<ContextBoardScratchpadRecallResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    auth.require_unrestricted_record_scope()?;
    let req = super::super::json_payload(payload)?;
    validate_session_id(&req.session_id, "session_id")?;
    if req.query.len() > SCRATCHPAD_LINE_MAX_BYTES {
        return Err(ApiError::payload_too_large(
            "query",
            SCRATCHPAD_LINE_MAX_BYTES,
            req.query.len(),
        )
        .into());
    }
    let Some(recall) = scratchpad_memory(&server, &auth)?
        .scratchpad_recall(&req.session_id, &req.query)
        .map_err(scratchpad_error)?
    else {
        return Ok(Json(ContextBoardScratchpadRecallResponse {
            pad: None,
            sealed: false,
            matched: 0,
            lines: Vec::new(),
        }));
    };
    Ok(Json(ContextBoardScratchpadRecallResponse {
        pad: Some(recall.pad.to_hex()),
        sealed: recall.sealed,
        matched: recall.matched,
        lines: recall
            .lines
            .into_iter()
            .map(|line| ContextBoardScratchpadRecallLine {
                index: line.index,
                mark: line.mark.map(ContextBoardScratchpadMark::served),
                pin: line.pin,
                text: line.text,
            })
            .collect(),
    }))
}

/// An agent run's live pad as its board serves it: the SCRATCHPAD section
/// for the frame, its full-view rows, and the pad NOTE for the served rows.
pub(super) struct ServedScratchpad {
    pub(super) pad: oneiron::EntityId,
    pub(super) rows: Vec<String>,
    pub(super) section: oneiron::context_board::BoardSection,
}

/// The session's live pad, read as the agent itself. Any other caller, or a
/// run without a session, gets none.
pub(super) fn served_scratchpad(
    server: &SyncServer,
    auth: &CoreAuth,
    session: Option<&str>,
) -> Result<Option<ServedScratchpad>, ApiError> {
    let Some(session) =
        session.filter(|_| auth.actor_class() == Some("agent") && auth.principal_ref().is_some())
    else {
        return Ok(None);
    };
    validate_session_id(session, "session.session_id")?;
    let Some(board) = scratchpad_memory(server, auth)?
        .scratchpad_board_section(session)
        .map_err(scratchpad_error)?
    else {
        return Ok(None);
    };
    let rows = board
        .section
        .pinned_rows()
        .iter()
        .chain(board.section.detail_rows())
        .cloned()
        .collect();
    Ok(Some(ServedScratchpad {
        pad: board.pad,
        rows,
        section: board.section,
    }))
}

/// An agent's reader list as its board serves it: the READERS section for
/// the frame and its full-view rows (ARCH-0032 #private-reads: the agent
/// sees who may read its diary and sealed pads). Any other caller gets none.
/// A list that does not read is logged and left off, so it never costs the
/// agent its board.
pub(super) fn served_readers(
    server: &SyncServer,
    auth: &CoreAuth,
    people: &oneiron::context_board::PeopleView<'_>,
) -> Option<(oneiron::context_board::BoardSection, Vec<String>)> {
    if auth.actor_class() != Some("agent") || auth.principal_ref().is_none() {
        return None;
    }
    let section = match scratchpad_memory(server, auth)
        .map(|memory| memory.board_readers_section(people))
    {
        Ok(Ok(section)) => section,
        Ok(Err(error)) => {
            tracing::warn!(code = %error.code, error = %error.message, "board readers section left off");
            return None;
        }
        Err(_) => return None,
    };
    let rows = section
        .pinned_rows()
        .iter()
        .chain(section.detail_rows())
        .cloned()
        .collect();
    Some((section, rows))
}

/// The pad belongs to the authenticated entity principal under its declared
/// class; the engine re-checks both on every write.
fn scratchpad_memory<'a>(
    server: &'a SyncServer,
    auth: &CoreAuth,
) -> Result<oneiron::memory::Memory<'a>, ApiError> {
    let refused = |message: &str| {
        ApiError::new(
            message,
            ApiErrorDetails::Forbidden {
                required_scope: None,
            },
            ["Present a slip minted with --principal-ref and --actor-class."],
        )
    };
    let actor = auth
        .principal_ref()
        .and_then(|reference| oneiron::EntityId::from_hex(reference).ok())
        .ok_or_else(|| refused("the scratchpad needs an entity principal"))?;
    let class = match auth.actor_class() {
        Some("human") => oneiron::EdgeActorClass::Human,
        Some("agent") => oneiron::EdgeActorClass::Agent,
        Some("system") => oneiron::EdgeActorClass::System,
        _ => return Err(refused("the scratchpad needs a declared actor class")),
    };
    Ok(
        super::super::credential_memory(&server.vault, Some(auth), actor, class)
            .at(auth.locality()),
    )
}

/// The engine's refusal on the board's error contract: its code picks the
/// status, its message and suggestions pass through.
fn scratchpad_error(error: oneiron::MemoryError) -> ApiError {
    let details = match error.code.as_str() {
        oneiron::MEMORY_CODE_BAD_REQUEST => ApiErrorDetails::BadRequest { field: None },
        oneiron::MEMORY_CODE_NOT_FOUND => return ApiError::not_found("scratchpad", None),
        oneiron::MEMORY_CODE_FORBIDDEN | oneiron::memory::MEMORY_CODE_OWNER_BINDING_REQUIRED => {
            ApiErrorDetails::Forbidden {
                required_scope: None,
            }
        }
        oneiron::MEMORY_CODE_INVALID_STATE => ApiErrorDetails::InvalidState {
            state: Some("scratchpad".to_owned()),
        },
        _ => {
            tracing::error!(code = %error.code, error = %error.message, "scratchpad failed");
            return ApiError::internal_server_error("scratchpad failed");
        }
    };
    ApiError::new(error.message, details, error.suggestions)
}
