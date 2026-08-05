//! Inbound SurfaceEvent handoff over `/v1/core` (OF-247 CID-6).
//!
//! `POST` admits a normalized inbound event: the engine routes it, commits the
//! attempt, and this route returns `202` with a stable attempt ref before any
//! dispatcher runs. `GET` reads the durable snapshot for one correlation id.
//! Production worker wiring is the later surface-serving ticket's scope.

use super::core_engine_error;
use super::json_payload;
use super::unix_seconds_now;
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;
use crate::error::ApiErrorEnvelope;
use crate::error::EnvelopedApiError;
use crate::server::SyncServer;
use axum::extract::Path;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::Json;
use serde::Deserialize;
use serde::Serialize;
use std::sync::Arc;
use utoipa::ToSchema;

/// Provider app an inbound event came from.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SurfaceSourceAppPayload {
    Email,
    Slack,
    Discord,
    Web,
    Voice,
    #[serde(rename = "imessage")]
    IMessage,
    Line,
    Telegram,
    #[serde(rename = "linkedin")]
    LinkedIn,
}

impl SurfaceSourceAppPayload {
    const fn to_engine(self) -> oneiron::SurfaceSourceApp {
        match self {
            Self::Email => oneiron::SurfaceSourceApp::Email,
            Self::Slack => oneiron::SurfaceSourceApp::Slack,
            Self::Discord => oneiron::SurfaceSourceApp::Discord,
            Self::Web => oneiron::SurfaceSourceApp::Web,
            Self::Voice => oneiron::SurfaceSourceApp::Voice,
            Self::IMessage => oneiron::SurfaceSourceApp::IMessage,
            Self::Line => oneiron::SurfaceSourceApp::Line,
            Self::Telegram => oneiron::SurfaceSourceApp::Telegram,
            Self::LinkedIn => oneiron::SurfaceSourceApp::LinkedIn,
        }
    }
}

/// Where an inbound event came from.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "app": "slack",
    "user_ref": "slack:U024BE7LH"
}))]
pub(crate) struct SurfaceEventSourcePayload {
    /// Closed source app the event arrived through.
    app: SurfaceSourceAppPayload,
    /// Provider-native sending user reference.
    #[schema(example = "slack:U024BE7LH")]
    user_ref: String,
}

/// Non-message interaction kinds an inbound event can carry.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SurfaceInteractionKindPayload {
    Reaction,
    CardCompletion,
    Dwell,
    Tap,
}

impl SurfaceInteractionKindPayload {
    const fn to_engine(self) -> oneiron::SurfaceInteractionKind {
        match self {
            Self::Reaction => oneiron::SurfaceInteractionKind::Reaction,
            Self::CardCompletion => oneiron::SurfaceInteractionKind::CardCompletion,
            Self::Dwell => oneiron::SurfaceInteractionKind::Dwell,
            Self::Tap => oneiron::SurfaceInteractionKind::Tap,
        }
    }
}

/// What the counterparty did on the surface.
///
/// A message dispatches toward the addressed actor's `self.*` flow; every
/// interaction normalizes into observed-source enrichment and never creates a
/// turn.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[schema(example = json!({ "kind": "message" }))]
pub(crate) enum SurfaceEventActionPayload {
    Message,
    Interaction {
        /// Interaction the counterparty performed.
        interaction: SurfaceInteractionKindPayload,
        /// Optional provider-native ref of the thing interacted with.
        #[serde(default)]
        #[schema(example = "slack:1735689600.000100")]
        target_ref: Option<String>,
    },
}

impl SurfaceEventActionPayload {
    fn into_engine(self) -> oneiron::SurfaceEventAction {
        match self {
            Self::Message => oneiron::SurfaceEventAction::Message,
            Self::Interaction {
                interaction,
                target_ref,
            } => oneiron::SurfaceEventAction::Interaction {
                interaction: interaction.to_engine(),
                target_ref,
            },
        }
    }
}

/// Counterparty identity known at inbound normalization time.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
#[schema(example = json!({
    "state": "unknown",
    "counterparty_key": "slack:U024BE7LH"
}))]
pub(crate) enum SurfaceCounterpartyPayload {
    /// A known counterparty/contact record, as a 32-char hex entity id.
    Known {
        #[schema(example = "0123456789abcdef0123456789abcdef")]
        counterparty_ref: String,
    },
    /// A provider-native sender key not yet attached to a contact record.
    Unknown {
        #[schema(example = "slack:U024BE7LH")]
        counterparty_key: String,
    },
}

impl SurfaceCounterpartyPayload {
    fn into_engine(self) -> oneiron::SurfaceCounterpartyStamp {
        match self {
            Self::Known { counterparty_ref } => {
                oneiron::SurfaceCounterpartyStamp::Known { counterparty_ref }
            }
            Self::Unknown { counterparty_key } => {
                oneiron::SurfaceCounterpartyStamp::unknown(counterparty_key)
            }
        }
    }
}

/// Normalized inbound event submitted by an adapter.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "event_id": "slack:Ev024BE7LH",
    "channel": "slack",
    "receiving_address_or_handle": "T024BE7LH/agent",
    "counterparty": { "state": "unknown", "counterparty_key": "slack:U024BE7LH" },
    "source": { "app": "slack", "user_ref": "slack:U024BE7LH" },
    "action": { "kind": "message" },
    "correlation_id": "slack:Ev024BE7LH",
    "received_at": 1782357600_u64,
    "foreign_inbound": true
}))]
pub(crate) struct SurfaceEventSubmitRequest {
    /// Provider-native event id.
    #[schema(example = "slack:Ev024BE7LH")]
    event_id: String,
    /// Raw provider channel key used to resolve the receiving identity.
    #[schema(example = "slack")]
    channel: String,
    /// Address or handle the provider delivered this event to.
    #[serde(
        rename = "receiving_address_or_handle",
        alias = "receivingAddressOrHandle"
    )]
    #[schema(example = "T024BE7LH/agent")]
    receiving_address_or_handle: String,
    /// Optional provider-native workspace/team stamp.
    #[serde(default)]
    #[schema(example = "T024BE7LH")]
    workspace_ref: Option<String>,
    /// Counterparty identity known at normalization time.
    counterparty: SurfaceCounterpartyPayload,
    /// Optional closed source stamp. Defaults from `channel` and `counterparty`.
    #[serde(default)]
    source: Option<SurfaceEventSourcePayload>,
    /// Optional typed action. Defaults to a message.
    #[serde(default)]
    action: Option<SurfaceEventActionPayload>,
    /// Optional public correlation id. Defaults to `event_id`.
    #[serde(default)]
    #[schema(example = "slack:Ev024BE7LH")]
    correlation_id: Option<String>,
    /// Optional adapter-local payload reference.
    #[serde(default)]
    #[schema(example = "blob:slack/Ev024BE7LH")]
    payload_ref: Option<String>,
    /// Provider receive timestamp in Unix seconds.
    #[schema(example = 1782357600_u64)]
    received_at: u64,
    /// Foreign/provider-authored inbound is claims, not owner instructions.
    #[schema(example = true)]
    foreign_inbound: bool,
}

impl SurfaceEventSubmitRequest {
    fn into_engine(self) -> oneiron::InboundSurfaceEventInput {
        let mut input = oneiron::InboundSurfaceEventInput::new(
            self.event_id,
            self.channel,
            self.receiving_address_or_handle,
            self.counterparty.into_engine(),
            self.received_at,
            self.foreign_inbound,
        );
        if let Some(workspace_ref) = self.workspace_ref {
            input = input.with_workspace_ref(workspace_ref);
        }
        if let Some(payload_ref) = self.payload_ref {
            input = input.with_payload_ref(payload_ref);
        }
        if let Some(source) = self.source {
            input = input.with_source(oneiron::SurfaceEventSource::new(
                source.app.to_engine(),
                source.user_ref,
            ));
        }
        if let Some(action) = self.action {
            input = input.with_action(action.into_engine());
        }
        if let Some(correlation_id) = self.correlation_id {
            input = input.with_correlation_id(correlation_id);
        }
        input
    }
}

/// Durable lifecycle of an admitted surface event.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SurfaceEventHandoffStatePayload {
    Queued,
    Leased,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

impl From<oneiron::SurfaceEventHandoffState> for SurfaceEventHandoffStatePayload {
    fn from(state: oneiron::SurfaceEventHandoffState) -> Self {
        match state {
            oneiron::SurfaceEventHandoffState::Queued => Self::Queued,
            oneiron::SurfaceEventHandoffState::Leased => Self::Leased,
            oneiron::SurfaceEventHandoffState::Paused => Self::Paused,
            oneiron::SurfaceEventHandoffState::Completed => Self::Completed,
            oneiron::SurfaceEventHandoffState::Failed => Self::Failed,
            oneiron::SurfaceEventHandoffState::Cancelled => Self::Cancelled,
        }
    }
}

/// Ack returned once an inbound event is durably committed.
#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({
    "correlation_id": "slack:Ev024BE7LH",
    "attempt_ref": "0123456789abcdef0123456789abcdef",
    "state": "queued",
    "replayed": false,
    "accepted_at": 1782357600_u64,
    "status_path": "/v1/core/surface-events/slack%3AEv024BE7LH"
}))]
pub(crate) struct SurfaceEventAckResponse {
    /// Public correlation id, preserved exactly as submitted.
    #[schema(example = "slack:Ev024BE7LH")]
    correlation_id: String,
    /// Lowercase 32-hex ref of the durable attempt backing this event.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    attempt_ref: String,
    /// Durable state at ack time.
    state: SurfaceEventHandoffStatePayload,
    /// `true` when this correlation id already had an attempt.
    #[schema(example = false)]
    replayed: bool,
    /// Admission timestamp in Unix seconds.
    #[schema(example = 1782357600_u64)]
    accepted_at: u64,
    /// URL path this event's durable status is readable at.
    #[schema(example = "/v1/core/surface-events/slack%3AEv024BE7LH")]
    status_path: String,
}

impl From<oneiron::SurfaceEventAck> for SurfaceEventAckResponse {
    fn from(ack: oneiron::SurfaceEventAck) -> Self {
        Self {
            correlation_id: ack.correlation_id,
            attempt_ref: ack.attempt_ref.as_str().to_owned(),
            state: ack.state.into(),
            replayed: ack.replayed,
            accepted_at: ack.accepted_at,
            status_path: ack.status_path,
        }
    }
}

/// Durable snapshot of one admitted event's handoff.
#[derive(Debug, Serialize, ToSchema)]
#[schema(example = json!({
    "correlation_id": "slack:Ev024BE7LH",
    "attempt_ref": "0123456789abcdef0123456789abcdef",
    "state": "queued",
    "attempt_count": 0,
    "created_at": 1782357600_u64,
    "updated_at": 1782357600_u64
}))]
pub(crate) struct SurfaceEventStatusResponse {
    /// Public correlation id this snapshot is keyed by.
    #[schema(example = "slack:Ev024BE7LH")]
    correlation_id: String,
    /// Lowercase 32-hex ref of the durable attempt.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    attempt_ref: String,
    /// Current durable state.
    state: SurfaceEventHandoffStatePayload,
    /// How many times a worker has leased this attempt.
    #[schema(example = 0)]
    attempt_count: u32,
    /// Failure or retry reason recorded on the row, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "downstream refused")]
    last_error: Option<String>,
    /// Admission timestamp in Unix seconds.
    #[schema(example = 1782357600_u64)]
    created_at: u64,
    /// Last transition timestamp in Unix seconds.
    #[schema(example = 1782357600_u64)]
    updated_at: u64,
}

impl From<oneiron::SurfaceEventHandoffStatus> for SurfaceEventStatusResponse {
    fn from(status: oneiron::SurfaceEventHandoffStatus) -> Self {
        Self {
            correlation_id: status.correlation_id,
            attempt_ref: status.attempt_ref.as_str().to_owned(),
            state: status.state.into(),
            attempt_count: status.attempt_count,
            last_error: status.last_error,
            created_at: status.created_at,
            updated_at: status.updated_at,
        }
    }
}

/// Admit a normalized inbound surface event.
///
/// `security` is declared inline rather than through `api/openapi.rs`'s
/// protected-route list: that list is a contested cross-lane file this ticket
/// does not claim, and utoipa emits the identical `security` block from here.
/// A later legitimate writer of that file may fold these two rows into it.
#[utoipa::path(
    post,
    path = "/v1/core/surface-events",
    security(("CoreBearer" = [])),
    request_body(content = SurfaceEventSubmitRequest, content_type = "application/json"),
    responses(
        (status = 202, description = "Event committed to the durable queue and acked before any dispatch. A correlation replay returns the original attempt ref with `replayed: true`.", body = SurfaceEventAckResponse, content_type = "application/json"),
        (status = 400, description = "Malformed submission, or identity routing rejected the event without queueing.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:write.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Admission failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn submit_core_surface_event(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<SurfaceEventSubmitRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<SurfaceEventAckResponse>), EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let req = json_payload(payload)?;

    let admission = server
        .vault
        .enqueue_inbound_surface_event(req.into_engine(), unix_seconds_now())
        .map_err(|error| {
            tracing::error!(error = %error, "surface event admission failed");
            core_engine_error("surface event admission failed", error)
        })?;

    match admission {
        oneiron::SurfaceEventAdmission::Accepted(ack) => {
            Ok((StatusCode::ACCEPTED, Json(ack.into())))
        }
        oneiron::SurfaceEventAdmission::Rejected(receipt) => Err(rejection_error(&receipt).into()),
    }
}

/// Read the durable handoff status for one correlation id.
#[utoipa::path(
    get,
    path = "/v1/core/surface-events/{correlation_id}",
    security(("CoreBearer" = [])),
    params(
        (
            "correlation_id" = String,
            Path,
            description = "Public correlation id an event was admitted under.",
            example = "slack:Ev024BE7LH"
        )
    ),
    responses(
        (status = 200, description = "Durable handoff snapshot for this correlation id.", body = SurfaceEventStatusResponse, content_type = "application/json"),
        (status = 400, description = "Blank correlation id.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "No surface event was admitted under this correlation id.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Handoff status read failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn get_core_surface_event(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(correlation_id): Path<String>,
) -> Result<Json<SurfaceEventStatusResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;

    let status = server
        .vault
        .surface_event_handoff_status(&correlation_id)
        .map_err(|error| {
            tracing::error!(error = %error, "surface event status read failed");
            core_engine_error("surface event status read failed", error)
        })?
        .ok_or_else(|| ApiError::not_found("surface_event", Some(&correlation_id)))?;

    Ok(Json(status.into()))
}

/// Maps a typed route rejection onto the shared error envelope.
///
/// Identity routing rejections are the adapter's problem to fix — a wrong
/// address, an unbound identity, an identity that is not accepting inbound —
/// so they stay `BAD_REQUEST` and carry the engine's stable reason string
/// rather than a new error code family.
fn rejection_error(receipt: &oneiron::InboundSurfaceRouteReceipt) -> ApiError {
    let reason = receipt
        .rejection_reason_str()
        .unwrap_or("unknown_receiving_identity");
    ApiError::bad_request(
        format!("inbound surface event was not routed: {reason}"),
        Some("receiving_address_or_handle"),
    )
}
