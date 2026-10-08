//! Live state of the server's background AI work, shared between the
//! workers that change it and the routes that report it.
use std::sync::Mutex;

use serde::Serialize;

/// Why a piece of AI work is not running. Stable snake_case wire names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdleReason {
    /// No `[models]` rung fills the seat this work needs.
    NoModelConfigured,
    /// The vault has no host root, so the Dreamer has no machine identity to
    /// write with (set an auth secret).
    NoHostAuthority,
    /// The Dreamer's model is off the device and `models.extraction_egress`
    /// is not set.
    ExtractionEgressNotAllowed,
    /// The vault's policy does not let its Dreamer read and land
    /// consolidation: a vault created before the rows shipped, or one whose
    /// owner removed them (`oneiron dreamer grant`, once, with the server
    /// stopped).
    NeedsOwnerGrant,
    /// The vault's extraction and consolidation defaults do not route to the
    /// Dreamer seat's widest rung (`oneiron dreamer grant --extraction-route`,
    /// or `PUT /v1/llm/defaults`).
    ExtractionRouteNotSet,
    /// Turned off in `[models]`.
    Disabled,
    /// The worker failed to start; the server log has the cause.
    StartFailed,
    /// The server is shutting down.
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkState {
    /// Running and waiting for its next trigger.
    Waiting,
    /// Inside a pass or a step right now.
    Working,
    /// Not running; see the reason.
    Idle,
}

/// One worker's state and tallies.
#[derive(Clone, Debug, Serialize)]
pub struct WorkStatus {
    pub state: WorkState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<IdleReason>,
    /// Passes (Dreamer) or steps (workflows) started since boot.
    pub started: u64,
    pub completed: u64,
    pub failed: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl WorkStatus {
    pub(crate) fn idle(reason: IdleReason) -> Self {
        Self {
            state: WorkState::Idle,
            reason: Some(reason),
            started: 0,
            completed: 0,
            failed: 0,
            last_error: None,
        }
    }

    pub(crate) fn waiting() -> Self {
        Self {
            reason: None,
            state: WorkState::Waiting,
            ..Self::idle(IdleReason::Stopped)
        }
    }
}

/// The three AI surfaces a server runs.
#[derive(Clone, Debug, Serialize)]
pub struct AiStatus {
    pub dreamer: WorkStatus,
    pub workflows: WorkStatus,
    pub chat: WorkStatus,
}

/// Interior-mutable status cell owned by one server.
pub(crate) struct StatusCell(Mutex<AiStatus>);

impl StatusCell {
    pub(crate) fn new(status: AiStatus) -> Self {
        Self(Mutex::new(status))
    }

    pub(crate) fn snapshot(&self) -> AiStatus {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn update(&self, change: impl FnOnce(&mut AiStatus)) {
        change(
            &mut self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
    }
}

/// The unauthenticated summary on `/api/health`: states and reasons only,
/// never model names or tallies.
#[derive(Clone, Debug, Serialize, utoipa::ToSchema)]
pub struct AiHealth {
    /// Dreamer state: `waiting`, `working` or `idle`.
    #[schema(value_type = String, example = "idle")]
    pub dreamer: WorkState,
    /// Why the Dreamer is idle, when it is.
    #[schema(value_type = Option<String>, example = "no_model_configured")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dreamer_reason: Option<IdleReason>,
}

impl AiStatus {
    pub(crate) fn health(&self) -> AiHealth {
        AiHealth {
            dreamer: self.dreamer.state,
            dreamer_reason: self.dreamer.reason,
        }
    }
}
