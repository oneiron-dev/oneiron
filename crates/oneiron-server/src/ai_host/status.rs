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
    /// The vault's extraction and consolidation defaults do not route to
    /// where the Dreamer extracts: the extraction teacher the vault's model
    /// manifest pins, else the Dreamer seat's widest rung (`oneiron dreamer
    /// grant --extraction-route`, or `PUT /v1/llm/defaults`).
    ExtractionRouteNotSet,
    /// The vault's model manifest pins an extraction teacher this server does
    /// not serve at the vault's route: add it to `[models]`, or change the pin.
    ExtractionModelNotServed,
    /// The vault's model manifest pins a model for the Dreamer's conflict
    /// verdict or narrative role that this server does not serve at the
    /// vault's route: add it to `[models]`, or change the pin.
    RoleModelNotServed,
    /// Turned off in `[models]`.
    Disabled,
    /// The worker failed to start; the server log has the cause.
    StartFailed,
    /// The worker's thread ended before shutdown asked it to (FIX 5776):
    /// it returned or panicked, and its timer work runs on the fallback
    /// sleepers. Its tallies and last error stand; the server log has the
    /// cause.
    WorkerExited,
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

/// Why a served attempt ended without its work. Stable snake_case wire
/// names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnservedReason {
    /// The host lends this server's Dreamer no resident instruction, so a
    /// resident's dreaming and its free time for its human end with no work
    /// (Engine 10-21). The owner sets `[models.dreamer] resident_prompt`, or
    /// `resident_prompt_file`, to serve them.
    NoHostInstruction,
}

/// The last attempt a worker ended unserved, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UnservedNote {
    pub reason: UnservedReason,
    /// The attempt's type constant (`dreamer.resident_dream`, say), never
    /// world text.
    pub attempt_kind: String,
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
    /// Attempts that ended without their work because the host lends them
    /// nothing to do it with: never counted completed. `last_unserved` says
    /// why and what the owner does about it.
    pub unserved: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_unserved: Option<UnservedNote>,
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
            unserved: 0,
            last_unserved: None,
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

/// Whether code mode's runs compact their own window (agent-runtime-v1 §d7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompactionState {
    On,
    Off,
}

/// Compaction's reason when the server serves no code mode.
pub(crate) const CODE_MODE_OFF: &str = "code_mode_off";

/// Code mode's compaction: on, or off and why. Settled at bind.
#[derive(Clone, Debug, Serialize)]
pub struct CompactionStatus {
    pub state: CompactionState,
    /// Why it is off: an engine `CompactionOff` name, or `code_mode_off`
    /// when the server serves no code mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    /// The seat role its passes run on, when it is on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// The window budget a run parks at, when it is on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_tokens: Option<u64>,
}

impl CompactionStatus {
    pub(crate) fn off(reason: &'static str) -> Self {
        Self {
            state: CompactionState::Off,
            reason: Some(reason),
            role: None,
            window_tokens: None,
        }
    }
}

/// The AI surfaces a server runs.
#[derive(Clone, Debug, Serialize)]
pub struct AiStatus {
    pub dreamer: WorkStatus,
    /// Dreamer passes that read in their writer after their guarded reads
    /// went stale, since the vault opened (FIX 11568).
    pub dreamer_one_writer_reads: u64,
    pub workflows: WorkStatus,
    pub chat: WorkStatus,
    pub compaction: CompactionStatus,
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
    /// Whether code mode's runs compact their window: `on` or `off`.
    #[schema(value_type = String, example = "off")]
    pub compaction: CompactionState,
    /// Why compaction is off, when it is.
    #[schema(value_type = Option<String>, example = "no_model_configured")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compaction_reason: Option<&'static str>,
}

impl AiStatus {
    pub(crate) fn health(&self) -> AiHealth {
        AiHealth {
            dreamer: self.dreamer.state,
            dreamer_reason: self.dreamer.reason,
            compaction: self.compaction.state,
            compaction_reason: self.compaction.reason,
        }
    }
}
