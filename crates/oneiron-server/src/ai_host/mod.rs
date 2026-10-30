//! The server's background AI work, built from `[models]`: the Dreamer, the
//! saved-workflow pump, and the seats chat turns run on.
//!
//! Nothing here is required. Without a model every model-free path works,
//! and each piece reports why it is idle (`no_model_configured`, say) on
//! `/api/health` and `GET /v1/ai/status`. Writes never wait on a model.
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use oneiron::attempt_queue::{AttemptQueue, AttemptState, CleanupAttemptLeases};
use oneiron::dreamer_consolidation::DREAMER_EXTRACTION_ROLE;
use oneiron::dreamer_wake::{AgentWakeSignals, WakeIdleState, WakeTurnSubject};
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::run_admission::RunReceiptSink;
use oneiron::{DreamerRunnerStore, EdgeActorClass, EntityId, ModelId, ModelLocality, Vault};
use oneiron_driver::{HintPusher, IdleSample, SessionHint};

use crate::config::models::{ChatSettings, ModelsConfig, VoiceSettings};
use crate::decision_host::DecisionHost;
use crate::models::{
    BrokerContext, LoggedReceipts, ModelRuntime, ModelsStatus, OfferCooldowns, RawInference,
    RoleCall, RoleRefusal, Seat,
};
use crate::server::SyncServer;

#[cfg(feature = "code-sandbox-wasmtime")]
mod code_mode;
mod compaction;
#[cfg(all(test, feature = "code-sandbox-wasmtime"))]
pub(crate) use compaction::tests::cross_the_passes;
pub(crate) use compaction::{ChatBreakpointCall, ChatSelfMode};
pub mod browser_planner;
pub(crate) mod browser_program_admission;
mod coach_browser_programs;
pub(crate) mod coach_heal;
mod coach_health;
pub(crate) mod coach_host;
mod coach_site_skills;
mod code_fix;
mod confession_wording;
mod connector_event;
pub(crate) use connector_event::run_connector_reply_job;
mod contribution;
mod dreamer;
pub(crate) use dreamer::DreamerControl;
mod dreamer_thing;
mod eval_authoring;
mod eval_measurement;
pub(crate) mod failure_signals;
mod feedback_report_delivery;
mod feedback_triage;
mod harness;
pub(crate) mod home_digests;
pub(crate) mod identity;
mod judge_swap;
mod lens_callbacks;
pub(crate) mod live_lease;
mod local_vision;
pub(crate) mod payer_funding;
mod policy;
mod question_timer;
pub(crate) mod resident_craft;
pub mod scoped_child;
pub(crate) mod self_heal_detectors;
pub mod shadow_runner;
mod skill_author;
mod skill_discovery;
mod status;
mod step;
mod step_failure;
mod stewardship;
mod sync_wake;
#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;
pub(crate) mod trained_serving;
mod training_offer;
pub(crate) mod training_pack;
mod turn_actions;
mod turn_program;
mod turn_program_host;
mod turns;
pub(crate) mod waves;
mod weave_lens;
mod workflows;

mod handle;
mod lifecycle;
mod workers;

pub(crate) use lens_callbacks::{LensCallback, queue_lens_callback};
pub(crate) use local_vision::LocalVisionModel;
pub(crate) use policy::route_dreamer_extraction;
pub use status::{
    AiHealth, AiStatus, CompactionState, CompactionStatus, IdleReason, UnservedNote,
    UnservedReason, WorkState, WorkStatus,
};
pub(crate) use weave_lens::{
    WeaveLensCaller, render_live_weave_lens, render_live_weave_lens_for_run,
    render_live_weave_lens_listing,
};

use dreamer::{DreamerHost, DreamerStart};
use policy::{DreamerRoute, dreamer_role_purpose};
use status::StatusCell;
use step::StepRunner;
pub(crate) use turns::TurnGuard;
use turns::TurnTracker;
use workers::{served_without_dreamer, start_dreamer, start_workflows};
use workflows::WorkflowPump;

/// The seat each piece of AI work runs on.
const DREAMER_ROLE: ModelRole = ModelRole::DreamerCurrent;
pub(crate) const CHAT_ROLE: ModelRole = ModelRole::GenerativeReasoner;
/// How long shutdown lets running chat turns finish before stopping them.
const TURN_GRACE: std::time::Duration = std::time::Duration::from_secs(10);
/// How the host words the house mind's project question (OF-501).
const PROJECT_DETECTION_WORDING: &str = "Does this message start or describe a piece of work \
with its own goal that will take more than one sitting, worth tracking as a project? \
Answer no for a passing question, a chat or a single task.";
/// What one project question may spend on the host's ladder.
const PROJECT_DETECTION_BUDGET: std::time::Duration = std::time::Duration::from_secs(20);

/// What request handlers need: seats, status and the session-hint producer.
/// Cheap to clone; inert when nothing is configured.
#[derive(Clone)]
pub struct AiHandle {
    runtime: Arc<ModelRuntime>,
    status: Arc<StatusCell>,
    hints: Option<Arc<HintPusher>>,
    chat: ChatSettings,
    /// The vault's `[models] prompt_layout`, if it sets one (FIX 6676).
    prompt_layout: Option<oneiron::prompt::PromptLayout>,
    voice: Option<VoiceSettings>,
    /// The raw routes' meter: `[models]`'s, else its default, so a device
    /// with no `[models]` serves the models the mesh discovered (FIX 3229).
    raw_budget_units: u64,
    /// Each paid recall's line for its rerank calls (`[models.recall]`).
    rerank_budget_units: u64,
    turns: TurnTracker,
    /// When the last turn landed, in seconds: the inbound silence the
    /// Dreamer's wake policy waits out before an idle recipe.
    inbound: Arc<AtomicU64>,
    /// The running Dreamer has a summary instruction to write bodies with.
    summaries: bool,
    /// The server's decision host, set once the server staffs it: the
    /// Dreamer's passes ask their typed questions through it, and the
    /// workflow pump rules on a wave cut's fan-out through it.
    decisions: Arc<OnceLock<DecisionHost>>,
    /// The same cheap compactor code mode serves, exposed to typed host
    /// triggers once that route is bound. No route means MODEL_UNAVAILABLE.
    host_compaction: Arc<
        OnceLock<(
            Arc<dyn oneiron::compaction::CompactionBackend>,
            oneiron::compaction::CompactionGatePolicy,
        )>,
    >,
    /// The host syncs as a device of another home (`[device_sync]`): it
    /// defers to the elected home and never claims it.
    device: bool,
    /// The compaction writer factory chat and code mode share, settled when
    /// the host attaches (FIX 4465 D).
    writer_compaction: Arc<OnceLock<compaction::CodeModeCompaction>>,
    /// The wording runs are asked for their confession in (FIX 8696).
    confession: Arc<str>,
    /// The control the Dreamer's passes are admitted and paused through,
    /// when this host attached under one (managed serve's reap freeze, FIX
    /// 6909): the owner's pause and resume doors set and clear their own
    /// cause on it. `None` elsewhere.
    dreamer_control: Option<DreamerControl>,
}

/// The running workers, owned by the serve path until shutdown.
pub struct AiHost {
    handle: AiHandle,
    dreamer: Option<DreamerHost>,
    workflows: Option<WorkflowPump>,
    sieve: Option<SieveDrain>,
    /// A peer's sync apply wakes the running Dreamer.
    sync_wake: Option<sync_wake::SyncWake>,
    /// The server the Dreamer's timer runs the standing questions on.
    question_timer: dreamer::QuestionTimer,
    /// The server a workflow step's `self.use` sends through, bound once it
    /// exists, Dreamer or none (FIX 7016).
    step_host: step::StepHost,
    /// The control each Dreamer pass is admitted and paused through.
    pass_admission: dreamer::PassAdmission,
    /// The watch that hands the bound Dreamer's timer work to its own
    /// sleepers should the Dreamer end before shutdown (FIX 1149).
    dreamer_fallback: OnceLock<question_timer::DreamerFallback>,
    /// The bound host's recheck of the turn programs held for want of it
    /// (FIX 6059), stopped with the host.
    program_monitor: OnceLock<turn_program_host::HostProgramMonitor>,
    /// The turn-action worker, started once: with a host started on its
    /// own, or at [`Self::bind_turn_actions`] for one attached to a server
    /// (FIX 6920), whose queue, boot backlog included, waits for it.
    turn_actions: OnceLock<()>,
}

/// How a host attached to a server starts: on a device of another home when
/// `device`, its Dreamer under `control` when set (FIX 6909).
struct Attached {
    device: bool,
    control: dreamer::PassAdmission,
}

/// The sieve's backlog drain and the stop it checks between passes.
struct SieveDrain {
    stop: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
