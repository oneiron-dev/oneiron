//! Moved from `crates/oneiron/src/feedback/triage.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::feedback::triage::github::GithubSweepContinuation;
pub use crate::feedback::triage::owner::FeedbackTriageBindingRequest;
pub use crate::feedback::triage::owner::FeedbackTriageErased;
pub use crate::feedback::triage::owner::FeedbackTriageProgress;
pub use crate::feedback::triage::owner::FeedbackTriageRun;
pub use crate::feedback::triage::owner::FeedbackTriageRunRequest;
pub use crate::feedback::triage::owner::FeedbackTriageStatusRequest;
pub use crate::feedback::triage::source::FeedbackTriageSourceError;
pub use crate::feedback::triage::source::FeedbackTriageSourceErrorKind;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The open inbox, as a triage source names it.
pub const FEEDBACK_TRIAGE_INBOX_SOURCE: &str = "inbox";

/// The skill the triage runs, as the owner bound it. Unset until the owner
/// binds one: no skill is bound for him.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageBinding {
    /// The SKILL entity the triage loads; `None` while none is bound.
    pub skill: Option<EntityId>,
    /// Queue the ordinary sweep when a new inbox note lands. Off keeps
    /// the existing manual and nightly batching.
    pub enqueue_on_intake: bool,
    /// 0 while never set, then one more for each change. A change names
    /// the revision it read.
    pub revision: u64,
    /// Vault seconds of the last change; `None` while never set.
    pub set_at: Option<u64>,
}

/// Keep intake batched unless the owner enables an ordinary sweep per intake.
pub const DEFAULT_ENQUEUE_ON_INTAKE: bool = false;

impl Default for FeedbackTriageBinding {
    fn default() -> Self {
        Self {
            skill: None,
            enqueue_on_intake: DEFAULT_ENQUEUE_ON_INTAKE,
            revision: 0,
            set_at: None,
        }
    }
}

/// One source's state: where the next sweep resumes it, the walk that last
/// reached its end, and what stopped it last.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageContinuation {
    /// The source.
    pub source: String,
    /// The inbox's last arrival number a sweep handed off or found handed
    /// off; the next sweep reads the notes after it. `None` for a GitHub
    /// source.
    pub after: Option<u64>,
    /// 32 hex: the sweep that last moved it, or that wrote it first.
    pub sweep: EntityId,
    /// Vault seconds it last moved, or was first written.
    pub moved_at: u64,
    /// A GitHub source's walk: its generation, next page and last ETag.
    /// `None` for the inbox, and before a GitHub source's first page.
    pub github: Option<GithubSweepContinuation>,
    /// Vault seconds a walk last reached the source's end; `None` while
    /// none has.
    pub completed_at: Option<u64>,
    /// 32 hex: the sweep whose walk last reached it.
    pub completed_by: Option<EntityId>,
    /// What stopped the source's last walk; cleared once a walk moves it or
    /// reaches its end.
    pub error: Option<FeedbackTriageSourceError>,
    /// Vault seconds the source named for a retry: the sweep leaves it
    /// until then.
    pub retry_after: Option<u64>,
    /// The items of the last page written that did not parse and were
    /// skipped, each by its number, id or place on the page; the walk went
    /// on past them (FIX 7631).
    pub skipped: Vec<String>,
}

/// One revision's committed triage result. An empty `findings` is a result:
/// the triage read the item and found nothing to propose.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedbackTriageResult {
    /// The triage job that committed it.
    pub attempt: EntityId,
    /// The Proposed findings it filed in the owner's run tray.
    pub findings: Vec<EntityId>,
    /// The SKILL entity that loaded, which may be an open proposal an
    /// exploration trial routed the job to.
    pub skill: EntityId,
    /// The version of the skill that loaded.
    pub skill_version: String,
    /// The model of the rung that answered, fallback included.
    pub served_model: String,
    /// Vault seconds it was committed.
    pub recorded_at: u64,
}
pub mod github;
pub mod owner;
pub mod source;
