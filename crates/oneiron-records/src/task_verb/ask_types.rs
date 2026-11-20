//! Moved from `crates/oneiron/src/task_verb/ask_types.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::authority::task_ask_handle::TaskAskHandle;
pub use oneiron_verb_wire::disclosure::task_ask_default::TaskAskDefault;
pub use oneiron_verb_wire::task_verb::ask_types::AskAuthorityScope;
pub use oneiron_verb_wire::task_verb::ask_types::TaskAskBranch;
pub use oneiron_verb_wire::task_verb::ask_types::TaskAskDisagree;
pub use oneiron_verb_wire::task_verb::ask_types::TaskAskElectorate;
pub use oneiron_verb_wire::task_verb::ask_types::TaskAskGuest;
pub use oneiron_verb_wire::task_verb::ask_types::TaskAskNeed;
pub use oneiron_verb_wire::task_verb::ask_types::TaskAskOption;
pub use oneiron_verb_wire::task_verb::ask_types::TaskAskProvisional;
pub use oneiron_verb_wire::task_verb::ask_types::TaskAskSurface;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// Live ask routing. `None` means no native channel, not a promise of delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskAskPreflightRecipient {
    pub who: EntityId,
    pub face: Option<String>,
    pub channel: Option<String>,
    pub word_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskAskPreflight {
    pub recipients: Vec<TaskAskPreflightRecipient>,
}

/// A typed explanation emitted at admission, without waiting for TTL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskAskHoldReason {
    /// Mailbox TASKs are queued, but no native delivery route is known now.
    NoLiveRoute,
    /// The vault's approval mode holds the ask for the owner's launch
    /// approval (OF-393): no member TASK or guest grant exists until the
    /// owner approves; a denial keeps it held and visible.
    ApprovalRequired,
}

/// The launch approval an ask waits on: the ref the owner's resume door
/// takes, the frozen plan digest a ruling names, and the durable hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskAskLaunchHold {
    pub launch_ref: EntityId,
    pub plan_digest: String,
    pub surface_ref: String,
    pub denied: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskAskSource {
    Human,
    /// Bearer-bound external word attributed to the intended person, not an instruction.
    ForeignStated,
    Companion,
    Inform,
    Executor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskAskEvidenceReason {
    Counted,
    CompanionHint,
    Inform,
    HumanDominates,
    Executor,
    Superseded,
    OutsideElectorate,
    MissingSource,
    Late,
}

/// One person's attributed answer at this read. `Unknown` carries no answer;
/// the agent's cutoff branch is never serialized as a person's default word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskAskPersonKind {
    Word,
    Companion,
    Default,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAskCoverage {
    pub met: bool,
    pub required: u16,
    pub responded: BTreeSet<EntityId>,
    pub unknown: BTreeSet<EntityId>,
    pub unmet_people: BTreeSet<EntityId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskAskFallback {
    /// The default or disagreement branch is the asking agent's act.
    pub branch: TaskAskDefault,
    pub surface: TaskAskSurface,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskAskSettlementReason {
    FirstWord,
    AllResponded,
    Deadline,
    Stale,
}

/// Ask settlement cannot grant or deny an external effect. Only the separate
/// effect gate evaluates that authority against its own live inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskAskEffectAuthorization {
    NotEvaluatedByAsk,
}
