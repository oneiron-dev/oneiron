//! Moved from `crates/oneiron/src/code_run/run_verbs.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::code_run::types::session_hooks::SessionHookDisposition;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::code_run::run_verbs::JS_SAFE_INTEGER;
pub use oneiron_verb_wire::code_run::run_verbs::LeaderAdviceInput;
pub use oneiron_verb_wire::code_run::run_verbs::LeaderPatternInput;
pub use oneiron_verb_wire::code_run::run_verbs::LeaderSplitInput;
pub use oneiron_verb_wire::code_run::run_verbs::MemoryClaimInput;
pub use oneiron_verb_wire::code_run::run_verbs::MemoryEdgeInput;
pub use oneiron_verb_wire::code_run::run_verbs::MemorySearchInput;
pub use oneiron_verb_wire::code_run::run_verbs::MemoryTimeRange;
pub use oneiron_verb_wire::code_run::run_verbs::ReportBlockedOutput;
pub use oneiron_verb_wire::code_run::run_verbs::SkillCallInput;
pub use oneiron_verb_wire::code_run::run_verbs::SpawnCare;
pub use oneiron_verb_wire::code_run::run_verbs::SummarizeInput;
pub use oneiron_verb_wire::code_run::run_verbs::SummarizeInputEffort;
pub use oneiron_verb_wire::code_run::run_verbs::TaskRefuseDomain;
pub use oneiron_verb_wire::code_run::run_verbs::TaskRefuseOutput;
pub use oneiron_verb_wire::code_run::run_verbs::TaskWaitSetRequest;
pub use oneiron_verb_wire::code_run::run_verbs::TaskWaitWorldRequest;
use serde::Deserialize;
use serde::Serialize;

/// `vault.search`'s output: the hits, best first, and in an off-record room
/// what each verb hook bound to the search did (WILL L11-01 S01-2c).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MemorySearchOutput {
    pub results: Vec<MemorySearchHit>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hooks: Vec<SessionHookDisposition>,
}

/// One `vault.search` hit.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct MemorySearchHit {
    pub id: EntityId,
    pub score: f32,
}

/// `vault.claims.put` and `vault.claims.supersede`'s output: the claim
/// written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryWriteOutput {
    pub id: EntityId,
}

/// `vault.edges.put`'s output: the edge written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemoryEdgeOutput {
    pub src: EntityId,
    /// The edge kind's name.
    pub kind: String,
    pub tgt: EntityId,
}

/// The `kind` every `self.agents.spawn` output carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSpawnKind {
    AgentSpawn,
}

/// `self.leader.pattern`'s output: the pattern loaded, as the leader reads
/// it (OF-389).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LeaderPatternOutput {
    /// The entity that loaded: an exploration trial may route to its
    /// proposal.
    pub skill: EntityId,
    pub skill_id: String,
    pub version: String,
    pub desc: String,
    pub files: Option<Vec<LeaderPatternFile>>,
}

/// `self.leader.split`'s output: the subproject her TASK wraps (OF-389).
/// A retry answers the same child.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaderSplitOutput {
    /// The child PROJECT.
    pub project: EntityId,
    /// The TASK that wraps it.
    pub task: EntityId,
    /// The project it was spawned under.
    pub parent: EntityId,
    pub leader: EntityId,
    /// How many more levels the child may spawn.
    pub depth_remaining: u64,
}

/// One file of a loaded pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LeaderPatternFile {
    pub path: String,
    pub text: String,
}
