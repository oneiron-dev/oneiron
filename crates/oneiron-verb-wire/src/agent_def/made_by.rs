//! Moved from `crates/oneiron/src/agent_def/made_by.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_state::AttemptState;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::VecDeque;

/// Everything one agent made, transitively, and what each is doing now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentMadeBy {
    /// The agent the lists answer for.
    pub agent_def_ref: EntityId,
    /// How many entries the five lists hold together.
    pub count: usize,
    /// The definitions it saved, and those they saved, each with what it is
    /// doing now.
    pub agents: Vec<MadeAgent>,
    /// The live branches its runs spawned or its TASKs realize, the
    /// subtrees under them included.
    pub branches: Vec<MadeBranch>,
    /// Its TASKs that still wait for their due tick.
    pub watchers: Vec<MadeWatcher>,
    /// The hook bindings whose outcomes run as it.
    pub hooks: Vec<MadeHook>,
    /// Its scheduled sends that have not gone out.
    pub sends: Vec<MadeSend>,
    /// The offer to pause what waits among them; absent when nothing does.
    pub pause_offer: Option<AgentTreePauseOffer>,
}

/// "Also pause these" (ARCH-0053 #author-off-no-cascade): one owner act with
/// one receipt and an undo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentTreePauseOffer {
    /// The verb that pauses them: `vault.agents.pause_tree`.
    pub verb: String,
    /// How many entries it would pause now: the saved agents that stand,
    /// the queued and scheduled branches, runs and sends, the running runs
    /// (each pauses at its next step boundary), the watchers not held and
    /// the hooks switched on. A landing branch, a send going out and a
    /// branch of no run are not paused.
    pub pausable: usize,
}

impl AgentMadeBy {
    /// The rows this answer names: the agent, each saved definition, each
    /// watcher's TASK and each hook binding, once each, in id order.
    #[must_use]
    pub fn listed_rows(&self) -> Vec<EntityId> {
        let mut rows: Vec<EntityId> = std::iter::once(self.agent_def_ref)
            .chain(self.agents.iter().map(|agent| agent.agent_def_ref))
            .chain(self.watchers.iter().map(|watcher| watcher.task_ref))
            .chain(self.hooks.iter().map(|hook| hook.binding_ref))
            .chain(self.sends.iter().map(|send| send.task_ref))
            .collect();
        rows.sort_unstable();
        rows.dedup();
        rows
    }
}

/// A definition an agent saved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MadeAgent {
    pub agent_def_ref: EntityId,
    /// The agent that saved it.
    pub made_by: EntityId,
    /// Its definition's agent id.
    pub agent_id: String,
    /// Whether its agent runs under it now: active, approved and switched on.
    pub stands: bool,
    /// Its own live runs.
    pub runs: Vec<AgentRunNow>,
    /// The agent Grants it holds that stand now.
    pub held_grants: usize,
}

/// One live run of a saved agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentRunNow {
    /// The attempt id, as `vault.runs.pause` names a branch.
    pub branch: String,
    pub state: AttemptState,
    /// When a scheduled run becomes ready, Unix seconds.
    pub scheduled_at: Option<u64>,
}

/// A live branch under an agent's runs or TASKs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MadeBranch {
    /// The attempt id, as `vault.runs.pause` names a branch.
    pub branch: String,
    /// The agent whose run or TASK it is under.
    pub made_by: EntityId,
    /// The agent it runs as, when it is an agent's run.
    pub agent_def_ref: Option<EntityId>,
    pub state: AttemptState,
    /// When a scheduled branch becomes ready, Unix seconds.
    pub scheduled_at: Option<u64>,
}

/// A TASK an agent owns that still waits for its due tick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MadeWatcher {
    pub task_ref: EntityId,
    /// The agent that owns it.
    pub made_by: EntityId,
    /// When it ticks, Unix seconds.
    pub due_at: u64,
    /// Whether a tree pause holds its tick.
    pub held: bool,
}

/// A scheduled send an agent made that has not gone out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MadeSend {
    /// The send's attempt id, as `vault.runs.pause` names a branch.
    pub branch: String,
    /// Its connector TASK.
    pub task_ref: EntityId,
    /// The agent that scheduled it.
    pub made_by: EntityId,
    pub state: AttemptState,
    /// When a scheduled send becomes ready, Unix seconds.
    pub scheduled_at: Option<u64>,
}

/// A pack hook binding whose outcomes run as an agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MadeHook {
    pub binding_ref: EntityId,
    /// The agent its outcomes run as.
    pub made_by: EntityId,
    pub pack: String,
    pub hook: String,
    pub enabled: bool,
}
