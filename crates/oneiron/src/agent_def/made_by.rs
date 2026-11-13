//! What an agent made, transitively: the blast radius the owner sees on
//! switching an agent off or narrowing it (owner ruling AUTHOR-OFF = A, 10 Nov
//! 2026, ARCH-0053 #author-off-no-cascade: "The switch-off and narrow flow
//! shows the blast radius: everything the agent made, transitively, with
//! what each is doing now (active runs, schedules and held grants)").
//!
//! Switching an agent off does not cascade: what it made keeps running on
//! its own records. This module only reads them. Each kind is attributed by
//! its own record:
//! - a definition it saved: an Active AGENT_DEF whose provenance names it as
//!   `author` (`mark_agent_authored`); a proposed change to another row is
//!   no agent of its own;
//! - a branch: a live attempt under one of its runs in the run tree, or one
//!   that realizes a TASK it owns, its own runs left out;
//! - a watcher: a TASK it owns that still waits for its due tick (ARCH-0080
//!   §4: a TASK with a due time is a watcher);
//! - a hook: a pack hook binding whose outcomes run as it
//!   (`HookAuthor::Agent`);
//! - a send: a live scheduled send whose connector TASK names it as the
//!   actor that scheduled it.
//!
//! A definition it saved made things of its own; those are listed too, as
//! far down as saved definitions go, each under the agent that made it.
//!
//! The answer carries the offer to pause them: how many entries
//! `vault.agents.pause_tree` would pause now (`agent_def::tree_pause`).
//!
//! Entry: [`Vault::agent_made_by_as`]. [`switches_off_or_narrows`] decides
//! which owner edits answer with it.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use super::doors::{grants_within, stands};
use super::proposed_change::{AUTHOR_KEY, REPLACES_KEY, provenance_text};
use super::types::AgentDefinition;
use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState};
use crate::claim::ClaimLifecycleStatus;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use crate::skill_hub::pack_catalog::{HookAuthor, PackHookBinding};
use crate::store::EngineScan;
use crate::store::scan_count::ScanCount;

/// `vault.agents.made_by.get`: the agent whose making the owner reads.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentMadeByRequest {
    pub agent_def_ref: EntityId,
}

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
    /// the queued and scheduled branches, runs and sends, the watchers not
    /// held and the hooks switched on. A running branch is not paused.
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

/// Whether the owner's edit from `prior` to `updated` switches the agent off
/// or narrows it, the edits that answer with what it made: it stood and no
/// longer does, the new row no longer holds a scope, skill, connector or
/// code-mode MCP the old one held, or its ceiling went down.
pub(crate) fn switches_off_or_narrows(prior: &AgentDefinition, updated: &AgentDefinition) -> bool {
    (stands(prior) && !stands(updated))
        || !grants_within(prior, updated)
        || prior.ceiling.widens_beyond(updated.ceiling)
}

/// What one snapshot holds that an agent can have made, read once and filed
/// by maker.
struct Makings {
    /// Each Active definition an agent saved, by the agent that saved it.
    saved: BTreeMap<EntityId, Vec<(EntityId, AgentDefinition)>>,
    /// Each agent's runs, every state, by the agent they run as.
    runs: BTreeMap<EntityId, Vec<AttemptRecord>>,
    /// Each hook binding whose outcomes run as an agent, by that agent.
    hooks: BTreeMap<EntityId, Vec<(EntityId, PackHookBinding)>>,
    /// Each live scheduled send with its connector TASK, by the actor its
    /// TASK names.
    sends: BTreeMap<EntityId, Vec<(EntityId, AttemptRecord)>>,
}

/// The verb the offer names.
pub(crate) const PAUSE_TREE_VERB: &str = "vault.agents.pause_tree";

/// The agent an attempt runs as, when it is an agent's run.
fn run_agent(record: &AttemptRecord) -> Option<EntityId> {
    crate::agent_dispatch::record_dispatch_input(record)
        .and_then(|input| input.target.agent_definition_ref().ok())
}

pub(super) fn branch_hex(id: AttemptId) -> String {
    crate::entity_id::bytes_to_hex_lower(id.as_bytes())
}

/// The attempt a branch id names ([`branch_hex`]'s inverse).
pub(super) fn branch_id(branch: &str) -> Result<AttemptId> {
    AttemptId::from_bytes(EntityId::from_hex(branch)?.as_bytes())
}

/// How many entries of `made` the tree pause would pause now.
fn pausable(made: &AgentMadeBy) -> usize {
    let waits = |state: AttemptState| state.is_ready_indexed();
    made.agents
        .iter()
        .map(|agent| {
            usize::from(agent.stands) + agent.runs.iter().filter(|run| waits(run.state)).count()
        })
        .sum::<usize>()
        + made
            .branches
            .iter()
            .filter(|branch| waits(branch.state))
            .count()
        + made.sends.iter().filter(|send| waits(send.state)).count()
        + made.watchers.iter().filter(|watcher| !watcher.held).count()
        + made.hooks.iter().filter(|hook| hook.enabled).count()
}

impl Vault {
    /// What `agent` made, transitively, and what each is doing now, read as
    /// `owner` in one snapshot that rechecks the proof (module docs).
    ///
    /// # Errors
    ///
    /// [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated)
    /// when the proof no longer holds or its actor does not own this vault;
    /// [`Error::EntityNotFound`](crate::error::Error::EntityNotFound) when no
    /// AGENT_DEF stands at `agent`; a stored row that does not decode.
    pub(crate) fn agent_made_by_as(
        &self,
        owner: &AuthenticatedOwner,
        agent: &EntityId,
    ) -> Result<AgentMadeBy> {
        let rtxn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &rtxn)?;
        let mut count = ScanCount::start(
            &self.store,
            &rtxn,
            EngineScan::TypeIndexRows,
            &[ENTITY_TYPE_AGENT_DEF],
        )?;
        let made = self.agent_made_by_in_txn(&rtxn, agent, &mut count)?;
        drop(rtxn);
        count.finish(self);
        Ok(made)
    }

    /// [`Self::agent_made_by_as`] in the caller's snapshot, the owner's
    /// proof already checked there; `count` counts the AGENT_DEF rows read.
    pub(crate) fn agent_made_by_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        agent: &EntityId,
        count: &mut ScanCount,
    ) -> Result<AgentMadeBy> {
        self.read_agent_definition_in_txn(txn, agent)?;
        let makings = self.makings_in_txn(txn, count)?;
        let queue = AttemptQueue::new(self);
        let now = self.instant_in_txn(txn)?.secs();
        let grants = self.agent_grants_in_txn(txn)?;
        let mut made = AgentMadeBy {
            agent_def_ref: *agent,
            count: 0,
            agents: Vec::new(),
            branches: Vec::new(),
            watchers: Vec::new(),
            hooks: Vec::new(),
            sends: Vec::new(),
            pause_offer: None,
        };
        let mut listed_branches = BTreeSet::new();
        let mut seen = BTreeSet::from([*agent]);
        let mut makers = VecDeque::from([*agent]);
        while let Some(maker) = makers.pop_front() {
            for (id, definition) in makings.saved.get(&maker).into_iter().flatten() {
                if !seen.insert(*id) {
                    continue;
                }
                let runs = makings
                    .runs
                    .get(id)
                    .into_iter()
                    .flatten()
                    .filter(|record| record.state.is_pending())
                    .map(|record| AgentRunNow {
                        branch: branch_hex(record.id),
                        state: record.state,
                        scheduled_at: record.scheduled_at,
                    })
                    .collect();
                let held_grants = grants
                    .iter()
                    .filter(|standing| standing.grant.member_ref == *id && standing.stands_at(now))
                    .count();
                made.agents.push(MadeAgent {
                    agent_def_ref: *id,
                    made_by: maker,
                    agent_id: definition.agent_id.clone(),
                    stands: stands(definition),
                    runs,
                    held_grants,
                });
                makers.push_back(*id);
            }
            // A send is listed once, as a send, before the branches.
            for (task, record) in makings.sends.get(&maker).into_iter().flatten() {
                if !listed_branches.insert(record.id) {
                    continue;
                }
                made.sends.push(MadeSend {
                    branch: branch_hex(record.id),
                    task_ref: *task,
                    made_by: maker,
                    state: record.state,
                    scheduled_at: record.scheduled_at,
                });
            }
            let own_runs = makings.runs.get(&maker).into_iter().flatten();
            let mut under = queue.descendant_rows_in_txn(txn, own_runs.map(|record| record.id))?;
            for task in crate::task_verb::indexed_tasks_of_in(&self.store, txn, &maker)? {
                // The index may hold a stale row: a forked or unprovable
                // authority is no TASK this agent owns.
                if !self
                    .task_authority_state_in(txn, task)
                    .ok()
                    .flatten()
                    .is_some_and(|state| state.owner_ref == maker)
                {
                    continue;
                }
                if let Some(due_at) =
                    crate::runtime_hooks::task_tick_waiting_in_txn(self, txn, task)?
                {
                    made.watchers.push(MadeWatcher {
                        task_ref: task,
                        made_by: maker,
                        due_at,
                        held: crate::runtime_hooks::task_tick_held_in_txn(self, txn, task)?,
                    });
                }
                under.extend(queue.task_subtree_in_txn(txn, &task.to_hex())?);
            }
            for record in under {
                let runs_as = run_agent(&record);
                if !record.state.is_pending()
                    || runs_as == Some(maker)
                    || !listed_branches.insert(record.id)
                {
                    continue;
                }
                made.branches.push(MadeBranch {
                    branch: branch_hex(record.id),
                    made_by: maker,
                    agent_def_ref: runs_as,
                    state: record.state,
                    scheduled_at: record.scheduled_at,
                });
            }
            for (id, binding) in makings.hooks.get(&maker).into_iter().flatten() {
                made.hooks.push(MadeHook {
                    binding_ref: *id,
                    made_by: maker,
                    pack: binding.pack.clone(),
                    hook: binding.hook.clone(),
                    enabled: binding.enabled,
                });
            }
        }
        made.count = made.agents.len()
            + made.branches.len()
            + made.watchers.len()
            + made.hooks.len()
            + made.sends.len();
        let pausable = pausable(&made);
        made.pause_offer = (pausable > 0).then(|| AgentTreePauseOffer {
            verb: PAUSE_TREE_VERB.to_owned(),
            pausable,
        });
        Ok(made)
    }

    /// Every saved definition, agent run, agent hook binding and live
    /// scheduled send `txn` holds, filed by maker. Every AGENT_DEF row is read (rule 5: past the
    /// type's threshold the scan raises one scan check and reads on).
    fn makings_in_txn(&self, txn: &heed::RoTxn<'_>, count: &mut ScanCount) -> Result<Makings> {
        let mut saved: BTreeMap<EntityId, Vec<(EntityId, AgentDefinition)>> = BTreeMap::new();
        for id in self
            .store
            .port_entity_ids_by_type(txn, ENTITY_TYPE_AGENT_DEF, None)?
        {
            count.row();
            let id = id?;
            let definition = self.read_agent_definition_in_txn(txn, &id)?;
            if definition.lifecycle_status != ClaimLifecycleStatus::Active
                || provenance_text(&definition, REPLACES_KEY).is_some()
            {
                continue;
            }
            let Some(author) = provenance_text(&definition, AUTHOR_KEY)
                .and_then(|hex| EntityId::from_hex(hex).ok())
            else {
                continue;
            };
            saved.entry(author).or_default().push((id, definition));
        }
        let mut runs: BTreeMap<EntityId, Vec<AttemptRecord>> = BTreeMap::new();
        for record in AttemptQueue::new(self)
            .working_kind_rows_in_txn(txn, crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND)?
        {
            if let Some(agent) = run_agent(&record) {
                runs.entry(agent).or_default().push(record);
            }
        }
        let mut hooks: BTreeMap<EntityId, Vec<(EntityId, PackHookBinding)>> = BTreeMap::new();
        for (id, binding) in self.pack_hook_binding_rows_in_txn(txn)? {
            if let HookAuthor::Agent { agent } = &binding.author {
                hooks.entry(*agent).or_default().push((id, binding));
            }
        }
        let mut sends: BTreeMap<EntityId, Vec<(EntityId, AttemptRecord)>> = BTreeMap::new();
        for record in AttemptQueue::new(self)
            .working_kind_rows_in_txn(txn, crate::outbound::BRIDGE_OUTBOUND_ATTEMPT_KIND)?
        {
            let Some(task) = record
                .task_ref
                .as_deref()
                .and_then(|hex| EntityId::from_hex(hex).ok())
            else {
                continue;
            };
            if !record.state.is_pending() {
                continue;
            }
            if let Some(send) = self.connector_send_task_in(txn, &task)? {
                sends
                    .entry(send.actor_ref)
                    .or_default()
                    .push((task, record));
            }
        }
        Ok(Makings {
            saved,
            runs,
            hooks,
            sends,
        })
    }
}
