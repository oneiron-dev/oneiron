//! "Also pause these": the owner pauses what one agent made in one act, with
//! one receipt and an undo (owner ruling AUTHOR-OFF = A, 10 Nov 2026,
//! ARCH-0053 #author-off-no-cascade: "It offers 'also pause these' with the
//! count and the list, as one tap with a receipt and an undo. The same bulk
//! action sits in the permissions registry as 'pause everything X made'").
//!
//! `vault.agents.pause_tree` reads what the agent made
//! ([`Vault::agent_made_by_in_txn`]) and, in the same write, pauses what
//! waits among it: each saved definition that stands is switched off, each
//! queued or scheduled branch, saved agent's run and scheduled send takes a
//! person's pause, each waiting watcher's tick is held, and each hook binding
//! switched on is switched off. One gate decision records the act, and one
//! pause record keeps what this act moved and nothing else, so the undo
//! never switches on what was off before. Grants are not touched.
//!
//! A running run is paused at its next step boundary (Engine RULING
//! PAUSE-BOUNDARY-SCOPE = B, 13 Nov): the same write posts a Pause signal
//! on its branch, and the run's executor takes it once the step it is
//! running has committed its checkpoint, moving its row to a person's pause
//! before its next model request (`attempt_queue::boundary_pause`). The
//! answer lists each such branch as pausing at its next step. A branch it
//! does not pause (a landing branch, one of no run, one whose pause another
//! act has pending) is listed as running, and the existing branch cancel
//! stops it.
//!
//! `vault.agents.resume_tree` undoes one pause: each member still in the
//! state the pause left it goes back, in one write with one gate decision;
//! a member someone moved since is left as found and named. A running
//! branch that took its pause is resumed as a paused one is; one whose
//! pause no step has taken yet has its Pause signal withdrawn, so no later
//! step takes it. A repeat answers the first resume and writes nothing.
//!
//! Both are owner acts: the only check is the owner's proof, rechecked in
//! the writer.

use serde::{Deserialize, Serialize};

use super::doors::stands;
use super::made_by::branch_id;
use crate::Vault;
use crate::attempt_queue::{
    AttemptInterventionKind, AttemptQueue, AttemptRecord, AttemptState, InterveneAttempt,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use crate::run_tree::{
    RunSignalInput, RunSignalKind, RunSignalState, RunTreeAdapter, takes_boundary_pause,
};
use crate::side_table::{self, Named, SideTable};
use crate::store::attempt_record::AttemptPause;
use crate::store::scan_count::ScanCount;
use crate::store::{EngineScan, GateDecisionId, GateDecisionRecord, GateSystemNoticeRecord};
use crate::temporal::TimeRange;
use crate::{EdgeActorClass, WriteActor};

/// Each tree pause, by its id.
const TREE_PAUSE: SideTable<EntityId, TreePauseRecord, Named> =
    SideTable::new(&side_table::AGENT_DEF_TREE_PAUSE);

/// The content kind of the gate decisions that record a pause and its resume.
const TREE_PAUSE_CONTENT_KIND: &str = "agent_tree_pause";
/// The reason code of a pause.
const PAUSE_REASON: &str = "gate.allow.owner_agent_tree_pause";
/// The reason code of a resume.
const RESUME_REASON: &str = "gate.allow.owner_agent_tree_resume";

/// The key of the Pause signal a tree pause posts on each running branch.
fn pause_signal_key(pause: &EntityId) -> String {
    format!("agent-tree-pause:{}", pause.to_hex())
}

/// The note that signal carries onto the branch's pause event.
fn boundary_pause_note(pause: &EntityId) -> String {
    format!("agent tree pause {}, at a step boundary", pause.to_hex())
}

/// The existing door that cancels one running branch (FIX 8219): the
/// owner's cancel stops it at once.
pub(crate) const BRANCH_CANCEL_DOOR: &str = "POST /v1/core/run-tree/intervene (kind cancel)";

/// `vault.agents.pause_tree`: the agent whose making the owner pauses.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentTreePauseRequest {
    pub agent_def_ref: EntityId,
}

/// `vault.agents.resume_tree`: the pause the owner undoes.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentTreeResumeRequest {
    /// The pause, as `vault.agents.pause_tree` answered it.
    pub pause_ref: EntityId,
}

/// The members one pause or resume moved, or left as found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentTreeMembers {
    /// Saved definitions switched off (on a resume: back on).
    pub agents: Vec<EntityId>,
    /// Branches paused (on a resume: resumed): spawned branches, saved
    /// agents' runs and scheduled sends, as `vault.runs.pause` names them.
    pub branches: Vec<String>,
    /// Watchers whose tick is held (on a resume: released).
    pub watchers: Vec<EntityId>,
    /// Hook bindings switched off (on a resume: back on).
    pub hooks: Vec<EntityId>,
}

impl AgentTreeMembers {
    /// How many members the four lists hold together.
    #[must_use]
    pub fn count(&self) -> usize {
        self.agents.len() + self.branches.len() + self.watchers.len() + self.hooks.len()
    }

    /// The rows the lists name: the definitions, the watchers' TASKs and
    /// the hook bindings.
    fn rows(&self) -> impl Iterator<Item = EntityId> + '_ {
        self.agents
            .iter()
            .chain(&self.watchers)
            .chain(&self.hooks)
            .copied()
    }
}

/// What one tree pause did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentTreePauseReceipt {
    /// The pause, as `vault.agents.resume_tree` names it.
    pub pause_ref: EntityId,
    /// The agent whose making it paused.
    pub agent_def_ref: EntityId,
    /// The gate decision that records it, as `gate:<id hex>`.
    pub receipt_ref: String,
    /// How many members it paused, with the running branches it pauses at
    /// their next step boundary.
    pub count: usize,
    pub paused: AgentTreeMembers,
    /// Running branches it pauses at their next step boundary: each run
    /// stops once the step it is running has committed.
    pub pausing_at_next_step: Vec<String>,
    /// Branches running when it committed that it does not pause: a
    /// landing branch, one of no run, or one whose pause another act has
    /// pending.
    pub running: Vec<String>,
    /// The door that cancels a running branch at once.
    pub running_cancel_door: String,
}

impl AgentTreePauseReceipt {
    /// The rows this answer names: the agent and every row it paused.
    #[must_use]
    pub fn listed_rows(&self) -> Vec<EntityId> {
        listed(self.agent_def_ref, &[&self.paused])
    }
}

/// What one resume of a tree pause did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentTreeResumeReceipt {
    pub pause_ref: EntityId,
    /// The agent whose making the pause paused.
    pub agent_def_ref: EntityId,
    /// The gate decision that records the resume, as `gate:<id hex>`.
    pub receipt_ref: String,
    /// True when the pause was resumed before: this answer is that resume's,
    /// and nothing was written.
    pub already_resumed: bool,
    pub resumed: AgentTreeMembers,
    /// Members no longer in the state the pause left them (switched back
    /// on, resumed, cancelled, changed or gone since), left as found.
    pub left_as_found: AgentTreeMembers,
    /// Running branches whose pause no step had taken yet: its Pause signal
    /// is withdrawn, so the run goes on unpaused.
    pub withdrawn: Vec<String>,
}

impl AgentTreeResumeReceipt {
    /// The rows this answer names: the agent and every row it moved or left.
    #[must_use]
    pub fn listed_rows(&self) -> Vec<EntityId> {
        listed(self.agent_def_ref, &[&self.resumed, &self.left_as_found])
    }
}

fn listed(agent: EntityId, members: &[&AgentTreeMembers]) -> Vec<EntityId> {
    let mut rows: Vec<EntityId> = std::iter::once(agent)
        .chain(members.iter().flat_map(|members| members.rows()))
        .collect();
    rows.sort_unstable();
    rows.dedup();
    rows
}

/// One pause as the vault keeps it: what it moved, each switched-off
/// definition with the version the pause wrote, the running branches it
/// signalled, and its resume once run.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TreePauseRecord {
    agent: EntityId,
    receipt_ref: String,
    paused: AgentTreeMembers,
    /// The version the pause wrote on each definition it switched off, in
    /// `paused.agents`' order.
    paused_versions: Vec<String>,
    /// The running branches it posted its Pause signal on
    /// ([`pause_signal_key`]).
    #[serde(default)]
    pausing: Vec<String>,
    resume: Option<TreeResumeRecord>,
}

/// What one gate decision of a tree pause or resume records.
struct TreeDecision<'a> {
    reason: &'static str,
    agent: &'a EntityId,
    pause: &'a EntityId,
    members: &'a AgentTreeMembers,
    /// A pause's running branches it signalled; a resume's it withdrew.
    pausing: &'a [String],
    running: &'a [String],
}

/// Whether `row` stands paused by the Pause signal `key`: a step took it at
/// its boundary, and the row's last pause event is the one it wrote, with
/// `note`. A row paused again by hand since is not this pause's to resume.
fn took_pause(row: &AttemptRecord, key: &str, note: &str) -> bool {
    let settled = row.signals.iter().any(|signal| {
        signal.key == key
            && signal.state == RunSignalState::Settled
            && matches!(signal.kind, RunSignalKind::Pause { .. })
    });
    settled
        && row
            .events
            .iter()
            .rev()
            .find(|event| event.kind == AttemptInterventionKind::Pause)
            .is_some_and(|event| event.note.as_deref() == Some(note))
}

/// A pause's resume as the vault keeps it, for a repeat's answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TreeResumeRecord {
    receipt_ref: String,
    resumed: AgentTreeMembers,
    left_as_found: AgentTreeMembers,
    #[serde(default)]
    withdrawn: Vec<String>,
}

/// The version a pause or resume writes on a definition: derived from the
/// version it replaces and the pause, so one pause writes one version.
fn tree_pause_version(step: &str, prior: &str, pause: &EntityId) -> String {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron.agent-tree-pause.version.v1");
    hasher.update(step.as_bytes());
    hasher.update(&[0]);
    hasher.update(prior.as_bytes());
    hasher.update(pause.as_bytes());
    format!("{step}-{}", hasher.finalize().to_hex())
}

impl Vault {
    /// `vault.agents.pause_tree`: pauses, as `owner`, what waits among what
    /// `agent` made, in one write with one gate decision (module docs).
    ///
    /// # Errors
    ///
    /// [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated)
    /// when the proof no longer holds or its actor does not own this vault;
    /// [`Error::EntityNotFound`] when no AGENT_DEF stands at `agent`; a
    /// stored row that does not decode; the refusals of the owner's own
    /// edits it makes. Every refusal writes nothing.
    pub(crate) fn pause_agent_tree_as(
        &self,
        owner: &AuthenticatedOwner,
        agent: &EntityId,
    ) -> Result<AgentTreePauseReceipt> {
        let pause = self.new_entity_id()?;
        let now = self.store.clock.now_recorded_at();
        let (receipt, count, hooks_moved) = self.with_write_txn(|txn| {
            let owner_id = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let mut count = ScanCount::start(
                &self.store,
                txn,
                EngineScan::TypeIndexRows,
                &[ENTITY_TYPE_AGENT_DEF],
            )?;
            let made = self.agent_made_by_in_txn(txn, agent, &mut count)?;
            let mut paused = AgentTreeMembers::default();
            let mut paused_versions = Vec::new();
            for made_agent in &made.agents {
                let id = made_agent.agent_def_ref;
                let existing = self.read_agent_definition_in_txn(txn, &id)?;
                if !stands(&existing) {
                    continue;
                }
                let mut off = existing.clone();
                off.enabled = false;
                off.version = tree_pause_version("pause", &existing.version, &pause);
                self.update_agent_definition_as_owner_in_txn(
                    txn,
                    owner,
                    &id,
                    Some(existing.version.as_str()),
                    &off,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                )?;
                paused.agents.push(id);
                paused_versions.push(off.version);
            }
            let queue = AttemptQueue::new(self);
            let signals = RunTreeAdapter::new(self);
            let mut pausing = Vec::new();
            let mut running = Vec::new();
            let mut seen = std::collections::BTreeSet::new();
            let branches = made
                .agents
                .iter()
                .flat_map(|made_agent| made_agent.runs.iter().map(|run| run.branch.as_str()))
                .chain(made.branches.iter().map(|branch| branch.branch.as_str()))
                .chain(made.sends.iter().map(|send| send.branch.as_str()));
            for branch in branches {
                if !seen.insert(branch) {
                    continue;
                }
                let id = branch_id(branch)?;
                let Some(record) = queue.get_in_write_txn(txn, id)? else {
                    continue;
                };
                if takes_boundary_pause(&record)
                    && let Some(run_id) = record.run_id.clone()
                {
                    signals.signal_in_txn(
                        txn,
                        RunSignalInput {
                            branch: id,
                            run_id,
                            key: pause_signal_key(&pause),
                            actor: owner_id.to_hex(),
                            kind: RunSignalKind::Pause {
                                note: Some(boundary_pause_note(&pause)),
                            },
                        },
                    )?;
                    pausing.push(branch.to_owned());
                    continue;
                }
                if record.state.is_running() {
                    running.push(branch.to_owned());
                    continue;
                }
                if !record.state.is_ready_indexed() {
                    continue;
                }
                queue.intervene_in_txn(
                    txn,
                    InterveneAttempt {
                        id,
                        kind: AttemptInterventionKind::Pause,
                        actor: owner_id.to_hex(),
                        note: Some(format!("agent tree pause {}", pause.to_hex())),
                        now,
                    },
                )?;
                paused.branches.push(branch.to_owned());
            }
            for watcher in &made.watchers {
                if crate::runtime_hooks::hold_task_tick_in_txn(self, txn, watcher.task_ref, pause)?
                {
                    paused.watchers.push(watcher.task_ref);
                }
            }
            for hook in &made.hooks {
                if hook.enabled {
                    self.set_pack_hook_enabled_by_owner_in_txn(
                        txn,
                        owner,
                        hook.binding_ref,
                        false,
                    )?;
                    paused.hooks.push(hook.binding_ref);
                }
            }
            let receipt_ref = self.record_tree_decision_in_txn(
                txn,
                owner_id,
                &TreeDecision {
                    reason: PAUSE_REASON,
                    agent,
                    pause: &pause,
                    members: &paused,
                    pausing: &pausing,
                    running: &running,
                },
            )?;
            TREE_PAUSE.put(
                &self.store,
                txn,
                &pause,
                &TreePauseRecord {
                    agent: *agent,
                    receipt_ref: receipt_ref.clone(),
                    paused: paused.clone(),
                    paused_versions,
                    pausing: pausing.clone(),
                    resume: None,
                },
            )?;
            let hooks_moved = !paused.hooks.is_empty();
            Ok((
                AgentTreePauseReceipt {
                    pause_ref: pause,
                    agent_def_ref: *agent,
                    receipt_ref,
                    count: paused.count() + pausing.len(),
                    paused,
                    pausing_at_next_step: pausing,
                    running,
                    running_cancel_door: BRANCH_CANCEL_DOOR.to_owned(),
                },
                count,
                hooks_moved,
            ))
        })?;
        count.finish(self);
        self.store.notify_attempt_observers();
        if hooks_moved {
            self.verb_hook_bindings_changed();
        }
        Ok(receipt)
    }

    /// `vault.agents.resume_tree`: undoes the tree pause `pause` as `owner`,
    /// in one write with one gate decision (module docs).
    ///
    /// # Errors
    ///
    /// [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated)
    /// when the proof no longer holds or its actor does not own this vault;
    /// [`Error::EntityNotFound`] when no pause has that id; a stored row
    /// that does not decode; the refusals of the owner's own edits it makes.
    /// Every refusal writes nothing.
    pub(crate) fn resume_agent_tree_as(
        &self,
        owner: &AuthenticatedOwner,
        pause: &EntityId,
    ) -> Result<AgentTreeResumeReceipt> {
        let now = self.store.clock.now_recorded_at();
        let (receipt, hooks_moved) = self.with_write_txn(|txn| {
            let owner_id = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let mut record = TREE_PAUSE
                .get(&self.store, txn, pause)?
                .ok_or(Error::EntityNotFound)?;
            if let Some(done) = &record.resume {
                return Ok((
                    AgentTreeResumeReceipt {
                        pause_ref: *pause,
                        agent_def_ref: record.agent,
                        receipt_ref: done.receipt_ref.clone(),
                        already_resumed: true,
                        resumed: done.resumed.clone(),
                        left_as_found: done.left_as_found.clone(),
                        withdrawn: done.withdrawn.clone(),
                    },
                    false,
                ));
            }
            let mut resumed = AgentTreeMembers::default();
            let mut left = AgentTreeMembers::default();
            for (id, version) in record.paused.agents.iter().zip(&record.paused_versions) {
                let existing = match self.read_agent_definition_in_txn(txn, id) {
                    Ok(existing) => existing,
                    Err(Error::EntityNotFound) => {
                        left.agents.push(*id);
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                if existing.version != *version || existing.enabled {
                    left.agents.push(*id);
                    continue;
                }
                let mut on = existing;
                on.enabled = true;
                on.version = tree_pause_version("resume", version, pause);
                self.update_agent_definition_as_owner_in_txn(
                    txn,
                    owner,
                    id,
                    Some(version.as_str()),
                    &on,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                )?;
                resumed.agents.push(*id);
            }
            let queue = AttemptQueue::new(self);
            for branch in &record.paused.branches {
                let id = branch_id(branch)?;
                let still_paused = queue.get_in_write_txn(txn, id)?.is_some_and(|row| {
                    row.state == AttemptState::Paused
                        && row.active_pause == Some(AttemptPause::Person)
                });
                if !still_paused {
                    left.branches.push(branch.clone());
                    continue;
                }
                queue.intervene_in_txn(
                    txn,
                    InterveneAttempt {
                        id,
                        kind: AttemptInterventionKind::Resume,
                        actor: owner_id.to_hex(),
                        note: Some(format!("agent tree resume {}", pause.to_hex())),
                        now,
                    },
                )?;
                resumed.branches.push(branch.clone());
            }
            // A running branch it signalled: one paused at its boundary is
            // resumed as above; one whose pause is still untaken has it
            // withdrawn.
            let signals = RunTreeAdapter::new(self);
            let key = pause_signal_key(pause);
            let note = boundary_pause_note(pause);
            let mut withdrawn = Vec::new();
            for branch in &record.pausing {
                let id = branch_id(branch)?;
                if signals.withdraw_pause_in_txn(txn, id, &key)? {
                    withdrawn.push(branch.clone());
                    continue;
                }
                let took = queue.get_in_write_txn(txn, id)?.is_some_and(|row| {
                    row.state == AttemptState::Paused
                        && row.active_pause == Some(AttemptPause::Person)
                        && took_pause(&row, &key, &note)
                });
                if !took {
                    left.branches.push(branch.clone());
                    continue;
                }
                queue.intervene_in_txn(
                    txn,
                    InterveneAttempt {
                        id,
                        kind: AttemptInterventionKind::Resume,
                        actor: owner_id.to_hex(),
                        note: Some(format!("agent tree resume {}", pause.to_hex())),
                        now,
                    },
                )?;
                resumed.branches.push(branch.clone());
            }
            for task in &record.paused.watchers {
                if crate::runtime_hooks::release_task_tick_hold_in_txn(self, txn, *task, *pause)? {
                    resumed.watchers.push(*task);
                } else {
                    left.watchers.push(*task);
                }
            }
            for binding in &record.paused.hooks {
                let off = self
                    .pack_hook_binding_in_txn(txn, binding)?
                    .is_some_and(|row| !row.enabled);
                if !off {
                    left.hooks.push(*binding);
                    continue;
                }
                self.set_pack_hook_enabled_by_owner_in_txn(txn, owner, *binding, true)?;
                resumed.hooks.push(*binding);
            }
            let receipt_ref = self.record_tree_decision_in_txn(
                txn,
                owner_id,
                &TreeDecision {
                    reason: RESUME_REASON,
                    agent: &record.agent,
                    pause,
                    members: &resumed,
                    pausing: &withdrawn,
                    running: &[],
                },
            )?;
            record.resume = Some(TreeResumeRecord {
                receipt_ref: receipt_ref.clone(),
                resumed: resumed.clone(),
                left_as_found: left.clone(),
                withdrawn: withdrawn.clone(),
            });
            TREE_PAUSE.put(&self.store, txn, pause, &record)?;
            let hooks_moved = !resumed.hooks.is_empty();
            Ok((
                AgentTreeResumeReceipt {
                    pause_ref: *pause,
                    agent_def_ref: record.agent,
                    receipt_ref,
                    already_resumed: false,
                    resumed,
                    left_as_found: left,
                    withdrawn,
                },
                hooks_moved,
            ))
        })?;
        self.store.notify_attempt_observers();
        if hooks_moved {
            self.verb_hook_bindings_changed();
        }
        Ok(receipt)
    }

    /// Appends the gate decision that records a tree pause or its resume:
    /// the agent, the pause, how many of each kind moved and a digest of
    /// the members (the pause record keeps the list). Returns its ref,
    /// `gate:<id hex>`.
    fn record_tree_decision_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner_id: EntityId,
        decision: &TreeDecision<'_>,
    ) -> Result<String> {
        let TreeDecision {
            reason,
            agent,
            pause,
            members,
            pausing,
            running,
        } = *decision;
        let members_body = serde_json::to_vec(&(members, pausing, running))
            .map_err(|_| Error::InvariantViolation("agent tree pause members encode"))?;
        let digest = blake3::hash(&members_body);
        let details = vec![
            format!("agent:{}", agent.to_hex()),
            format!("pause:{}", pause.to_hex()),
            format!("agents:{}", members.agents.len()),
            format!("branches:{}", members.branches.len()),
            format!("watchers:{}", members.watchers.len()),
            format!("hooks:{}", members.hooks.len()),
            format!("pausing:{}", pausing.len()),
            format!("running:{}", running.len()),
            format!("members_digest:{}", digest.to_hex()),
        ];
        let actor = WriteActor::new(owner_id, EdgeActorClass::Human);
        let mut record = GateDecisionRecord {
            version: crate::store::GATE_DECISION_LEDGER_VERSION,
            decision_id: GateDecisionId::from_bytes(self.store.clock.ulid()?),
            created_at: crate::ports::recorded_at_in_txn(&self.store, txn)?,
            outcome: "allow".to_owned(),
            reason_codes: vec![reason.to_owned()],
            receipt_reasons: Vec::new(),
            system_notices: GateSystemNoticeRecord::receipt_details(
                TREE_PAUSE_CONTENT_KIND,
                details,
            ),
            actor_class: actor.actor_class().gate_actor_class().to_owned(),
            actor_ref: Some(actor.entity_ref().to_hex()),
            content_kind: TREE_PAUSE_CONTENT_KIND.to_owned(),
            policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
            claim_id: None,
            grant_ref: Some(format!("agent_tree_pause:{}", pause.to_hex())),
            diff_handle: digest.as_bytes().to_vec(),
            read_frontier_hash: crate::gate::resolve_policy_manifest(&self.store, txn)?
                .read_frontier_hash()?,
            context: Default::default(),
            redacted_at: None,
        };
        self.store
            .append_fresh_gate_decision_in_txn(txn, &mut record)?;
        Ok(format!("gate:{}", record.decision_id.to_hex()))
    }
}
