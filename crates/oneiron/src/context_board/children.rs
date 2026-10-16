//! The agent's own runs on the board (PEOPLE ruling, ARCH-0067): the children
//! it spawned, whose state rides their task in TASKS, and its forks, which the
//! `you:` line lists with where each runs and what it does.

use std::collections::{BTreeMap, BTreeSet};

use super::one_line_token;
use super::people::PeopleView;
use super::tasks::TaskIntentPresence;
use crate::agent_run_status::{AgentRunStatus, project_agent_run_status_with_park};
use crate::attempt_queue::AttemptRecord;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::run_tree::RunTreeNode;

/// Role token for a child that has agent-dispatch children of its own.
const AGENT_ROLE_LEAD: &str = "lead";
/// Role token for a child with nothing under it.
const AGENT_ROLE_WORKER: &str = "worker";

/// One live child agent: the attempt it runs under, the agent it runs as and
/// the task it realizes, kept typed so TASKS joins on ids, never on labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildState {
    pub attempt: String,
    /// The AGENT_DEF actor the child runs as, when its payload names one.
    pub agent: Option<EntityId>,
    /// The definition's `agent_id`, shown when the agent is no person.
    pub label: Option<String>,
    pub status: AgentRunStatus,
    /// `lead` for a child that spawned children of its own, else `worker`.
    pub role: &'static str,
    /// The hex TASK the child's attempt realizes.
    pub task_ref: Option<String>,
}

impl ChildState {
    /// `<agent> <status>[ lead]`, the agent named as the reader's board names
    /// people.
    #[must_use]
    pub fn token(&self, people: &PeopleView<'_>) -> String {
        let who = match self.agent {
            Some(agent) => people.label(agent),
            None => self
                .label
                .as_deref()
                .map_or_else(|| self.attempt.clone(), one_line_token),
        };
        let mut token = format!("{who}:{}", self.status.as_str());
        if self.role == AGENT_ROLE_LEAD {
            token.push_str(":lead");
        }
        token
    }
}

/// The live children `actor` spawned: every present agent under an attempt
/// the queue dispatched AS `actor`, in tree order and once each. A host read:
/// the attempt queue has no caller-visibility filter, and the only rows it
/// yields are the ones `actor` itself spawned.
pub fn child_states_for_actor(
    vault: &crate::Vault,
    actor: EntityId,
) -> crate::Result<Vec<ChildState>> {
    let records = crate::AttemptQueue::new(vault).list()?;
    let own: BTreeSet<String> = records
        .iter()
        .filter(|record| dispatched_actor(record) == Some(actor))
        .map(|record| bytes_to_hex_lower(record.id.as_bytes()))
        .collect();
    if own.is_empty() {
        return Ok(Vec::new());
    }
    let by_attempt: BTreeMap<String, (Option<EntityId>, Option<String>)> = records
        .iter()
        .map(|record| {
            (
                bytes_to_hex_lower(record.id.as_bytes()),
                (dispatched_actor(record), record.task_ref.clone()),
            )
        })
        .collect();
    let tree = crate::run_tree::render_run_tree(records)?;
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for root in &tree.roots {
        collect_spawned(root, &own, &by_attempt, &mut seen, &mut out);
    }
    Ok(out)
}

fn collect_spawned(
    node: &RunTreeNode,
    own: &BTreeSet<String>,
    by_attempt: &BTreeMap<String, (Option<EntityId>, Option<String>)>,
    seen: &mut BTreeSet<String>,
    out: &mut Vec<ChildState>,
) {
    if own.contains(&node.attempt_id) {
        for child in &node.children {
            collect_branch(child, own, by_attempt, seen, out);
        }
    }
    for child in &node.children {
        collect_spawned(child, own, by_attempt, seen, out);
    }
}

fn collect_branch(
    node: &RunTreeNode,
    own: &BTreeSet<String>,
    by_attempt: &BTreeMap<String, (Option<EntityId>, Option<String>)>,
    seen: &mut BTreeSet<String>,
    out: &mut Vec<ChildState>,
) {
    if !own.contains(&node.attempt_id)
        && let Some(state) = child_state(node, by_attempt)
        && seen.insert(state.attempt.clone())
    {
        out.push(state);
    }
    for child in &node.children {
        collect_branch(child, own, by_attempt, seen, out);
    }
}

fn child_state(
    node: &RunTreeNode,
    by_attempt: &BTreeMap<String, (Option<EntityId>, Option<String>)>,
) -> Option<ChildState> {
    if node.worker_kind != crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE {
        return None;
    }
    let status = project_agent_run_status_with_park(node.status, false);
    if !status.is_live_presence() {
        return None;
    }
    let (agent, task_ref) = by_attempt
        .get(&node.attempt_id)
        .cloned()
        .unwrap_or_default();
    Some(ChildState {
        attempt: node.attempt_id.clone(),
        agent,
        label: node
            .agent_id
            .as_deref()
            .map(str::trim)
            .filter(|label| !label.is_empty())
            .map(str::to_owned),
        status,
        role: if node
            .children
            .iter()
            .any(|child| child.worker_kind == crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE)
        {
            AGENT_ROLE_LEAD
        } else {
            AGENT_ROLE_WORKER
        },
        task_ref,
    })
}

/// One fork of this agent: a live attempt the queue dispatched AS it, or an
/// open sitting it holds on a machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForkState {
    Run {
        attempt: String,
        /// The worker holding the lease, or `None` while it waits.
        worker: Option<String>,
        state: &'static str,
        task_ref: Option<String>,
    },
    Sitting {
        /// The SESSION's short id, else its hex.
        session: String,
        /// The MACHINE's short id, else its hex.
        machine: String,
    },
}

/// This agent's forks: its own live dispatched attempts, then its open
/// sittings, in stable order.
pub fn fork_states_for_actor(
    vault: &crate::Vault,
    actor: EntityId,
) -> crate::Result<Vec<ForkState>> {
    let mut forks: Vec<ForkState> = crate::AttemptQueue::new(vault)
        .list()?
        .iter()
        .filter(|record| !record.state.is_terminal() && dispatched_actor(record) == Some(actor))
        .map(|record| ForkState::Run {
            attempt: bytes_to_hex_lower(record.id.as_bytes()),
            worker: record.lease_owner.clone(),
            state: record.state.as_str(),
            task_ref: record.task_ref.clone(),
        })
        .collect();
    let short = |id: &EntityId| -> crate::Result<String> {
        Ok(crate::retrieval_depth::short_ref_or_hex(vault, id)?
            .split(':')
            .next()
            .unwrap_or_default()
            .to_owned())
    };
    for sitting in vault.open_sessions()? {
        if sitting.key.actor == actor {
            forks.push(ForkState::Sitting {
                session: short(&sitting.session)?,
                machine: short(&sitting.key.machine)?,
            });
        }
    }
    Ok(forks)
}

/// The `you:` line: each fork with where it runs and what it does, or `None`
/// when the agent has no fork. A fork's task is named by its board label.
#[must_use]
pub fn render_you_line(forks: &[ForkState], intents: &[TaskIntentPresence]) -> Option<String> {
    if forks.is_empty() {
        return None;
    }
    let label = |task: &str| {
        intents
            .iter()
            .find(|intent| intent.id == task)
            .and_then(|intent| intent.label.as_deref())
            .map(one_line_token)
    };
    let parts: Vec<String> = forks
        .iter()
        .map(|fork| match fork {
            ForkState::Run {
                attempt,
                worker,
                state,
                task_ref,
            } => {
                let short = attempt.get(..8).unwrap_or(attempt);
                let place = worker
                    .as_deref()
                    .map_or_else(|| "unplaced".to_owned(), one_line_token);
                let doing = match task_ref.as_deref() {
                    Some(task) => match label(task) {
                        Some(label) => format!("{task} {label}"),
                        None => task.to_owned(),
                    },
                    None => "no task".to_owned(),
                };
                format!("{short} {state} on {place} doing {doing}")
            }
            ForkState::Sitting { session, machine } => {
                format!("{session} sitting on {machine}")
            }
        })
        .collect();
    Some(format!("you: {}", parts.join("; ")))
}

/// The AGENT_DEF actor an agent-dispatch attempt runs as; `None` for any
/// other attempt, or one whose payload does not decode.
pub(crate) fn dispatched_actor(record: &AttemptRecord) -> Option<EntityId> {
    if record.kind != crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND {
        return None;
    }
    let payload = crate::dreamer_runner::decode_dreamer_attempt_payload(&record.payload).ok()?;
    if payload.attempt_type != crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE {
        return None;
    }
    let input = crate::agent_dispatch::decode_agent_dispatch_input(&payload.input).ok()?;
    crate::agent_dispatch::agent_dispatch_actor(&input)
        .ok()
        .map(|actor| actor.entity_ref())
}
