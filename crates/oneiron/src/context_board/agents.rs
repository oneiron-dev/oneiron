//! AGENTS section projections — child agents and peer connections.

use super::one_line_token;
use crate::agent_run_status::{AgentRunStatus, project_agent_run_status_with_park};
use crate::run_tree::RunTreeNode;

/// AGENTS row lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentLane {
    Child,
    Peer,
    Cand,
    Fanout,
}

impl AgentLane {
    /// Stable structural token for the lane.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Child => "child",
            Self::Peer => "peer",
            Self::Cand => "cand",
            Self::Fanout => "fanout",
        }
    }
}

/// One collapsed AGENTS row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRow {
    pub id: String,
    pub lane: AgentLane,
    pub line: String,
    pub harness_label: Option<String>,
}

/// Collapsed AGENTS section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentsSection {
    pub rows: Vec<AgentRow>,
}

/// Role token for a child that has agent-dispatch children of its own.
///
/// Crate-visible: `context_board`'s public surface is the curated re-export
/// list in its `mod.rs`, and the token's contract for outside readers is the
/// rendered `"lead"` / `"worker"` string itself.
const AGENT_ROLE_LEAD: &str = "lead";
/// Role token for a child with nothing under it.
const AGENT_ROLE_WORKER: &str = "worker";

/// A child's structural place in its own spawn subtree, as a rendered TOKEN.
///
/// Derived from the existing `RunTreeNode` mapping — it reads the shipped tree
/// rather than adding a second one, and it is a display label, never authority.
/// A child that spawned children of its own is leading; one that has not is
/// working. Deliberately a token rather than a new enum: the AGENTS row
/// vocabulary is rendered text, and this label rides it.
#[must_use]
fn agent_role_token(node: &RunTreeNode) -> &'static str {
    if node
        .children
        .iter()
        .any(|child| child.worker_kind == crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE)
    {
        AGENT_ROLE_LEAD
    } else {
        AGENT_ROLE_WORKER
    }
}

/// One present child agent projected from M8 driver state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildAgentPresence {
    pub id: String,
    pub status: AgentRunStatus,
    pub label: Option<String>,
    /// Structural role rendered as a suffix for agents that lead descendants.
    pub role: String,
}

impl ChildAgentPresence {
    /// Presents a running M8 agent-dispatch subagent; row identity is its per-spawn
    /// attempt id, while its AgentDefinition label (`agent_id`) is optional display text.
    /// Returns `None` for non-agent-dispatch attempts and terminal nodes because the
    /// section shows children working here now.
    #[must_use]
    pub fn from_run_tree_node(node: &RunTreeNode) -> Option<ChildAgentPresence> {
        Self::from_run_tree_node_with_park(node, false)
    }

    #[must_use]
    pub fn from_run_tree_node_with_park(
        node: &RunTreeNode,
        is_parked: bool,
    ) -> Option<ChildAgentPresence> {
        if node.worker_kind != crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE {
            return None;
        }
        let status = project_agent_run_status_with_park(node.status, is_parked);
        if !status.is_live_presence() {
            return None;
        }
        Some(ChildAgentPresence {
            id: node.attempt_id.clone(),
            status,
            label: node
                .agent_id
                .as_deref()
                .map(str::trim)
                .filter(|label| !label.is_empty())
                .map(str::to_owned),
            role: agent_role_token(node).to_owned(),
        })
    }

    /// Every present descendant of `node`, itself included, in tree order.
    #[must_use]
    pub fn from_run_tree_branch(node: &RunTreeNode) -> Vec<ChildAgentPresence> {
        let mut presences = Vec::new();
        collect_branch_presence(node, &mut presences);
        presences
    }
}

fn collect_branch_presence(node: &RunTreeNode, out: &mut Vec<ChildAgentPresence>) {
    out.extend(ChildAgentPresence::from_run_tree_node(node));
    for child in &node.children {
        collect_branch_presence(child, out);
    }
}

/// Registry-populated peer-presence view; identity and registry storage remain upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPresence {
    pub actor_handle: String,
    pub harness_label: String,
    pub last_seen: Option<u64>,
}

/// Renders provided agent presence into stable, collapsed rows.
#[must_use]
pub fn render_agents_section(
    children: &[ChildAgentPresence],
    peers: &[PeerPresence],
) -> AgentsSection {
    let mut rows = Vec::with_capacity(children.len() + peers.len());

    rows.extend(children.iter().map(|child| AgentRow {
        id: child.id.clone(),
        lane: AgentLane::Child,
        line: {
            let mut line = match child.label.as_deref() {
                Some(label) => format!(
                    "{} {} {}",
                    one_line_token(&child.id),
                    one_line_token(label),
                    one_line_token(child.status.as_str())
                ),
                None => format!(
                    "{} {}",
                    one_line_token(&child.id),
                    one_line_token(child.status.as_str())
                ),
            };
            if child.role == AGENT_ROLE_LEAD {
                line.push(' ');
                line.push_str(AGENT_ROLE_LEAD);
            }
            line
        },
        harness_label: None,
    }));
    rows.extend(peers.iter().map(|peer| AgentRow {
        id: peer.actor_handle.clone(),
        lane: AgentLane::Peer,
        line: format!(
            "{} {}",
            one_line_token(&peer.actor_handle),
            one_line_token(&peer.harness_label)
        ),
        harness_label: Some(peer.harness_label.clone()),
    }));

    AgentsSection { rows }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paused_agent_dispatch_renders_needs_input_and_resume_renders_working() {
        use super::{ChildAgentPresence, render_agents_section};
        use crate::agent_dispatch::{AgentDispatchOutcome, AgentDispatcher};
        use crate::dreamer_runner::{DreamerRunnerStore, ParkDreamerAttempt};
        use crate::llm::{
            DurableStepContext, consume_trap_signal, open_trap, register_wait, send_trap_signal,
            trap_for_durable_wait, trap_park_owner,
        };
        use crate::{
            AttemptQueue, EdgeActorClass, EntityId, VaultConfig, WriteActor,
            code_run::SelfDurableWait, code_run::SelfDurableWaitReason, code_run::SelfEffect,
        };

        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let dispatcher = AgentDispatcher::new(&vault);
        let AgentDispatchOutcome::Dispatched(status) = dispatcher
            .dispatch_default_base(None, None, None, 1)
            .expect("dispatch")
        else {
            panic!("expected fresh dispatch")
        };
        let attempt_id = status.attempt.id;
        let step_hash = [0x71u8; 32];
        let subject = EntityId::from_bytes([0x42; 16]).expect("subject");
        vault
            .put_entity(
                &subject,
                crate::registry::ENTITY_TYPE_PERSON,
                crate::TimeRange { start: 1, end: 1 },
                1,
                b"agent subject",
            )
            .expect("subject entity");
        let wait = SelfDurableWait {
            wait_id: subject,
            effect: SelfEffect::Ask,
            reason: SelfDurableWaitReason::HumanInput,
            prompt: Some("decide".to_owned()),
        };
        let ctx = DurableStepContext {
            vault: &vault,
            attempt_id,
            run_id: Some("agent-run".to_owned()),
            envelope_actor: WriteActor::new(subject, EdgeActorClass::Agent),
            subject,
            deadline: None,
            now_ms: 1,
        };
        let trap = open_trap(
            &vault,
            &ctx,
            trap_for_durable_wait(&wait, step_hash),
            step_hash,
            "human response",
        )
        .expect("open trap");
        let queue = AttemptQueue::new(&vault);
        queue
            .claim(crate::attempt_queue::ClaimAttempt {
                lease_owner: "agent-worker".to_owned(),
                now: 2,
            })
            .expect("claim dispatched attempt");
        let runner = DreamerRunnerStore::new(&vault);
        runner
            .park_attempt(ParkDreamerAttempt {
                attempt_id,
                reason: "human response".to_owned(),
                park_owner: trap_park_owner(&trap.trap_claim_id),
                now: 1,
            })
            .expect("park");
        register_wait(&vault, &trap, 1).expect("register wait");

        let is_parked = runner.parked_attempt(attempt_id).expect("parked").is_some();
        assert!(is_parked);
        let record = queue
            .get(attempt_id)
            .expect("read attempt")
            .expect("attempt");
        let node = crate::run_tree::render_run_tree(vec![record])
            .expect("render tree")
            .roots
            .remove(0);
        let presence = ChildAgentPresence::from_run_tree_node_with_park(&node, is_parked)
            .expect("parked child");
        let waiting = render_agents_section(&[presence], &[]);
        assert!(
            waiting.rows[0]
                .line
                .ends_with(AgentRunStatus::NeedsInput.as_str())
        );

        send_trap_signal(&vault, &trap.trap_claim_id, step_hash, 2).expect("send signal");
        consume_trap_signal(&vault, &runner, &trap, 3).expect("consume signal");
        let is_parked = runner.parked_attempt(attempt_id).expect("parked").is_some();
        assert!(!is_parked);
        let record = queue
            .get(attempt_id)
            .expect("read resumed")
            .expect("resumed");
        let node = crate::run_tree::render_run_tree(vec![record])
            .expect("render resumed tree")
            .roots
            .remove(0);
        let presence = ChildAgentPresence::from_run_tree_node_with_park(&node, is_parked)
            .expect("working child");
        let resumed = render_agents_section(&[presence], &[]);
        assert!(
            resumed.rows[0]
                .line
                .ends_with(AgentRunStatus::Working.as_str())
        );
    }
}
