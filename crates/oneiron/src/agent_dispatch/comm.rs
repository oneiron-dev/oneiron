//! FIX 1380: the comm dial. Whom a dispatched agent may address, frozen on
//! every dispatch, and the evaluator a message is admitted by.
//!
//! Canon, ARCH-0067 :388-396: "`comm` is whom the child may address, `scope`
//! is what it may read", and "Slices only narrow". ARCH-0028 :611: "A child's
//! comm reach sits on its slip, set by the parent at spawn: parent-only by
//! default for a worker, subtree by default for a planner, project by default
//! for a coordinator, vault for people and the house mind." ARCH-0067
//! :53-56: "An explorer hears only from its parent, through its comm dial":
//! the dial binds what reaches an agent as well as what leaves it.
//!
//! Relations read the real dispatch lineage: a dispatch's parent is the
//! attempt that spawned it, across a registered workflow wrapper to that
//! wrapper's own parent, never a run tag, a retry link or the render tree.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::agent_def::AgentDefinition;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use crate::dreamer_runner::{DREAMER_RUNNER_ATTEMPT_KIND, decode_dreamer_attempt_payload};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;

use super::AgentDispatcher;
use super::codec::{agent_dispatch_actor, decode_agent_dispatch_input};
use super::types::{AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatchInput, AgentDispatchTarget};
use super::widen_record::invalid;

/// Most dispatch hops a lineage walk follows before it refuses as a cycle.
pub(super) const MAX_LINEAGE_HOPS: usize = 256;

/// Whom a dispatched agent may address. Declaration order is the narrowing
/// order (CALLS C1): a child's reach is never wider than its parent's.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CommReach {
    /// Its parent and its own children.
    Parent,
    /// Also every live dispatch below it.
    Subtree,
    /// Also its project's leader and every live dispatch in that project.
    Project,
    /// Anyone in the vault.
    Vault,
}

impl CommReach {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Parent => "parent",
            Self::Subtree => "subtree",
            Self::Project => "project",
            Self::Vault => "vault",
        }
    }

    pub(super) fn parse(value: &str) -> Option<Self> {
        match value {
            "parent" => Some(Self::Parent),
            "subtree" => Some(Self::Subtree),
            "project" => Some(Self::Project),
            "vault" => Some(Self::Vault),
            _ => None,
        }
    }
}

/// The role a dispatch's default reach is read from (ARCH-0028 :611). An
/// explorer is a worker: it hears only from its parent (ARCH-0067 :53-56).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpawnRole {
    Worker,
    #[expect(
        dead_code,
        reason = "no spawn path derives a planner (CALLS C2); its subtree reach is reached only by an explicit request"
    )]
    Planner,
    Coordinator,
}

/// The reach a dispatch takes when its spawn names none: the ONE default
/// policy (ARCH-0028 :611; CALLS C2).
pub(crate) const fn default_comm_reach(role: SpawnRole) -> CommReach {
    match role {
        SpawnRole::Worker => CommReach::Parent,
        SpawnRole::Planner => CommReach::Subtree,
        SpawnRole::Coordinator => CommReach::Project,
    }
}

/// The reach of a sender outside any live dispatch: a person, the owner, the
/// house mind, or an agent acting on its own. Canon gives "vault for people
/// and the house mind"; the unbound agent is CALLS C5.
const fn unbound_comm_reach() -> CommReach {
    CommReach::Vault
}

/// A dispatch's role (CALLS C2): a coordinator when the dispatched AGENT_DEF,
/// or the row it was forked from, is the effective leader of the project the
/// dispatch works in (the project's CEO is its leader); a worker otherwise.
/// A team-run stamp names no leader (its actors stay in the run's receipt),
/// so a team's leader is not read here, and no spawn path derives a planner.
pub(crate) fn spawn_role_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    target: EntityId,
    forked_from: Option<EntityId>,
    project: Option<EntityId>,
) -> Result<SpawnRole> {
    let Some(project) = project else {
        return Ok(SpawnRole::Worker);
    };
    let leads = vault
        .effective_project_in_txn(txn, project)?
        .is_some_and(|(_, effective)| {
            effective.leader == target.to_hex()
                || forked_from.is_some_and(|row| effective.leader == row.to_hex())
        });
    Ok(if leads {
        SpawnRole::Coordinator
    } else {
        SpawnRole::Worker
    })
}

impl AgentDispatcher<'_> {
    /// The reach a dispatch freezes, resolved once before it forks or
    /// enqueues: the spawn's request, else its role's default, never wider
    /// than its real parent's. A wider request is clamped, not refused and
    /// not proposed (CALLS C3). A dispatch with no agent parent takes its own.
    pub(super) fn resolve_comm_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        requested: Option<CommReach>,
        parent: Option<AttemptId>,
        target: &AgentDispatchTarget,
        definition: &AgentDefinition,
        project: Option<EntityId>,
    ) -> Result<CommReach> {
        let role = spawn_role_in_txn(
            self.vault,
            txn,
            target.agent_definition_ref()?,
            definition.forked_from,
            project,
        )?;
        let reach = requested.unwrap_or(default_comm_reach(role));
        Ok(match dispatch_parent_in_txn(self, txn, parent)? {
            Some((_, parent)) => reach.min(parent.comm),
            None => reach,
        })
    }
}

/// A queue row's agent-dispatch input, read strictly: `None` for a row that
/// is not an agent dispatch, an error for one whose input fails the codec.
pub(super) fn dispatch_input(row: &AttemptRecord) -> Result<Option<AgentDispatchInput>> {
    if row.kind != DREAMER_RUNNER_ATTEMPT_KIND {
        return Ok(None);
    }
    // An envelope that does not decode names no attempt type, so it is not
    // known to be an agent dispatch at all.
    let Ok(payload) = decode_dreamer_attempt_payload(&row.payload) else {
        return Ok(None);
    };
    if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
        return Ok(None);
    }
    decode_agent_dispatch_input(&payload.input).map(Some)
}

/// The real dispatch parent `parent` names: that attempt, or, for a
/// registered workflow wrapper, the wrapper's recorded parent. `None` when
/// there is none, or when it is not an agent dispatch.
pub(super) fn dispatch_parent_in_txn(
    dispatcher: &AgentDispatcher<'_>,
    txn: &heed::RoTxn<'_>,
    parent: Option<AttemptId>,
) -> Result<Option<(AttemptId, AgentDispatchInput)>> {
    let queue = AttemptQueue::new(dispatcher.vault);
    let Some(id) = parent else {
        return Ok(None);
    };
    let Some(mut row) = queue.get_in_txn(txn, id)? else {
        return Ok(None);
    };
    if super::workflow_record::is_wrapper(&row) {
        let Some(real) = dispatcher.workflow_authority_parent_in_txn(txn, Some(id))? else {
            return Ok(None);
        };
        row = queue
            .get_in_txn(txn, real)?
            .ok_or_else(|| invalid("workflow real parent is missing"))?;
    }
    Ok(dispatch_input(&row)?.map(|input| (row.id, input)))
}

/// One dispatch as the evaluator reads it: its attempt, the agent it runs,
/// its effective reach and project, and its real dispatch parent with that
/// parent's agent.
struct Dispatch {
    attempt: AttemptId,
    actor: EntityId,
    comm: CommReach,
    project: Option<EntityId>,
    parent: Option<(AttemptId, EntityId)>,
}

impl Dispatch {
    fn of(
        dispatcher: &AgentDispatcher<'_>,
        txn: &heed::RoTxn<'_>,
        row: &AttemptRecord,
        input: &AgentDispatchInput,
    ) -> Result<Self> {
        let payload = decode_dreamer_attempt_payload(&row.payload)?;
        let parent = match dispatch_parent_in_txn(dispatcher, txn, payload.parent_attempt)? {
            Some((id, input)) => Some((id, agent_dispatch_actor(&input)?.entity_ref())),
            None => None,
        };
        Ok(Self {
            attempt: row.id,
            actor: agent_dispatch_actor(input)?.entity_ref(),
            comm: super::comm_widen::effective_comm_in_txn(dispatcher.vault, txn, row.id, input)?,
            project: input.project_ref,
            parent,
        })
    }
}

/// Every live (non-terminal) agent dispatch, read in `txn`.
fn live_dispatches_in_txn(
    dispatcher: &AgentDispatcher<'_>,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<Dispatch>> {
    let mut live = Vec::new();
    for row in AttemptQueue::new(dispatcher.vault).list_in_txn(txn)? {
        if row.state.is_terminal() {
            continue;
        }
        if let Some(input) = dispatch_input(&row)? {
            live.push(Dispatch::of(dispatcher, txn, &row, &input)?);
        }
    }
    Ok(live)
}

/// The projects `actor`'s live dispatches work in.
pub(crate) fn live_dispatch_projects_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
) -> Result<Vec<EntityId>> {
    let mut projects = Vec::new();
    for row in AttemptQueue::new(vault).list_in_txn(txn)? {
        if row.state.is_terminal() {
            continue;
        }
        if let Some(input) = dispatch_input(&row)?
            && agent_dispatch_actor(&input)?.entity_ref() == actor
            && let Some(project) = input.project_ref
        {
            projects.push(project);
        }
    }
    Ok(projects)
}

/// A root dispatch's parent: the vault owner's PERSON, as the people roster
/// reads the owner (CALLS C10). A dispatch whose spawner is no agent run has
/// no other parent to hear from.
fn is_root_parent(vault: &Vault, txn: &heed::RoTxn<'_>, actor: EntityId) -> bool {
    crate::memory::actor_is_vault_owner_in_txn(vault, txn, actor, EdgeActorClass::Human)
        .unwrap_or(false)
}

/// Whether `actor` is `dispatch`'s parent or runs one of its live children.
/// Every reach includes both (CALLS C4).
fn is_parent_or_child(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    dispatch: &Dispatch,
    live: &[Dispatch],
    actor: EntityId,
) -> bool {
    let parent = match dispatch.parent {
        Some((_, parent)) => parent == actor,
        None => is_root_parent(vault, txn, actor),
    };
    parent
        || live.iter().any(|child| {
            child.actor == actor && child.parent.is_some_and(|(id, _)| id == dispatch.attempt)
        })
}

/// Whether `dispatch`'s real-parent chain passes through `ancestor`.
fn descends_from(
    dispatcher: &AgentDispatcher<'_>,
    txn: &heed::RoTxn<'_>,
    dispatch: &Dispatch,
    live: &[Dispatch],
    ancestor: AttemptId,
) -> Result<bool> {
    let queue = AttemptQueue::new(dispatcher.vault);
    let mut cursor = dispatch.parent.map(|(id, _)| id);
    let mut seen = HashSet::new();
    while let Some(id) = cursor {
        if id == ancestor {
            return Ok(true);
        }
        if !seen.insert(id) || seen.len() > MAX_LINEAGE_HOPS {
            return Err(invalid("dispatch lineage bound or cycle"));
        }
        cursor = match live.iter().find(|row| row.attempt == id) {
            Some(row) => row.parent.map(|(parent, _)| parent),
            None => match queue.get_in_txn(txn, id)? {
                Some(row) => dispatch_parent_in_txn(
                    dispatcher,
                    txn,
                    decode_dreamer_attempt_payload(&row.payload)?.parent_attempt,
                )?
                .map(|(parent, _)| parent),
                None => None,
            },
        };
    }
    Ok(false)
}

/// The narrowest reach from which `me` may address `target` (CALLS C4):
/// its parent or a live child at any reach; a live dispatch below it at
/// `Subtree`; its project's effective leader, or a live dispatch in that
/// exact project, at `Project`; anyone else at `Vault`.
fn needed_reach_in_txn(
    dispatcher: &AgentDispatcher<'_>,
    txn: &heed::RoTxn<'_>,
    me: &Dispatch,
    live: &[Dispatch],
    target: EntityId,
) -> Result<CommReach> {
    let vault = dispatcher.vault;
    if is_parent_or_child(vault, txn, me, live, target) {
        return Ok(CommReach::Parent);
    }
    for dispatch in live.iter().filter(|row| row.actor == target) {
        if descends_from(dispatcher, txn, dispatch, live, me.attempt)? {
            return Ok(CommReach::Subtree);
        }
    }
    if let Some(project) = me.project {
        let leads = vault
            .effective_project_in_txn(txn, project)?
            .is_some_and(|(_, effective)| effective.leader == target.to_hex());
        if leads
            || live
                .iter()
                .any(|row| row.actor == target && row.project == Some(project))
        {
            return Ok(CommReach::Project);
        }
    }
    Ok(CommReach::Vault)
}

/// Who a message is sent by, as the dial reads it.
pub(crate) enum SenderDispatch<'a> {
    /// An agent speaking from the live dispatch its host bound.
    Bound {
        attempt: &'a AttemptRecord,
        input: &'a AgentDispatchInput,
    },
    /// A person, the owner, the house mind, or an agent outside any live
    /// dispatch.
    Unbound { actor: EntityId },
}

/// Why the dial refused an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddressRefusal {
    /// The target is outside the sender's reach; `needed` is the narrowest
    /// reach that would admit it.
    OutboundReach { reach: CommReach, needed: CommReach },
    /// A live dispatch of the target hears only its parent and its children.
    TargetHearsParentOnly,
}

impl AddressRefusal {
    /// The stable refusal text.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::OutboundReach { .. } => "outbound_reach",
            Self::TargetHearsParentOnly => "target_hears_parent_only",
        }
    }

    /// The narrowest sender reach that would admit the target; `None` when
    /// no sender reach would, because the target's own dial refused.
    pub(crate) const fn needed_reach(self) -> Option<CommReach> {
        match self {
            Self::OutboundReach { needed, .. } => Some(needed),
            Self::TargetHearsParentOnly => None,
        }
    }
}

/// The dial's answer for one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddressDecision {
    Allow,
    Refuse(AddressRefusal),
}

/// Whether `sender` may address the actor `target`: the sender's reach must
/// cover it, and every live dispatch of the target must hear the sender
/// (the most restrictive wins). A storage or codec failure is an error,
/// never an allow.
pub(crate) fn may_address_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    sender: &SenderDispatch<'_>,
    target: EntityId,
) -> Result<AddressDecision> {
    address_in_txn(vault, txn, sender, target, true)
}

/// The target half of [`may_address_in_txn`] alone: every live dispatch of
/// `target` must hear the sender. A leader-to-leader message takes its
/// outbound rule from leader chat (CALLS C8) and this check still.
pub(crate) fn target_admits_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    sender: &SenderDispatch<'_>,
    target: EntityId,
) -> Result<AddressDecision> {
    address_in_txn(vault, txn, sender, target, false)
}

fn address_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    sender: &SenderDispatch<'_>,
    target: EntityId,
    outbound: bool,
) -> Result<AddressDecision> {
    let dispatcher = AgentDispatcher::new(vault);
    let live = live_dispatches_in_txn(&dispatcher, txn)?;
    let actor = match sender {
        SenderDispatch::Bound { attempt, input } => {
            let me = Dispatch::of(&dispatcher, txn, attempt, input)?;
            if outbound {
                let needed = needed_reach_in_txn(&dispatcher, txn, &me, &live, target)?;
                if needed > me.comm {
                    return Ok(AddressDecision::Refuse(AddressRefusal::OutboundReach {
                        reach: me.comm,
                        needed,
                    }));
                }
            }
            me.actor
        }
        SenderDispatch::Unbound { actor } => {
            // No lineage to measure: only the vault-wide reach reaches anyone.
            let reach = unbound_comm_reach();
            if outbound && reach < CommReach::Vault {
                return Ok(AddressDecision::Refuse(AddressRefusal::OutboundReach {
                    reach,
                    needed: CommReach::Vault,
                }));
            }
            *actor
        }
    };
    for dispatch in live
        .iter()
        .filter(|row| row.actor == target && row.comm == CommReach::Parent)
    {
        if !is_parent_or_child(vault, txn, dispatch, &live, actor) {
            return Ok(AddressDecision::Refuse(
                AddressRefusal::TargetHearsParentOnly,
            ));
        }
    }
    Ok(AddressDecision::Allow)
}
