//! The drafter's doors (FIX 12569): the owner lists versions, reads the
//! status and reverts a target to a retained version; an agent lists and
//! reverts under its own live Grant naming the act (DRAFTER-ACTIVATE = A +
//! revert: "the owner or the agent can revert to any of them"). Each door
//! judges its caller again in the snapshot it reads or writes.
//!
//! A revert moves the binding's pointer and then tells the attached serving
//! host, which restarts its own managed worker with the pointed-at head
//! (FIX 14976, `serving`). The status shows what each target's worker serves
//! now, and why a binding is not applied where it is not.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    BINDINGS, BindingMove, DRAFTER_READ_GRANT_VERB, DRAFTER_REVERT_GRANT_VERB, DrafterActor,
    DrafterBinding, DrafterEvent, DrafterEventKind, DrafterPolicy, DrafterServedView,
    DrafterServing, DrafterTarget, DrafterVersion, DrafterVersionState, EVENTS, VERSIONS, ancestry,
    ancestry_names_world, invalid, move_binding_in_txn, policy_in_txn, versions_by_id,
};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::store::drafter_custody::drafter_artifact_retained_in_txn;
use crate::{Vault, authority};

/// Which versions to list: every one, or one target's.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterListRequest {
    #[serde(default)]
    pub target: Option<DrafterTarget>,
}

/// One version as a reader sees it: what it is and where it stands, never
/// the ids its training read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterVersionView {
    pub id: EntityId,
    pub target: DrafterTarget,
    pub parent: DrafterServing,
    /// The recipe's name.
    pub recipe: String,
    pub state: DrafterVersionState,
    pub generation: u64,
    pub created_at: u64,
    pub updated_at: u64,
    /// How many distinct source records its whole ancestry trained on.
    pub sources: u64,
    /// Whether its sealed artifact's key still stands live.
    pub retained: bool,
    /// Whether its target's binding serves it now.
    pub serving: bool,
    /// Whether a revert to it would pass now: qualified, retained, the
    /// policy on, no excluded world in its ancestry, and not serving already.
    pub revertible: bool,
}

/// The status read: events after `events_after` only, when given.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterStatusRequest {
    #[serde(default)]
    pub events_after: Option<EntityId>,
}

/// The owner's policy, every bound target's pointer, what each target's
/// worker serves now, and the events, oldest first.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterStatus {
    pub policy: DrafterPolicy,
    pub bindings: Vec<DrafterBinding>,
    /// What serves each target now, as the serving host's worker proved it,
    /// and why a binding is not applied where it is not.
    pub served: Vec<DrafterServedView>,
    pub events: Vec<DrafterEvent>,
}

/// A revert of `version`'s target to `version`, at the binding generation
/// the caller read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterRevertRequest {
    pub version: EntityId,
    pub expected_binding_generation: u64,
}

/// The binding as the revert left it, and the event that records it;
/// `None` when the version already served.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrafterRevertReceipt {
    pub binding: DrafterBinding,
    pub event: Option<DrafterEvent>,
}

/// Who calls a drafter door.
enum Caller<'o> {
    Owner(&'o AuthenticatedOwner),
    Agent(EntityId),
}

/// `caller`'s standing in `txn` for an act under the Grant verb `verb`: the
/// owner's proof revalidated, or the agent's live Grant listing `verb`.
fn admit_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: &Caller<'_>,
    verb: &str,
) -> Result<DrafterActor> {
    match caller {
        Caller::Owner(owner) => Ok(DrafterActor::Owner(owner.revalidate_in_txn(vault, txn)?)),
        Caller::Agent(agent) => {
            authority::principal_standing_in_txn(vault, txn, *agent, EdgeActorClass::Agent, verb)?
                .ok_or_else(|| {
                    invalid("no live Grant from a live owner names this agent and lists the act")
                })?;
            Ok(DrafterActor::Agent(*agent))
        }
    }
}

/// The handle's own agent, or the refusal of any other caller.
fn agent_of(memory: &Memory<'_>, verb: &str, grant: &str) -> MemoryResult<EntityId> {
    if memory.actor_class() != EdgeActorClass::Agent {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!(
                "{verb} takes an agent's own live Grant naming {grant}: the caller is no agent"
            ),
            &[
                "Call the owner's door with the owner's own credential, or have the owner grant \
                 this agent the act by name.",
            ],
        ));
    }
    Ok(memory.actor())
}

/// The owner lists the vault's drafter versions, one target's or all.
///
/// # Errors
/// An owner proof that does not revalidate, and storage and custody faults.
pub fn list_drafters_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &DrafterListRequest,
) -> Result<Vec<DrafterVersionView>> {
    list_in(vault, &Caller::Owner(owner), input)
}

/// `vault.drafters.list_as`: the handle's own agent lists the vault's
/// drafter versions under its live Grant listing [`DRAFTER_READ_GRANT_VERB`].
///
/// # Errors
/// A caller that is no agent, an agent with no such Grant, and storage
/// faults.
pub fn list_drafters_as_agent(
    memory: &Memory<'_>,
    input: DrafterListRequest,
) -> MemoryResult<Vec<DrafterVersionView>> {
    let agent = agent_of(memory, "vault.drafters.list_as", DRAFTER_READ_GRANT_VERB)?;
    list_in(memory.vault(), &Caller::Agent(agent), &input).map_err(MemoryError::from)
}

fn list_in(
    vault: &Vault,
    caller: &Caller<'_>,
    input: &DrafterListRequest,
) -> Result<Vec<DrafterVersionView>> {
    let store = &vault.store;
    let txn = store.env.read_txn()?;
    admit_in_txn(vault, &txn, caller, DRAFTER_READ_GRANT_VERB)?;
    let policy = policy_in_txn(store, &txn)?;
    let versions = versions_by_id(store, &txn)?;
    let bindings: BTreeMap<[u8; 32], DrafterBinding> =
        BINDINGS.scan(store, &txn)?.into_iter().collect();
    let mut views = Vec::new();
    for version in versions.values() {
        if input
            .target
            .as_ref()
            .is_some_and(|target| *target != version.target)
        {
            continue;
        }
        let retained = match &version.artifact {
            Some(artifact) => {
                drafter_artifact_retained_in_txn(store, &txn, &version.id, &artifact.key_ref)?
            }
            None => false,
        };
        let serving = bindings
            .get(&version.target.key()?)
            .is_some_and(|binding| binding.serving == DrafterServing::Version(version.id));
        let sources: BTreeSet<EntityId> = ancestry(&versions, version)
            .iter()
            .flat_map(|step| step.dependencies.sources.iter().copied())
            .collect();
        let revertible = retained
            && version.state == DrafterVersionState::Qualified
            && policy.enabled
            && !serving
            && !ancestry_names_world(&versions, version, &policy.excluded_worlds);
        views.push(DrafterVersionView {
            id: version.id,
            target: version.target.clone(),
            parent: version.parent,
            recipe: version.recipe.id.clone(),
            state: version.state,
            generation: version.generation,
            created_at: version.created_at,
            updated_at: version.updated_at,
            sources: sources.len() as u64,
            retained,
            serving,
            revertible,
        });
    }
    Ok(views)
}

/// The owner reads the drafter status: the policy, every bound target's
/// pointer, and the events after `events_after` (all when none), oldest
/// first.
///
/// # Errors
/// An owner proof that does not revalidate, and storage faults.
pub fn drafter_status_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &DrafterStatusRequest,
) -> Result<DrafterStatus> {
    let store = &vault.store;
    let txn = store.env.read_txn()?;
    owner.revalidate_in_txn(vault, &txn)?;
    let policy = policy_in_txn(store, &txn)?;
    let bindings: Vec<DrafterBinding> = BINDINGS
        .scan(store, &txn)?
        .into_iter()
        .map(|(_, binding)| binding)
        .collect();
    let events = EVENTS
        .scan(store, &txn)?
        .into_iter()
        .filter(|(id, _)| input.events_after.is_none_or(|after| *id > after))
        .map(|(_, event)| event)
        .collect();
    drop(txn);
    let served = vault.drafter_served(&bindings);
    Ok(DrafterStatus {
        policy,
        bindings,
        served,
        events,
    })
}

/// The owner reverts `version`'s target to `version` at the binding
/// generation they read.
///
/// # Errors
/// A check of the revert that fails, an unknown version, and storage and
/// custody faults.
pub fn revert_drafter_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &DrafterRevertRequest,
) -> Result<DrafterRevertReceipt> {
    revert_in(vault, &Caller::Owner(owner), input)
}

/// `vault.drafters.revert_as`: the handle's own agent reverts `version`'s
/// target to `version` under its live Grant listing
/// [`DRAFTER_REVERT_GRANT_VERB`], checked again in the revert's write.
///
/// # Errors
/// A caller that is no agent, an agent with no such Grant, a check of the
/// revert that fails, an unknown version, and storage and custody faults.
pub fn revert_drafter_as_agent(
    memory: &Memory<'_>,
    input: DrafterRevertRequest,
) -> MemoryResult<DrafterRevertReceipt> {
    let agent = agent_of(
        memory,
        "vault.drafters.revert_as",
        DRAFTER_REVERT_GRANT_VERB,
    )?;
    revert_in(memory.vault(), &Caller::Agent(agent), &input).map_err(MemoryError::from)
}

/// Reverts in one write: the caller stands; the version is qualified, not
/// erased, keeps its artifact and that artifact's key stands live; the
/// policy is on and no excluded world is in its ancestry; the binding of
/// its target holds the same target pins and sits at the generation the
/// caller read. An erased version never comes back. A revert that moved the
/// binding tells the serving host after commit.
///
/// # Errors
/// Any check above that fails, an unknown version, and storage and custody
/// faults.
fn revert_in(
    vault: &Vault,
    caller: &Caller<'_>,
    input: &DrafterRevertRequest,
) -> Result<DrafterRevertReceipt> {
    let receipt = revert_in_txn(vault, caller, input)?;
    if receipt.event.is_some() {
        vault.notify_drafter_serving();
    }
    Ok(receipt)
}

fn revert_in_txn(
    vault: &Vault,
    caller: &Caller<'_>,
    input: &DrafterRevertRequest,
) -> Result<DrafterRevertReceipt> {
    vault.with_write_txn_grouped(|txn| {
        let store = &vault.store;
        let by = admit_in_txn(vault, txn, caller, DRAFTER_REVERT_GRANT_VERB)?;
        let version: DrafterVersion = VERSIONS
            .get(store, txn, &input.version)?
            .ok_or(Error::EntityNotFound)?;
        if version.state == DrafterVersionState::Erased {
            return Err(invalid("an erased drafter version never serves again"));
        }
        if version.state != DrafterVersionState::Qualified {
            return Err(invalid("only a qualified drafter version is reverted to"));
        }
        let Some(artifact) = version.artifact.as_ref() else {
            return Err(invalid("the drafter version keeps no artifact"));
        };
        if !drafter_artifact_retained_in_txn(store, txn, &version.id, &artifact.key_ref)? {
            return Err(invalid(
                "the drafter version's artifact is no longer retained",
            ));
        }
        let policy = policy_in_txn(store, txn)?;
        if !policy.enabled {
            return Err(invalid("the drafter policy is off"));
        }
        let versions = versions_by_id(store, txn)?;
        if ancestry_names_world(&versions, &version, &policy.excluded_worlds) {
            return Err(invalid("the drafter version trained on an excluded world"));
        }
        let key = version.target.key()?;
        let binding = BINDINGS
            .get(store, txn, &key)?
            .unwrap_or_else(|| DrafterBinding::stock(version.target.clone()));
        if binding.target != version.target {
            return Err(invalid(
                "the drafter version does not fit the binding's target",
            ));
        }
        if binding.generation != input.expected_binding_generation {
            return Err(invalid("the drafter binding moved since it was read"));
        }
        let to = DrafterServing::Version(version.id);
        if binding.serving == to {
            return Ok(DrafterRevertReceipt {
                binding,
                event: None,
            });
        }
        let previous = binding.serving;
        let (binding, event) = move_binding_in_txn(
            store,
            txn,
            &key,
            binding,
            BindingMove {
                to,
                previous,
                by,
                kind: DrafterEventKind::Revert {
                    version: version.id,
                },
                at: vault.now_recorded_at(),
            },
        )?;
        Ok(DrafterRevertReceipt {
            binding,
            event: Some(event),
        })
    })
}
