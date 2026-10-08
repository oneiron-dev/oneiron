//! What a task, an ask and an agent may do: the authority a task's facts
//! prove through the `ScopedTo` edges that reach them, whether an ask is
//! stale, whether an agent dispatches, wakes as a resident, and how far its
//! writes are bounded, and who holds the authority a scope ask is put to.
use super::{Decision, held_by_both};
use crate::agent_dispatch::{AgentDispatchTarget, AgentDispatcher, ResidentWakeMode};
use crate::consent::{
    ActionClass, ActionEnvelope, BoundClass, BoundEnvelope, StandingConsentGrant,
};
use crate::gate::PolicyApprovalCeiling;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_TASK};
use crate::task_authority::TaskAuthorityFacts;
use crate::task_verb::AskStanding;
use crate::{EdgeActorClass, EntityId, Result, Vault, WriteActor};
use std::cmp::Ordering;
use std::collections::BTreeSet;

/// Who owns a task, whether it is cancelled, and whom its owner assigned it
/// to, as the task's authority facts prove them: the fold of every fact a
/// `ScopedTo` edge reaches the task from (`Vault::task_authority_facts_in`),
/// which the owner-proof lens, the board's cancellation and the human
/// assignment witness all read. An acknowledgement only takes a task off the
/// board.
pub(super) struct TaskAuthority;

impl Decision for TaskAuthority {
    type Subject = EntityId;
    type Answer = TaskAuthorityFacts;

    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        held_by_both(vaults, ENTITY_TYPE_TASK)
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<Self::Answer>>> {
        let txn = vault.store.env.read_txn()?;
        Ok(subjects
            .iter()
            .map(|task| vault.task_authority_facts_in(&txn, *task).ok())
            .collect())
    }

    fn loosens(live: &TaskAuthorityFacts, restored: &TaskAuthorityFacts) -> bool {
        (restored.owner_ref.is_some() && restored.owner_ref != live.owner_ref)
            || (live.cancelled && !restored.cancelled)
            || (restored.human_assigner.is_some() && restored.human_assigner != live.human_assigner)
    }
}

/// Whether an ask is stale, which settles it with no decision and closes its
/// option links: its question's bytes, its members' presence, the holders of
/// the authority it was put to, and the task it is bound to
/// (`task_verb::ask_standing_in`, which reads them as the settlement cut
/// does). Every TASK both vaults hold is asked; the ask groups among them
/// answer. One the restored vault has settled reads nothing more.
pub(super) struct StaleAsks;

impl Decision for StaleAsks {
    type Subject = EntityId;
    type Answer = AskStanding;

    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        held_by_both(vaults, ENTITY_TYPE_TASK)
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<Self::Answer>>> {
        let txn = vault.store.env.read_txn()?;
        Ok(subjects
            .iter()
            .map(|group| {
                crate::task_verb::ask_standing_in(vault, &txn, *group)
                    .ok()
                    .flatten()
            })
            .collect())
    }

    fn loosens(live: &AskStanding, restored: &AskStanding) -> bool {
        live.stale && !restored.stale && !restored.settled
    }
}

/// Whether the dispatcher runs an agent definition: the live stored row, and
/// whether it is active, approved and enabled
/// (`AgentDispatcher::dispatchable_definition_in_txn`). A definition the
/// dispatcher refuses, for any reason, is one it does not run. A definition
/// deleted since, and not purged, keeps its shell, so it is one both vaults
/// hold.
pub(super) struct DispatchableAgents;

impl Decision for DispatchableAgents {
    type Subject = EntityId;
    type Answer = bool;

    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        held_by_both(vaults, ENTITY_TYPE_AGENT_DEF)
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<Self::Answer>>> {
        let dispatcher = AgentDispatcher::new(vault);
        let txn = vault.store.env.read_txn()?;
        Ok(subjects
            .iter()
            .map(|agent| {
                Some(
                    dispatcher
                        .dispatchable_definition_in_txn(&txn, &AgentDispatchTarget::Custom(*agent))
                        .is_ok(),
                )
            })
            .collect())
    }

    fn loosens(live: &bool, restored: &bool) -> bool {
        !live && *restored
    }

    fn refusal() -> Option<bool> {
        Some(false)
    }
}

/// What wakes an agent as a resident: its binding, which must name a home
/// message in its home room, goal records that resolve and an inbox bound to
/// the agent, or it binds nothing (`Vault::resident_agent`), and the inbox
/// and wake mode the resident inbox dispatch reads from it.
pub(super) struct ResidentWakes;

/// The inbox a resident reads, and which messages there wake it.
#[derive(Clone, Copy)]
pub(super) struct ResidentWake {
    inbox: EntityId,
    mode: ResidentWakeMode,
}

impl Decision for ResidentWakes {
    type Subject = EntityId;
    type Answer = Option<ResidentWake>;

    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        held_by_both(vaults, ENTITY_TYPE_AGENT_DEF)
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<Self::Answer>>> {
        Ok(subjects
            .iter()
            .map(|agent| {
                vault.resident_agent(*agent).ok().map(|spec| {
                    spec.map(|spec| ResidentWake {
                        inbox: spec.inbox_identity_ref,
                        mode: spec.wake,
                    })
                })
            })
            .collect())
    }

    fn loosens(live: &Option<ResidentWake>, restored: &Option<ResidentWake>) -> bool {
        let Some(restored) = restored.filter(|wake| wake.mode != ResidentWakeMode::Manual) else {
            return false;
        };
        live.is_none_or(|live| {
            live.inbox != restored.inbox || wakes_on(live.mode) < wakes_on(restored.mode)
        })
    }

    fn refusal() -> Option<Option<ResidentWake>> {
        Some(None)
    }
}

/// How many of the messages addressed to a resident wake it: none, those a
/// person sent, or all.
fn wakes_on(mode: ResidentWakeMode) -> u8 {
    match mode {
        ResidentWakeMode::Manual => 0,
        ResidentWakeMode::HumanMessages => 1,
        ResidentWakeMode::AllAddressed => 2,
    }
}

/// How far the gate lets an agent's writes go without asking: the bound its
/// own definition puts on it, restricted by its fork parent row's
/// (`gate::definition_only_ceiling_for_actor`), and the bound an owner's
/// introduction of it puts on it, through its introducer's
/// (`gate::resolve_foreign_agent_ceiling`). Asked of every definition both
/// vaults hold and every actor an introduction names.
pub(super) struct AgentCeilings;

/// The two bounds the gate reads for an agent; `None` bounds nothing.
pub(super) struct Ceilings {
    definition: Option<PolicyApprovalCeiling>,
    foreign: Option<PolicyApprovalCeiling>,
}

impl Decision for AgentCeilings {
    type Subject = EntityId;
    type Answer = Ceilings;

    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        let mut agents = held_by_both(vaults, ENTITY_TYPE_AGENT_DEF)?;
        for vault in vaults {
            let txn = vault.store.env.read_txn()?;
            agents.extend(crate::gate::introduced_foreign_agents(&vault.store, &txn)?);
        }
        Ok(agents)
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<Self::Answer>>> {
        let txn = vault.store.env.read_txn()?;
        Ok(subjects
            .iter()
            .map(|agent| {
                let actor = WriteActor::new(*agent, EdgeActorClass::Agent);
                let foreign =
                    crate::gate::resolve_foreign_agent_ceiling(&vault.store, &txn, actor).ok()?;
                Some(Ceilings {
                    definition: crate::gate::definition_only_ceiling_for_actor(
                        &vault.store,
                        &txn,
                        actor,
                    ),
                    foreign,
                })
            })
            .collect())
    }

    fn loosens(live: &Ceilings, restored: &Ceilings) -> bool {
        reach(restored.definition) > reach(live.definition)
            || reach(restored.foreign) > reach(live.foreign)
    }
}

/// How far a bound lets a write go without asking.
fn reach(ceiling: Option<PolicyApprovalCeiling>) -> u8 {
    match ceiling {
        Some(PolicyApprovalCeiling::Proposed) => 0,
        Some(PolicyApprovalCeiling::Auto) => 1,
        None => 2,
    }
}

/// Who holds the authority a scope ask is put to, and so whom it asks:
/// every addressable delegate and granting owner of a live action grant that
/// covers the scope (`Vault::ask_authority_holders_in_txn`). Asked of each
/// live action grant's own scope: a delegate who left or returned changes
/// the holders of that scope, and of every scope the grant covers alike.
pub(super) struct AskHolders;

/// A scope an ask can be put to: an action class within an envelope.
#[derive(PartialEq, Eq)]
pub(super) struct Scope {
    class: ActionClass,
    envelope: ActionEnvelope,
}

impl Scope {
    /// Every part of the scope, in the order scopes sort by.
    fn parts(&self) -> (&str, &[String], Option<&str>, Option<u64>, bool) {
        (
            self.class.as_str(),
            self.envelope.selectors(),
            self.envelope.target(),
            self.envelope.budget(),
            self.envelope.receipt_required(),
        )
    }
}

impl Ord for Scope {
    fn cmp(&self, other: &Self) -> Ordering {
        self.parts().cmp(&other.parts())
    }
}

impl PartialOrd for Scope {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Decision for AskHolders {
    type Subject = Scope;
    type Answer = BTreeSet<EntityId>;

    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        let mut scopes = BTreeSet::new();
        for vault in vaults {
            let txn = vault.store.env.read_txn()?;
            for grant in vault.active_standing_consent_grants_in_txn(&txn)? {
                let StandingConsentGrant::Action(action) = grant else {
                    continue;
                };
                if let (BoundClass::Action(class), BoundEnvelope::Action(envelope)) =
                    (action.bound().class(), action.bound().envelope())
                {
                    scopes.insert(Scope {
                        class: class.clone(),
                        envelope: envelope.clone(),
                    });
                }
            }
        }
        Ok(scopes)
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<Self::Answer>>> {
        let txn = vault.store.env.read_txn()?;
        Ok(subjects
            .iter()
            .map(|scope| {
                vault
                    .ask_authority_holders_in_txn(&txn, &scope.class, &scope.envelope)
                    .ok()
                    .map(|holders| holders.into_iter().collect())
            })
            .collect())
    }

    fn loosens(live: &BTreeSet<EntityId>, restored: &BTreeSet<EntityId>) -> bool {
        !restored.is_subset(live)
    }

    fn refusal() -> Option<BTreeSet<EntityId>> {
        Some(BTreeSet::new())
    }
}
