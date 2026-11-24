//! Who may call the lane economy's doors (design pass 32 section 5; substrate
//! behind grants, 9 Nov): the vault owner under their own proof, or an agent
//! whose own live Grant from a live owner names the verb. That Grant's scope
//! must also reach the line the call acts on: a scope with no project reaches
//! every line, and one that names a project reaches the line of that project
//! and of every project descending from it. A door admits its caller before
//! its hooks fire ([`Memory::verb_grant_holder_admits`]); each act judges an
//! agent again in its own write ([`VerbGrantAgent::grant_in_txn`]), so a Grant
//! revoked between the two admits nothing. The verb row names this check as
//! `host_door_proof: "verb_grant_holder"`. Which verbs are the owner's acts
//! alone is each verb's own business: their rows prove `owner`.

use std::collections::BTreeSet;

use crate::authority::{
    NoStanding, PACT_STANDING_LAPSED, VerifiedSlip, principal_standing_covering_or_lapse_in_txn,
};
use crate::consent::AuthenticatedOwner;
use crate::federation::FederationGrant;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::{EdgeActorClass, EntityId, Vault};

/// A lane-economy door's caller, as the engine admitted it.
#[derive(Debug, Clone, Copy)]
pub enum VerbGrantHolder<'a> {
    /// The vault owner under their own proof.
    Owner(&'a AuthenticatedOwner),
    /// An agent under its own Grant naming the verb.
    Agent(&'a VerbGrantAgent),
}

impl VerbGrantHolder<'_> {
    /// The caller's actor id, as its act records it: the owner's revalidated
    /// in `txn`, or the agent's after its Grant admits it to `verb` over the
    /// line of `project` now.
    ///
    /// # Errors
    ///
    /// `forbidden` naming why; a store read failure.
    pub fn actor_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        verb: &str,
        project: EntityId,
    ) -> MemoryResult<EntityId> {
        match self {
            Self::Owner(owner) => Ok(owner.revalidate_in_txn(vault, txn)?),
            Self::Agent(agent) => {
                agent.grant_in_txn(vault, txn, verb, Some(project))?;
                Ok(agent.actor())
            }
        }
    }

    /// Admits the caller to `verb` again, whatever line it reaches: the
    /// owner's proof revalidated, or an agent's standing Grant naming the
    /// verb.
    ///
    /// # Errors
    ///
    /// `forbidden` naming why; a store read failure.
    pub fn admitted_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        verb: &str,
    ) -> MemoryResult<()> {
        match self {
            Self::Owner(owner) => owner
                .revalidate_in_txn(vault, txn)
                .map(drop)
                .map_err(Into::into),
            Self::Agent(agent) => agent.grant_in_txn(vault, txn, verb, None).map(drop),
        }
    }

    /// Whether the caller may read the line of `project`: the owner reads
    /// every line, an agent each line its Grant for `verb` reaches.
    ///
    /// # Errors
    ///
    /// A store read failure; a caller with no standing Grant at all is
    /// refused.
    pub fn reads_line_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        verb: &str,
        project: EntityId,
    ) -> MemoryResult<bool> {
        match self {
            Self::Owner(owner) => {
                owner.revalidate_in_txn(vault, txn)?;
                Ok(true)
            }
            Self::Agent(agent) => match agent.grant_in_txn(vault, txn, verb, Some(project)) {
                Ok(_) => Ok(true),
                Err(error) if error.code == MEMORY_CODE_FORBIDDEN => {
                    // Refuse a caller no Grant admits at all; hide only the
                    // lines its standing Grant does not reach.
                    agent.grant_in_txn(vault, txn, verb, None)?;
                    Ok(false)
                }
                Err(error) => Err(error),
            },
        }
    }
}

/// An agent caller of a lane-economy door, as its own handle bound it. Only
/// [`Memory::verb_grant_agent`] makes one; each act judges its Grant again in
/// its own write.
#[derive(Debug, Clone)]
pub struct VerbGrantAgent {
    actor: EntityId,
    class: EdgeActorClass,
    credential: Option<VerifiedSlip>,
}

impl VerbGrantAgent {
    /// The agent's actor id.
    #[must_use]
    pub fn actor(&self) -> EntityId {
        self.actor
    }

    /// The live Grant that admits this agent to `verb` now, as the standing
    /// rule picks it (one Grant answers alone, never a union): its actor
    /// binding holds, its presented credential is still live, and one live
    /// Grant from a live owner names it, lists the verb and, with `project`,
    /// reaches the line of that project.
    ///
    /// # Errors
    ///
    /// `forbidden` naming why; a store read failure.
    pub fn grant_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        verb: &str,
        project: Option<EntityId>,
    ) -> MemoryResult<EntityId> {
        crate::memory::verify_actor_binding_in_txn(vault, txn, self.actor, self.class)?;
        if let Some(slip) = &self.credential
            && !vault.capability_slip_is_live_in_txn(txn, slip)?
        {
            return Err(refused(verb, "the caller's credential is no longer live"));
        }
        let reached = match project {
            Some(project) => Some(project_and_ancestors_in_txn(vault, txn, project)?),
            None => None,
        };
        let covers = |grant: &FederationGrant| match (&reached, grant.authority_scope.project) {
            (None, _) | (Some(_), None) => true,
            (Some(reached), Some(scoped)) => reached.contains(&scoped),
        };
        let standing = match self.class {
            EdgeActorClass::Agent | EdgeActorClass::System => {
                principal_standing_covering_or_lapse_in_txn(
                    vault, txn, self.actor, self.class, verb, &covers,
                )?
            }
            EdgeActorClass::Human => Err(NoStanding::NotStanding),
        };
        match standing.map(|standing| standing.grant) {
            Ok(Some(grant))
                if reached.is_none()
                    || grant_covers_in_txn(vault, txn, self.actor, &grant, &covers)? =>
            {
                Ok(grant)
            }
            Ok(Some(_)) => Err(refused(
                verb,
                "no live Grant naming this verb reaches the line's project",
            )),
            Err(NoStanding::PactStandingLapsed) => Err(refused(verb, PACT_STANDING_LAPSED)),
            Ok(None) | Err(NoStanding::NotStanding) => Err(refused(
                verb,
                "no live Grant from a live owner names this agent and lists the verb",
            )),
        }
    }
}

impl Memory<'_> {
    /// Admits this handle's caller to the lane-economy verb `verb`. With
    /// `owner`, the caller's own proof decides: revalidated as a live owner
    /// of this vault and this handle's own human actor. Without one, the
    /// caller is this handle's agent, its presented credential still live,
    /// and one live Grant a live owner gave it must confer now and name the
    /// verb. Which line the call reaches is judged by the act.
    ///
    /// # Errors
    ///
    /// `forbidden` for a caller it does not admit; a store read failure.
    pub fn verb_grant_holder_admits(
        &self,
        owner: Option<&AuthenticatedOwner>,
        verb: &str,
    ) -> MemoryResult<()> {
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        crate::memory::verify_actor_binding_in_txn(vault, &txn, self.actor(), self.actor_class())?;
        if let Some(owner) = owner {
            if owner.revalidate_in_txn(vault, &txn)? != self.actor()
                || self.actor_class() != EdgeActorClass::Human
            {
                return Err(refused(
                    verb,
                    "the owner proof does not belong to this caller",
                ));
            }
            return Ok(());
        }
        self.verb_grant_agent()
            .grant_in_txn(vault, &txn, verb, None)
            .map(drop)
    }

    /// This handle's caller as an agent of a lane-economy door.
    #[must_use]
    pub fn verb_grant_agent(&self) -> VerbGrantAgent {
        VerbGrantAgent {
            actor: self.actor(),
            class: self.actor_class(),
            credential: self.presented_credential().cloned(),
        }
    }
}

/// Whether the Grant `grant`, which the standing rule picked for `agent`,
/// reaches the line: the covering pick falls back to the first standing
/// Grant when none covers, so the pick is checked again here.
fn grant_covers_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    grant: &EntityId,
    covers: &dyn Fn(&FederationGrant) -> bool,
) -> MemoryResult<bool> {
    Ok(
        crate::federation::agent_grants_for_store_in_txn(&vault.store, txn)?
            .into_iter()
            .find(|standing| standing.id == *grant && standing.grant.member_ref == agent)
            .is_some_and(|standing| covers(&standing.grant)),
    )
}

/// `project` and every project it descends from through the effective
/// parents of live projects, read in `txn`, as
/// [`crate::agent_dispatch::scope`]'s descent walk reads them: a project the
/// fold does not serve carries no path, so it neither joins nor leads on.
fn project_and_ancestors_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: EntityId,
) -> crate::Result<BTreeSet<EntityId>> {
    let mut reached = BTreeSet::new();
    let mut seen = BTreeSet::from([project]);
    let mut pending = vec![project];
    while let Some(next) = pending.pop() {
        let Some((_, effective)) = vault.effective_project_in_txn(txn, next)? else {
            continue;
        };
        reached.insert(next);
        for parent in effective.parents {
            if let Ok(parent) = EntityId::from_hex(&parent)
                && seen.insert(parent)
            {
                pending.push(parent);
            }
        }
    }
    Ok(reached)
}

/// The refusal of a caller `verb` does not admit.
pub(crate) fn refused(verb: &str, why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!(
            "{verb} takes the vault owner's own proof or an agent's own Grant that names it: {why}"
        ),
        &["Call it as the vault owner, or name the verb in the agent's Grant."],
    )
}
